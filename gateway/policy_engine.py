"""
Security Policy Engine for tool call monitoring (allow / deny / ask).

The policy engine evaluates every tool call against a set of configurable rules.
Each rule maps a tool + parameter condition → a decision:

  - ALLOW — execute without restriction
  - DENY  — block with logged reason
  - ASK   — require human approval before execution

Architecture:
  PolicyEngine.evaluate(tool_name, params) → PolicyDecision
    iterates policies in priority order; the first match wins.
    Falls back to a configurable default_action (default: ASK).
"""

from __future__ import annotations

import re
import time
import uuid
from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum
from typing import Any, Literal, Optional


# ── Policy Types ───────────────────────────────────────────────────────────────


class PolicyAction(str, Enum):
    ALLOW = "allow"
    DENY = "deny"
    ASK = "ask"


class PolicyScope(str, Enum):
    """What the policy condition applies to."""
    GLOBAL = "global"          # Applies to all tools
    TOOL = "tool"              # Matches by tool name
    PARAM = "param"            # Matches a specific parameter value


@dataclass
class PolicyCondition:
    """
    A condition that a tool call must match for the policy to apply.

    Examples:
      PolicyCondition(field="to", pattern="@trusted\\.com$")   # email to trusted domain
      PolicyCondition(field="path", pattern="\\.txt$")          # file path ends with .txt
      PolicyCondition(field="url", pattern="^https://api\\.")   # api subdomain only
      PolicyCondition()  # empty = matches everything (catch-all)
    """
    field: str = ""              # Parameter name to check (empty = match any)
    pattern: str = ""            # Regex pattern (empty = match any value)
    negate: bool = False         # If True, match when pattern does NOT match

    def matches(self, params: dict[str, Any]) -> bool:
        """Check if the given parameters satisfy this condition."""
        if not self.field and not self.pattern:
            return True  # Empty condition matches everything

        if self.field:
            value = params.get(self.field)
            if value is None:
                return False
            # Convert list values to string for matching
            if isinstance(value, list):
                value = " ".join(str(v) for v in value)
            else:
                value = str(value)

            if self.pattern:
                try:
                    matched = bool(re.search(self.pattern, value, re.I))
                except re.error:
                    matched = False
            else:
                matched = bool(value)  # field exists and is non-empty

            return not matched if self.negate else matched

        # Only pattern is set (no field) — check all parameter values
        if self.pattern:
            for v in params.values():
                str_v = str(v) if not isinstance(v, list) else " ".join(str(x) for x in v)
                try:
                    if re.search(self.pattern, str_v, re.I):
                        return True
                except re.error:
                    continue
            return False

        return True


@dataclass
class PolicyRule:
    """
    A single security policy rule.

    Attributes:
      id:          Unique rule identifier
      tool_name:   Tool name this rule applies to ("*" = all tools)
      action:      ALLOW / DENY / ASK
      conditions:  List of conditions (ALL must match for rule to apply)
      priority:    Higher priority rules are evaluated first (default: 0)
      reason:      Human-readable explanation for the rule
      max_calls:   Optional rate limit (max calls per window_seconds)
      window_seconds: Rate limit time window
    """
    id: str = ""
    tool_name: str = "*"
    action: PolicyAction = PolicyAction.ASK
    conditions: list[PolicyCondition] = field(default_factory=list)
    priority: int = 0
    reason: str = ""
    max_calls: int = 0          # 0 = no rate limit
    window_seconds: int = 60

    def applies_to(self, tool_name: str, params: dict[str, Any]) -> bool:
        """Check if this rule applies to the given tool call."""
        if self.tool_name != "*" and self.tool_name != tool_name:
            return False
        return all(c.matches(params) for c in self.conditions)


@dataclass
class PolicyDecision:
    """Result of evaluating a tool call against policies."""
    action: PolicyAction
    rule_id: str
    reason: str
    approval_id: Optional[str] = None  # Set when action == ASK


# ── Rate Limiter ────────────────────────────────────────────────────────────────


@dataclass
class _RateBucket:
    timestamps: list[float] = field(default_factory=list)

    def hit(self, max_calls: int, window_seconds: int) -> bool:
        """Record a hit and return True if under the limit."""
        now = time.time()
        cutoff = now - window_seconds
        self.timestamps = [t for t in self.timestamps if t > cutoff]
        if len(self.timestamps) >= max_calls:
            return False  # Rate limited
        self.timestamps.append(now)
        return True


# ── Approval Store ──────────────────────────────────────────────────────────────


@dataclass
class PendingApproval:
    """A tool call waiting for human approval (action == ASK)."""
    approval_id: str
    tool_name: str
    params: dict[str, Any]
    rule_id: str
    reason: str
    created_at: str = field(default_factory=lambda: datetime.now(timezone.utc).isoformat())
    status: Literal["pending", "approved", "denied"] = "pending"
    decided_at: Optional[str] = None
    decided_by: str = ""


# ── Policy Engine ───────────────────────────────────────────────────────────────


# Default policies used when none are configured
_DEFAULT_POLICIES: list[PolicyRule] = [
    # High-risk tool: shell command — always ask unless it's a benign command
    PolicyRule(
        id="default_shell_deny_high_risk",
        tool_name="run_command",
        action=PolicyAction.DENY,
        conditions=[PolicyCondition(field="command", pattern=r"(?:rm\s+-[rf]|nc\s+-[el]|mkfs|dd\s+if=)")],
        priority=100,
        reason="High-risk shell command blocked by default policy",
    ),
    PolicyRule(
        id="default_shell_ask",
        tool_name="run_command",
        action=PolicyAction.ASK,
        conditions=[],
        priority=10,
        reason="Shell command execution requires human approval",
    ),
    # File I/O to sensitive paths — deny
    PolicyRule(
        id="default_file_deny_system",
        tool_name="file_io",
        action=PolicyAction.DENY,
        conditions=[PolicyCondition(field="path", pattern=r"(?:/etc/|/boot/|/var/log/|/\.ssh/|/\.git/)")],
        priority=100,
        reason="Access to system paths blocked by default policy",
    ),
    PolicyRule(
        id="default_file_deny_destructive",
        tool_name="file_io",
        action=PolicyAction.DENY,
        conditions=[
            PolicyCondition(field="operation", pattern=r"delete"),
            PolicyCondition(field="path", pattern=r"(?:/bin/|/sbin/|/usr/|/opt/)"),
        ],
        priority=90,
        reason="Deleting system binaries blocked by default policy",
    ),
    PolicyRule(
        id="default_file_ask_write",
        tool_name="file_io",
        action=PolicyAction.ASK,
        conditions=[PolicyCondition(field="operation", pattern=r"write|append|delete")],
        priority=10,
        reason="Write/delete operations require human approval",
    ),
    # API calls to internal networks — deny
    PolicyRule(
        id="default_api_deny_internal",
        tool_name="call_api",
        action=PolicyAction.DENY,
        conditions=[PolicyCondition(field="url", pattern=r"(?:localhost|127\.|10\.|192\.168\.|172\.1[6-9]|172\.2\d|172\.3[01])")],
        priority=100,
        reason="Internal network API calls blocked by default policy",
    ),
    PolicyRule(
        id="default_api_ask_external",
        tool_name="call_api",
        action=PolicyAction.ASK,
        conditions=[],
        priority=10,
        reason="External API calls require human approval",
    ),
    # Email to suspicious domains — deny
    PolicyRule(
        id="default_email_deny_suspicious",
        tool_name="send_email",
        action=PolicyAction.DENY,
        conditions=[PolicyCondition(field="to", pattern=r"(?:tempmail|throwaway|mailinator|10minutemail)")],
        priority=100,
        reason="Sending to disposable email domains blocked by default policy",
    ),
    PolicyRule(
        id="default_email_ask",
        tool_name="send_email",
        action=PolicyAction.ASK,
        conditions=[PolicyCondition(field="to", pattern=r".+")],
        priority=10,
        reason="Sending email requires human approval",
    ),
    # Unknown tools — ask by default
    PolicyRule(
        id="default_unknown_tool_ask",
        tool_name="*",
        action=PolicyAction.ASK,
        conditions=[],
        priority=0,
        reason="Unknown tool call requires human approval",
    ),
]


class PolicyEngine:
    """
    Security policy engine for tool call monitoring.

    Usage:
        engine = PolicyEngine()
        decision = engine.evaluate("send_email", {"to": ["evil@phish.com"], ...})
        # decision.action → DENY
    """

    def __init__(self, policies: Optional[list[PolicyRule]] = None):
        self._rules: list[PolicyRule] = policies or list(_DEFAULT_POLICIES)
        self._rate_buckets: dict[str, _RateBucket] = {}
        self._approvals: dict[str, PendingApproval] = {}
        self._approval_counter = 0

    # ── Policy management ──────────────────────────────────────────────────────

    def add_rule(self, rule: PolicyRule) -> None:
        """Add or replace a policy rule."""
        for i, existing in enumerate(self._rules):
            if existing.id == rule.id:
                self._rules[i] = rule
                return
        self._rules.append(rule)

    def remove_rule(self, rule_id: str) -> bool:
        """Remove a policy rule by ID. Returns True if found and removed."""
        for i, rule in enumerate(self._rules):
            if rule.id == rule_id:
                self._rules.pop(i)
                return True
        return False

    def list_rules(self) -> list[dict[str, Any]]:
        """Return all policy rules for display."""
        return [
            {
                "id": r.id,
                "tool_name": r.tool_name,
                "action": r.action.value,
                "conditions": [
                    {"field": c.field, "pattern": c.pattern, "negate": c.negate}
                    for c in r.conditions
                ],
                "priority": r.priority,
                "reason": r.reason,
            }
            for r in sorted(self._rules, key=lambda x: -x.priority)
        ]

    # ── Evaluation ─────────────────────────────────────────────────────────────

    def evaluate(self, tool_name: str, params: dict[str, Any]) -> PolicyDecision:
        """
        Evaluate a tool call against all policies.

        Rules are evaluated in priority order (highest first).
        The first matching rule determines the decision.
        Falls back to default_action if no rules match.
        """
        # Sort rules by priority descending, then evaluate
        sorted_rules = sorted(self._rules, key=lambda r: -r.priority)

        for rule in sorted_rules:
            if not rule.applies_to(tool_name, params):
                continue

            action = rule.action

            # Rate limit check
            if rule.max_calls > 0:
                bucket_key = f"{tool_name}:{rule.id}"
                if bucket_key not in self._rate_buckets:
                    self._rate_buckets[bucket_key] = _RateBucket()
                if not self._rate_buckets[bucket_key].hit(rule.max_calls, rule.window_seconds):
                    action = PolicyAction.DENY
                    rule.reason = f"{rule.reason} — rate limit exceeded ({rule.max_calls}/{rule.window_seconds}s)"

            # If ASK, create a pending approval
            approval_id = None
            if action == PolicyAction.ASK:
                approval_id = self._create_approval(tool_name, params, rule)

            return PolicyDecision(
                action=action,
                rule_id=rule.id,
                reason=rule.reason,
                approval_id=approval_id,
            )

        # Fallback — deny unknown/unmatched
        return PolicyDecision(
            action=PolicyAction.DENY,
            rule_id="(fallback)",
            reason=f"No policy rule matched for tool '{tool_name}'; blocked by default",
        )

    # ── Approval workflow ──────────────────────────────────────────────────────

    def _create_approval(self, tool_name: str, params: dict[str, Any], rule: PolicyRule) -> str:
        """Create a pending approval record."""
        self._approval_counter += 1
        aid = f"apv_{int(time.time())}_{self._approval_counter}"
        self._approvals[aid] = PendingApproval(
            approval_id=aid,
            tool_name=tool_name,
            params=params,
            rule_id=rule.id,
            reason=rule.reason,
        )
        return aid

    def approve(self, approval_id: str, decided_by: str = "admin") -> Optional[PendingApproval]:
        """Approve a pending tool call."""
        apv = self._approvals.get(approval_id)
        if apv is None or apv.status != "pending":
            return None
        apv.status = "approved"
        apv.decided_at = datetime.now(timezone.utc).isoformat()
        apv.decided_by = decided_by
        return apv

    def deny_approval(self, approval_id: str, decided_by: str = "admin") -> Optional[PendingApproval]:
        """Deny a pending tool call."""
        apv = self._approvals.get(approval_id)
        if apv is None or apv.status != "pending":
            return None
        apv.status = "denied"
        apv.decided_at = datetime.now(timezone.utc).isoformat()
        apv.decided_by = decided_by
        return apv

    def get_pending_approvals(self) -> list[PendingApproval]:
        """List all pending approvals."""
        return [
            apv for apv in self._approvals.values()
            if apv.status == "pending"
        ]

    def get_approval(self, approval_id: str) -> Optional[PendingApproval]:
        """Get a specific approval by ID."""
        return self._approvals.get(approval_id)

    @property
    def rule_count(self) -> int:
        return len(self._rules)
