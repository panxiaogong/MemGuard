"""
Tool Call Proxy — intercepts all agent ↔ external-tool interactions.

Architecture:
  Agent → ToolProxy → PolicyEngine → (Tool or Block) → Audit → Response

The proxy:
  1. Receives tool call requests from agents
  2. Validates parameters against the tool's JSON Schema
  3. Evaluates the call against the PolicyEngine (allow/deny/ask)
  4. If ALLOW or ASK-approved: executes the tool (simulated), logs, returns result
  5. If DENY: blocks, logs, returns denial reason
  6. All decisions and executions are recorded in the audit log
"""

from __future__ import annotations

import time
from datetime import datetime, timezone
from typing import Any, Optional

from fastapi import APIRouter, HTTPException
from pydantic import BaseModel, Field

from ..audit.audit_log import StructuredAuditLogger
from ..tools.base import BaseTool, ToolRegistry, ToolResult
from .chain_monitor import ChainMonitor
from .policy_engine import PolicyAction, PolicyDecision, PolicyEngine, PolicyRule


# ── Request / Response schemas ──────────────────────────────────────────────────


class ToolCallRequest(BaseModel):
    tool_name: str = Field(description="Name of the tool to call")
    parameters: dict[str, Any] = Field(default_factory=dict, description="Tool parameters")
    session_hash: str = Field(default="", description="Session identifier for audit")
    source_id: str = Field(default="agent:unknown", description="Caller identifier")


class ToolCallResponse(BaseModel):
    status: str  # "allowed" | "blocked" | "needs_approval"
    result: Optional[dict] = None
    decision: str  # "allow" | "deny" | "ask"
    rule_id: str = ""
    reason: str = ""
    approval_id: Optional[str] = None
    execution_time_ms: float = 0.0


class PolicyRuleCreateRequest(BaseModel):
    id: str = Field(description="Unique rule identifier")
    tool_name: str = Field(default="*", description="Tool name this rule applies to (* = all)")
    action: str = Field(description="allow | deny | ask")
    conditions: list[dict] = Field(default_factory=list, description="List of condition objects")
    priority: int = Field(default=0, description="Rule priority (higher = evaluated first)")
    reason: str = Field(default="", description="Human-readable rule explanation")
    max_calls: int = Field(default=0, description="Rate limit max calls (0 = unlimited)")
    window_seconds: int = Field(default=60, description="Rate limit window")


class ApprovalDecisionRequest(BaseModel):
    approval_id: str
    decision: str  # "approve" | "deny"
    decided_by: str = "admin"


# ── Tool Proxy ──────────────────────────────────────────────────────────────────


class ToolProxy:
    """
    Central proxy that intercepts and monitors all agent tool calls.

    Usage:
        proxy = ToolProxy(audit_logger=audit_logger, chain_monitor=chain_monitor)
        proxy.register_default_tools()
        app.include_router(proxy.router, prefix="/v1/tools")
    """

    def __init__(
        self,
        audit_logger: Optional[StructuredAuditLogger] = None,
        policy_engine: Optional[PolicyEngine] = None,
        chain_monitor: Optional[ChainMonitor] = None,
    ):
        self._registry = ToolRegistry()
        self._policy = policy_engine or PolicyEngine()
        self._audit = audit_logger
        self._chain_monitor = chain_monitor
        self._call_count = 0
        self.router = APIRouter(tags=["tool_proxy"])
        self._register_routes()

    # ── Tool registration ──────────────────────────────────────────────────────

    def register_tool(self, tool: BaseTool) -> None:
        """Register a single tool."""
        self._registry.register(tool)

    def register_default_tools(self) -> None:
        """Register the built-in tool set."""
        from ..tools.email_tool import EmailTool
        from ..tools.file_tool import FileTool
        from ..tools.api_tool import APITool
        from ..tools.shell_tool import ShellTool

        self.register_tool(EmailTool())
        self.register_tool(FileTool())
        self.register_tool(APITool())
        self.register_tool(ShellTool())

    # ── Core call method ────────────────────────────────────────────────────────

    async def call_tool(
        self,
        tool_name: str,
        params: dict[str, Any],
        session_hash: str = "",
        source_id: str = "agent:unknown",
    ) -> ToolCallResponse:
        """
        Full tool call lifecycle: lookup → validate → policy check → execute → audit.
        """
        start = time.time()

        # ── Trace step: tool lookup ─────────────────────────────────────────────
        lookup_step = self._chain_monitor.start_step(
            "tool.lookup", input_summary=f"tool={tool_name}",
        ) if self._chain_monitor else None

        # 1. Look up tool
        tool = self._registry.get(tool_name)
        if tool is None:
            if self._chain_monitor:
                self._chain_monitor.finish_step(
                    lookup_step, status="error",
                    output_summary=f"unknown tool: {tool_name}",
                )
            self._log_action(
                action="TOOL_CALL_UNKNOWN",
                tool_name=tool_name,
                params=params,
                session=session_hash,
                source=source_id,
                detail=f"Unknown tool: {tool_name}",
                blocked=True,
            )
            return ToolCallResponse(
                status="blocked",
                decision="deny",
                rule_id="(unknown_tool)",
                reason=f"Tool '{tool_name}' is not registered",
                execution_time_ms=(time.time() - start) * 1000,
            )

        if self._chain_monitor:
            self._chain_monitor.finish_step(lookup_step, status="success")

        # ── Trace step: validation ──────────────────────────────────────────────
        validate_step = self._chain_monitor.start_step(
            "tool.validate",
            input_summary=f"params={str(list(params.keys()))}",
        ) if self._chain_monitor else None

        # 2. Validate parameters against schema
        validation_errors = tool.validate_params(params)
        if validation_errors:
            if self._chain_monitor:
                self._chain_monitor.finish_step(
                    validate_step, status="blocked",
                    output_summary="; ".join(validation_errors),
                )
            self._log_action(
                action="TOOL_CALL_INVALID_PARAMS",
                tool_name=tool_name,
                params=params,
                session=session_hash,
                source=source_id,
                detail="; ".join(validation_errors),
                blocked=True,
            )
            return ToolCallResponse(
                status="blocked",
                decision="deny",
                rule_id="(validation)",
                reason="; ".join(validation_errors),
                execution_time_ms=(time.time() - start) * 1000,
            )

        if self._chain_monitor:
            self._chain_monitor.finish_step(validate_step, status="success")

        # ── Trace step: policy evaluation ───────────────────────────────────────
        policy_step = self._chain_monitor.start_step(
            "policy.evaluate",
            input_summary=f"tool={tool_name}",
        ) if self._chain_monitor else None

        # 3. Policy evaluation
        decision = self._policy.evaluate(tool_name, params)

        if decision.action == PolicyAction.DENY:
            if self._chain_monitor:
                self._chain_monitor.finish_step(
                    policy_step, status="blocked",
                    output_summary=f"rule={decision.rule_id}: {decision.reason}",
                )
            self._log_action(
                action="TOOL_CALL_BLOCKED",
                tool_name=tool_name,
                params=params,
                session=session_hash,
                source=source_id,
                detail=f"policy={decision.rule_id}: {decision.reason}",
                blocked=True,
            )
            return ToolCallResponse(
                status="blocked",
                decision="deny",
                rule_id=decision.rule_id,
                reason=decision.reason,
                execution_time_ms=(time.time() - start) * 1000,
            )

        if decision.action == PolicyAction.ASK:
            if self._chain_monitor:
                self._chain_monitor.finish_step(
                    policy_step, status="pending",
                    output_summary=f"ask: rule={decision.rule_id} approval={decision.approval_id}",
                )
            self._log_action(
                action="TOOL_CALL_PENDING_APPROVAL",
                tool_name=tool_name,
                params=params,
                session=session_hash,
                source=source_id,
                detail=f"policy={decision.rule_id}: {decision.reason}",
                blocked=False,
            )
            return ToolCallResponse(
                status="needs_approval",
                decision="ask",
                rule_id=decision.rule_id,
                reason=decision.reason,
                approval_id=decision.approval_id,
                execution_time_ms=(time.time() - start) * 1000,
            )

        if self._chain_monitor:
            self._chain_monitor.finish_step(
                policy_step, status="success",
                output_summary=f"allow: rule={decision.rule_id}",
            )

        # ── Trace step: execute ────────────────────────────────────────────────
        exec_step = self._chain_monitor.start_step(
            "tool.execute",
            input_summary=f"tool={tool_name}",
        ) if self._chain_monitor else None

        # 4. ALLOW — execute the tool
        try:
            result = await tool.execute(params)
        except Exception as exc:
            if self._chain_monitor:
                self._chain_monitor.finish_step(
                    exec_step, status="error", output_summary=str(exc)[:200],
                )
            self._log_action(
                action="TOOL_CALL_ERROR",
                tool_name=tool_name,
                params=params,
                session=session_hash,
                source=source_id,
                detail=str(exc),
                blocked=False,
            )
            return ToolCallResponse(
                status="allowed",
                decision="allow",
                rule_id=decision.rule_id,
                reason="execution_error",
                result={"error": str(exc)},
                execution_time_ms=(time.time() - start) * 1000,
            )

        # 5. Log successful execution
        self._call_count += 1

        if self._chain_monitor:
            self._chain_monitor.finish_step(
                exec_step, status="success",
                output_summary=f"outcome={result.outcome.value}",
            )

        self._log_action(
            action="TOOL_CALL_EXECUTED",
            tool_name=tool_name,
            params=params,
            session=session_hash,
            source=source_id,
            detail=f"policy={decision.rule_id}: executed (outcome={result.outcome.value})",
            blocked=False,
            extra={
                "outcome": result.outcome.value,
                "execution_time_ms": result.execution_time_ms,
                "simulated": result.simulated,
            },
        )

        elapsed = (time.time() - start) * 1000
        return ToolCallResponse(
            status="allowed",
            decision="allow",
            rule_id=decision.rule_id,
            reason=decision.reason,
            result=result.output,
            execution_time_ms=round(elapsed, 2),
        )

    # ── Audit helper ────────────────────────────────────────────────────────────

    def _log_action(
        self,
        action: str,
        tool_name: str,
        params: dict[str, Any],
        session: str,
        source: str,
        detail: str,
        blocked: bool,
        extra: Optional[dict] = None,
    ) -> None:
        """Log a tool call event to the audit system."""
        if self._audit is None:
            return
        self._audit.log_interception(
            entry_id=f"tool:{tool_name}:{int(time.time())}",
            source_id=source,
            action=action,
            reason=detail,
            actor="gateway.tool_proxy",
            extra={
                "tool_name": tool_name,
                "session_hash": session,
                "params_summary": {k: str(v)[:80] for k, v in params.items()},
                "blocked": blocked,
                **(extra or {}),
            },
        )

    # ── FastAPI routes ──────────────────────────────────────────────────────────

    def _register_routes(self) -> None:
        router = self.router

        @router.post("/call")
        async def call_tool_endpoint(req: ToolCallRequest) -> ToolCallResponse:
            """Call a tool through the security proxy."""
            return await self.call_tool(
                tool_name=req.tool_name,
                params=req.parameters,
                session_hash=req.session_hash,
                source_id=req.source_id,
            )

        @router.get("/list")
        async def list_tools() -> dict:
            """List all registered tools with metadata."""
            return {
                "tools": self._registry.list_tools(),
                "count": self._registry.tool_count,
            }

        @router.post("/approve")
        async def approve_tool_call(req: ApprovalDecisionRequest) -> dict:
            """Approve or deny a pending tool call."""
            if req.decision == "approve":
                apv = self._policy.approve(req.approval_id, req.decided_by)
            elif req.decision == "deny":
                apv = self._policy.deny_approval(req.approval_id, req.decided_by)
            else:
                raise HTTPException(status_code=400, detail="decision must be 'approve' or 'deny'")

            if apv is None:
                raise HTTPException(status_code=404, detail="Approval not found or already decided")

            return {
                "status": "ok",
                "approval_id": apv.approval_id,
                "decision": req.decision,
                "tool_name": apv.tool_name,
            }

        @router.get("/pending")
        async def list_pending_approvals() -> dict:
            """List all pending tool call approvals."""
            pending = self._policy.get_pending_approvals()
            return {
                "pending": [
                    {
                        "approval_id": a.approval_id,
                        "tool_name": a.tool_name,
                        "params": a.params,
                        "reason": a.reason,
                        "created_at": a.created_at,
                    }
                    for a in pending
                ],
                "count": len(pending),
            }

        @router.get("/policies")
        async def list_policies() -> dict:
            """List all security policy rules."""
            return {
                "policies": self._policy.list_rules(),
                "count": self._policy.rule_count,
            }

        @router.post("/policies")
        async def add_policy(rule: PolicyRuleCreateRequest) -> dict:
            """Add a new policy rule."""
            from .policy_engine import PolicyAction, PolicyCondition

            conditions = [
                PolicyCondition(
                    field=c.get("field", ""),
                    pattern=c.get("pattern", ""),
                    negate=c.get("negate", False),
                )
                for c in rule.conditions
            ]
            policy_rule = PolicyRule(
                id=rule.id,
                tool_name=rule.tool_name,
                action=PolicyAction(rule.action),
                conditions=conditions,
                priority=rule.priority,
                reason=rule.reason,
                max_calls=rule.max_calls,
                window_seconds=rule.window_seconds,
            )
            self._policy.add_rule(policy_rule)
            return {"status": "ok", "rule_id": rule.id}

        @router.delete("/policies/{rule_id}")
        async def remove_policy(rule_id: str) -> dict:
            """Remove a policy rule by ID."""
            removed = self._policy.remove_rule(rule_id)
            if not removed:
                raise HTTPException(status_code=404, detail=f"Rule '{rule_id}' not found")
            return {"status": "ok", "rule_id": rule_id}

        @router.get("/stats")
        async def tool_proxy_stats() -> dict:
            """Get tool proxy statistics."""
            return {
                "registered_tools": self._registry.tool_count,
                "total_calls": self._call_count,
                "pending_approvals": len(self._policy.get_pending_approvals()),
                "policy_rules": self._policy.rule_count,
            }
