"""
Simulated Email Tool — monitored by MemGuard ToolProxy.

Detects dangerous email patterns:
  - Sending to suspicious domains
  - Phishing-like content
  - Mass mailing attempts
  - Credential exfiltration in email body
"""

from __future__ import annotations

import re
import time
from typing import Any

from .base import BaseTool, ToolOutcome, ToolResult

# Suspicious domains commonly used in phishing / data exfiltration
_SUSPICIOUS_DOMAINS: list[str] = [
    "tempmail", "throwaway", "mailinator", "guerrillamail",
    "10minutemail", "sharklasers", "yopmail", "trashmail",
    "fakeinbox", "mailnator", "spam4", "tempemail",
]

_SUSPICIOUS_PATTERNS: list[re.Pattern] = [
    re.compile(r"(?:password|credential|token|secret|key|login)\s*[:=]", re.I),
    re.compile(r"(?:https?://|http://)\S+(?:hook|callback|webhook|collect|grab)", re.I),
    re.compile(r"(?:all\s+(?:user|employee|customer|contact|member)s?\s*(?:list|email|address))", re.I),
]


class EmailTool(BaseTool):
    """Simulated email sending tool — all sends are logged and parameter-checked."""

    name = "send_email"
    description = "Send an email to one or more recipients"
    parameters: dict[str, Any] = {
        "type": "object",
        "properties": {
            "to": {
                "type": "array",
                "items": {"type": "string", "pattern": r"^[^@]+@[^@]+\.[^@]+$"},
                "description": "List of recipient email addresses",
                "minItems": 1,
            },
            "subject": {"type": "string", "description": "Email subject line", "maxLength": 200},
            "body": {"type": "string", "description": "Email body content"},
            "cc": {
                "type": "array",
                "items": {"type": "string", "pattern": r"^[^@]+@[^@]+\.[^@]+$"},
                "description": "CC recipients (optional)",
            },
            "priority": {
                "type": "string",
                "enum": ["low", "normal", "high", "urgent"],
                "description": "Email priority",
            },
        },
        "required": ["to", "subject", "body"],
    }

    def __init__(self) -> None:
        self._send_count = 0

    async def execute(self, params: dict[str, Any]) -> ToolResult:
        start = time.time()
        to_list = params.get("to", [])
        subject = params.get("subject", "")
        body = params.get("body", "")
        cc_list = params.get("cc", [])

        # ── Dangerous pattern detection ──
        warnings: list[str] = []

        # Check for suspicious recipient domains
        for addr in to_list + (cc_list or []):
            domain = addr.split("@")[-1].lower() if "@" in addr else ""
            if any(sus in domain for sus in _SUSPICIOUS_DOMAINS):
                warnings.append(f"suspicious_domain:{domain}")

        # Check for suspicious content patterns
        for pattern in _SUSPICIOUS_PATTERNS:
            if pattern.search(subject) or pattern.search(body):
                warnings.append(f"suspicious_content:{pattern.pattern[:40]}")

        # Bulk detection
        if len(to_list) > 10:
            warnings.append("bulk_recipient_count")

        self._send_count += 1
        elapsed = (time.time() - start) * 1000

        return ToolResult(
            tool_name=self.name,
            outcome=ToolOutcome.SIMULATED,
            output={
                "message_id": f"msg_{int(time.time())}_{self._send_count}",
                "to_count": len(to_list),
                "cc_count": len(cc_list or []),
                "subject_preview": subject[:80],
                "warnings": warnings,
            },
            execution_time_ms=round(elapsed, 2),
            simulated=True,
        )
