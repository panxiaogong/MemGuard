"""
Simulated API Call Tool — monitored by MemGuard ToolProxy.

Detects dangerous API calls:
  - Requests to known phishing/malware endpoints
  - Data exfiltration to external URLs
  - Internal network scanning
  - Credential transmission in query params
  - Webhook/callback abuse
"""

from __future__ import annotations

import re
import time
from typing import Any

from .base import BaseTool, ToolOutcome, ToolResult

# Internal / private IP patterns that agents should not be calling
_INTERNAL_HOST_PATTERNS: list[re.Pattern] = [
    re.compile(r"^127\.\d+\.\d+\.\d+", re.I),
    re.compile(r"^10\.\d+\.\d+\.\d+", re.I),
    re.compile(r"^172\.(1[6-9]|2\d|3[01])\.\d+\.\d+", re.I),
    re.compile(r"^192\.168\.\d+\.\d+", re.I),
    re.compile(r"^169\.254\.\d+\.\d+", re.I),
    re.compile(r"^0\.0\.0\.0$", re.I),
    re.compile(r"^localhost$", re.I),
    re.compile(r"^[0-9a-f]{0,4}::", re.I),  # IPv6 loopback / private
]

# High-risk API patterns (data exfiltration, destructive actions)
_HIGH_RISK_PATTERNS: list[re.Pattern] = [
    re.compile(r"(?:webhook|callback|notify|hook)", re.I),
    re.compile(r"(?:drop|truncate|delete)\s+(?:table|database|schema)", re.I),
    re.compile(r"(?:api|v[12])\/(?:key|secret|token|credential)", re.I),
    re.compile(r"(?:passwd|password|secret)\s*[:=]", re.I),
]

# Suspicious TLDs / URL patterns
_SUSPICIOUS_TLDS: set[str] = {
    ".xyz", ".top", ".gq", ".ml", ".cf", ".tk", ".ga",
    ".download", ".review", ".work", ".date", ".men",
    ".loan", ".click", ".link", ".win", ".bid",
}

SENSITIVE_PARAM_NAMES: set[str] = {
    "password", "secret", "token", "api_key", "apikey",
    "key", "passwd", "access_token", "auth", "credential",
    "session", "jwt", "refresh", "private_key",
}


class APITool(BaseTool):
    """Simulated API call tool — all calls are logged and URL-checked."""

    name = "call_api"
    description = "Make HTTP requests to external APIs"
    parameters: dict[str, Any] = {
        "type": "object",
        "properties": {
            "url": {
                "type": "string",
                "description": "Full URL to call (https://... or http://...)",
                "minLength": 5,
            },
            "method": {
                "type": "string",
                "enum": ["GET", "POST", "PUT", "PATCH", "DELETE"],
                "description": "HTTP method",
            },
            "headers": {
                "type": "object",
                "description": "HTTP headers as key-value pairs",
            },
            "body": {
                "type": "object",
                "description": "Request body for POST/PUT/PATCH",
            },
            "timeout": {
                "type": "integer",
                "description": "Request timeout in seconds",
                "minimum": 1,
                "maximum": 120,
            },
        },
        "required": ["url"],
    }

    def __init__(self) -> None:
        self._call_count = 0

    async def execute(self, params: dict[str, Any]) -> ToolResult:
        start = time.time()
        url = params.get("url", "")
        method = params.get("method", "GET")
        headers = params.get("headers", {}) or {}
        body = params.get("body", {}) or {}

        # ── Security checks ──
        blocked_reasons: list[str] = []
        severity: str = "info"

        # Check for internal network targets
        from urllib.parse import urlparse
        try:
            parsed = urlparse(url)
            hostname = parsed.hostname or ""
            # Check internal IP patterns
            for pattern in _INTERNAL_HOST_PATTERNS:
                if pattern.search(hostname):
                    blocked_reasons.append(f"internal_network_target:{hostname}")
                    severity = "danger"

            # Check for suspicious TLDs
            for tld in _SUSPICIOUS_TLDS:
                if hostname.endswith(tld):
                    blocked_reasons.append(f"suspicious_tld:{tld}")
                    severity = "warning"

            # Check URL params for sensitive data
            if parsed.query:
                for param_name in SENSITIVE_PARAM_NAMES:
                    if param_name in parsed.query.lower():
                        blocked_reasons.append(f"sensitive_data_in_url:{param_name}")
                        severity = "danger"

            # Check high-risk URL patterns
            for pattern in _HIGH_RISK_PATTERNS:
                if pattern.search(url):
                    blocked_reasons.append(f"high_risk_pattern:{pattern.pattern[:40]}")
                    severity = "warning"

        except Exception:
            blocked_reasons.append("url_parse_error")

        # Check headers for sensitive data
        if headers:
            for key, value in headers.items():
                if key.lower() in ("authorization", "x-api-key", "token", "api-key"):
                    blocked_reasons.append(f"sensitive_header:{key}")

        # Destructive HTTP methods
        if method in ("DELETE", "PUT", "PATCH") and not blocked_reasons:
            severity = "warning"

        self._call_count += 1
        elapsed = (time.time() - start) * 1000

        return ToolResult(
            tool_name=self.name,
            outcome=ToolOutcome.SIMULATED,
            output={
                "url": url[:120],
                "method": method,
                "status_code": 200,
                "response_size": 0,
                "warnings": blocked_reasons,
                "severity": severity,
            },
            execution_time_ms=round(elapsed, 2),
            simulated=True,
        )
