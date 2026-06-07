"""
Simulated File I/O Tool — monitored by MemGuard ToolProxy.

Detects dangerous file operations:
  - Reading/writing to system-critical paths
  - Writing executable content
  - Mass file operations
  - Path traversal attacks
"""

from __future__ import annotations

import re
import time
from pathlib import Path
from typing import Any

from .base import BaseTool, ToolOutcome, ToolResult

# Paths that should never be read or written by an AI agent
_BLOCKED_PATHS: list[re.Pattern] = [
    re.compile(r"/etc/(passwd|shadow|sudoers|crontab|hosts|pam\.d)", re.I),
    re.compile(r"/etc/environment", re.I),
    re.compile(r"/etc/kubernetes/", re.I),
    re.compile(r"/var/log/(auth|secure|syslog|messages)", re.I),
    re.compile(r"/var/lib/", re.I),
    re.compile(r"/\.ssh/", re.I),
    re.compile(r"/\.gnupg/", re.I),
    re.compile(r"/\.aws/", re.I),
    re.compile(r"/\.kube/", re.I),
    re.compile(r"/boot/", re.I),
    re.compile(r"/\.git/config", re.I),
    re.compile(r"~?/\.bashrc", re.I),
    re.compile(r"~?/\.zshrc", re.I),
    re.compile(r"~?/\.profile", re.I),
    re.compile(r"~?/\.bash_history", re.I),
]

# Suspicious file extensions (executables, scripts, sensitive data)
_SUSPICIOUS_EXTENSIONS: set[str] = {
    ".exe", ".bat", ".cmd", ".ps1", ".vbs", ".sh", ".bash",
    ".dll", ".so", ".dylib", ".sys", ".bin",
    ".pem", ".key", ".p12", ".pfx",
    ".sqlite", ".db", ".sql",
}

# Self-modification patterns — agent writing to its own files
_SELF_MOD_PATTERNS: list[re.Pattern] = [
    re.compile(r"agent|memguard|mem[_\s]?guard", re.I),
]


class FileTool(BaseTool):
    """Simulated file read/write tool — all operations logged and path-checked."""

    name = "file_io"
    description = "Read from or write to files in the workspace"
    parameters: dict[str, Any] = {
        "type": "object",
        "properties": {
            "operation": {
                "type": "string",
                "enum": ["read", "write", "append", "delete", "list", "copy", "move"],
                "description": "File operation to perform",
            },
            "path": {
                "type": "string",
                "description": "Target file path (absolute or relative to workspace)",
                "minLength": 1,
            },
            "content": {
                "type": "string",
                "description": "Content to write (only for write/append operations)",
            },
            "target_path": {
                "type": "string",
                "description": "Destination for copy/move operations",
            },
        },
        "required": ["operation", "path"],
    }

    def __init__(self, workspace_root: str = "/tmp/memguard_workspace") -> None:
        self._workspace = workspace_root
        self._op_count = 0

    async def execute(self, params: dict[str, Any]) -> ToolResult:
        start = time.time()
        operation = params.get("operation", "")
        path = params.get("path", "")
        content = params.get("content", "")

        # ── Security checks ──
        blocked_reasons: list[str] = []
        severity: str = "info"

        # Path traversal check
        if ".." in path or path.startswith("~"):
            blocked_reasons.append(f"path_traversal:{path}")

        # Blocked path patterns
        for pattern in _BLOCKED_PATHS:
            if pattern.search(path):
                blocked_reasons.append(f"blocked_path:{pattern.pattern[:40]}")
                severity = "danger"

        # Suspicious extension check
        ext = Path(path).suffix.lower()
        if ext in _SUSPICIOUS_EXTENSIONS:
            blocked_reasons.append(f"suspicious_extension:{ext}")
            severity = "warning"

        # Self-modification check
        for pattern in _SELF_MOD_PATTERNS:
            if pattern.search(path):
                blocked_reasons.append(f"self_modification:{path[:60]}")
                severity = "danger"

        # Dangerous write content
        if operation in ("write", "append") and content:
            if re.search(r"rm\s+-[rf]", content, re.I):
                blocked_reasons.append("destructive_content_in_write")
                severity = "danger"
            if re.search(r"chmod\s+777", content, re.I):
                blocked_reasons.append("privilege_escalation_content")
                severity = "danger"

        # Destructive operations
        if operation == "delete" and not blocked_reasons:
            severity = "warning"

        self._op_count += 1
        elapsed = (time.time() - start) * 1000

        return ToolResult(
            tool_name=self.name,
            outcome=ToolOutcome.SIMULATED,
            output={
                "operation": operation,
                "path": path,
                "file_exists_simulated": False,
                "content_size": len(content) if content else 0,
                "warnings": blocked_reasons,
                "severity": severity,
            },
            execution_time_ms=round(elapsed, 2),
            simulated=True,
        )
