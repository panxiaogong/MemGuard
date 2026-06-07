"""
Simulated Shell / Command Execution Tool — monitored by MemGuard ToolProxy.

Detects dangerous shell commands:
  - Reverse shells (nc, bash -i, etc.)
  - Destructive operations (rm -rf, dd, mkfs)
  - Privilege escalation (sudo, chmod 777, su)
  - Data exfiltration (curl/wget piping to shell)
  - Package manager manipulation
  - Encoded / obfuscated commands
"""

from __future__ import annotations

import re
import time
from typing import Any

from .base import BaseTool, ToolOutcome, ToolResult

# High-risk command patterns (from the scanner's constitutional.py — kept in sync)
_HIGH_RISK_COMMANDS: list[tuple[re.Pattern, str, float]] = [
    (re.compile(r"\bnc\s+-[el].*\d{4,5}\b", re.I), "reverse_shell_netcat", 1.0),
    (re.compile(r"base64\s+-d.*\|", re.I), "encoded_command_exec", 1.0),
    (re.compile(r"rm\s+-[rf]{1,2}\s+/", re.I), "destructive_delete", 0.95),
    (re.compile(r"chmod\s+777\s+/", re.I), "privilege_escalation_chmod", 0.9),
    (re.compile(r"(?:curl|wget)\s+\S+\s*\|\s*(?:ba|z|da)?sh\b", re.I), "piped_remote_exec", 1.0),
    (re.compile(r"\bsudo\s+(rm|dd|mkfs|fdisk|mke2fs)", re.I), "sudo_destructive", 0.95),
    (re.compile(r"\bshutdown\b|\breboot\b|\binit\s+0\b", re.I), "system_shutdown", 0.9),
    (re.compile(r"\bdd\s+if=/\w+\s+of=/\w+", re.I), "raw_device_write", 1.0),
    (re.compile(r"route\s+(add|delete|change)", re.I), "network_route_mod", 0.85),
    (re.compile(r"iptables\s+-\w+\s+(INPUT|OUTPUT|FORWARD)", re.I), "firewall_modification", 0.85),
    (re.compile(r"passwd\s+(root|\w+)", re.I), "password_change", 0.8),
    (re.compile(r"usermod\s+-[a-zG]", re.I), "user_modification", 0.8),
    (re.compile(r">\s*/dev/sd", re.I), "raw_disk_write", 1.0),
]

# Medium-risk commands that need context
_MEDIUM_RISK_COMMANDS: list[tuple[re.Pattern, str]] = [
    (re.compile(r"\bcurl\s+", re.I), "curl_network_request"),
    (re.compile(r"\bwget\s+", re.I), "wget_network_request"),
    (re.compile(r"\bsudo\s+", re.I), "sudo_use"),
    (re.compile(r"/etc/", re.I), "etc_access"),
    (re.compile(r"chmod\s+", re.I), "chmod_use"),
    (re.compile(r"chown\s+", re.I), "chown_use"),
    (re.compile(r"python[23]?\s+-c\s+", re.I), "inline_python_exec"),
    (re.compile(r"/dev/", re.I), "dev_access"),
]

# Injection / obfuscation patterns
_OBFUSCATION_PATTERNS: list[re.Pattern] = [
    re.compile(r"\$\(.*\)", re.I),       # $() command substitution
    re.compile(r"`[^`]+`"),               # backtick command substitution
    re.compile(r"\\x[0-9a-f]{2}", re.I),  # hex-encoded chars
    re.compile(r"eval\s+\$", re.I),       # eval
    re.compile(r"\$\{.*\}"),               # ${} variable substitution
    re.compile(r"exec\s+", re.I),         # exec
    re.compile(r"source\s+/", re.I),      # source external file
]


class ShellTool(BaseTool):
    """Simulated shell command execution tool — all commands logged and pattern-checked."""

    name = "run_command"
    description = "Execute a shell command or script in the sandbox environment"
    parameters: dict[str, Any] = {
        "type": "object",
        "properties": {
            "command": {
                "type": "string",
                "description": "Shell command to execute",
                "minLength": 1,
            },
            "cwd": {
                "type": "string",
                "description": "Working directory for command execution",
            },
            "timeout": {
                "type": "integer",
                "description": "Command timeout in seconds",
                "minimum": 1,
                "maximum": 300,
            },
            "env": {
                "type": "object",
                "description": "Additional environment variables",
            },
        },
        "required": ["command"],
    }

    def __init__(self) -> None:
        self._exec_count = 0

    async def execute(self, params: dict[str, Any]) -> ToolResult:
        start = time.time()
        command = params.get("command", "")

        # ── Security analysis ──
        high_risk_matches: list[str] = []
        medium_risk_matches: list[str] = []
        obfuscation_matches: list[str] = []

        # Check high-risk commands
        for pattern, label, _ in _HIGH_RISK_COMMANDS:
            if pattern.search(command):
                high_risk_matches.append(label)

        # Check medium-risk commands
        for pattern, label in _MEDIUM_RISK_COMMANDS:
            if pattern.search(command):
                medium_risk_matches.append(label)

        # Check obfuscation
        for pattern in _OBFUSCATION_PATTERNS:
            if pattern.search(command):
                obfuscation_matches.append(pattern.pattern[:30])

        # Determine severity
        severity = "info"
        if high_risk_matches:
            severity = "danger"
        elif obfuscation_matches:
            severity = "high"
        elif medium_risk_matches:
            severity = "warning"

        # Build warnings
        warnings = []
        warnings.extend(f"high_risk:{m}" for m in high_risk_matches)
        warnings.extend(f"medium_risk:{m}" for m in medium_risk_matches)
        warnings.extend(f"obfuscation:{m}" for m in obfuscation_matches)

        self._exec_count += 1
        elapsed = (time.time() - start) * 1000

        return ToolResult(
            tool_name=self.name,
            outcome=ToolOutcome.SIMULATED,
            output={
                "command_preview": command[:120],
                "command_length": len(command),
                "high_risk_matches": high_risk_matches,
                "medium_risk_matches": medium_risk_matches,
                "obfuscation_detected": len(obfuscation_matches) > 0,
                "warnings": warnings,
                "severity": severity,
            },
            execution_time_ms=round(elapsed, 2),
            simulated=True,
        )
