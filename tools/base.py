"""
Base tool abstraction for the MemGuard tool call monitoring system.

Every tool that agents interact with through MemGuard must implement BaseTool.
The ToolRegistry manages registered tools and is used by the ToolProxy
to look up and execute tool calls under security policy control.

Tools operate in simulation mode by default — they log what WOULD happen
without actually performing real-world side effects.
"""

from __future__ import annotations

import time
import uuid
from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum
from typing import Any, Optional


class ToolOutcome(str, Enum):
    SUCCESS = "success"
    FAILURE = "failure"
    BLOCKED = "blocked"
    SIMULATED = "simulated"


@dataclass
class ToolResult:
    """Result of a single tool execution."""

    tool_name: str
    outcome: ToolOutcome
    output: Any = None
    error: Optional[str] = None
    execution_time_ms: float = 0.0
    simulated: bool = True  # True = simulated execution (no real side effects)
    timestamp: str = field(default_factory=lambda: datetime.now(timezone.utc).isoformat())


class BaseTool(ABC):
    """
    Abstract base class for all tools monitored by MemGuard.

    Subclasses must set:
      name         — short unique identifier (e.g. "send_email")
      description  — human-readable description
      parameters   — JSON Schema dict describing expected parameters
    """

    name: str = ""
    description: str = ""
    parameters: dict[str, Any] = {}  # JSON Schema

    def __init_subclass__(cls, **kwargs: Any) -> None:
        super().__init_subclass__(**kwargs)
        if not cls.name:
            raise TypeError(f"{cls.__name__} must define a non-empty 'name' class variable")

    @abstractmethod
    async def execute(self, params: dict[str, Any]) -> ToolResult:
        """Execute the tool with the given parameters and return a result."""
        ...

    def validate_params(self, params: dict[str, Any]) -> list[str]:
        """
        Basic parameter validation against the JSON Schema.
        Returns a list of error messages (empty = valid).
        """
        errors: list[str] = []
        schema = self.parameters
        required = schema.get("required", [])
        properties = schema.get("properties", {})

        for req in required:
            if req not in params or params[req] is None:
                errors.append(f"Missing required parameter: '{req}'")

        for key, value in params.items():
            prop = properties.get(key)
            if prop is None:
                continue
            # Type check
            expected_type = prop.get("type")
            if expected_type == "string" and not isinstance(value, str):
                errors.append(f"Parameter '{key}' should be string, got {type(value).__name__}")
            elif expected_type == "integer" and not isinstance(value, int):
                errors.append(f"Parameter '{key}' should be integer, got {type(value).__name__}")
            elif expected_type == "boolean" and not isinstance(value, bool):
                errors.append(f"Parameter '{key}' should be boolean, got {type(value).__name__}")
            # Pattern check
            pattern = prop.get("pattern")
            if pattern and isinstance(value, str):
                import re
                if not re.match(pattern, value):
                    errors.append(f"Parameter '{key}' does not match required pattern")
            # Enum check
            enum_values = prop.get("enum")
            if enum_values and value not in enum_values:
                errors.append(f"Parameter '{key}' must be one of {enum_values}")

        return errors


class ToolRegistry:
    """Registry of all available tools."""

    def __init__(self) -> None:
        self._tools: dict[str, BaseTool] = {}

    def register(self, tool: BaseTool) -> None:
        """Register a tool instance by its name."""
        if tool.name in self._tools:
            raise ValueError(f"Tool '{tool.name}' is already registered")
        self._tools[tool.name] = tool

    def get(self, name: str) -> Optional[BaseTool]:
        """Look up a tool by name."""
        return self._tools.get(name)

    def list_tools(self) -> list[dict[str, Any]]:
        """Return metadata for all registered tools."""
        return [
            {
                "name": t.name,
                "description": t.description,
                "parameters": t.parameters,
            }
            for t in self._tools.values()
        ]

    @property
    def tool_count(self) -> int:
        return len(self._tools)
