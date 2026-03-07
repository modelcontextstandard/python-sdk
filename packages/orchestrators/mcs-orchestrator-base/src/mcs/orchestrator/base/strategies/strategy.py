"""Resolution strategy interface for orchestrators.

A ``ResolutionStrategy`` controls how an orchestrator exposes and
executes tools when multiple drivers are registered.

Concrete implementations shipped with this package:

- ``NamespacingLayer`` -- prefixes tool names with the driver label
  when more than one driver is registered.
- ``ToolSwitchingLayer`` -- only one driver is active at a time;
  the caller switches explicitly via ``set_active(label)``.

To add a custom strategy, subclass ``ToolLayer`` and override
``list_tools()``, ``execute_tool()``, and optionally
``get_instructions()``.
"""

from __future__ import annotations

from abc import ABC, abstractmethod
from typing import Any

from mcs.driver.core import MCSToolDriver, Tool


class ResolutionStrategy(ABC):
    """Decides how tools are presented and executed across multiple drivers."""

    @abstractmethod
    def list_tools(self, labeled: dict[str, MCSToolDriver]) -> list[Tool]:
        """Return the aggregated tool list for the LLM."""

    @abstractmethod
    def execute_tool(
        self,
        labeled: dict[str, MCSToolDriver],
        tool_name: str,
        arguments: dict[str, Any],
    ) -> Any:
        """Execute the named tool.  Resolve the target driver internally."""
