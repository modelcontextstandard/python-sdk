"""FlatCollector -- innermost base strategy.

Collects all tools from all registered drivers without any
transformation and dispatches ``execute_tool()`` by matching the
tool name across all drivers.
"""

from __future__ import annotations

from typing import Any

from mcs.driver.core import MCSToolDriver, Tool

from .strategy import ResolutionStrategy


class FlatCollector(ResolutionStrategy):
    """Collects all tools from all drivers and dispatches by name."""

    def list_tools(self, labeled: dict[str, MCSToolDriver]) -> list[Tool]:
        tools: list[Tool] = []
        for driver in labeled.values():
            tools.extend(driver.list_tools())
        return tools

    def execute_tool(
        self,
        labeled: dict[str, MCSToolDriver],
        tool_name: str,
        arguments: dict[str, Any],
    ) -> Any:
        for driver in labeled.values():
            if any(t.name == tool_name for t in driver.list_tools()):
                return driver.execute_tool(tool_name, arguments)
        raise ValueError(f"No tool '{tool_name}' found across registered drivers.")
