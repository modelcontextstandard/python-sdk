"""ToolLayer -- composable decorator for resolution strategies.

A ``ToolLayer`` wraps another ``ResolutionStrategy`` (or another
``ToolLayer``) and can transform the tool list, intercept or delegate
tool execution, and contribute LLM instructions.

Subclass ``ToolLayer`` and override only what you need:

- ``list_tools()`` to transform the tool list
- ``execute_tool()`` to intercept calls or delegate to ``self._inner``
- ``get_instructions()`` to contribute text to the LLM system message
"""

from __future__ import annotations

from typing import Any

from mcs.driver.core import MCSToolDriver, Tool

from .strategy import ResolutionStrategy


class ToolLayer(ResolutionStrategy):
    """Decorator that wraps another ``ResolutionStrategy``.

    Default behaviour: delegate everything to ``self._inner``.
    Concrete layers override only the methods they need.
    """

    def __init__(self, inner: ResolutionStrategy | None = None) -> None:
        from .flat_collector import FlatCollector

        self._inner: ResolutionStrategy = inner or FlatCollector()

    def list_tools(self, labeled: dict[str, MCSToolDriver]) -> list[Tool]:
        return self._inner.list_tools(labeled)

    def execute_tool(
        self,
        labeled: dict[str, MCSToolDriver],
        tool_name: str,
        arguments: dict[str, Any],
    ) -> Any:
        return self._inner.execute_tool(labeled, tool_name, arguments)

    def get_instructions(self) -> str | None:
        """Return LLM instructions for this layer, or ``None``."""
        return None
