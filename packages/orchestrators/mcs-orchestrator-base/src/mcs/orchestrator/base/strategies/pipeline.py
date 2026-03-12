"""ToolPipeline -- immutable decorator chain of ToolLayers.

Build a pipeline at construction time; the layer order you provide is
the order they are chained (first layer = innermost, last = outermost).
The pipeline itself is a ``ResolutionStrategy`` and can be passed
directly to ``BaseOrchestrator``.
"""

from __future__ import annotations

from typing import Any

from mcs.driver.core import MCSToolDriver, Tool

from .strategy import ResolutionStrategy
from .flat_collector import FlatCollector
from .layer import ToolLayer


class ToolPipeline(ResolutionStrategy):
    """Immutable decorator chain of :class:`ToolLayer` instances."""

    def __init__(self, layers: list[ToolLayer] | None = None) -> None:
        self._layers: tuple[ToolLayer, ...] = tuple(layers or [])
        chain: ResolutionStrategy = FlatCollector()
        for layer in self._layers:
            layer._inner = chain
            chain = layer
        self._chain: ResolutionStrategy = chain

    @property
    def layers(self) -> tuple[ToolLayer, ...]:
        """The layers in construction order (first = innermost)."""
        return self._layers

    def list_tools(self, labeled: dict[str, MCSToolDriver]) -> list[Tool]:
        return self._chain.list_tools(labeled)

    def execute_tool(
        self,
        labeled: dict[str, MCSToolDriver],
        tool_name: str,
        arguments: dict[str, Any],
    ) -> Any:
        return self._chain.execute_tool(labeled, tool_name, arguments)

    def get_instructions(self) -> str:
        """Collect instructions from all layers."""
        return "\n\n".join(
            inst
            for layer in self._layers
            if (inst := layer.get_instructions())
        )
