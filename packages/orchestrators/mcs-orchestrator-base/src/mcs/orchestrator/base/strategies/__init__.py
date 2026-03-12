"""Pluggable resolution strategies and composable layers for orchestrators.

Shipped layers:

- ``NamespacingLayer`` -- prefix tool names with driver labels
- ``ToolSwitchingLayer`` -- only one driver active at a time
- ``PaginationLayer`` -- paginate large tool lists
- ``DetailLoadingLayer`` -- abbreviated descriptions with on-demand detail

Composition helpers:

- ``ToolPipeline`` -- immutable decorator chain of ``ToolLayer`` instances
- ``FlatCollector`` -- innermost base that collects tools from all drivers

To add a custom layer, subclass ``ToolLayer`` and override
``list_tools()``, ``execute_tool()``, and optionally
``get_instructions()``.
"""

from .strategy import ResolutionStrategy
from .layer import ToolLayer
from .flat_collector import FlatCollector
from .pipeline import ToolPipeline
from .namespacing import NamespacingLayer
from .tool_switching import ToolSwitchingLayer
from .pagination import PaginationLayer
from .detail_loading import DetailLoadingLayer

__all__ = [
    "ResolutionStrategy",
    "ToolLayer",
    "FlatCollector",
    "ToolPipeline",
    "NamespacingLayer",
    "ToolSwitchingLayer",
    "PaginationLayer",
    "DetailLoadingLayer",
]
