"""Pluggable resolution strategies for orchestrators.

Shipped strategies:

- ``NamespacingStrategy`` -- prefix tool names with driver labels
- ``ToolSwitchingStrategy`` -- only one driver active at a time

Planned (not yet implemented):

- **PriorityRoutingStrategy** -- resolve name collisions by driver priority
- **ContextRoutingStrategy** -- auto-select driver based on request context

To add a custom strategy, subclass ``ResolutionStrategy`` and implement
``list_tools()`` and ``resolve()``.
"""

from .strategy import ResolutionStrategy
from .namespacing import NamespacingStrategy
from .tool_switching import ToolSwitchingStrategy

__all__ = ["ResolutionStrategy", "NamespacingStrategy", "ToolSwitchingStrategy"]
