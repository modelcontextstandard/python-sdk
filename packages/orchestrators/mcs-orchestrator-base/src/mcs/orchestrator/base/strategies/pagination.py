"""Pagination layer.

When the total number of tools exceeds ``page_size``, only one page is
exposed to the LLM at a time.  Two synthetic navigation tools
(``tools__next_page`` / ``tools__prev_page``) are injected so the LLM
can browse the full catalogue.  ``get_instructions()`` tells the LLM
which page it is currently viewing.
"""

from __future__ import annotations

import math
from typing import Any

from mcs.driver.core import MCSToolDriver, Tool

from .layer import ToolLayer


class PaginationLayer(ToolLayer):
    """Paginate large tool lists with synthetic navigation tools."""

    def __init__(self, page_size: int = 20, *, inner=None) -> None:
        super().__init__(inner)
        self._page_size = page_size
        self._offset = 0
        self._total = 0

    @property
    def page_size(self) -> int:
        return self._page_size

    @property
    def current_page(self) -> int:
        return self._offset // self._page_size + 1

    @property
    def total_pages(self) -> int:
        if self._total == 0:
            return 1
        return math.ceil(self._total / self._page_size)

    def _nav_tools(self) -> list[Tool]:
        tools: list[Tool] = []
        if self._offset + self._page_size < self._total:
            tools.append(Tool(
                name="tools__next_page",
                description="Show the next page of available tools.",
                parameters=[],
            ))
        if self._offset > 0:
            tools.append(Tool(
                name="tools__prev_page",
                description="Show the previous page of available tools.",
                parameters=[],
            ))
        return tools

    def list_tools(self, labeled: dict[str, MCSToolDriver]) -> list[Tool]:
        all_tools = self._inner.list_tools(labeled)
        self._total = len(all_tools)
        if self._total <= self._page_size:
            return all_tools
        page = all_tools[self._offset : self._offset + self._page_size]
        page.extend(self._nav_tools())
        return page

    def execute_tool(
        self,
        labeled: dict[str, MCSToolDriver],
        tool_name: str,
        arguments: dict[str, Any],
    ) -> Any:
        if tool_name == "tools__next_page":
            self._offset = min(self._offset + self._page_size, self._total - 1)
            return {
                "page": self.current_page,
                "total_pages": self.total_pages,
            }
        if tool_name == "tools__prev_page":
            self._offset = max(0, self._offset - self._page_size)
            return {
                "page": self.current_page,
                "total_pages": self.total_pages,
            }
        return self._inner.execute_tool(labeled, tool_name, arguments)

    def get_instructions(self) -> str | None:
        if self._total <= self._page_size:
            return None
        return (
            f"You see tools {self._offset + 1}"
            f"--{min(self._offset + self._page_size, self._total)} "
            f"of {self._total} (page {self.current_page}/{self.total_pages}). "
            f"Use 'tools__next_page' / 'tools__prev_page' to navigate."
        )
