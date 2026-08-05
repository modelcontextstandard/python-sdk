"""MCS Hybrid Driver for searching the web.

Inherits prompt generation and LLM response parsing from ``BaseDriver``; adds
only ToolDriver delegation.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any

from mcs.driver.core import (
    BaseDriver,
    DriverBinding,
    DriverMeta,
    MCSToolDriver,
    PromptStrategy,
    Tool,
)

from .ports import WebSearchPort


@dataclass(frozen=True)
class _WebsearchDriverMeta(DriverMeta):
    id: str = "b7a1c3d5-web-4004-9000-websearchdrv01"
    name: str = "Websearch MCS Driver"
    version: str = "0.1.0"
    bindings: tuple[DriverBinding, ...] = (
        DriverBinding(capability="websearch", adapter="*", spec_format="Custom"),
    )
    supported_llms: tuple[str, ...] = ("*",)
    capabilities: tuple[str, ...] = ("standalone", "orchestratable")


class WebsearchDriver(BaseDriver):
    """Hybrid search driver: ``BaseDriver`` prompt engine + ``WebsearchToolDriver``."""

    meta: DriverMeta = _WebsearchDriverMeta()

    def __init__(
        self,
        *,
        connector: WebSearchPort | None = None,
        api_key: str | None = None,
        base_url: str | None = None,
        custom_tool_description: str | None = None,
        custom_driver_system_message: str | None = None,
        prompt_strategy: PromptStrategy | None = None,
        _tooldriver: MCSToolDriver | None = None,
        **connector_kwargs: Any,
    ) -> None:
        super().__init__(
            prompt_strategy=prompt_strategy,
            custom_tool_description=custom_tool_description,
            custom_system_message=custom_driver_system_message,
        )
        if _tooldriver is not None:
            self._td = _tooldriver
        else:
            from .tooldriver import WebsearchToolDriver

            if api_key is not None:
                connector_kwargs["api_key"] = api_key
            if base_url is not None:
                connector_kwargs["base_url"] = base_url
            self._td = WebsearchToolDriver(connector, **connector_kwargs)

    def list_tools(self) -> list[Tool]:
        return self._td.list_tools()

    def execute_tool(self, tool_name: str, arguments: dict[str, Any]) -> Any:
        return self._td.execute_tool(tool_name, arguments)
