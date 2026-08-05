"""MCS Hybrid Driver for the web: search + fetch behind one interface.

The web counterpart to ``MailDriver``. Use it standalone with an LLM, or plug it
into an Orchestrator as a composable ToolDriver.

    driver = WebDriver(api_key=..., base_url="https://my-search-service")
    system = driver.get_driver_system_message()
    ...
    driver.process_llm_response(llm_output)

The model then has the pattern it wants: ``web_search`` to find sources,
``fetch_page`` to read the promising ones.
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


@dataclass(frozen=True)
class _WebDriverMeta(DriverMeta):
    id: str = "b7a1c3d5-web-4006-9000-webdriver00001"
    name: str = "Web MCS Driver"
    version: str = "0.1.0"
    bindings: tuple[DriverBinding, ...] = (
        DriverBinding(capability="websearch", adapter="*", spec_format="Custom"),
        DriverBinding(capability="webfetch", adapter="*", spec_format="Custom"),
    )
    supported_llms: tuple[str, ...] = ("*",)
    capabilities: tuple[str, ...] = ("standalone", "orchestratable")


class WebDriver(BaseDriver):
    """Hybrid web driver: ``BaseDriver`` prompt engine + ``WebToolDriver``."""

    meta: DriverMeta = _WebDriverMeta()

    def __init__(
        self,
        *,
        api_key: str | None = None,
        base_url: str | None = None,
        allow_raw: bool = False,
        search_kwargs: dict[str, Any] | None = None,
        fetch_kwargs: dict[str, Any] | None = None,
        custom_tool_description: str | None = None,
        custom_driver_system_message: str | None = None,
        prompt_strategy: PromptStrategy | None = None,
        _tooldriver: MCSToolDriver | None = None,
    ) -> None:
        super().__init__(
            prompt_strategy=prompt_strategy,
            custom_tool_description=custom_tool_description,
            custom_system_message=custom_driver_system_message,
        )
        if _tooldriver is not None:
            self._td = _tooldriver
        else:
            from .tooldriver import WebToolDriver

            self._td = WebToolDriver(
                api_key=api_key,
                base_url=base_url,
                allow_raw=allow_raw,
                search_kwargs=search_kwargs,
                fetch_kwargs=fetch_kwargs,
            )

    def list_tools(self) -> list[Tool]:
        return self._td.list_tools()

    def execute_tool(self, tool_name: str, arguments: dict[str, Any]) -> Any:
        return self._td.execute_tool(tool_name, arguments)
