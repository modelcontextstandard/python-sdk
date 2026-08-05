"""MCS Hybrid Driver for reading web pages.

Inherits prompt generation and LLM response parsing from ``BaseDriver``; adds
only ToolDriver delegation. Use it standalone (``get_driver_system_message()`` +
``process_llm_response()``) or plug it into an Orchestrator as a composable
ToolDriver.

See Section 4 of the MCS specification for the hybrid driver pattern.
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

from .ports import WebFetchPort
from .strategies import ContentStrategy


@dataclass(frozen=True)
class _WebfetchDriverMeta(DriverMeta):
    id: str = "b7a1c3d5-web-4002-9000-webfetchdrv001"
    name: str = "Webfetch MCS Driver"
    version: str = "0.1.0"
    bindings: tuple[DriverBinding, ...] = (
        DriverBinding(capability="webfetch", adapter="*", spec_format="Custom"),
    )
    supported_llms: tuple[str, ...] = ("*",)
    capabilities: tuple[str, ...] = ("standalone", "orchestratable")


class WebfetchDriver(BaseDriver):
    """Hybrid web-fetching driver: ``BaseDriver`` prompt engine + ``WebfetchToolDriver``."""

    meta: DriverMeta = _WebfetchDriverMeta()

    def __init__(
        self,
        *,
        connector: WebFetchPort | None = None,
        text_strategy: ContentStrategy | None = None,
        markdown_strategy: ContentStrategy | None = None,
        max_chars: int | None = None,
        allow_raw: bool = False,
        custom_tool_description: str | None = None,
        custom_driver_system_message: str | None = None,
        prompt_strategy: PromptStrategy | None = None,
        _tooldriver: MCSToolDriver | None = None,
        **connector_kwargs: Any,
    ) -> None:
        """
        Parameters
        ----------
        connector :
            Retrieval backend. Defaults to plain HTTP over ``mcs-adapter-http``.
        allow_raw :
            Permit ``format="raw"``. Off by default -- see
            :class:`~.tooldriver.RawNotAllowed` for why, and note that while off
            the format is not advertised to the model at all.
        """
        super().__init__(
            prompt_strategy=prompt_strategy,
            custom_tool_description=custom_tool_description,
            custom_system_message=custom_driver_system_message,
        )
        if _tooldriver is not None:
            self._td = _tooldriver
        else:
            from .tooldriver import DEFAULT_MAX_CHARS, WebfetchToolDriver

            self._td = WebfetchToolDriver(
                connector,
                text_strategy=text_strategy,
                markdown_strategy=markdown_strategy,
                max_chars=DEFAULT_MAX_CHARS if max_chars is None else max_chars,
                allow_raw=allow_raw,
                **connector_kwargs,
            )

    def list_tools(self) -> list[Tool]:
        return self._td.list_tools()

    def execute_tool(self, tool_name: str, arguments: dict[str, Any]) -> Any:
        return self._td.execute_tool(tool_name, arguments)
