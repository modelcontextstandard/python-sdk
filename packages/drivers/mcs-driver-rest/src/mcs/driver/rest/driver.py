"""MCS Hybrid Driver for REST APIs.

Inherits prompt generation and LLM response parsing from ``DriverBase``.
Only adds ToolDriver delegation and HealthCheck support.

See Section 4 of the MCS specification for the hybrid driver pattern.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any

from mcs.driver.core import (
    DriverBase,
    MCSToolDriver,
    Tool,
    DriverMeta,
    DriverBinding,
    PromptStrategy,
)
from mcs.driver.core.mixins import SupportsHealthcheck, HealthCheckResult, HealthStatus


@dataclass(frozen=True)
class _RestDriverMeta(DriverMeta):
    id: str = "42144fa5-ed09-4c63-be1f-48122847835a"
    name: str = "REST MCS Driver"
    version: str = "0.3.0"
    bindings: tuple[DriverBinding, ...] = (
        DriverBinding(capability="rest", adapter="http", spec_format="OpenAPI"),
    )
    supported_llms: tuple[str, ...] = ("*",)
    capabilities: tuple[str, ...] = ("standalone", "orchestratable", "healthcheck")


class RestDriver(DriverBase, SupportsHealthcheck):
    """Hybrid REST driver: DriverBase + ToolDriver delegation + healthcheck."""

    meta: DriverMeta = _RestDriverMeta()

    def __init__(
        self,
        url: str = "",
        *,
        include_tags: list[str] | None = None,
        include_paths: list[str] | None = None,
        custom_tool_description: str | None = None,
        custom_driver_system_message: str | None = None,
        prompt_strategy: PromptStrategy | None = None,
        _tooldriver: MCSToolDriver | None = None,
        **http_kwargs: Any,
    ) -> None:
        super().__init__(
            prompt_strategy=prompt_strategy,
            custom_tool_description=custom_tool_description,
            custom_system_message=custom_driver_system_message,
        )
        if _tooldriver is not None:
            self._td = _tooldriver
        elif url:
            from mcs.driver.rest.tooldriver import RestToolDriver
            self._td = RestToolDriver(
                url,
                include_tags=include_tags,
                include_paths=include_paths,
                **http_kwargs,
            )
        else:
            raise ValueError("Either 'url' or '_tooldriver' must be provided")

    # -- MCSToolDriver delegation ---------------------------------------------

    def list_tools(self) -> list[Tool]:
        return self._td.list_tools()

    def execute_tool(self, tool_name: str, arguments: dict[str, Any]) -> Any:
        return self._td.execute_tool(tool_name, arguments)

    # -- SupportsHealthcheck delegation ---------------------------------------

    def healthcheck(self) -> HealthCheckResult:
        if isinstance(self._td, SupportsHealthcheck):
            return self._td.healthcheck()
        return {"status": HealthStatus.UNKNOWN}
