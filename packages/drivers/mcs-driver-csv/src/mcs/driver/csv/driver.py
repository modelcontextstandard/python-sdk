"""MCS Hybrid Driver for CSV file access.

Inherits prompt generation and LLM response parsing from ``DriverBase``.
Only adds ToolDriver delegation.

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


@dataclass(frozen=True)
class _CsvDriverMeta(DriverMeta):
    id: str = "a7b2f4d9-3e8c-4a1f-9b6d-5e2c8f1a4d7e"
    name: str = "CSV Driver"
    version: str = "0.1.0"
    bindings: tuple[DriverBinding, ...] = (
        DriverBinding(capability="csv", adapter="localfs", spec_format="Custom"),
    )
    supported_llms: tuple[str, ...] = ("*",)
    capabilities: tuple[str, ...] = ("standalone", "orchestratable")


class CsvDriver(DriverBase):
    """Hybrid CSV driver: DriverBase + ToolDriver delegation."""

    meta: DriverMeta = _CsvDriverMeta()

    def __init__(
        self,
        *,
        base_dir: str | None = None,
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
            from mcs.driver.csv.tooldriver import CsvToolDriver
            self._td = CsvToolDriver(base_dir=base_dir)

    # -- MCSToolDriver delegation ---------------------------------------------

    def list_tools(self) -> list[Tool]:
        return self._td.list_tools()

    def execute_tool(self, tool_name: str, arguments: dict[str, Any]) -> Any:
        return self._td.execute_tool(tool_name, arguments)
