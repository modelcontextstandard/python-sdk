"""MCS Hybrid Driver for filesystem access.

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
class _FsDriverMeta(DriverMeta):
    id: str = "a1b2c3d4-fs02-4000-9000-filesystem0002"
    name: str = "Filesystem MCS Driver"
    version: str = "0.3.0"
    bindings: tuple[DriverBinding, ...] = (
        DriverBinding(capability="filesystem", adapter="*", spec_format="Custom"),
    )
    supported_llms: tuple[str, ...] = ("*",)
    capabilities: tuple[str, ...] = ("standalone", "orchestratable")


class FilesystemDriver(DriverBase):
    """Hybrid filesystem driver: DriverBase + ToolDriver delegation."""

    meta: DriverMeta = _FsDriverMeta()

    def __init__(
        self,
        *,
        adapter: str = "localfs",
        custom_tool_description: str | None = None,
        custom_driver_system_message: str | None = None,
        prompt_strategy: PromptStrategy | None = None,
        _tooldriver: MCSToolDriver | None = None,
        **adapter_kwargs: Any,
    ) -> None:
        super().__init__(
            prompt_strategy=prompt_strategy,
            custom_tool_description=custom_tool_description,
            custom_system_message=custom_driver_system_message,
        )
        if _tooldriver is not None:
            self._td = _tooldriver
        else:
            from mcs.driver.filesystem.tooldriver import FilesystemToolDriver
            self._td = FilesystemToolDriver(adapter=adapter, **adapter_kwargs)

    # -- MCSToolDriver delegation ---------------------------------------------

    def list_tools(self) -> list[Tool]:
        return self._td.list_tools()

    def execute_tool(self, tool_name: str, arguments: dict[str, Any]) -> Any:
        return self._td.execute_tool(tool_name, arguments)
