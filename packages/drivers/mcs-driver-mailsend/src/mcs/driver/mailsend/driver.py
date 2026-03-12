"""MCS Hybrid Driver for sending e-mail.

Inherits prompt generation and LLM response parsing from ``DriverBase``.
Only adds ToolDriver delegation.

See Section 4 of the MCS specification for the hybrid driver pattern.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any

from mcs.driver.core import (
    DriverBase,
    DriverBinding,
    DriverMeta,
    MCSToolDriver,
    PromptStrategy,
    Tool,
)


@dataclass(frozen=True)
class _MailsendDriverMeta(DriverMeta):
    id: str = "c4e8f1a2-mail-4004-9000-mailsenddrv001"
    name: str = "Mailsend MCS Driver"
    version: str = "0.1.0"
    bindings: tuple[DriverBinding, ...] = (
        DriverBinding(capability="mailsend", adapter="*", spec_format="Custom"),
    )
    supported_llms: tuple[str, ...] = ("*",)
    capabilities: tuple[str, ...] = ("standalone", "orchestratable")


class MailsendDriver(DriverBase):
    """Hybrid mail-sending driver: ``DriverBase`` prompt engine + ``MailsendToolDriver``.

    Use this driver standalone (with ``get_driver_system_message()`` and
    ``process_llm_response()``) or plug it into an Orchestrator as a
    composable ToolDriver.
    """

    meta: DriverMeta = _MailsendDriverMeta()

    def __init__(
        self,
        *,
        adapter: str = "smtp",
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
            from mcs.driver.mailsend.tooldriver import MailsendToolDriver

            self._td = MailsendToolDriver(adapter=adapter, **adapter_kwargs)

    def list_tools(self) -> list[Tool]:
        return self._td.list_tools()

    def execute_tool(self, tool_name: str, arguments: dict[str, Any]) -> Any:
        return self._td.execute_tool(tool_name, arguments)
