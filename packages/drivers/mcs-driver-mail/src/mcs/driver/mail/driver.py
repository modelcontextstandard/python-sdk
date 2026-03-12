"""MCS Hybrid Driver for full e-mail access (read + send).

Composite driver that stacks ``MailreadToolDriver`` and
``MailsendToolDriver``, inheriting prompt generation from ``DriverBase``.

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
class _MailDriverMeta(DriverMeta):
    id: str = "c4e8f1a2-mail-4006-9000-maildriver0001"
    name: str = "Mail MCS Driver"
    version: str = "0.1.0"
    bindings: tuple[DriverBinding, ...] = (
        DriverBinding(capability="mailread", adapter="*", spec_format="Custom"),
        DriverBinding(capability="mailsend", adapter="*", spec_format="Custom"),
    )
    supported_llms: tuple[str, ...] = ("*",)
    capabilities: tuple[str, ...] = ("standalone", "orchestratable")


class MailDriver(DriverBase):
    """Hybrid composite mail driver: read + send e-mail.

    Use this driver when you need the LLM to have full e-mail access
    (read, organise, and send) through a single driver.
    """

    meta: DriverMeta = _MailDriverMeta()

    def __init__(
        self,
        *,
        read_adapter: str = "imap",
        send_adapter: str = "smtp",
        read_kwargs: dict[str, Any] | None = None,
        send_kwargs: dict[str, Any] | None = None,
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
            from mcs.driver.mail.tooldriver import MailToolDriver

            self._td = MailToolDriver(
                read_adapter=read_adapter,
                send_adapter=send_adapter,
                read_kwargs=read_kwargs,
                send_kwargs=send_kwargs,
            )

    def list_tools(self) -> list[Tool]:
        return self._td.list_tools()

    def execute_tool(self, tool_name: str, arguments: dict[str, Any]) -> Any:
        return self._td.execute_tool(tool_name, arguments)
