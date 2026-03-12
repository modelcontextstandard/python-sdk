"""MCS Composite ToolDriver for full e-mail access (read + send).

Stacks ``MailreadToolDriver`` and ``MailsendToolDriver`` into a single
ToolDriver that exposes all ten tools.  This demonstrates MCS driver
composition -- two single-responsibility drivers combined into one
unified interface for the LLM.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass
from typing import Any, Dict, List

from mcs.driver.core import (
    DriverBinding,
    DriverMeta,
    MCSToolDriver,
    Tool,
)

logger = logging.getLogger(__name__)


@dataclass(frozen=True)
class _MailToolDriverMeta(DriverMeta):
    id: str = "c4e8f1a2-mail-4005-9000-mailtooldrv001"
    name: str = "Mail MCS ToolDriver"
    version: str = "0.1.0"
    bindings: tuple[DriverBinding, ...] = (
        DriverBinding(capability="mailread", adapter="*", spec_format="Custom"),
        DriverBinding(capability="mailsend", adapter="*", spec_format="Custom"),
    )
    supported_llms: None = None
    capabilities: tuple[str, ...] = ("orchestratable",)


class MailToolDriver(MCSToolDriver):
    """Composite ToolDriver that stacks mailread + mailsend.

    Accepts either pre-built ToolDrivers or adapter names with kwargs
    for automatic construction.

    Parameters
    ----------
    read_adapter :
        Adapter name for mail reading (default: ``"imap"``).
    send_adapter :
        Adapter name for mail sending (default: ``"smtp"``).
    _read_driver :
        Inject a pre-built ``MailreadToolDriver`` (for testing / custom setups).
    _send_driver :
        Inject a pre-built ``MailsendToolDriver`` (for testing / custom setups).
    read_kwargs :
        Keyword arguments forwarded to the read adapter constructor.
    send_kwargs :
        Keyword arguments forwarded to the send adapter constructor.
    """

    meta: DriverMeta = _MailToolDriverMeta()

    def __init__(
        self,
        *,
        read_adapter: str = "imap",
        send_adapter: str = "smtp",
        _read_driver: MCSToolDriver | None = None,
        _send_driver: MCSToolDriver | None = None,
        read_kwargs: dict[str, Any] | None = None,
        send_kwargs: dict[str, Any] | None = None,
    ) -> None:
        if _read_driver is not None:
            self._read = _read_driver
        else:
            from mcs.driver.mailread import MailreadToolDriver
            self._read = MailreadToolDriver(adapter=read_adapter, **(read_kwargs or {}))

        if _send_driver is not None:
            self._send = _send_driver
        else:
            from mcs.driver.mailsend import MailsendToolDriver
            self._send = MailsendToolDriver(adapter=send_adapter, **(send_kwargs or {}))

        # Build lookup: tool_name → owning driver
        self._dispatch: dict[str, MCSToolDriver] = {}
        for tool in self._read.list_tools():
            self._dispatch[tool.name] = self._read
        for tool in self._send.list_tools():
            self._dispatch[tool.name] = self._send

    def list_tools(self) -> List[Tool]:
        return self._read.list_tools() + self._send.list_tools()

    def execute_tool(self, tool_name: str, arguments: Dict[str, Any]) -> Any:
        driver = self._dispatch.get(tool_name)
        if driver is None:
            raise ValueError(f"Unknown tool: {tool_name}")
        return driver.execute_tool(tool_name, arguments)
