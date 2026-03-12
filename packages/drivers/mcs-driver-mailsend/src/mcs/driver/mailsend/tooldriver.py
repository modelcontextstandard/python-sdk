"""MCS ToolDriver for sending e-mail.

Provides two tools for sending plain-text and HTML e-mail.
Delegates all I/O to the injected adapter so the same driver works
with any backend that satisfies ``MailsendPort`` (SMTP, Gmail API,
Microsoft Graph, ...).
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
    ToolParameter,
)

from .ports import MailsendPort

logger = logging.getLogger(__name__)


@dataclass(frozen=True)
class _MailsendToolDriverMeta(DriverMeta):
    id: str = "c4e8f1a2-mail-4003-9000-mailsendtd0001"
    name: str = "Mailsend MCS ToolDriver"
    version: str = "0.1.0"
    bindings: tuple[DriverBinding, ...] = (
        DriverBinding(capability="mailsend", adapter="*", spec_format="Custom"),
    )
    supported_llms: None = None
    capabilities: tuple[str, ...] = ("orchestratable",)


_TOOLS: list[Tool] = [
    Tool(
        name="send_message",
        title="Send a plain-text e-mail",
        description=(
            "Send an e-mail with a plain-text body.  Supports To, CC, BCC, "
            "and Reply-To headers."
        ),
        parameters=[
            ToolParameter(
                name="to",
                description="Comma-separated recipient addresses.",
                required=True,
                schema={"type": "string"},
            ),
            ToolParameter(
                name="subject",
                description="E-mail subject line.",
                required=True,
                schema={"type": "string"},
            ),
            ToolParameter(
                name="body",
                description="Plain-text message body.",
                required=True,
                schema={"type": "string", "format": "multiline"},
            ),
            ToolParameter(
                name="cc",
                description="Comma-separated CC addresses (default: none).",
                required=False,
                schema={"type": "string", "default": ""},
            ),
            ToolParameter(
                name="bcc",
                description="Comma-separated BCC addresses (default: none).",
                required=False,
                schema={"type": "string", "default": ""},
            ),
            ToolParameter(
                name="reply_to",
                description="Reply-To address (default: none).",
                required=False,
                schema={"type": "string", "default": ""},
            ),
        ],
    ),
    Tool(
        name="send_html_message",
        title="Send an HTML e-mail",
        description=(
            "Send an e-mail with an HTML body and an optional plain-text "
            "fallback.  Supports To, CC, BCC, and Reply-To headers."
        ),
        parameters=[
            ToolParameter(
                name="to",
                description="Comma-separated recipient addresses.",
                required=True,
                schema={"type": "string"},
            ),
            ToolParameter(
                name="subject",
                description="E-mail subject line.",
                required=True,
                schema={"type": "string"},
            ),
            ToolParameter(
                name="html_body",
                description="HTML message body.",
                required=True,
                schema={"type": "string", "format": "multiline"},
            ),
            ToolParameter(
                name="text_body",
                description="Plain-text fallback body (default: none).",
                required=False,
                schema={"type": "string", "default": "", "format": "multiline"},
            ),
            ToolParameter(
                name="cc",
                description="Comma-separated CC addresses (default: none).",
                required=False,
                schema={"type": "string", "default": ""},
            ),
            ToolParameter(
                name="bcc",
                description="Comma-separated BCC addresses (default: none).",
                required=False,
                schema={"type": "string", "default": ""},
            ),
            ToolParameter(
                name="reply_to",
                description="Reply-To address (default: none).",
                required=False,
                schema={"type": "string", "default": ""},
            ),
        ],
    ),
]


class MailsendToolDriver(MCSToolDriver):
    """Provides mail-sending operations as structured tools.

    The adapter can be selected by name (``adapter="smtp"``) or injected
    directly via ``_adapter`` for testing.  Any object satisfying
    ``MailsendPort`` works.
    """

    meta: DriverMeta = _MailsendToolDriverMeta()

    def __init__(
        self,
        *,
        adapter: str = "smtp",
        _adapter: MailsendPort | None = None,
        **adapter_kwargs: Any,
    ) -> None:
        if _adapter is not None:
            self._adapter: MailsendPort = _adapter
        elif adapter == "smtp":
            from mcs.adapter.smtp import SmtpAdapter
            self._adapter = SmtpAdapter(**adapter_kwargs)
        elif adapter == "gmail":
            from mcs.adapter.gmail import GmailAdapter
            self._adapter = GmailAdapter(**adapter_kwargs)
        else:
            raise ValueError(
                f"Unknown mailsend adapter: {adapter!r}.  "
                f"Available: 'smtp', 'gmail'.  Or inject a custom adapter via _adapter=..."
            )

    def list_tools(self) -> List[Tool]:
        return list(_TOOLS)

    def execute_tool(self, tool_name: str, arguments: Dict[str, Any]) -> Any:
        if tool_name == "send_message":
            return self._adapter.send_message(
                to=arguments["to"],
                subject=arguments["subject"],
                body=arguments["body"],
                cc=arguments.get("cc", ""),
                bcc=arguments.get("bcc", ""),
                reply_to=arguments.get("reply_to", ""),
            )

        if tool_name == "send_html_message":
            return self._adapter.send_html_message(
                to=arguments["to"],
                subject=arguments["subject"],
                html_body=arguments["html_body"],
                text_body=arguments.get("text_body", ""),
                cc=arguments.get("cc", ""),
                bcc=arguments.get("bcc", ""),
                reply_to=arguments.get("reply_to", ""),
            )

        raise ValueError(f"Unknown tool: {tool_name}")
