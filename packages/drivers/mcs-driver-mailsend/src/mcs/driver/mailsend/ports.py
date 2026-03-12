"""Adapter port for mail-sending drivers.

Defines the contract that any mail-sending adapter must satisfy.
Adapters fulfil this protocol through structural subtyping -- they do
**not** need to import or inherit from this module.

The reference implementation is ``SmtpAdapter`` from ``mcs-adapter-smtp``.
Future adapters (Gmail API, Microsoft Graph, ...) only need to implement
these methods.
"""

from __future__ import annotations

from typing import Protocol, runtime_checkable


@runtime_checkable
class MailsendPort(Protocol):
    """Contract that any mail-sending adapter must satisfy."""

    def send_message(
        self,
        *,
        to: str,
        subject: str,
        body: str,
        cc: str = "",
        bcc: str = "",
        reply_to: str = "",
    ) -> str: ...

    def send_html_message(
        self,
        *,
        to: str,
        subject: str,
        html_body: str,
        text_body: str = "",
        cc: str = "",
        bcc: str = "",
        reply_to: str = "",
    ) -> str: ...
