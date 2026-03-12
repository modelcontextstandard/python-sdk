"""MCS SMTP Adapter -- send e-mail via SMTP.

Encapsulates all SMTP wire-level details (``smtplib``, MIME construction)
behind a clean interface.  ToolDrivers never import ``smtplib``
directly, making the adapter swappable (e.g. for tests or transactional
mail APIs).
"""

from __future__ import annotations

import json
import logging
import smtplib
from email.message import EmailMessage
from email.utils import formataddr
from typing import Sequence

logger = logging.getLogger(__name__)


class SmtpAdapter:
    """Adapter for sending e-mail via SMTP.

    Parameters
    ----------
    host :
        SMTP server hostname (e.g. ``smtp.gmail.com``).
    user :
        Login username / e-mail address.
    password :
        Login password or app-specific password.
    port :
        Server port.  When *None* the port is chosen automatically:
        ``465`` for SSL, ``587`` for STARTTLS, ``25`` for plaintext.
    ssl :
        Connect via implicit SSL/TLS (port 465).  Defaults to ``False``.
    starttls :
        Upgrade a plaintext connection to TLS via the STARTTLS command
        (port 587).  Defaults to ``True``.
    sender :
        Default sender address (``From`` header).  When *None*, *user*
        is used as the sender.
    sender_name :
        Display name for the sender (e.g. ``"Danny Gerst"``).  When set,
        the ``From`` header is formatted as ``"Danny Gerst <email>"``
        following RFC 5322.
    """

    def __init__(
        self,
        *,
        host: str,
        user: str,
        password: str,
        port: int | None = None,
        ssl: bool = False,
        starttls: bool = True,
        sender: str | None = None,
        sender_name: str | None = None,
    ) -> None:
        self._host = host
        self._user = user
        self._password = password
        self._ssl = ssl
        self._starttls = starttls and not ssl
        self._sender_addr = sender or user
        self._sender = (
            formataddr((sender_name, self._sender_addr))
            if sender_name
            else self._sender_addr
        )

        if port is not None:
            self._port = port
        elif self._ssl:
            self._port = 465
        elif self._starttls:
            self._port = 587
        else:
            self._port = 25

    def _connect(self) -> smtplib.SMTP | smtplib.SMTP_SSL:
        """Open an authenticated SMTP connection."""
        if self._ssl:
            conn: smtplib.SMTP = smtplib.SMTP_SSL(self._host, self._port)
        else:
            conn = smtplib.SMTP(self._host, self._port)
            if self._starttls:
                conn.starttls()
        conn.login(self._user, self._password)
        return conn

    @staticmethod
    def _parse_recipients(raw: str) -> list[str]:
        """Split a comma-separated recipient string into a clean list."""
        return [addr.strip() for addr in raw.split(",") if addr.strip()]

    def send_message(
        self,
        *,
        to: str,
        subject: str,
        body: str,
        cc: str = "",
        bcc: str = "",
        reply_to: str = "",
    ) -> str:
        """Send a plain-text e-mail.

        Returns JSON with ``{status, message_id, recipients}``.
        """
        msg = EmailMessage()
        msg["From"] = self._sender
        msg["To"] = to
        msg["Subject"] = subject
        if cc:
            msg["Cc"] = cc
        if reply_to:
            msg["Reply-To"] = reply_to
        # LLMs often emit literal "\n" instead of real newlines.
        body = body.replace("\\n", "\n")
        msg.set_content(body)

        all_recipients = self._parse_recipients(to)
        if cc:
            all_recipients += self._parse_recipients(cc)
        if bcc:
            all_recipients += self._parse_recipients(bcc)

        try:
            conn = self._connect()
            try:
                conn.send_message(msg, to_addrs=all_recipients)
            finally:
                conn.quit()
        except Exception as exc:
            return json.dumps({"error": f"SMTP send failed: {exc}"})

        return json.dumps({
            "status": "sent",
            "from": self._sender,
            "recipients": all_recipients,
            "subject": subject,
        })

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
    ) -> str:
        """Send an HTML e-mail with optional plain-text fallback.

        Returns JSON with ``{status, message_id, recipients}``.
        """
        msg = EmailMessage()
        msg["From"] = self._sender
        msg["To"] = to
        msg["Subject"] = subject
        if cc:
            msg["Cc"] = cc
        if reply_to:
            msg["Reply-To"] = reply_to

        if text_body:
            msg.set_content(text_body)
            msg.add_alternative(html_body, subtype="html")
        else:
            msg.set_content(html_body, subtype="html")

        all_recipients = self._parse_recipients(to)
        if cc:
            all_recipients += self._parse_recipients(cc)
        if bcc:
            all_recipients += self._parse_recipients(bcc)

        try:
            conn = self._connect()
            try:
                conn.send_message(msg, to_addrs=all_recipients)
            finally:
                conn.quit()
        except Exception as exc:
            return json.dumps({"error": f"SMTP send failed: {exc}"})

        return json.dumps({
            "status": "sent",
            "from": self._sender,
            "recipients": all_recipients,
            "subject": subject,
        })

    def check_connection(self) -> str:
        """Test SMTP connectivity and authentication.

        Returns JSON with ``{status, server, port}``.
        """
        try:
            conn = self._connect()
            conn.quit()
        except Exception as exc:
            return json.dumps({
                "status": "error",
                "server": self._host,
                "port": self._port,
                "detail": str(exc),
            })

        return json.dumps({
            "status": "ok",
            "server": self._host,
            "port": self._port,
        })
