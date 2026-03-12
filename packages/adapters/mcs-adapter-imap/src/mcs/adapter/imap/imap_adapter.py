"""MCS IMAP Adapter -- read-only e-mail access via IMAP.

Encapsulates all IMAP wire-level details (``imaplib``, MIME parsing)
behind a clean interface.  ToolDrivers never import ``imaplib``
directly, making the adapter swappable (e.g. for tests or Exchange
Web Services).

Only **read and organise** operations are exposed -- sending mail
is the job of an SMTP adapter.
"""

from __future__ import annotations

import email
import email.header
import email.utils
import imaplib
import json
import logging
import re
from contextlib import contextmanager
from typing import Any, Generator

logger = logging.getLogger(__name__)


class ImapAdapter:
    """Adapter for IMAP mailbox access.

    Parameters
    ----------
    host :
        IMAP server hostname (e.g. ``imap.gmail.com``).
    user :
        Login username / e-mail address.
    password :
        Login password or app-specific password.
    port :
        Server port.  When *None* the port is chosen automatically:
        ``993`` for SSL, ``143`` for STARTTLS or plaintext.
    ssl :
        Connect via implicit SSL/TLS (port 993).  Defaults to ``True``.
    starttls :
        Upgrade a plaintext connection to TLS via the STARTTLS command
        (port 143).  Only used when *ssl* is ``False``.
    """

    def __init__(
        self,
        *,
        host: str,
        user: str,
        password: str,
        port: int | None = None,
        ssl: bool = True,
        starttls: bool = False,
    ) -> None:
        self._host = host
        self._user = user
        self._password = password
        self._ssl = ssl
        self._starttls = starttls and not ssl

        if port is not None:
            self._port = port
        else:
            self._port = 993 if self._ssl else 143

    @contextmanager
    def _connection(self) -> Generator[imaplib.IMAP4 | imaplib.IMAP4_SSL, None, None]:
        """Open an authenticated IMAP connection, yield it, then close."""
        if self._ssl:
            conn: imaplib.IMAP4 = imaplib.IMAP4_SSL(self._host, self._port)
        else:
            conn = imaplib.IMAP4(self._host, self._port)
            if self._starttls:
                conn.starttls()
        try:
            conn.login(self._user, self._password)
            yield conn
        finally:
            try:
                conn.logout()
            except Exception:
                pass

    @staticmethod
    def _decode_header(raw: str | None) -> str:
        """Decode an RFC-2047-encoded header value into a plain string."""
        if not raw:
            return ""
        parts = email.header.decode_header(raw)
        decoded: list[str] = []
        for fragment, charset in parts:
            if isinstance(fragment, bytes):
                decoded.append(fragment.decode(charset or "utf-8", errors="replace"))
            else:
                decoded.append(fragment)
        return " ".join(decoded)

    @staticmethod
    def _extract_text(msg: email.message.Message) -> str:
        """Walk a MIME message and return the best plain-text body."""
        if msg.is_multipart():
            for part in msg.walk():
                ct = part.get_content_type()
                if ct == "text/plain":
                    payload = part.get_payload(decode=True)
                    if payload:
                        charset = part.get_content_charset() or "utf-8"
                        return payload.decode(charset, errors="replace")
            for part in msg.walk():
                ct = part.get_content_type()
                if ct == "text/html":
                    payload = part.get_payload(decode=True)
                    if payload:
                        charset = part.get_content_charset() or "utf-8"
                        return payload.decode(charset, errors="replace")
            return ""
        payload = msg.get_payload(decode=True)
        if payload:
            charset = msg.get_content_charset() or "utf-8"
            return payload.decode(charset, errors="replace")
        return ""

    def list_folders(self) -> str:
        """Return a JSON array of folder names on the server."""
        with self._connection() as conn:
            status, data = conn.list()
            if status != "OK":
                return json.dumps({"error": f"LIST failed: {status}"})
            folders: list[str] = []
            for item in data:
                if isinstance(item, bytes):
                    match = re.search(rb'"([^"]*)"$|(\S+)$', item)
                    if match:
                        name = (match.group(1) or match.group(2)).decode(
                            "utf-7-imap" if b"&" in (match.group(1) or match.group(2) or b"") else "utf-8",
                            errors="replace",
                        )
                        folders.append(name)
            return json.dumps(folders)

    def list_messages(self, folder: str = "INBOX", *, limit: int = 20) -> str:
        """List message headers in *folder* (newest first).

        Returns a JSON array of ``{uid, subject, from, date, flags}``.
        """
        with self._connection() as conn:
            status, _ = conn.select(f'"{folder}"', readonly=True)
            if status != "OK":
                return json.dumps({"error": f"Cannot select folder '{folder}'"})

            status, data = conn.uid("search", None, "ALL")
            if status != "OK" or not data[0]:
                return json.dumps([])

            uids = data[0].split()
            uids.reverse()
            uids = uids[:max(0, limit)]

            messages: list[dict[str, Any]] = []
            for uid_bytes in uids:
                uid_str = uid_bytes.decode()
                status, msg_data = conn.uid(
                    "fetch", uid_str, "(FLAGS BODY.PEEK[HEADER.FIELDS (SUBJECT FROM DATE)])"
                )
                if status != "OK" or not msg_data or not msg_data[0]:
                    continue
                raw_header = msg_data[0][1] if isinstance(msg_data[0], tuple) else msg_data[0]
                if isinstance(raw_header, bytes):
                    header_msg = email.message_from_bytes(raw_header)
                else:
                    continue

                flags_raw = msg_data[0][0] if isinstance(msg_data[0], tuple) else b""
                flags_match = re.search(rb"FLAGS \(([^)]*)\)", flags_raw)
                flags_str = flags_match.group(1).decode() if flags_match else ""

                messages.append({
                    "uid": int(uid_str),
                    "subject": self._decode_header(header_msg.get("Subject")),
                    "from": self._decode_header(header_msg.get("From")),
                    "date": header_msg.get("Date", ""),
                    "flags": flags_str,
                })

            return json.dumps(messages, ensure_ascii=False)

    def fetch_message(self, uid: int, folder: str = "INBOX") -> str:
        """Fetch the full message identified by *uid*.

        Returns JSON with ``{uid, subject, from, to, date, body, flags}``.
        """
        with self._connection() as conn:
            conn.select(f'"{folder}"', readonly=True)
            status, msg_data = conn.uid("fetch", str(uid), "(FLAGS RFC822)")
            if status != "OK" or not msg_data or not msg_data[0]:
                return json.dumps({"error": f"Message UID {uid} not found in '{folder}'"})

            raw = msg_data[0][1] if isinstance(msg_data[0], tuple) else msg_data[0]
            if not isinstance(raw, bytes):
                return json.dumps({"error": "Unexpected response format"})

            msg = email.message_from_bytes(raw)

            flags_raw = msg_data[0][0] if isinstance(msg_data[0], tuple) else b""
            flags_match = re.search(rb"FLAGS \(([^)]*)\)", flags_raw)
            flags_str = flags_match.group(1).decode() if flags_match else ""

            return json.dumps({
                "uid": uid,
                "subject": self._decode_header(msg.get("Subject")),
                "from": self._decode_header(msg.get("From")),
                "to": self._decode_header(msg.get("To")),
                "date": msg.get("Date", ""),
                "body": self._extract_text(msg),
                "flags": flags_str,
            }, ensure_ascii=False)

    def move_message(self, uid: int, destination: str, folder: str = "INBOX") -> str:
        """Move a message to *destination* folder via COPY + delete."""
        with self._connection() as conn:
            conn.select(f'"{folder}"')
            status, _ = conn.uid("copy", str(uid), f'"{destination}"')
            if status != "OK":
                return json.dumps({"error": f"COPY failed for UID {uid} -> '{destination}'"})
            conn.uid("store", str(uid), "+FLAGS", r"(\Deleted)")
            conn.expunge()
            return json.dumps({"moved": uid, "from": folder, "to": destination})

    def set_flags(self, uid: int, flags: str, *, remove: bool = False, folder: str = "INBOX") -> str:
        """Add or remove IMAP flags on a message.

        *flags* is a space-separated string, e.g. ``\\Seen \\Flagged``.
        """
        with self._connection() as conn:
            conn.select(f'"{folder}"')
            action = "-FLAGS" if remove else "+FLAGS"
            status, _ = conn.uid("store", str(uid), action, f"({flags})")
            if status != "OK":
                return json.dumps({"error": f"STORE {action} failed for UID {uid}"})
            return json.dumps({"uid": uid, "action": action, "flags": flags})

    def create_folder(self, name: str) -> str:
        """Create a new mailbox / folder."""
        with self._connection() as conn:
            status, _ = conn.create(f'"{name}"')
            if status != "OK":
                return json.dumps({"error": f"CREATE failed for '{name}'"})
            return json.dumps({"created": name})

    def search_messages(
        self,
        criteria: str = "ALL",
        folder: str = "INBOX",
        *,
        limit: int = 20,
    ) -> str:
        """Search messages matching IMAP *criteria* (e.g. ``FROM "alice"``).

        Returns a JSON array of ``{uid, subject, from, date}``.
        """
        with self._connection() as conn:
            status, _ = conn.select(f'"{folder}"', readonly=True)
            if status != "OK":
                return json.dumps({"error": f"Cannot select folder '{folder}'"})

            status, data = conn.uid("search", None, criteria)
            if status != "OK" or not data[0]:
                return json.dumps([])

            uids = data[0].split()
            uids.reverse()
            uids = uids[:max(0, limit)]

            messages: list[dict[str, Any]] = []
            for uid_bytes in uids:
                uid_str = uid_bytes.decode()
                status, msg_data = conn.uid(
                    "fetch", uid_str, "(BODY.PEEK[HEADER.FIELDS (SUBJECT FROM DATE)])"
                )
                if status != "OK" or not msg_data or not msg_data[0]:
                    continue
                raw_header = msg_data[0][1] if isinstance(msg_data[0], tuple) else msg_data[0]
                if isinstance(raw_header, bytes):
                    header_msg = email.message_from_bytes(raw_header)
                else:
                    continue
                messages.append({
                    "uid": int(uid_str),
                    "subject": self._decode_header(header_msg.get("Subject")),
                    "from": self._decode_header(header_msg.get("From")),
                    "date": header_msg.get("Date", ""),
                })

            return json.dumps(messages, ensure_ascii=False)
