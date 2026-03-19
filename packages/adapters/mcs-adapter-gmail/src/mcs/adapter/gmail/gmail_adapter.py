"""MCS Gmail Adapter -- read and send e-mail via the Gmail REST API.

Implements both ``MailboxPort`` (read) and ``MailsendPort`` (send) so it can
be used with ``mcs-driver-mailread``, ``mcs-driver-mailsend``, or the
composite ``mcs-driver-mail``.

Depends only on ``HttpPort`` (a Protocol), **not** on any concrete HTTP
implementation.  Pass an ``HttpAdapter`` from ``mcs-adapter-http``, a
future ``httpx``-based adapter, or any object with a matching ``request``
method.

The adapter is **auth-agnostic**: it receives an ``access_token`` (or a
callable that returns one) and never touches OAuth flows itself.  This
makes it work with Auth0 Token Vault, a manual OAuth2 refresh flow,
a service account, or any future credential provider.
"""

from __future__ import annotations

import base64
import json
import logging
from email.message import EmailMessage
from email.utils import formataddr
from typing import Any, Callable, Union

from .ports import HttpPort

logger = logging.getLogger(__name__)

_BASE = "https://gmail.googleapis.com/gmail/v1/users/me"

# Maps IMAP-style flag names to Gmail label operations.
_FLAG_TO_LABEL: dict[str, tuple[str, bool]] = {
    "\\Seen": ("UNREAD", True),       # Seen → remove UNREAD
    "\\Flagged": ("STARRED", False),   # Flagged → add STARRED
    "\\Deleted": ("TRASH", False),     # Deleted → add TRASH
}


class GmailAdapter:
    """Adapter for reading and sending e-mail via the Gmail REST API.

    Parameters
    ----------
    access_token :
        A Google OAuth2 access token (string), a zero-argument callable
        that returns a fresh token, **or** *None* when ``_credential``
        is provided instead.
    sender_name :
        Optional display name for the ``From`` header (e.g. ``"Danny Gerst"``).
    timeout :
        HTTP request timeout in seconds (used when creating the default
        ``HttpAdapter``).
    _credential :
        Any object satisfying ``CredentialProvider`` (``get_token(scope) -> str``).
        When provided, ``access_token`` may be omitted -- the adapter calls
        ``_credential.get_token("gmail")`` automatically.
    _http :
        Any object satisfying ``HttpPort`` (e.g. ``HttpAdapter`` from
        ``mcs-adapter-http``).  When *None*, a default ``HttpAdapter``
        is created.  Pass your own to configure proxies, SSL settings,
        or to swap in a different HTTP backend (e.g. httpx).
    """

    def __init__(
        self,
        *,
        access_token: Union[str, Callable[[], str], None] = None,
        sender_name: str | None = None,
        timeout: int = 30,
        _credential: Any | None = None,
        _http: HttpPort | None = None,
    ) -> None:
        if _credential is not None:
            self._token: Union[str, Callable[[], str]] = lambda: _credential.get_token("gmail")
        elif access_token is not None:
            self._token = access_token
        else:
            raise ValueError("Either 'access_token' or '_credential' must be provided")
        self._sender_name = sender_name
        if _http is not None:
            self._http: HttpPort = _http
        else:
            from mcs.adapter.http import HttpAdapter
            self._http = HttpAdapter(timeout=timeout)

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    def _get_token(self) -> str:
        if callable(self._token):
            return self._token()
        return self._token

    def _auth_headers(self) -> dict[str, str]:
        return {"Authorization": f"Bearer {self._get_token()}"}

    def _get(self, path: str, params: dict[str, Any] | None = None) -> Any:
        raw = self._http.request(
            "GET", f"{_BASE}{path}",
            params=params,
            headers=self._auth_headers(),
        )
        return json.loads(raw)

    def _post(self, path: str, body: dict[str, Any]) -> Any:
        raw = self._http.request(
            "POST", f"{_BASE}{path}",
            json_body=body,
            headers=self._auth_headers(),
        )
        return json.loads(raw)

    @staticmethod
    def _extract_header(headers: list[dict[str, str]], name: str) -> str:
        for h in headers:
            if h.get("name", "").lower() == name.lower():
                return h.get("value", "")
        return ""

    @staticmethod
    def _decode_body(payload: dict[str, Any]) -> str:
        """Recursively extract the text body from a Gmail message payload."""
        mime = payload.get("mimeType", "")

        # Simple single-part message
        body_data = payload.get("body", {}).get("data")
        if body_data and mime.startswith("text/"):
            return base64.urlsafe_b64decode(body_data + "==").decode("utf-8", errors="replace")

        # Multipart -- prefer text/plain, fall back to text/html
        parts = payload.get("parts", [])
        plain = ""
        html = ""
        for part in parts:
            part_mime = part.get("mimeType", "")
            data = part.get("body", {}).get("data")
            if data and part_mime == "text/plain":
                plain = base64.urlsafe_b64decode(data + "==").decode("utf-8", errors="replace")
            elif data and part_mime == "text/html":
                html = base64.urlsafe_b64decode(data + "==").decode("utf-8", errors="replace")
            # Nested multipart
            if part.get("parts"):
                nested = GmailAdapter._decode_body(part)
                if nested:
                    plain = plain or nested

        return plain or html

    def _get_profile(self) -> dict[str, str]:
        """Fetch the authenticated user's email address."""
        data = self._get("/profile")
        return {"email": data.get("emailAddress", "")}

    # ------------------------------------------------------------------
    # MailboxPort implementation (7 methods)
    # ------------------------------------------------------------------

    def list_folders(self) -> str:
        """List Gmail labels (analogous to IMAP folders)."""
        data = self._get("/labels")
        labels = [lbl["name"] for lbl in data.get("labels", [])]
        return json.dumps(sorted(labels))

    def list_messages(self, folder: str = "INBOX", *, limit: int = 20) -> str:
        """List message summaries in a label."""
        params: dict[str, Any] = {"labelIds": folder, "maxResults": limit}
        data = self._get("/messages", params=params)

        messages = []
        for msg_stub in data.get("messages", []):
            msg = self._get(f"/messages/{msg_stub['id']}", params={"format": "metadata",
                            "metadataHeaders": ["From", "Subject", "Date"]})
            headers = msg.get("payload", {}).get("headers", [])
            messages.append({
                "uid": msg["id"],
                "from": self._extract_header(headers, "From"),
                "subject": self._extract_header(headers, "Subject"),
                "date": self._extract_header(headers, "Date"),
                "snippet": msg.get("snippet", ""),
                "labels": msg.get("labelIds", []),
            })

        return json.dumps(messages)

    def fetch_message(self, uid: int | str, folder: str = "INBOX") -> str:
        """Fetch a full message by ID."""
        msg = self._get(f"/messages/{uid}", params={"format": "full"})
        headers = msg.get("payload", {}).get("headers", [])
        body = self._decode_body(msg.get("payload", {}))

        return json.dumps({
            "uid": msg["id"],
            "thread_id": msg.get("threadId", ""),
            "from": self._extract_header(headers, "From"),
            "to": self._extract_header(headers, "To"),
            "cc": self._extract_header(headers, "Cc"),
            "subject": self._extract_header(headers, "Subject"),
            "date": self._extract_header(headers, "Date"),
            "labels": msg.get("labelIds", []),
            "snippet": msg.get("snippet", ""),
            "body": body,
        })

    def search_messages(self, criteria: str = "ALL", folder: str = "INBOX", *, limit: int = 20) -> str:
        """Search messages using Gmail query syntax."""
        params: dict[str, Any] = {"maxResults": limit}
        if folder and folder != "ALL":
            params["labelIds"] = folder
        if criteria and criteria != "ALL":
            params["q"] = criteria

        data = self._get("/messages", params=params)

        messages = []
        for msg_stub in data.get("messages", []):
            msg = self._get(f"/messages/{msg_stub['id']}", params={"format": "metadata",
                            "metadataHeaders": ["From", "Subject", "Date"]})
            headers = msg.get("payload", {}).get("headers", [])
            messages.append({
                "uid": msg["id"],
                "from": self._extract_header(headers, "From"),
                "subject": self._extract_header(headers, "Subject"),
                "date": self._extract_header(headers, "Date"),
                "snippet": msg.get("snippet", ""),
            })

        return json.dumps(messages)

    def move_message(self, uid: int | str, destination: str, folder: str = "INBOX") -> str:
        """Move a message by adding/removing labels."""
        body: dict[str, Any] = {
            "addLabelIds": [destination],
            "removeLabelIds": [folder],
        }
        result = self._post(f"/messages/{uid}/modify", body)
        return json.dumps({
            "uid": result["id"],
            "labels": result.get("labelIds", []),
        })

    def set_flags(self, uid: int | str, flags: str, *, remove: bool = False, folder: str = "INBOX") -> str:
        """Set or remove flags (mapped to Gmail labels).

        Supports IMAP-style flags (``\\Seen``, ``\\Flagged``, ``\\Deleted``)
        and raw Gmail label names (``UNREAD``, ``STARRED``, etc.).
        """
        add: list[str] = []
        rm: list[str] = []

        for flag in [f.strip() for f in flags.split(",") if f.strip()]:
            if flag in _FLAG_TO_LABEL:
                label, is_inverse = _FLAG_TO_LABEL[flag]
                if remove != is_inverse:
                    rm.append(label)
                else:
                    add.append(label)
            else:
                if remove:
                    rm.append(flag)
                else:
                    add.append(flag)

        body: dict[str, Any] = {}
        if add:
            body["addLabelIds"] = add
        if rm:
            body["removeLabelIds"] = rm

        result = self._post(f"/messages/{uid}/modify", body)
        return json.dumps({"uid": result["id"], "labels": result.get("labelIds", [])})

    def create_folder(self, name: str) -> str:
        """Create a new Gmail label."""
        body = {
            "name": name,
            "labelListVisibility": "labelShow",
            "messageListVisibility": "show",
        }
        result = self._post("/labels", body)
        return json.dumps({"id": result["id"], "name": result["name"]})

    # ------------------------------------------------------------------
    # MailsendPort implementation (2 methods)
    # ------------------------------------------------------------------

    def _build_and_send(self, msg: EmailMessage) -> str:
        """Base64url-encode and send a prepared EmailMessage."""
        raw = base64.urlsafe_b64encode(msg.as_bytes()).decode("ascii")
        result = self._post("/messages/send", {"raw": raw})
        return json.dumps({
            "status": "sent",
            "id": result.get("id", ""),
            "thread_id": result.get("threadId", ""),
            "labels": result.get("labelIds", []),
        })

    def _sender_address(self) -> str:
        """Get the formatted sender address."""
        profile = self._get_profile()
        email = profile["email"]
        if self._sender_name:
            return formataddr((self._sender_name, email))
        return email

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
        """Send a plain-text e-mail via the Gmail API."""
        msg = EmailMessage()
        msg["From"] = self._sender_address()
        msg["To"] = to
        msg["Subject"] = subject
        if cc:
            msg["Cc"] = cc
        if reply_to:
            msg["Reply-To"] = reply_to
        body = body.replace("\\n", "\n")
        msg.set_content(body)

        return self._build_and_send(msg)

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
        """Send an HTML e-mail via the Gmail API."""
        msg = EmailMessage()
        msg["From"] = self._sender_address()
        msg["To"] = to
        msg["Subject"] = subject
        if cc:
            msg["Cc"] = cc
        if reply_to:
            msg["Reply-To"] = reply_to

        html_body = html_body.replace("\\n", "\n")
        if text_body:
            text_body = text_body.replace("\\n", "\n")
            msg.set_content(text_body)
            msg.add_alternative(html_body, subtype="html")
        else:
            msg.set_content(html_body, subtype="html")

        return self._build_and_send(msg)
