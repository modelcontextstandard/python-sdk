"""Gmail Connector for mailread -- read e-mail via the Gmail REST API.

Satisfies ``MailboxPort`` so it can be used as a drop-in backend for
``MailreadToolDriver``.  Delegates HTTP to any object satisfying
``HttpPort`` (default: ``HttpAdapter`` from ``mcs-adapter-http``).

This is a *Connector*, not a Transport Adapter: it translates between
the Gmail REST API and the ``MailboxPort`` contract.  The real transport
is HTTP, handled by the injected ``_http`` backend.
"""

from __future__ import annotations

import base64
import json
import logging
from typing import Any, Callable, Protocol, Union, runtime_checkable

from mcs.adapter.http import HttpResponse

logger = logging.getLogger(__name__)

_BASE = "https://gmail.googleapis.com/gmail/v1/users/me"

# Maps IMAP-style flag names to Gmail label operations.
_FLAG_TO_LABEL: dict[str, tuple[str, bool]] = {
    "\\Seen": ("UNREAD", True),       # Seen -> remove UNREAD
    "\\Flagged": ("STARRED", False),   # Flagged -> add STARRED
    "\\Deleted": ("TRASH", False),     # Deleted -> add TRASH
}


@runtime_checkable
class HttpPort(Protocol):
    """Contract for HTTP transport."""

    def request(
        self,
        method: str,
        url: str,
        *,
        params: dict[str, Any] | None = None,
        json_body: dict[str, Any] | None = None,
        headers: dict[str, str] | None = None,
        timeout: int | None = None,
    ) -> HttpResponse: ...


class GmailMailboxConnector:
    """Read e-mail via the Gmail REST API.

    Parameters
    ----------
    access_token :
        A Google OAuth2 access token (string) or a zero-argument callable
        that returns a fresh token.
    timeout :
        HTTP request timeout in seconds (used when creating the default
        ``HttpAdapter``).
    _credential :
        Any object with ``get_token(scope) -> str``.  When provided,
        ``access_token`` may be omitted.
    _http :
        Any object satisfying ``HttpPort``.  When *None*, a default
        ``HttpAdapter`` is created.
    """

    def __init__(
        self,
        *,
        access_token: Union[str, Callable[[], str], None] = None,
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
        if _http is not None:
            self._http: HttpPort = _http
        else:
            from mcs.adapter.http import HttpAdapter
            self._http = HttpAdapter(timeout=timeout)

    def _get_token(self) -> str:
        if callable(self._token):
            return self._token()
        return self._token

    def _auth_headers(self) -> dict[str, str]:
        return {"Authorization": f"Bearer {self._get_token()}"}

    def _get(self, path: str, params: dict[str, Any] | None = None) -> Any:
        resp = self._http.request(
            "GET", f"{_BASE}{path}",
            params=params,
            headers=self._auth_headers(),
        )
        resp.raise_for_status()
        return resp.json()

    def _post(self, path: str, body: dict[str, Any]) -> Any:
        resp = self._http.request(
            "POST", f"{_BASE}{path}",
            json_body=body,
            headers=self._auth_headers(),
        )
        resp.raise_for_status()
        return resp.json()

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

        body_data = payload.get("body", {}).get("data")
        if body_data and mime.startswith("text/"):
            return base64.urlsafe_b64decode(body_data + "==").decode("utf-8", errors="replace")

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
            if part.get("parts"):
                nested = GmailMailboxConnector._decode_body(part)
                if nested:
                    plain = plain or nested

        return plain or html

    # ------------------------------------------------------------------
    # MailboxPort implementation
    # ------------------------------------------------------------------

    def list_folders(self) -> str:
        data = self._get("/labels")
        labels = [lbl["name"] for lbl in data.get("labels", [])]
        return json.dumps(sorted(labels))

    def list_messages(self, folder: str = "INBOX", *, limit: int = 20) -> str:
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
        body = {
            "name": name,
            "labelListVisibility": "labelShow",
            "messageListVisibility": "show",
        }
        result = self._post("/labels", body)
        return json.dumps({"id": result["id"], "name": result["name"]})
