"""Gmail Connector for mailsend -- send e-mail via the Gmail REST API.

Satisfies ``MailsendPort`` so it can be used as a drop-in backend for
``MailsendToolDriver``.  Delegates HTTP to any object satisfying
``HttpPort`` (default: ``HttpAdapter`` from ``mcs-adapter-http``).

This is a *Connector*, not a Transport Adapter: it translates between
the Gmail REST API and the ``MailsendPort`` contract.  The real transport
is HTTP, handled by the injected ``_http`` backend.
"""

from __future__ import annotations

import base64
import json
import logging
from email.message import EmailMessage
from email.utils import formataddr
from typing import Any, Callable, Protocol, Union, runtime_checkable

from mcs.adapter.http import HttpResponse

logger = logging.getLogger(__name__)

_BASE = "https://gmail.googleapis.com/gmail/v1/users/me"


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


class GmailMailsendConnector:
    """Send e-mail via the Gmail REST API.

    Parameters
    ----------
    access_token :
        A Google OAuth2 access token (string) or a zero-argument callable
        that returns a fresh token.
    sender_name :
        Optional display name for the ``From`` header.
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
        sender_name: str | None = None,
        timeout: int = 30,
        _credential: Any | None = None,
        _http: HttpPort | None = None,
    ) -> None:
        self._credential = _credential
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

    def _get_token(self) -> str:
        if callable(self._token):
            return self._token()
        return self._token

    def _auth_headers(self) -> dict[str, str]:
        return {"Authorization": f"Bearer {self._get_token()}"}

    def _request_json(
        self,
        method: str,
        path: str,
        *,
        params: dict[str, Any] | None = None,
        json_body: dict[str, Any] | None = None,
        _retried: bool = False,
    ) -> Any:
        resp = self._http.request(
            method,
            f"{_BASE}{path}",
            params=params,
            json_body=json_body,
            headers=self._auth_headers(),
        )
        if (
            resp.status_code == 401
            and self._credential is not None
            and hasattr(self._credential, "invalidate_token")
            and not _retried
        ):
            logger.info(
                "Gmail access token rejected (401) -- retrying once with fresh token",
            )
            self._credential.invalidate_token("gmail")
            return self._request_json(
                method,
                path,
                params=params,
                json_body=json_body,
                _retried=True,
            )
        resp.raise_for_status()
        return resp.json()

    def _get(self, path: str, params: dict[str, Any] | None = None) -> Any:
        return self._request_json("GET", path, params=params)

    def _post(self, path: str, body: dict[str, Any]) -> Any:
        return self._request_json("POST", path, json_body=body)

    def _get_profile(self) -> dict[str, str]:
        data = self._get("/profile")
        return {"email": data.get("emailAddress", "")}

    def _sender_address(self) -> str:
        profile = self._get_profile()
        email = profile["email"]
        if self._sender_name:
            return formataddr((self._sender_name, email))
        return email

    def _build_and_send(self, msg: EmailMessage) -> str:
        raw = base64.urlsafe_b64encode(msg.as_bytes()).decode("ascii")
        result = self._post("/messages/send", {"raw": raw})
        return json.dumps({
            "status": "sent",
            "id": result.get("id", ""),
            "thread_id": result.get("threadId", ""),
            "labels": result.get("labelIds", []),
        })

    # ------------------------------------------------------------------
    # MailsendPort implementation
    # ------------------------------------------------------------------

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
