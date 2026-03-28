"""Focused retry tests for GmailMailsendConnector."""

from __future__ import annotations

import json
from typing import Any

import pytest

from mcs.adapter.http import HttpError, HttpResponse
from mcs.driver.mailsend.gmail_connector import GmailMailsendConnector


def _make_response(status_code: int, data: dict[str, Any]) -> HttpResponse:
    text = json.dumps(data)
    return HttpResponse(
        status_code=status_code,
        text=text,
        content=text.encode(),
        headers={"Content-Type": "application/json"},
        reason="Unauthorized" if status_code == 401 else "",
    )


class FakeCredential:
    def __init__(self) -> None:
        self.calls = 0
        self.invalidations: list[str] = []

    def get_token(self, scope: str) -> str:
        self.calls += 1
        return f"token-{self.calls}"

    def invalidate_token(self, scope: str) -> None:
        self.invalidations.append(scope)


class FakeHttp:
    def __init__(self, responses: list[HttpResponse]) -> None:
        self.responses = responses
        self.calls: list[dict[str, Any]] = []

    def request(self, method: str, url: str, *, params=None, json_body=None, headers=None, **kwargs):
        self.calls.append({
            "method": method,
            "url": url,
            "params": params,
            "json_body": json_body,
            "headers": headers,
        })
        return self.responses.pop(0)


def test_retries_once_after_401_with_fresh_token() -> None:
    credential = FakeCredential()
    http = FakeHttp([
        _make_response(401, {"error": "invalid_token"}),
        _make_response(200, {"emailAddress": "sender@example.com"}),
        _make_response(200, {"id": "msg-1", "threadId": "thr-1", "labelIds": ["SENT"]}),
    ])
    connector = GmailMailsendConnector(_credential=credential, _http=http)

    result = json.loads(
        connector.send_message(to="alice@example.com", subject="Hi", body="Hello"),
    )

    assert result["status"] == "sent"
    assert credential.invalidations == ["gmail"]
    assert len(http.calls) == 3
    assert http.calls[0]["headers"]["Authorization"] == "Bearer token-1"
    assert http.calls[1]["headers"]["Authorization"] == "Bearer token-2"


def test_does_not_loop_when_retry_also_fails() -> None:
    credential = FakeCredential()
    http = FakeHttp([
        _make_response(401, {"error": "invalid_token"}),
        _make_response(401, {"error": "invalid_token"}),
    ])
    connector = GmailMailsendConnector(_credential=credential, _http=http)

    with pytest.raises(HttpError):
        connector.send_message(to="alice@example.com", subject="Hi", body="Hello")

    assert credential.invalidations == ["gmail"]
    assert len(http.calls) == 2
