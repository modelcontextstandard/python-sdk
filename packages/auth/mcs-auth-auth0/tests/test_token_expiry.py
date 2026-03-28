"""Focused token-expiry tests for Auth0Provider."""

from __future__ import annotations

import json
import time
from base64 import urlsafe_b64encode
from typing import Any

from mcs.adapter.http import HttpResponse
from mcs.auth.auth0 import Auth0Provider


def _make_http_response(data: dict[str, Any], *, status_code: int | None = None) -> HttpResponse:
    text = json.dumps(data)
    if status_code is None:
        status_code = 400 if "error" in data else 200
    return HttpResponse(
        status_code=status_code,
        text=text,
        content=text.encode(),
        headers={"Content-Type": "application/json"},
        reason="",
    )


def _make_jwt(exp: int) -> str:
    def _b64(data: dict[str, Any]) -> str:
        raw = json.dumps(data).encode()
        return urlsafe_b64encode(raw).rstrip(b"=").decode()

    return f"{_b64({'alg': 'none', 'typ': 'JWT'})}.{_b64({'exp': exp})}."


class FakeCache:
    def __init__(self) -> None:
        self.store: dict[str, str] = {}

    def read(self, key: str) -> str | None:
        return self.store.get(key)

    def write(self, key: str, value: str, ttl: float | None = None) -> None:
        self.store[key] = value

    def delete(self, key: str) -> None:
        self.store.pop(key, None)


class FakeHttp:
    def __init__(self, responses: list[dict[str, Any]]) -> None:
        self._responses = [_make_http_response(data) for data in responses]
        self.calls: list[dict[str, Any]] = []

    def request(self, method: str, url: str, *, json_body=None, headers=None, **kwargs):
        self.calls.append({"method": method, "url": url, "json_body": json_body})
        return self._responses.pop(0)


class FakeAuth:
    def __init__(self, refresh_token: str = "rt_new") -> None:
        self.refresh_token = refresh_token
        self.calls: list[str] = []

    def authenticate(self, scope: str) -> str:
        self.calls.append(scope)
        return self.refresh_token


def test_expired_cached_jwt_is_refreshed_before_use() -> None:
    cache = FakeCache()
    cache.write("at:gmail", _make_jwt(int(time.time()) - 120))
    http = FakeHttp([{"access_token": "fresh-access", "expires_in": 3600}])

    provider = Auth0Provider(
        domain="test.auth0.com",
        client_id="client",
        client_secret="secret",
        refresh_token="rt_existing",
        _http=http,
        _token_cache=cache,
    )

    assert provider.get_token("gmail") == "fresh-access"
    assert len(http.calls) == 1
    assert cache.read("at:gmail") == "fresh-access"


def test_invalid_grant_clears_refresh_token_and_reauthenticates() -> None:
    cache = FakeCache()
    auth = FakeAuth(refresh_token="rt_reauthed")
    http = FakeHttp([
        {"error": "invalid_grant", "error_description": "Refresh token expired"},
        {"access_token": "fresh-access", "expires_in": 3600},
    ])

    provider = Auth0Provider(
        domain="test.auth0.com",
        client_id="client",
        client_secret="secret",
        refresh_token="rt_expired",
        _auth=auth,
        _http=http,
        _token_cache=cache,
    )

    assert provider.get_token("gmail") == "fresh-access"
    assert auth.calls == ["gmail"]
    assert cache.read("rt:test.auth0.com") == "rt_reauthed"
