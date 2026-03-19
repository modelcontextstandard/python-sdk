"""Tests for Auth0Provider -- mocks HTTP, no network needed."""

from __future__ import annotations

import json
import time

import pytest

from mcs.auth.challenge import AuthChallenge
from mcs.auth.provider import CredentialProvider
from mcs.auth.auth0 import Auth0Provider


class FakeHttpError(Exception):
    """Simulates an HTTP error with a response body (like requests.HTTPError)."""

    def __init__(self, data: dict) -> None:
        self.response = type("Response", (), {"text": json.dumps(data)})()
        super().__init__(f"Fake HTTP error")


class FakeHttp:
    """Stub HTTP adapter that returns canned responses based on URL/grant_type."""

    def __init__(self) -> None:
        self._responses: list[dict | FakeHttpError] = []
        self._call_log: list[dict] = []

    def push_response(self, data: dict, *, as_http_error: bool = False) -> None:
        """Queue a response (FIFO).  With as_http_error=True, raises instead."""
        if as_http_error:
            self._responses.append(FakeHttpError(data))
        else:
            self._responses.append(data)

    def set_response(self, data: dict) -> None:
        """Set a single response (backwards compat)."""
        self._responses = [data]

    def request(self, method, url, *, json_body=None, headers=None, **kw):
        self._call_log.append({"method": method, "url": url, "json_body": json_body})
        if self._responses:
            item = self._responses.pop(0)
            if isinstance(item, FakeHttpError):
                raise item
            return json.dumps(item)
        return json.dumps({"error": "no_response_configured"})


@pytest.fixture()
def http() -> FakeHttp:
    return FakeHttp()


@pytest.fixture()
def provider_with_token(http: FakeHttp) -> Auth0Provider:
    """Provider with a refresh token already set (token-exchange mode)."""
    return Auth0Provider(
        domain="test.auth0.com",
        client_id="client123",
        client_secret="secret456",
        refresh_token="rt_abc",
        _http=http,
    )


@pytest.fixture()
def provider_no_token(http: FakeHttp) -> Auth0Provider:
    """Provider without a refresh token (device-flow mode)."""
    return Auth0Provider(
        domain="test.auth0.com",
        client_id="client123",
        client_secret="secret456",
        _http=http,
    )


class TestTokenExchange:
    """Tests for the existing token-exchange flow (with refresh_token)."""

    def test_satisfies_protocol(self, provider_with_token: Auth0Provider):
        assert isinstance(provider_with_token, CredentialProvider)

    def test_get_token_gmail(self, provider_with_token: Auth0Provider, http: FakeHttp):
        http.push_response({"access_token": "goog-tok-123", "expires_in": 3600})
        token = provider_with_token.get_token("gmail")
        assert token == "goog-tok-123"

    def test_get_token_caches(self, provider_with_token: Auth0Provider, http: FakeHttp):
        http.push_response({"access_token": "goog-tok-123", "expires_in": 3600})
        provider_with_token.get_token("gmail")
        http.push_response({"access_token": "new-tok", "expires_in": 3600})
        assert provider_with_token.get_token("gmail") == "goog-tok-123"

    def test_cache_expires(self, provider_with_token: Auth0Provider, http: FakeHttp):
        provider_with_token._cache["gmail"] = ("old-tok", time.time() - 1)
        http.push_response({"access_token": "fresh-tok", "expires_in": 3600})
        assert provider_with_token.get_token("gmail") == "fresh-tok"

    def test_unknown_scope_raises(self, provider_with_token: Auth0Provider):
        with pytest.raises(LookupError, match="No Auth0 connection"):
            provider_with_token.get_token("UNKNOWN_SERVICE")

    def test_custom_connection_mapping(self, http: FakeHttp):
        http.push_response({"access_token": "custom-tok", "expires_in": 3600})
        provider = Auth0Provider(
            domain="test.auth0.com",
            client_id="c",
            client_secret="s",
            refresh_token="rt",
            connections={"myservice": "my-custom-connection"},
            _http=http,
        )
        assert provider.get_token("myservice") == "custom-tok"

    def test_auth0_error_raises_runtime_error(
        self, provider_with_token: Auth0Provider, http: FakeHttp
    ):
        provider_with_token._cache.clear()
        http.push_response({
            "error": "invalid_grant",
            "error_description": "Refresh token is expired",
        })
        with pytest.raises(RuntimeError, match="Auth0 token exchange failed"):
            provider_with_token.get_token("gmail")

    def test_passthrough_connection_name(
        self, provider_with_token: Auth0Provider, http: FakeHttp
    ):
        http.push_response({"access_token": "pass-tok", "expires_in": 3600})
        token = provider_with_token.get_token("google-oauth2")
        assert token == "pass-tok"


class TestAuthPort:
    """Tests for AuthPort-based token acquisition (no refresh_token)."""

    def test_no_auth_no_token_raises_lookup(self, http: FakeHttp):
        """Without refresh_token or _auth, get_token raises LookupError."""
        provider = Auth0Provider(
            domain="test.auth0.com",
            client_id="c",
            client_secret="s",
            _http=http,
        )
        with pytest.raises(LookupError, match="No refresh token"):
            provider.get_token("gmail")

    def test_auth_adapter_provides_refresh_token(self, http: FakeHttp):
        """AuthPort adapter provides refresh token, then Token Vault exchange works."""

        class FakeAuth:
            def authenticate(self, scope: str) -> str:
                return "rt_from_adapter"

        http.push_response({"access_token": "google-tok-via-adapter", "expires_in": 3600})
        provider = Auth0Provider(
            domain="test.auth0.com",
            client_id="c",
            client_secret="s",
            _auth=FakeAuth(),
            _http=http,
        )
        token = provider.get_token("gmail")
        assert token == "google-tok-via-adapter"

    def test_auth_adapter_raises_auth_challenge(self, http: FakeHttp):
        """AuthPort raising AuthChallenge propagates to caller."""

        class ChallengeAuth:
            def authenticate(self, scope: str) -> str:
                raise AuthChallenge(
                    "Please login",
                    url="https://example.com/login",
                    code="ABCD",
                    scope=scope,
                )

        provider = Auth0Provider(
            domain="test.auth0.com",
            client_id="c",
            client_secret="s",
            _auth=ChallengeAuth(),
            _http=http,
        )
        with pytest.raises(AuthChallenge) as exc_info:
            provider.get_token("gmail")
        assert exc_info.value.url == "https://example.com/login"
        assert exc_info.value.code == "ABCD"

    def test_auth_adapter_called_only_once(self, http: FakeHttp):
        """Once refresh token is obtained, adapter is not called again."""
        call_count = 0

        class CountingAuth:
            def authenticate(self, scope: str) -> str:
                nonlocal call_count
                call_count += 1
                return "rt_counted"

        http.push_response({"access_token": "tok1", "expires_in": 3600})
        http.push_response({"access_token": "tok2", "expires_in": 3600})

        provider = Auth0Provider(
            domain="test.auth0.com",
            client_id="c",
            client_secret="s",
            _auth=CountingAuth(),
            _http=http,
        )
        provider.get_token("gmail")
        # Second call for different scope — should reuse refresh token
        provider.get_token("google-drive")
        assert call_count == 1

    def test_refresh_token_optional(self, http: FakeHttp):
        """Constructor works without refresh_token."""
        provider = Auth0Provider(
            domain="test.auth0.com",
            client_id="c",
            client_secret="s",
            _http=http,
        )
        assert provider._refresh_token is None
