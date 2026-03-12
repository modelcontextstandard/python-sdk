"""Tests for Auth0Provider -- mocks HTTP, no network needed."""

from __future__ import annotations

import json
import time

import pytest

from mcs.auth.provider import CredentialProvider
from mcs.auth.auth0 import Auth0Provider


class FakeHttp:
    """Stub HTTP adapter that returns canned token exchange responses."""

    def __init__(self) -> None:
        self._response: dict = {}

    def set_response(self, data: dict) -> None:
        self._response = data

    def request(self, method, url, *, json_body=None, headers=None, **kw):
        return json.dumps(self._response)


@pytest.fixture()
def http() -> FakeHttp:
    h = FakeHttp()
    h.set_response({
        "access_token": "goog-tok-123",
        "token_type": "Bearer",
        "expires_in": 3600,
        "scope": "https://www.googleapis.com/auth/gmail.readonly",
    })
    return h


@pytest.fixture()
def provider(http: FakeHttp) -> Auth0Provider:
    return Auth0Provider(
        domain="test.auth0.com",
        client_id="client123",
        client_secret="secret456",
        refresh_token="rt_abc",
        _http=http,
    )


class TestAuth0Provider:

    def test_satisfies_protocol(self, provider: Auth0Provider):
        assert isinstance(provider, CredentialProvider)

    def test_get_token_gmail(self, provider: Auth0Provider):
        token = provider.get_token("gmail")
        assert token == "goog-tok-123"

    def test_get_token_caches(self, provider: Auth0Provider, http: FakeHttp):
        provider.get_token("gmail")
        # Change the response -- should still get cached token
        http.set_response({"access_token": "new-tok"})
        assert provider.get_token("gmail") == "goog-tok-123"

    def test_cache_expires(self, provider: Auth0Provider, http: FakeHttp):
        # Prime cache with very short expiry
        provider._cache["gmail"] = ("old-tok", time.time() - 1)
        http.set_response({"access_token": "fresh-tok", "expires_in": 3600})
        assert provider.get_token("gmail") == "fresh-tok"

    def test_unknown_scope_raises(self, provider: Auth0Provider):
        with pytest.raises(LookupError, match="No Auth0 connection"):
            provider.get_token("UNKNOWN_SERVICE")

    def test_custom_connection_mapping(self, http: FakeHttp):
        http.set_response({"access_token": "custom-tok", "expires_in": 3600})
        provider = Auth0Provider(
            domain="test.auth0.com",
            client_id="c",
            client_secret="s",
            refresh_token="rt",
            connections={"myservice": "my-custom-connection"},
            _http=http,
        )
        assert provider.get_token("myservice") == "custom-tok"

    def test_auth0_error_raises_runtime_error(self, provider: Auth0Provider, http: FakeHttp):
        http.set_response({
            "error": "invalid_grant",
            "error_description": "Refresh token is expired",
        })
        with pytest.raises(RuntimeError, match="Auth0 token exchange failed"):
            provider.get_token("gmail")

    def test_passthrough_connection_name(self, provider: Auth0Provider):
        """Scope that looks like a connection name is passed through."""
        # This will attempt a token exchange with "google-oauth2" as connection
        # The default FakeHttp returns a valid response
        token = provider.get_token("google-oauth2")
        assert token == "goog-tok-123"
