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


class TestDeviceFlow:
    """Tests for the device authorization flow (no refresh_token)."""

    def test_first_call_raises_auth_challenge(
        self, provider_no_token: Auth0Provider, http: FakeHttp
    ):
        """First get_token() starts device flow and raises AuthChallenge."""
        http.push_response({
            "device_code": "dev_abc",
            "user_code": "ABCD-1234",
            "verification_uri": "https://test.auth0.com/activate",
            "verification_uri_complete": "https://test.auth0.com/activate?user_code=ABCD-1234",
            "interval": 5,
            "expires_in": 900,
        })

        with pytest.raises(AuthChallenge) as exc_info:
            provider_no_token.get_token("gmail")

        challenge = exc_info.value
        assert challenge.url == "https://test.auth0.com/activate?user_code=ABCD-1234"
        assert challenge.code == "ABCD-1234"
        assert challenge.scope == "gmail"

    def test_second_call_polls_and_succeeds(
        self, provider_no_token: Auth0Provider, http: FakeHttp
    ):
        """After user authenticates, second call polls and gets tokens."""
        # First call: device code response
        http.push_response({
            "device_code": "dev_abc",
            "user_code": "ABCD-1234",
            "verification_uri": "https://test.auth0.com/activate",
            "interval": 0,
            "expires_in": 900,
        })

        with pytest.raises(AuthChallenge):
            provider_no_token.get_token("gmail")

        # Second call: poll succeeds → returns tokens + then token exchange
        http.push_response({
            "access_token": "auth0-access",
            "refresh_token": "rt_new",
            "token_type": "Bearer",
            "expires_in": 86400,
        })
        http.push_response({
            "access_token": "google-tok-456",
            "token_type": "Bearer",
            "expires_in": 3600,
        })

        token = provider_no_token.get_token("gmail")
        assert token == "google-tok-456"

    def test_poll_authorization_pending_then_success(
        self, provider_no_token: Auth0Provider, http: FakeHttp
    ):
        """Polling with authorization_pending before eventual success."""
        # Start device flow
        http.push_response({
            "device_code": "dev_abc",
            "user_code": "WXYZ-5678",
            "verification_uri": "https://test.auth0.com/activate",
            "interval": 0,  # No delay for tests
            "expires_in": 900,
        })

        with pytest.raises(AuthChallenge):
            provider_no_token.get_token("gmail")

        # Polling: first pending, then success
        http.push_response({"error": "authorization_pending"})
        http.push_response({
            "access_token": "auth0-access",
            "refresh_token": "rt_polled",
            "token_type": "Bearer",
            "expires_in": 86400,
        })
        http.push_response({
            "access_token": "google-tok-polled",
            "token_type": "Bearer",
            "expires_in": 3600,
        })

        # Use short poll timeout for the test
        provider_no_token._poll_timeout = 5
        provider_no_token._device_interval = 0

        token = provider_no_token.get_token("gmail")
        assert token == "google-tok-polled"

    def test_poll_timeout_raises_auth_challenge_again(
        self, provider_no_token: Auth0Provider, http: FakeHttp
    ):
        """If polling times out, AuthChallenge is raised again."""
        # Start device flow
        http.push_response({
            "device_code": "dev_abc",
            "user_code": "TMOT-0000",
            "verification_uri": "https://test.auth0.com/activate",
            "interval": 0,
            "expires_in": 900,
        })

        with pytest.raises(AuthChallenge):
            provider_no_token.get_token("gmail")

        # All polls return pending → timeout
        for _ in range(20):
            http.push_response({"error": "authorization_pending"})

        provider_no_token._poll_timeout = 0  # Immediate timeout
        provider_no_token._device_interval = 0

        with pytest.raises(AuthChallenge) as exc_info:
            provider_no_token.get_token("gmail")

        assert exc_info.value.code == "TMOT-0000"

    def test_device_flow_error_raises_runtime(
        self, provider_no_token: Auth0Provider, http: FakeHttp
    ):
        """Auth0 returning an error from /oauth/device/code raises RuntimeError."""
        http.push_response({
            "error": "unauthorized_client",
            "error_description": "Device flow not enabled",
        })

        with pytest.raises(RuntimeError, match="device authorization failed"):
            provider_no_token.get_token("gmail")

    def test_access_denied_during_poll(
        self, provider_no_token: Auth0Provider, http: FakeHttp
    ):
        """User denies access during device flow."""
        http.push_response({
            "device_code": "dev_abc",
            "user_code": "DENY-0001",
            "verification_uri": "https://test.auth0.com/activate",
            "interval": 0,
            "expires_in": 900,
        })

        with pytest.raises(AuthChallenge):
            provider_no_token.get_token("gmail")

        http.push_response({"error": "access_denied"})
        provider_no_token._poll_timeout = 5

        with pytest.raises(RuntimeError, match="denied by user"):
            provider_no_token.get_token("gmail")

    def test_poll_handles_http_403_authorization_pending(
        self, provider_no_token: Auth0Provider, http: FakeHttp
    ):
        """Auth0 sends authorization_pending as HTTP 403 -- must be handled."""
        http.push_response({
            "device_code": "dev_abc",
            "user_code": "HTTP-4030",
            "verification_uri": "https://test.auth0.com/activate",
            "interval": 0,
            "expires_in": 900,
        })

        with pytest.raises(AuthChallenge):
            provider_no_token.get_token("gmail")

        # Auth0 returns authorization_pending as HTTP 403 (raises in adapter)
        http.push_response(
            {"error": "authorization_pending"},
            as_http_error=True,
        )
        # Then user completes → success
        http.push_response({
            "access_token": "auth0-tok",
            "refresh_token": "rt_403",
            "token_type": "Bearer",
            "expires_in": 86400,
        })
        # Token exchange
        http.push_response({
            "access_token": "google-tok-403",
            "token_type": "Bearer",
            "expires_in": 3600,
        })

        provider_no_token._poll_timeout = 5
        provider_no_token._device_interval = 0

        token = provider_no_token.get_token("gmail")
        assert token == "google-tok-403"

    def test_refresh_token_optional(self, http: FakeHttp):
        """Constructor works without refresh_token."""
        provider = Auth0Provider(
            domain="test.auth0.com",
            client_id="c",
            client_secret="s",
            _http=http,
        )
        assert provider._refresh_token is None
