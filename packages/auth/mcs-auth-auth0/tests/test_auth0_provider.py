"""Tests for Auth0Provider -- mocks HTTP, no network needed."""

from __future__ import annotations

import json
import time

import pytest

from mcs.adapter.http import HttpResponse
from mcs.auth.challenge import AuthChallenge
from mcs.auth.provider import CredentialProvider
from mcs.auth.auth0 import Auth0Provider


def _make_http_response(data: dict, *, status_code: int | None = None) -> HttpResponse:
    """Build an ``HttpResponse`` from a dict.

    Auto-detects status code: 400 if the dict contains ``"error"``, 200 otherwise.
    """
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


class FakeHttp:
    """Stub HTTP adapter that returns canned HttpResponse objects."""

    def __init__(self) -> None:
        self._responses: list[HttpResponse] = []
        self._call_log: list[dict] = []

    def push_response(self, data: dict, *, status_code: int | None = None) -> None:
        """Queue a response (FIFO)."""
        self._responses.append(_make_http_response(data, status_code=status_code))

    def set_response(self, data: dict, *, status_code: int | None = None) -> None:
        """Set a single response (backwards compat)."""
        self._responses = [_make_http_response(data, status_code=status_code)]

    def request(self, method, url, *, json_body=None, headers=None, **kw):
        self._call_log.append({"method": method, "url": url, "json_body": json_body})
        if self._responses:
            return self._responses.pop(0)
        return _make_http_response({"error": "no_response_configured"}, status_code=500)


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


class TestConnectedAccounts:
    """Tests for Connected Accounts auto-setup when Token Vault returns
    ``federated_connection_refresh_token_not_found``.
    """

    @staticmethod
    def _make_provider(http: FakeHttp, **kw) -> Auth0Provider:
        defaults = dict(
            domain="test.auth0.com",
            client_id="c",
            client_secret="s",
            refresh_token="rt_test",
            connection_scopes={"gmail": ["https://mail.google.com/", "openid"]},
            _http=http,
        )
        defaults.update(kw)
        return Auth0Provider(**defaults)

    def test_skip_setup_when_exchange_works(self, http: FakeHttp):
        """No Connected Accounts flow when Token Vault exchange succeeds."""
        http.push_response({"access_token": "ya29.direct", "expires_in": 3600})
        provider = self._make_provider(http)
        assert provider.get_token("gmail") == "ya29.direct"
        assert provider._ca_pending is None

    def test_no_connection_scopes_raises(self, http: FakeHttp):
        """Without connection_scopes, a clear error is raised."""
        http.push_response({
            "error": "federated_connection_refresh_token_not_found",
            "error_description": "Federated connection Refresh Token not found.",
        })
        provider = Auth0Provider(
            domain="test.auth0.com",
            client_id="c",
            client_secret="s",
            refresh_token="rt",
            _http=http,
        )
        with pytest.raises(RuntimeError, match="no connection_scopes"):
            provider.get_token("gmail")

    def test_auto_setup_raises_challenge_then_succeeds(self, http: FakeHttp):
        """Full Connected Accounts state machine:

        Call 1: Token Vault fails -> MRRT + /connect -> AuthChallenge
        Call 2: callback ready -> /complete -> Token Vault retry -> success
        """
        from unittest.mock import patch, MagicMock
        from mcs.auth.auth0.auth0_provider import _PendingConnect

        # --- Call 1 ---
        # 1a. Token Vault exchange -> not_found
        http.push_response({
            "error": "federated_connection_refresh_token_not_found",
            "error_description": "Federated connection Refresh Token not found.",
        })
        # 1b. MRRT exchange -> success
        http.push_response({"access_token": "ma_tok", "scope": "create:me:connected_accounts"})

        provider = self._make_provider(http)

        # Mock _post_json_bearer for /connect and _PendingConnect.start
        connect_resp = json.dumps({
            "connect_uri": "https://test.auth0.com/connected-accounts/connect",
            "connect_params": {"ticket": "tkt-123"},
            "auth_session": "session-abc",
            "expires_in": 300,
        })

        with patch.object(provider, "_post_json_bearer", return_value=connect_resp) as mock_post, \
             patch.object(_PendingConnect, "start"):

            with pytest.raises(AuthChallenge, match="One-time setup"):
                provider.get_token("gmail")

            # Verify /connect was called
            mock_post.assert_called_once()
            call_args = mock_post.call_args
            assert "/connected-accounts/connect" in call_args[0][0]

        assert provider._ca_pending is not None

        # --- Call 2 ---
        # Simulate callback arrived
        provider._ca_pending._result = {"code": "connect-code-xyz", "state": "s"}
        provider._ca_pending._expected_state = "s"

        # 2a. Token Vault still fails (triggers _ensure_connected_account)
        http.push_response({
            "error": "federated_connection_refresh_token_not_found",
            "error_description": "...",
        })
        # 2b. /complete -> success (mocked via _post_json_bearer)
        complete_resp = json.dumps({
            "id": "cac_test123",
            "connection": "google-oauth2",
        })
        # 2c. Token Vault exchange (retry after /complete) -> success
        http.push_response({"access_token": "ya29.final", "expires_in": 3600})

        with patch.object(provider, "_post_json_bearer", return_value=complete_resp):
            token = provider.get_token("gmail")

        assert token == "ya29.final"
        assert provider._ca_pending is None

    def test_pending_still_waiting_raises_challenge(self, http: FakeHttp):
        """While waiting for callback, repeated calls raise AuthChallenge."""
        from unittest.mock import patch
        from mcs.auth.auth0.auth0_provider import _PendingConnect

        # Call 1: trigger setup
        http.push_response({
            "error": "federated_connection_refresh_token_not_found",
            "error_description": "Federated connection Refresh Token not found.",
        })
        http.push_response({"access_token": "ma_tok", "scope": "..."})

        provider = self._make_provider(http)

        connect_resp = json.dumps({
            "connect_uri": "https://test.auth0.com/connected-accounts/connect",
            "connect_params": {"ticket": "tkt-123"},
            "auth_session": "session-abc",
            "expires_in": 300,
        })

        with patch.object(provider, "_post_json_bearer", return_value=connect_resp), \
             patch.object(_PendingConnect, "start"):
            with pytest.raises(AuthChallenge, match="One-time setup"):
                provider.get_token("gmail")

        # Call 2: callback NOT ready -- pending still waiting
        # The _PendingAuth thread mock: is_ready=False, is_waiting=True
        provider._ca_pending._result = {}  # no callback yet

        # Token Vault fails again
        http.push_response({
            "error": "federated_connection_refresh_token_not_found",
            "error_description": "...",
        })

        with pytest.raises(AuthChallenge, match="Waiting for Token Vault"):
            provider.get_token("gmail")
