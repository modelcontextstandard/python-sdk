"""Tests for OAuthConnector -- passthrough mode, callback_url, and standard flow."""

from __future__ import annotations

from unittest.mock import patch

import pytest

from mcs.auth.challenge import AuthChallenge
from mcs.auth.oauth import OAuthConnector


@pytest.fixture()
def connector() -> OAuthConnector:
    return OAuthConnector(
        authorize_url="https://auth.example.com/authorize",
        token_url="https://auth.example.com/token",
        client_id="test-client",
        client_secret="test-secret",
        callback_port=9999,
        callback_path="/cb",
    )


class TestCallbackUrl:
    def test_callback_url_property(self, connector: OAuthConnector):
        assert connector.callback_url == "http://localhost:9999/cb"


class TestPassthroughMode:
    def test_passthrough_starts_server_and_raises(self, connector: OAuthConnector):
        """authenticate() with url= starts server and raises AuthChallenge."""
        from mcs.auth.oauth.oauth_connector import _PendingAuth

        with patch.object(_PendingAuth, "start") as mock_start:
            with pytest.raises(AuthChallenge):
                connector.authenticate(
                    "gmail:connect",
                    url="https://auth0.example.com/connect?ticket=t1",
                    callback_params=["connect_code"],
                    state="my-state",
                )

            mock_start.assert_called_once_with(
                "https://auth0.example.com/connect?ticket=t1"
            )

    def test_passthrough_returns_captured_param(self, connector: OAuthConnector):
        """When passthrough callback arrives, authenticate() returns the captured value."""
        from mcs.auth.oauth.oauth_connector import _PendingAuth

        # First call: start the flow
        with patch.object(_PendingAuth, "start"):
            with pytest.raises(AuthChallenge):
                connector.authenticate(
                    "gmail:connect",
                    url="https://auth0.example.com/connect?ticket=t1",
                    callback_params=["connect_code"],
                    state="st-1",
                )

        # Simulate callback arrived
        cache_key = "gmail:connect:redirect:st-1"
        pending = connector._pending[cache_key]
        pending._result = {"code": "cc-result-42", "connect_code": "cc-result-42", "state": "st-1"}

        # Second call: returns the captured value
        result = connector.authenticate(
            "gmail:connect",
            url="https://auth0.example.com/connect?ticket=t1",
            callback_params=["connect_code"],
            state="st-1",
        )
        assert result == "cc-result-42"

    def test_passthrough_pending_raises_challenge(self, connector: OAuthConnector):
        """While waiting, repeated calls raise AuthChallenge."""
        from mcs.auth.oauth.oauth_connector import _PendingAuth

        with patch.object(_PendingAuth, "start"):
            with pytest.raises(AuthChallenge):
                connector.authenticate(
                    "test:connect",
                    url="https://example.com/redirect",
                    callback_params=["code"],
                    state="s1",
                )

        # Callback NOT ready yet
        cache_key = "test:connect:redirect:s1"
        pending = connector._pending[cache_key]
        pending._result = {}  # empty = not ready

        with pytest.raises(AuthChallenge, match="Waiting"):
            connector.authenticate(
                "test:connect",
                url="https://example.com/redirect",
                callback_params=["code"],
                state="s1",
            )


class TestStandardMode:
    def test_standard_flow_starts_and_raises(self, connector: OAuthConnector):
        """Standard authenticate() (no url=) starts OAuth flow."""
        from mcs.auth.oauth.oauth_connector import _PendingAuth

        with patch.object(_PendingAuth, "start") as mock_start:
            with pytest.raises(AuthChallenge, match="browser"):
                connector.authenticate("gmail")

            mock_start.assert_called_once()
            call_url = mock_start.call_args[0][0]
            assert "auth.example.com/authorize" in call_url
            assert "response_type=code" in call_url
