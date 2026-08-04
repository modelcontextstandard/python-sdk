"""Tests for AuthChallenge and AuthMiddleware."""

from __future__ import annotations

import json

import pytest

from mcs.driver.core import ToolMiddleware
from mcs.auth.challenge import AuthChallenge
from mcs.auth.middleware import AuthMiddleware, SupportsAuth


def _returns(value):
    """A call_next that returns *value* (the tool executed normally)."""
    return lambda name, args: value


def _raises(exc):
    """A call_next that raises *exc* (execution hit a challenge / error)."""
    def call_next(name, args):
        raise exc
    return call_next


class TestAuthChallenge:

    def test_basic_attributes(self):
        exc = AuthChallenge(
            "Please login",
            url="https://example.com/activate",
            code="ABCD-1234",
            scope="gmail",
        )
        assert str(exc) == "Please login"
        assert exc.url == "https://example.com/activate"
        assert exc.code == "ABCD-1234"
        assert exc.scope == "gmail"

    def test_defaults_to_none(self):
        exc = AuthChallenge("login needed")
        assert exc.url is None
        assert exc.code is None
        assert exc.scope is None

    def test_is_exception(self):
        assert issubclass(AuthChallenge, Exception)


class TestAuthMiddleware:

    def test_normal_execution_passes_through(self):
        mw = AuthMiddleware()
        assert mw.on_execute_tool("list_messages", {}, _returns('{"messages": []}')) == '{"messages": []}'

    def test_auth_challenge_converted_to_json(self):
        challenge = AuthChallenge(
            "Please authenticate",
            url="https://auth0.com/activate",
            code="WXYZ-5678",
            scope="gmail",
        )
        data = json.loads(AuthMiddleware().on_execute_tool("list_messages", {}, _raises(challenge)))
        assert data["auth_required"] is True
        assert data["message"] == "Please authenticate"
        assert data["url"] == "https://auth0.com/activate"
        assert data["code"] == "WXYZ-5678"
        assert data["scope"] == "gmail"

    def test_auth_challenge_without_optional_fields(self):
        data = json.loads(
            AuthMiddleware().on_execute_tool("some_tool", {}, _raises(AuthChallenge("API key needed")))
        )
        assert data["auth_required"] is True
        assert data["message"] == "API key needed"
        assert "url" not in data and "code" not in data and "scope" not in data

    def test_other_exceptions_propagate(self):
        with pytest.raises(ValueError, match="something broke"):
            AuthMiddleware().on_execute_tool("list_messages", {}, _raises(ValueError("something broke")))

    # -- Contract: it is a ToolMiddleware carrying the auth capability ---------

    def test_is_a_tool_middleware(self):
        assert isinstance(AuthMiddleware(), ToolMiddleware)

    def test_carries_auth_capability(self):
        assert isinstance(AuthMiddleware(), SupportsAuth)
        assert SupportsAuth.CAPABILITY == "auth"
