"""Tests for AuthChallenge and AuthMixin."""

from __future__ import annotations

import json
from typing import Any

import pytest

from mcs.auth.challenge import AuthChallenge
from mcs.auth.mixin import AuthMixin


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


class FakeToolDriver:
    """Simulates a DriverBase with execute_tool."""

    def __init__(self, result: Any = None, error: Exception | None = None):
        self._result = result
        self._error = error

    def execute_tool(self, tool_name: str, arguments: dict[str, Any]) -> Any:
        if self._error:
            raise self._error
        return self._result


class MixedDriver(AuthMixin, FakeToolDriver):
    """AuthMixin + FakeToolDriver via MRO."""
    pass


class TestAuthMixin:

    def test_normal_execution_passes_through(self):
        driver = MixedDriver(result='{"messages": []}')
        result = driver.execute_tool("list_messages", {})
        assert result == '{"messages": []}'

    def test_auth_challenge_converted_to_json(self):
        challenge = AuthChallenge(
            "Please authenticate",
            url="https://auth0.com/activate",
            code="WXYZ-5678",
            scope="gmail",
        )
        driver = MixedDriver(error=challenge)
        result = driver.execute_tool("list_messages", {})
        data = json.loads(result)

        assert data["auth_required"] is True
        assert data["message"] == "Please authenticate"
        assert data["url"] == "https://auth0.com/activate"
        assert data["code"] == "WXYZ-5678"
        assert data["scope"] == "gmail"

    def test_auth_challenge_without_optional_fields(self):
        challenge = AuthChallenge("API key needed")
        driver = MixedDriver(error=challenge)
        result = driver.execute_tool("some_tool", {})
        data = json.loads(result)

        assert data["auth_required"] is True
        assert data["message"] == "API key needed"
        assert "url" not in data
        assert "code" not in data
        assert "scope" not in data

    def test_other_exceptions_propagate(self):
        driver = MixedDriver(error=ValueError("something broke"))
        with pytest.raises(ValueError, match="something broke"):
            driver.execute_tool("list_messages", {})
