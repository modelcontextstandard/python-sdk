"""Tests for AuthChallenge and AuthDecorator."""

from __future__ import annotations

import json
from dataclasses import dataclass
from typing import Any

import pytest

from mcs.driver.core import MCSToolDriver, DriverMeta, DriverBinding, Tool
from mcs.auth.challenge import AuthChallenge
from mcs.auth.decorator import AuthDecorator, SupportsAuth


@dataclass(frozen=True)
class _Meta(DriverMeta):
    id: str = "fake-0001"
    name: str = "Fake"
    version: str = "0.0.1"
    bindings: tuple[DriverBinding, ...] = ()
    supported_llms: tuple[str, ...] | None = None
    capabilities: tuple[str, ...] = ()


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


class FakeToolDriver(MCSToolDriver):
    """A minimal tool driver whose ``execute_tool`` can be made to raise."""

    meta: DriverMeta = _Meta()

    def __init__(self, result: Any = None, error: Exception | None = None):
        self._result = result
        self._error = error

    def list_tools(self) -> list[Tool]:
        return []

    def execute_tool(self, tool_name: str, arguments: dict[str, Any]) -> Any:
        if self._error:
            raise self._error
        return self._result


class TestAuthDecorator:

    def test_normal_execution_passes_through(self):
        dec = AuthDecorator(FakeToolDriver(result='{"messages": []}'))
        assert dec.execute_tool("list_messages", {}) == '{"messages": []}'

    def test_auth_challenge_converted_to_json(self):
        challenge = AuthChallenge(
            "Please authenticate",
            url="https://auth0.com/activate",
            code="WXYZ-5678",
            scope="gmail",
        )
        dec = AuthDecorator(FakeToolDriver(error=challenge))
        data = json.loads(dec.execute_tool("list_messages", {}))

        assert data["auth_required"] is True
        assert data["message"] == "Please authenticate"
        assert data["url"] == "https://auth0.com/activate"
        assert data["code"] == "WXYZ-5678"
        assert data["scope"] == "gmail"

    def test_auth_challenge_without_optional_fields(self):
        dec = AuthDecorator(FakeToolDriver(error=AuthChallenge("API key needed")))
        data = json.loads(dec.execute_tool("some_tool", {}))

        assert data["auth_required"] is True
        assert data["message"] == "API key needed"
        assert "url" not in data
        assert "code" not in data
        assert "scope" not in data

    def test_other_exceptions_propagate(self):
        dec = AuthDecorator(FakeToolDriver(error=ValueError("something broke")))
        with pytest.raises(ValueError, match="something broke"):
            dec.execute_tool("list_messages", {})

    # -- Composition: capability + delegation + resolution --------------------

    def test_advertises_auth_capability(self):
        dec = AuthDecorator(FakeToolDriver())
        assert "auth" in dec.meta.capabilities

    def test_resolves_as_supports_auth(self):
        dec = AuthDecorator(FakeToolDriver())
        assert DriverMeta.resolve_capability(dec, SupportsAuth) is dec

    def test_list_tools_is_delegated(self):
        inner = FakeToolDriver()
        dec = AuthDecorator(inner)
        assert dec.list_tools() == inner.list_tools()
