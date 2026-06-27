"""Tests for PermissionDecorator and SupportsConsent."""

from __future__ import annotations

import json
from dataclasses import dataclass
from typing import Any

import pytest

from mcs.driver.core import MCSToolDriver, DriverMeta, DriverBinding, Tool
from mcs.permission.decorator import PermissionDecorator, SupportsConsent


@dataclass(frozen=True)
class _Meta(DriverMeta):
    id: str = "fake-0001"
    name: str = "Fake"
    version: str = "0.0.1"
    bindings: tuple[DriverBinding, ...] = ()
    supported_llms: tuple[str, ...] | None = None
    capabilities: tuple[str, ...] = ()


class FakeTool(MCSToolDriver):
    meta: DriverMeta = _Meta()

    def list_tools(self) -> list[Tool]:
        return []

    def execute_tool(self, tool_name: str, arguments: dict[str, Any]) -> Any:
        return f"ran:{tool_name}"


class TestPermissionDecorator:

    def test_allows_when_consent_granted(self):
        dec = PermissionDecorator(FakeTool(), consent_handler=lambda n, a: True)
        assert dec.execute_tool("send", {}) == "ran:send"

    def test_blocks_when_consent_denied(self):
        dec = PermissionDecorator(FakeTool(), consent_handler=lambda n, a: False)
        data = json.loads(dec.execute_tool("send", {}))
        assert data["permission_denied"] is True
        assert data["tool"] == "send"

    def test_consent_receives_name_and_args(self):
        seen: dict[str, Any] = {}

        def consent(name, args):
            seen["name"] = name
            seen["args"] = args
            return True

        PermissionDecorator(FakeTool(), consent_handler=consent).execute_tool("send", {"to": "x"})
        assert seen == {"name": "send", "args": {"to": "x"}}

    def test_advertises_consent_capability(self):
        dec = PermissionDecorator(FakeTool(), consent_handler=lambda n, a: True)
        assert "consent" in dec.meta.capabilities

    def test_resolves_as_supports_consent(self):
        dec = PermissionDecorator(FakeTool(), consent_handler=lambda n, a: True)
        assert DriverMeta.resolve_capability(dec, SupportsConsent) is dec

    def test_handler_can_be_registered_at_runtime(self):
        dec = PermissionDecorator(FakeTool())            # no handler yet
        dec.set_consent_handler(lambda n, a: True)
        assert dec.execute_tool("send", {}) == "ran:send"

    def test_set_consent_replaces_handler(self):
        dec = PermissionDecorator(FakeTool(), consent_handler=lambda n, a: True)
        dec.set_consent_handler(lambda n, a: False)              # replace at runtime
        data = json.loads(dec.execute_tool("send", {}))
        assert data["permission_denied"] is True

    def test_missing_handler_raises(self):
        dec = PermissionDecorator(FakeTool())            # never given a handler
        with pytest.raises(RuntimeError, match="no consent handler"):
            dec.execute_tool("send", {})
