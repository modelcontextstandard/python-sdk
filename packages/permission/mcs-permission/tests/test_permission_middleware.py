"""Tests for PermissionMiddleware and SupportsConsent."""

from __future__ import annotations

import json
from typing import Any

import pytest

from mcs.driver.core import ToolMiddleware
from mcs.permission.middleware import PermissionMiddleware, SupportsConsent


def _ran(name, args):
    """Terminal call_next: the tool executed."""
    return f"ran:{name}"


class TestPermissionMiddleware:

    def test_allows_when_consent_granted(self):
        mw = PermissionMiddleware(consent_handler=lambda n, a: True)
        assert mw.on_execute_tool("send", {}, _ran) == "ran:send"

    def test_blocks_when_consent_denied(self):
        mw = PermissionMiddleware(consent_handler=lambda n, a: False)
        data = json.loads(mw.on_execute_tool("send", {}, _ran))
        assert data["permission_denied"] is True
        assert data["tool"] == "send"

    def test_denied_never_calls_next(self):
        called = []
        mw = PermissionMiddleware(consent_handler=lambda n, a: False)
        mw.on_execute_tool("send", {}, lambda n, a: called.append(n))
        assert called == []                              # short-circuit: terminal not reached

    def test_consent_receives_name_and_args(self):
        seen: dict[str, Any] = {}

        def consent(name, args):
            seen["name"], seen["args"] = name, args
            return True

        PermissionMiddleware(consent_handler=consent).on_execute_tool("send", {"to": "x"}, _ran)
        assert seen == {"name": "send", "args": {"to": "x"}}

    def test_handler_can_be_registered_at_runtime(self):
        mw = PermissionMiddleware()                      # no handler yet
        mw.set_consent_handler(lambda n, a: True)
        assert mw.on_execute_tool("send", {}, _ran) == "ran:send"

    def test_set_consent_replaces_handler(self):
        mw = PermissionMiddleware(consent_handler=lambda n, a: True)
        mw.set_consent_handler(lambda n, a: False)       # replace at runtime
        data = json.loads(mw.on_execute_tool("send", {}, _ran))
        assert data["permission_denied"] is True

    def test_missing_handler_raises(self):
        mw = PermissionMiddleware()                      # never given a handler
        with pytest.raises(RuntimeError, match="no consent handler"):
            mw.on_execute_tool("send", {}, _ran)

    # -- Contract -------------------------------------------------------------

    def test_is_a_tool_middleware(self):
        assert isinstance(PermissionMiddleware(), ToolMiddleware)

    def test_carries_consent_capability(self):
        assert isinstance(PermissionMiddleware(), SupportsConsent)
        assert SupportsConsent.CAPABILITY == "consent"
