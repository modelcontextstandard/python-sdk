"""Tests for HooksMiddleware and SupportsHooks."""

from __future__ import annotations

import pytest

from mcs.driver.core import ToolMiddleware
from mcs.hooks.middleware import HooksMiddleware, SupportsHooks


def _ran(name, args):
    """Terminal call_next: the tool executed successfully."""
    return f"ran:{name}"


def _raises(exc):
    def call_next(name, args):
        raise exc
    return call_next


class TestHooksMiddleware:

    def test_pre_and_post_fire_in_order(self):
        events: list = []
        mw = HooksMiddleware(
            pre=[lambda n, a: events.append(("pre", n))],
            post=[lambda n, a, r: events.append(("post", n, r))],
        )
        result = mw.on_execute_tool("send", {}, _ran)
        assert result == "ran:send"
        assert events == [("pre", "send"), ("post", "send", "ran:send")]

    def test_failure_hook_fires_then_reraises(self):
        events: list = []
        mw = HooksMiddleware(on_failure=[lambda n, a, e: events.append(("fail", n, str(e)))])
        with pytest.raises(ValueError, match="boom"):
            mw.on_execute_tool("send", {}, _raises(ValueError("boom")))
        assert events == [("fail", "send", "boom")]

    def test_post_not_called_on_failure(self):
        seen: list = []
        mw = HooksMiddleware(post=[lambda n, a, r: seen.append("post")])
        with pytest.raises(ValueError):
            mw.on_execute_tool("x", {}, _raises(ValueError("x")))
        assert seen == []

    def test_multiple_observers_per_phase(self):
        seen: list = []
        mw = HooksMiddleware()
        mw.add_pre_hook(lambda n, a: seen.append("h1"))
        mw.add_pre_hook(lambda n, a: seen.append("h2"))
        mw.on_execute_tool("x", {}, _ran)
        assert seen == ["h1", "h2"]

    def test_remove_hook(self):
        seen: list = []

        def h(n, a):
            seen.append("h")

        mw = HooksMiddleware(pre=[h])
        mw.remove_pre_hook(h)
        mw.on_execute_tool("x", {}, _ran)
        assert seen == []

    # -- Contract -------------------------------------------------------------

    def test_is_a_tool_middleware(self):
        assert isinstance(HooksMiddleware(), ToolMiddleware)

    def test_carries_hooks_capability(self):
        assert isinstance(HooksMiddleware(), SupportsHooks)
        assert SupportsHooks.CAPABILITY == "hooks"
