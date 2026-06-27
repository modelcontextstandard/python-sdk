"""Tests for HooksDecorator and SupportsHooks."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any

import pytest

from mcs.driver.core import MCSToolDriver, DriverMeta, DriverBinding, Tool
from mcs.hooks.decorator import HooksDecorator, SupportsHooks


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

    def __init__(self, error: Exception | None = None):
        self._error = error

    def list_tools(self) -> list[Tool]:
        return []

    def execute_tool(self, tool_name: str, arguments: dict[str, Any]) -> Any:
        if self._error:
            raise self._error
        return f"ran:{tool_name}"


class TestHooksDecorator:

    def test_pre_and_post_fire_in_order(self):
        events: list = []
        dec = HooksDecorator(
            FakeTool(),
            pre=[lambda n, a: events.append(("pre", n))],
            post=[lambda n, a, r: events.append(("post", n, r))],
        )
        result = dec.execute_tool("send", {})
        assert result == "ran:send"
        assert events == [("pre", "send"), ("post", "send", "ran:send")]

    def test_failure_hook_fires_then_reraises(self):
        events: list = []
        dec = HooksDecorator(
            FakeTool(error=ValueError("boom")),
            on_failure=[lambda n, a, e: events.append(("fail", n, str(e)))],
        )
        with pytest.raises(ValueError, match="boom"):
            dec.execute_tool("send", {})
        assert events == [("fail", "send", "boom")]

    def test_post_not_called_on_failure(self):
        seen: list = []
        dec = HooksDecorator(
            FakeTool(error=ValueError("x")),
            post=[lambda n, a, r: seen.append("post")],
        )
        with pytest.raises(ValueError):
            dec.execute_tool("x", {})
        assert seen == []

    def test_multiple_observers_per_phase(self):
        seen: list = []
        dec = HooksDecorator(FakeTool())
        dec.add_pre_hook(lambda n, a: seen.append("h1"))
        dec.add_pre_hook(lambda n, a: seen.append("h2"))
        dec.execute_tool("x", {})
        assert seen == ["h1", "h2"]

    def test_remove_hook(self):
        seen: list = []

        def h(n, a):
            seen.append("h")

        dec = HooksDecorator(FakeTool(), pre=[h])
        dec.remove_pre_hook(h)
        dec.execute_tool("x", {})
        assert seen == []

    def test_advertises_hooks_capability(self):
        dec = HooksDecorator(FakeTool())
        assert "hooks" in dec.meta.capabilities

    def test_resolves_as_supports_hooks(self):
        dec = HooksDecorator(FakeTool())
        assert DriverMeta.resolve_capability(dec, SupportsHooks) is dec
