"""Tests for the composite web driver: both halves under one interface."""

from __future__ import annotations

import pytest

from mcs.driver.core import DriverBinding, DriverMeta, MCSToolDriver, Tool
from mcs.driver.web import WebDriver, WebToolDriver


class _Half(MCSToolDriver):
    """A stand-in ToolDriver exposing named tools."""

    meta: DriverMeta = DriverMeta(
        id="x", name="half", version="1",
        bindings=(DriverBinding("web", "*", "Custom"),),
        supported_llms=None, capabilities=("orchestratable",),
    )

    def __init__(self, names, label):
        self._names, self._label = names, label
        self.calls: list[tuple[str, dict]] = []

    def list_tools(self):
        return [Tool(n, description=f"{self._label} tool") for n in self._names]

    def execute_tool(self, tool_name, arguments):
        self.calls.append((tool_name, arguments))
        return {"handled_by": self._label, "tool": tool_name}


class TestComposition:

    def test_lists_tools_from_both_halves(self):
        td = WebToolDriver(_search_driver=_Half(["web_search"], "search"),
                           _fetch_driver=_Half(["fetch_page"], "fetch"))
        assert [t.name for t in td.list_tools()] == ["web_search", "fetch_page"]

    def test_dispatches_to_the_owning_half(self):
        search = _Half(["web_search"], "search")
        fetch = _Half(["fetch_page"], "fetch")
        td = WebToolDriver(_search_driver=search, _fetch_driver=fetch)

        assert td.execute_tool("web_search", {"query": "x"})["handled_by"] == "search"
        assert td.execute_tool("fetch_page", {"url": "https://x"})["handled_by"] == "fetch"
        assert search.calls and fetch.calls

    def test_unknown_tool_rejected(self):
        td = WebToolDriver(_search_driver=_Half(["web_search"], "s"),
                           _fetch_driver=_Half(["fetch_page"], "f"))
        with pytest.raises(ValueError, match="not found"):
            td.execute_tool("crawl_site", {})

    def test_name_collision_fails_at_construction(self):
        """Two halves claiming one name would make dispatch arbitrary, and the
        failure would only surface at call time."""
        with pytest.raises(ValueError, match="collision"):
            WebToolDriver(_search_driver=_Half(["same"], "s"),
                          _fetch_driver=_Half(["same"], "f"))

    def test_advertises_both_capabilities(self):
        td = WebToolDriver(_search_driver=_Half(["a"], "s"),
                           _fetch_driver=_Half(["b"], "f"))
        caps = {b.capability for b in td.meta.bindings}
        assert caps == {"websearch", "webfetch"}


class TestDriver:

    def _driver(self):
        td = WebToolDriver(_search_driver=_Half(["web_search"], "search"),
                           _fetch_driver=_Half(["fetch_page"], "fetch"))
        return WebDriver(_tooldriver=td)

    def test_exposes_both_tools(self):
        assert [t.name for t in self._driver().list_tools()] == ["web_search", "fetch_page"]

    def test_system_prompt_offers_the_research_pattern(self):
        """Find sources, then read the promising ones -- both tools in one prompt,
        so the model needs no orchestration on the client side."""
        prompt = self._driver().get_driver_system_message()
        assert "web_search" in prompt and "fetch_page" in prompt

    def test_is_standalone_and_orchestratable(self):
        meta = self._driver().meta
        assert "standalone" in meta.capabilities
        assert "orchestratable" in meta.capabilities

    def test_delegates_execution(self):
        assert self._driver().execute_tool(
            "fetch_page", {"url": "https://x"})["handled_by"] == "fetch"


class TestRealHalves:
    """Wiring check against the actual halves, without network access."""

    def test_builds_from_real_tooldrivers(self):
        td = WebToolDriver(api_key="dummy", base_url="https://svc.invalid")
        assert [t.name for t in td.list_tools()] == ["web_search", "fetch_page"]

    def test_raw_stays_opt_in_through_the_composite(self):
        """The fetch half's safety default must survive composition."""
        td = WebToolDriver(api_key="dummy", base_url="https://svc.invalid")
        fetch_tool = [t for t in td.list_tools() if t.name == "fetch_page"][0]
        fmt = {p.name: p for p in fetch_tool.parameters}["format"]
        assert fmt.schema["enum"] == ["text", "markdown"]

        td_raw = WebToolDriver(api_key="dummy", base_url="https://svc.invalid",
                               allow_raw=True)
        fetch_tool = [t for t in td_raw.list_tools() if t.name == "fetch_page"][0]
        fmt = {p.name: p for p in fetch_tool.parameters}["format"]
        assert "raw" in fmt.schema["enum"]
