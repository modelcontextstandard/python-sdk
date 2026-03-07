"""Tests for PaginationLayer and DetailLoadingLayer."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any

import pytest

from mcs.driver.core import MCSToolDriver, Tool, ToolParameter, DriverMeta, DriverBinding
from mcs.orchestrator.base import (
    ToolPipeline,
    NamespacingLayer,
    PaginationLayer,
    DetailLoadingLayer,
)


@dataclass(frozen=True)
class _FakeMeta(DriverMeta):
    id: str = "fake-0001"
    name: str = "Fake"
    version: str = "0.1.0"
    bindings: tuple[DriverBinding, ...] = ()
    supported_llms: None = None
    capabilities: tuple[str, ...] = ()


class FakeToolDriver(MCSToolDriver):
    meta: DriverMeta = _FakeMeta()

    def __init__(self, tools: list[Tool], results: dict[str, str] | None = None):
        self._tools = tools
        self._results = results or {}

    def list_tools(self) -> list[Tool]:
        return self._tools

    def execute_tool(self, tool_name: str, arguments: dict[str, Any]) -> Any:
        if tool_name in self._results:
            return self._results[tool_name]
        return f"executed:{tool_name}"


def _make_tools(n: int) -> list[Tool]:
    return [
        Tool(name=f"tool_{i}", description=f"Tool {i} description", parameters=[])
        for i in range(n)
    ]


def _make_driver(n: int) -> FakeToolDriver:
    tools = _make_tools(n)
    results = {t.name: f"result_{t.name}" for t in tools}
    return FakeToolDriver(tools, results)


# -- PaginationLayer ---------------------------------------------------------

class TestPaginationLayer:
    def test_no_pagination_when_small(self):
        pipeline = ToolPipeline(layers=[PaginationLayer(page_size=10)])
        labeled = {"a": _make_driver(5)}
        tools = pipeline.list_tools(labeled)
        assert len(tools) == 5
        assert all("next" not in t.name for t in tools)

    def test_paginated_first_page(self):
        pl = PaginationLayer(page_size=3)
        pipeline = ToolPipeline(layers=[pl])
        labeled = {"a": _make_driver(10)}
        tools = pipeline.list_tools(labeled)
        real = [t for t in tools if not t.name.startswith("tools__")]
        nav = [t for t in tools if t.name.startswith("tools__")]
        assert len(real) == 3
        assert any(t.name == "tools__next_page" for t in nav)
        assert not any(t.name == "tools__prev_page" for t in nav)

    def test_navigate_next(self):
        pl = PaginationLayer(page_size=3)
        pipeline = ToolPipeline(layers=[pl])
        labeled = {"a": _make_driver(10)}
        pipeline.list_tools(labeled)
        result = pipeline.execute_tool(labeled, "tools__next_page", {})
        assert result["page"] == 2
        tools = pipeline.list_tools(labeled)
        real_names = [t.name for t in tools if not t.name.startswith("tools__")]
        assert real_names == ["tool_3", "tool_4", "tool_5"]

    def test_navigate_prev(self):
        pl = PaginationLayer(page_size=3)
        pipeline = ToolPipeline(layers=[pl])
        labeled = {"a": _make_driver(10)}
        pipeline.list_tools(labeled)
        pipeline.execute_tool(labeled, "tools__next_page", {})
        result = pipeline.execute_tool(labeled, "tools__prev_page", {})
        assert result["page"] == 1

    def test_passthrough_real_tool(self):
        pl = PaginationLayer(page_size=3)
        pipeline = ToolPipeline(layers=[pl])
        labeled = {"a": _make_driver(10)}
        pipeline.list_tools(labeled)
        assert pipeline.execute_tool(labeled, "tool_0", {}) == "result_tool_0"

    def test_get_instructions_when_paginated(self):
        pl = PaginationLayer(page_size=3)
        pipeline = ToolPipeline(layers=[pl])
        labeled = {"a": _make_driver(10)}
        pipeline.list_tools(labeled)
        inst = pipeline.get_instructions()
        assert "page" in inst
        assert "tools__next_page" in inst

    def test_get_instructions_none_when_small(self):
        pl = PaginationLayer(page_size=20)
        pipeline = ToolPipeline(layers=[pl])
        labeled = {"a": _make_driver(5)}
        pipeline.list_tools(labeled)
        assert pipeline.get_instructions() == ""

    def test_pagination_with_namespacing(self):
        pipeline = ToolPipeline(layers=[
            NamespacingLayer(),
            PaginationLayer(page_size=3),
        ])
        labeled = {"a": _make_driver(5), "b": _make_driver(3)}
        tools = pipeline.list_tools(labeled)
        real = [t for t in tools if not t.name.startswith("tools__")]
        assert len(real) == 3
        assert all("__" in t.name for t in real)


# -- DetailLoadingLayer ------------------------------------------------------

class TestDetailLoadingLayer:
    def test_abbreviates_long_descriptions(self):
        driver = FakeToolDriver(
            [Tool(name="t", description="x" * 200, parameters=[])],
        )
        pipeline = ToolPipeline(layers=[DetailLoadingLayer(max_desc_length=50)])
        labeled = {"a": driver}
        tools = pipeline.list_tools(labeled)
        tool_t = next(t for t in tools if t.name == "t")
        assert len(tool_t.description) == 50
        assert tool_t.description.endswith("...")

    def test_short_descriptions_untouched(self):
        driver = FakeToolDriver(
            [Tool(name="t", description="Short desc", parameters=[])],
        )
        pipeline = ToolPipeline(layers=[DetailLoadingLayer(max_desc_length=80)])
        labeled = {"a": driver}
        tools = pipeline.list_tools(labeled)
        tool_t = next(t for t in tools if t.name == "t")
        assert tool_t.description == "Short desc"

    def test_injects_get_tool_details(self):
        pipeline = ToolPipeline(layers=[DetailLoadingLayer()])
        labeled = {"a": _make_driver(3)}
        tools = pipeline.list_tools(labeled)
        assert any(t.name == "get_tool_details" for t in tools)

    def test_get_tool_details_returns_full_info(self):
        desc = "A very detailed description " * 10
        driver = FakeToolDriver(
            [Tool(
                name="my_tool",
                description=desc,
                parameters=[ToolParameter(name="x", description="param", required=True)],
            )],
        )
        pipeline = ToolPipeline(layers=[DetailLoadingLayer(max_desc_length=30)])
        labeled = {"a": driver}
        pipeline.list_tools(labeled)
        result = pipeline.execute_tool(
            labeled, "get_tool_details", {"tool_name": "my_tool"},
        )
        assert result["name"] == "my_tool"
        assert result["description"] == desc
        assert len(result["parameters"]) == 1

    def test_get_tool_details_unknown(self):
        pipeline = ToolPipeline(layers=[DetailLoadingLayer()])
        labeled = {"a": _make_driver(1)}
        pipeline.list_tools(labeled)
        result = pipeline.execute_tool(
            labeled, "get_tool_details", {"tool_name": "nope"},
        )
        assert "error" in result

    def test_passthrough_real_tool(self):
        pipeline = ToolPipeline(layers=[DetailLoadingLayer()])
        labeled = {"a": _make_driver(3)}
        pipeline.list_tools(labeled)
        assert pipeline.execute_tool(labeled, "tool_0", {}) == "result_tool_0"

    def test_get_instructions(self):
        dl = DetailLoadingLayer()
        pipeline = ToolPipeline(layers=[dl])
        labeled = {"a": _make_driver(1)}
        pipeline.list_tools(labeled)
        inst = pipeline.get_instructions()
        assert "get_tool_details" in inst

    def test_combined_with_pagination(self):
        pipeline = ToolPipeline(layers=[
            NamespacingLayer(),
            DetailLoadingLayer(max_desc_length=40),
            PaginationLayer(page_size=5),
        ])
        labeled = {"a": _make_driver(10), "b": _make_driver(5)}
        tools = pipeline.list_tools(labeled)
        real = [t for t in tools if not t.name.startswith("tools__") and t.name != "get_tool_details"]
        assert len(real) <= 5
        inst = pipeline.get_instructions()
        assert "get_tool_details" in inst
        assert "page" in inst
