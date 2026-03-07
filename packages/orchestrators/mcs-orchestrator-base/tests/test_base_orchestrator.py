"""Tests for BaseOrchestrator + ToolLayer pipeline."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any

import pytest

from mcs.driver.core import MCSToolDriver, Tool, ToolParameter, DriverMeta, DriverBinding
from mcs.orchestrator.base import (
    BaseOrchestrator,
    ToolLayer,
    ToolPipeline,
    FlatCollector,
    NamespacingLayer,
    ToolSwitchingLayer,
)


# -- Fake ToolDrivers --------------------------------------------------------

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


TOOL_A = Tool(name="tool_a", description="Tool A", parameters=[])
TOOL_B = Tool(name="tool_b", description="Tool B", parameters=[
    ToolParameter(name="x", description="param x", required=True),
])
TOOL_C = Tool(name="tool_c", description="Tool C", parameters=[])


def _driver_ab() -> FakeToolDriver:
    return FakeToolDriver([TOOL_A, TOOL_B], {"tool_a": "result_a", "tool_b": "result_b"})


def _driver_c() -> FakeToolDriver:
    return FakeToolDriver([TOOL_C], {"tool_c": "result_c"})


# -- BaseOrchestrator: add/remove --------------------------------------------

class TestDriverManagement:
    def test_add_and_list_labels(self):
        orch = BaseOrchestrator()
        orch.add_driver(_driver_ab(), label="alpha")
        orch.add_driver(_driver_c(), label="beta")
        assert sorted(orch.labels) == ["alpha", "beta"]

    def test_add_duplicate_label_raises(self):
        orch = BaseOrchestrator()
        orch.add_driver(_driver_ab(), label="alpha")
        with pytest.raises(ValueError, match="already in use"):
            orch.add_driver(_driver_c(), label="alpha")

    def test_remove_driver(self):
        orch = BaseOrchestrator()
        orch.add_driver(_driver_ab(), label="alpha")
        removed = orch.remove_driver("alpha")
        assert removed is not None
        assert orch.labels == []

    def test_remove_nonexistent_returns_none(self):
        orch = BaseOrchestrator()
        assert orch.remove_driver("nope") is None


# -- NamespacingLayer ---------------------------------------------------------

class TestNamespacingLayer:
    def test_single_driver_no_prefix(self):
        orch = BaseOrchestrator()
        orch.add_driver(_driver_ab(), label="alpha")
        names = [t.name for t in orch.list_tools()]
        assert names == ["tool_a", "tool_b"]

    def test_multiple_drivers_prefixed(self):
        orch = BaseOrchestrator()
        orch.add_driver(_driver_ab(), label="alpha")
        orch.add_driver(_driver_c(), label="beta")
        names = [t.name for t in orch.list_tools()]
        assert "alpha__tool_a" in names
        assert "alpha__tool_b" in names
        assert "beta__tool_c" in names

    def test_descriptions_prefixed(self):
        orch = BaseOrchestrator()
        orch.add_driver(_driver_ab(), label="alpha")
        orch.add_driver(_driver_c(), label="beta")
        tools = {t.name: t for t in orch.list_tools()}
        assert tools["beta__tool_c"].description.startswith("[beta]")

    def test_execute_namespaced(self):
        orch = BaseOrchestrator()
        orch.add_driver(_driver_ab(), label="alpha")
        orch.add_driver(_driver_c(), label="beta")
        assert orch.execute_tool("alpha__tool_a", {}) == "result_a"
        assert orch.execute_tool("beta__tool_c", {}) == "result_c"

    def test_execute_unknown_raises(self):
        orch = BaseOrchestrator()
        orch.add_driver(_driver_ab(), label="alpha")
        with pytest.raises(ValueError, match="No tool"):
            orch.execute_tool("nonexistent", {})

    def test_fallback_to_original_name(self):
        orch = BaseOrchestrator()
        orch.add_driver(_driver_ab(), label="alpha")
        assert orch.execute_tool("tool_a", {}) == "result_a"


# -- ToolSwitchingLayer ------------------------------------------------------

class TestToolSwitchingLayer:
    def test_auto_active_with_single_driver(self):
        layer = ToolSwitchingLayer()
        orch = BaseOrchestrator(resolution_strategy=ToolPipeline(layers=[layer]))
        orch.add_driver(_driver_ab(), label="alpha")
        names = [t.name for t in orch.list_tools()]
        assert names == ["tool_a", "tool_b"]

    def test_no_active_with_multiple_raises(self):
        layer = ToolSwitchingLayer()
        orch = BaseOrchestrator(resolution_strategy=ToolPipeline(layers=[layer]))
        orch.add_driver(_driver_ab(), label="alpha")
        orch.add_driver(_driver_c(), label="beta")
        with pytest.raises(ValueError, match="No active driver"):
            orch.list_tools()

    def test_set_active_switches(self):
        layer = ToolSwitchingLayer()
        orch = BaseOrchestrator(resolution_strategy=ToolPipeline(layers=[layer]))
        orch.add_driver(_driver_ab(), label="alpha")
        orch.add_driver(_driver_c(), label="beta")

        layer.set_active("alpha")
        assert [t.name for t in orch.list_tools()] == ["tool_a", "tool_b"]

        layer.set_active("beta")
        assert [t.name for t in orch.list_tools()] == ["tool_c"]

    def test_execute_active_only(self):
        layer = ToolSwitchingLayer()
        orch = BaseOrchestrator(resolution_strategy=ToolPipeline(layers=[layer]))
        orch.add_driver(_driver_ab(), label="alpha")
        orch.add_driver(_driver_c(), label="beta")

        layer.set_active("beta")
        assert orch.execute_tool("tool_c", {}) == "result_c"

        with pytest.raises(ValueError, match="not found in active"):
            orch.execute_tool("tool_a", {})

    def test_invalid_active_label_raises(self):
        layer = ToolSwitchingLayer()
        orch = BaseOrchestrator(resolution_strategy=ToolPipeline(layers=[layer]))
        orch.add_driver(_driver_ab(), label="alpha")
        layer.set_active("nope")
        with pytest.raises(ValueError, match="not found in registry"):
            orch.list_tools()

    def test_strategy_accessible_via_property(self):
        pipeline = ToolPipeline(layers=[ToolSwitchingLayer()])
        orch = BaseOrchestrator(resolution_strategy=pipeline)
        assert orch.resolution_strategy is pipeline


# -- FlatCollector -----------------------------------------------------------

class TestFlatCollector:
    def test_collects_all_tools(self):
        fc = FlatCollector()
        labeled = {"a": _driver_ab(), "b": _driver_c()}
        tools = fc.list_tools(labeled)
        assert len(tools) == 3

    def test_execute_dispatches(self):
        fc = FlatCollector()
        labeled = {"a": _driver_ab(), "b": _driver_c()}
        assert fc.execute_tool(labeled, "tool_a", {}) == "result_a"
        assert fc.execute_tool(labeled, "tool_c", {}) == "result_c"

    def test_unknown_tool_raises(self):
        fc = FlatCollector()
        with pytest.raises(ValueError, match="No tool"):
            fc.execute_tool({"a": _driver_ab()}, "nope", {})


# -- ToolPipeline: composition -----------------------------------------------

class TestToolPipeline:
    def test_empty_pipeline_uses_flat_collector(self):
        pipeline = ToolPipeline()
        labeled = {"a": _driver_ab()}
        assert [t.name for t in pipeline.list_tools(labeled)] == ["tool_a", "tool_b"]
        assert pipeline.execute_tool(labeled, "tool_a", {}) == "result_a"

    def test_single_layer(self):
        pipeline = ToolPipeline(layers=[NamespacingLayer()])
        labeled = {"a": _driver_ab(), "b": _driver_c()}
        names = [t.name for t in pipeline.list_tools(labeled)]
        assert "a__tool_a" in names
        assert "b__tool_c" in names

    def test_layers_property(self):
        ns = NamespacingLayer()
        pipeline = ToolPipeline(layers=[ns])
        assert pipeline.layers == (ns,)

    def test_get_instructions_empty(self):
        pipeline = ToolPipeline(layers=[NamespacingLayer()])
        assert pipeline.get_instructions() == ""

    def test_chained_layers_execute(self):
        """A passthrough layer wrapping NamespacingLayer still routes correctly."""
        passthrough = ToolLayer()
        ns = NamespacingLayer()
        pipeline = ToolPipeline(layers=[ns, passthrough])
        labeled = {"a": _driver_ab(), "b": _driver_c()}
        assert pipeline.execute_tool(labeled, "a__tool_a", {}) == "result_a"


# -- Custom layer with synthetic tools ---------------------------------------

class _DoubleLayer(ToolLayer):
    """Test layer that injects a synthetic 'double' tool."""

    def list_tools(self, labeled):
        tools = self._inner.list_tools(labeled)
        tools.append(Tool(name="double", description="Doubles a number", parameters=[]))
        return tools

    def execute_tool(self, labeled, tool_name, arguments):
        if tool_name == "double":
            return arguments.get("n", 0) * 2
        return self._inner.execute_tool(labeled, tool_name, arguments)

    def get_instructions(self):
        return "Use 'double' to double a number."


class TestCustomLayer:
    def test_synthetic_tool_in_list(self):
        pipeline = ToolPipeline(layers=[_DoubleLayer()])
        labeled = {"a": _driver_ab()}
        names = [t.name for t in pipeline.list_tools(labeled)]
        assert "double" in names
        assert "tool_a" in names

    def test_synthetic_tool_executes(self):
        pipeline = ToolPipeline(layers=[_DoubleLayer()])
        labeled = {"a": _driver_ab()}
        assert pipeline.execute_tool(labeled, "double", {"n": 5}) == 10

    def test_real_tool_still_works(self):
        pipeline = ToolPipeline(layers=[_DoubleLayer()])
        labeled = {"a": _driver_ab()}
        assert pipeline.execute_tool(labeled, "tool_a", {}) == "result_a"

    def test_get_instructions(self):
        pipeline = ToolPipeline(layers=[_DoubleLayer()])
        assert "double" in pipeline.get_instructions()

    def test_layer_wrapping_namespacing(self):
        pipeline = ToolPipeline(layers=[NamespacingLayer(), _DoubleLayer()])
        labeled = {"a": _driver_ab(), "b": _driver_c()}
        names = [t.name for t in pipeline.list_tools(labeled)]
        assert "a__tool_a" in names
        assert "double" in names
        assert pipeline.execute_tool(labeled, "double", {"n": 3}) == 6
        assert pipeline.execute_tool(labeled, "a__tool_a", {}) == "result_a"


# -- DriverBase integration ---------------------------------------------------

class TestDriverBaseIntegration:
    def test_get_function_description(self):
        orch = BaseOrchestrator()
        orch.add_driver(_driver_ab(), label="alpha")
        desc = orch.get_function_description()
        assert "tool_a" in desc
        assert "tool_b" in desc

    def test_get_driver_system_message(self):
        orch = BaseOrchestrator()
        orch.add_driver(_driver_ab(), label="alpha")
        msg = orch.get_driver_system_message()
        assert "tool_a" in msg

    def test_system_message_includes_layer_instructions(self):
        pipeline = ToolPipeline(layers=[_DoubleLayer()])
        orch = BaseOrchestrator(resolution_strategy=pipeline)
        orch.add_driver(_driver_ab(), label="alpha")
        msg = orch.get_driver_system_message()
        assert "double" in msg

    def test_process_llm_response_executes(self):
        orch = BaseOrchestrator()
        orch.add_driver(_driver_ab(), label="alpha")
        dr = orch.process_llm_response('{"tool": "tool_a", "arguments": {}}')
        assert dr.call_executed is True
        assert dr.tool_call_result == "result_a"

    def test_process_llm_response_unknown_tool_retries(self):
        orch = BaseOrchestrator()
        orch.add_driver(_driver_ab(), label="alpha")
        dr = orch.process_llm_response('{"tool": "nope", "arguments": {}}')
        assert dr.call_failed is True
        assert "nope" in (dr.call_detail or "")
