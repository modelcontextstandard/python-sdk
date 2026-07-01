"""Tests for BaseOrchestrator + ToolLayer pipeline."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any

import pytest

from mcs.driver.core import (
    MCSToolDriver,
    Tool,
    ToolParameter,
    DriverMeta,
    DriverBinding,
    SupportsHealthcheck,
    SupportsNativeTools,
    BaseDecorator,
)
from mcs.driver.core.mixins.healthcheck import HealthStatus
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


# -- BaseDriver integration ---------------------------------------------------

class TestBaseDriverIntegration:
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


# -- Capability resolution: opaque composition -------------------------------
# The orchestrator is opaque -- it advertises and resolves only its OWN
# capabilities, never those of the drivers it holds. (A decorator is the
# transparent counterpart: it *does* pass inner capabilities through.)

class _HealthDriver(FakeToolDriver, SupportsHealthcheck):
    """A registered driver reporting a (configurable) health status."""

    def __init__(self, tools: list[Tool], status: Any = "OK"):
        super().__init__(tools)
        self._status = status

    def healthcheck(self) -> dict[str, Any]:
        return {"status": self._status}


class _SupportsFoo:
    """Test-only capability the orchestrator does NOT implement."""

    CAPABILITY = "foo"

    def foo(self) -> str:
        return "foo"


class _FooDriver(FakeToolDriver, _SupportsFoo):
    """A driver carrying a capability the orchestrator must NOT surface."""


def _orch_with(*drivers: MCSToolDriver) -> BaseOrchestrator:
    """Build an orchestrator holding *drivers* under labels ``d0``, ``d1`` ..."""
    orch = BaseOrchestrator()
    for i, d in enumerate(drivers):
        orch.add_driver(d, label=f"d{i}")
    return orch


class TestCapabilityResolution:
    """The orchestrator resolves/advertises only its OWN capabilities."""

    def test_resolves_own_capability_to_self(self):
        """A capability the orchestrator provides itself resolves to itself."""
        orch = _orch_with(_driver_ab())
        assert DriverMeta.resolve_capability(orch, SupportsNativeTools) is orch

    def test_healthcheck_resolves_to_self(self):
        """Healthcheck is implemented by the orchestrator itself -> resolves to
        self, not to an inner healthcheck-capable driver."""
        orch = _orch_with(_HealthDriver([TOOL_C]))
        assert DriverMeta.resolve_capability(orch, SupportsHealthcheck) is orch

    def test_inner_capability_not_passed_through(self):
        """Opaque: a contract held only by an inner driver is NOT surfaced."""
        orch = _orch_with(_FooDriver([TOOL_C]))
        assert DriverMeta.resolve_capability(orch, _SupportsFoo) is None

    def test_detect_and_resolve_agree(self):
        """detect <-> resolve are consistent for owned and non-owned contracts."""
        orch = _orch_with(_FooDriver([TOOL_C]))
        # owned: healthcheck
        assert orch.meta.has_capability(SupportsHealthcheck)
        assert DriverMeta.resolve_capability(orch, SupportsHealthcheck) is orch
        # not owned: foo (held by an inner driver only)
        assert not orch.meta.has_capability(_SupportsFoo)
        assert DriverMeta.resolve_capability(orch, _SupportsFoo) is None


class TestHealthcheck:
    """Default healthcheck: AND-aggregate over first-level drivers."""

    def test_no_drivers_is_ok(self):
        assert BaseOrchestrator().healthcheck()["status"] is HealthStatus.OK

    def test_no_healthcheck_capable_driver_is_ok(self):
        orch = _orch_with(_driver_ab())
        assert orch.healthcheck()["status"] is HealthStatus.OK

    def test_single_ok(self):
        orch = _orch_with(_HealthDriver([TOOL_C], "OK"))
        assert orch.healthcheck()["status"] is HealthStatus.OK

    def test_single_error(self):
        orch = _orch_with(_HealthDriver([TOOL_C], "ERROR"))
        assert orch.healthcheck()["status"] is HealthStatus.ERROR

    def test_all_ok_aggregates_ok(self):
        orch = _orch_with(_HealthDriver([TOOL_A], "OK"), _HealthDriver([TOOL_C], "OK"))
        assert orch.healthcheck()["status"] is HealthStatus.OK

    def test_one_error_wins(self):
        orch = _orch_with(_HealthDriver([TOOL_A], "OK"), _HealthDriver([TOOL_C], "ERROR"))
        assert orch.healthcheck()["status"] is HealthStatus.ERROR

    def test_warning_wins_over_ok(self):
        orch = _orch_with(_HealthDriver([TOOL_A], "OK"), _HealthDriver([TOOL_C], "WARNING"))
        assert orch.healthcheck()["status"] is HealthStatus.WARNING

    def test_error_wins_over_warning(self):
        orch = _orch_with(_HealthDriver([TOOL_A], "WARNING"), _HealthDriver([TOOL_C], "ERROR"))
        assert orch.healthcheck()["status"] is HealthStatus.ERROR

    def test_plain_driver_skipped(self):
        orch = _orch_with(_driver_ab(), _HealthDriver([TOOL_C], "ERROR"))
        assert orch.healthcheck()["status"] is HealthStatus.ERROR

    def test_unknown_status_coerced(self):
        orch = _orch_with(_HealthDriver([TOOL_C], "bogus"))
        assert orch.healthcheck()["status"] is HealthStatus.UNKNOWN

    def test_capability_advertised(self):
        assert "healthcheck" in BaseOrchestrator().meta.capabilities


class TestNestedHealthcheck:
    """Nesting cascades through delegation -- no recursive capability search."""

    def test_nested_orchestrator_cascades(self):
        inner = _orch_with(_HealthDriver([TOOL_C], "ERROR"))
        outer = _orch_with(inner)
        assert outer.healthcheck()["status"] is HealthStatus.ERROR

    def test_nested_all_ok(self):
        inner = _orch_with(_HealthDriver([TOOL_C], "OK"))
        outer = _orch_with(_HealthDriver([TOOL_A], "OK"), inner)
        assert outer.healthcheck()["status"] is HealthStatus.OK

    def test_depth_three_cascades(self):
        deep = _orch_with(_orch_with(_orch_with(_HealthDriver([TOOL_C], "WARNING"))))
        assert deep.healthcheck()["status"] is HealthStatus.WARNING


class _Wrapped(BaseDecorator, SupportsHealthcheck):
    """A decorator that adds the healthcheck capability to whatever it wraps."""

    CONTRACT = SupportsHealthcheck

    def healthcheck(self):
        return {"status": "WARNING"}


class TestDecoratorInOrchestrator:
    """A BaseDecorator registered as a ToolDriver inside the orchestrator."""

    def test_healthcheck_reaches_through_bare_decorator(self):
        """A healthcheck-capable driver behind a bare decorator is still found
        (the decorator transparently resolves inward)."""
        dec = BaseDecorator(_HealthDriver([TOOL_C], "ERROR"))
        orch = _orch_with(dec)
        assert orch.healthcheck()["status"] is HealthStatus.ERROR

    def test_decorator_that_adds_healthcheck_contributes(self):
        """A decorator whose CONTRACT is SupportsHealthcheck contributes its status."""
        orch = _orch_with(_Wrapped(_driver_ab()))
        assert orch.healthcheck()["status"] is HealthStatus.WARNING

    def test_decorator_delegates_execution_in_orchestrator(self):
        dec = _Wrapped(_driver_ab())           # bare execute_tool -> delegates
        orch = _orch_with(dec)
        assert orch.execute_tool("tool_a", {}) == "result_a"
