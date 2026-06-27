"""Tests for BaseDecorator -- the single-inner wrapping driver.

Covers delegation, capability-flag aggregation, the interception seam
(`execute_tool` override), and capability resolution through nested decorators.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any

from mcs.driver.core import (
    BaseDecorator,
    MCSToolDriver,
    Tool,
    DriverMeta,
    DriverBinding,
    SupportsHealthcheck,
    SupportsCapabilityResolution,
)


@dataclass(frozen=True)
class _Meta(DriverMeta):
    id: str = "dec-0000"
    name: str = "Decorator Test"
    version: str = "0.0.1"
    bindings: tuple[DriverBinding, ...] = ()
    supported_llms: tuple[str, ...] | None = None
    capabilities: tuple[str, ...] = ()


TOOL_A = Tool(name="tool_a", description="Tool A")
TOOL_B = Tool(name="tool_b", description="Tool B")


class FakeTool(MCSToolDriver):
    """A plain inner tool driver (not resolution-aware on its own)."""

    def __init__(self, tools=None, results=None, capabilities=()):
        self.meta: DriverMeta = _Meta(capabilities=tuple(capabilities))
        self._tools = tools if tools is not None else [TOOL_A, TOOL_B]
        self._results = results or {}

    def list_tools(self) -> list[Tool]:
        return self._tools

    def execute_tool(self, tool_name: str, arguments: dict[str, Any]) -> Any:
        return self._results.get(tool_name, f"exec:{tool_name}")


class FakeHealthTool(FakeTool, SupportsHealthcheck):
    """An inner tool driver that also provides the healthcheck capability."""

    def healthcheck(self) -> dict[str, Any]:
        return {"status": "inner"}


class _HealthcheckDecorator(BaseDecorator, SupportsHealthcheck):
    """A concrete decorator: adds the healthcheck capability and wraps results."""

    CONTRACT = SupportsHealthcheck

    def healthcheck(self) -> dict[str, Any]:
        return {"status": "decorator"}

    def execute_tool(self, tool_name: str, arguments: dict[str, Any]) -> Any:
        return f"wrapped:{self._inner.execute_tool(tool_name, arguments)}"


# -- Delegation ---------------------------------------------------------------

class TestDelegation:
    def test_list_tools_delegates(self):
        inner = FakeTool()
        dec = BaseDecorator(inner)
        assert dec.list_tools() == inner.list_tools()

    def test_execute_tool_delegates_by_default(self):
        dec = BaseDecorator(FakeTool(results={"tool_a": "A"}))
        assert dec.execute_tool("tool_a", {}) == "A"

    def test_subclass_intercepts_only_execute_tool(self):
        inner = FakeTool(results={"tool_a": "A"})
        dec = _HealthcheckDecorator(inner)
        assert dec.execute_tool("tool_a", {}) == "wrapped:A"   # intercepted
        assert dec.list_tools() == inner.list_tools()           # still delegated


# -- Capability-flag aggregation ---------------------------------------------

class TestMetaAggregation:
    def test_bare_decorator_adds_nothing(self):
        inner = FakeTool(capabilities=("native_tools",))
        dec = BaseDecorator(inner)
        assert dec.meta.capabilities == inner.meta.capabilities

    def test_decorator_adds_its_own_flag(self):
        dec = _HealthcheckDecorator(FakeTool())
        assert "healthcheck" in dec.meta.capabilities

    def test_aggregates_inner_and_own_flags(self):
        dec = _HealthcheckDecorator(FakeTool(capabilities=("native_tools",)))
        assert "native_tools" in dec.meta.capabilities
        assert "healthcheck" in dec.meta.capabilities

    def test_idempotent_when_inner_already_has_flag(self):
        dec = _HealthcheckDecorator(FakeTool(capabilities=("healthcheck",)))
        assert dec.meta.capabilities.count("healthcheck") == 1


# -- Capability resolution ----------------------------------------------------

class TestResolveCapability:
    def test_decorator_is_a_resolution_node(self):
        assert isinstance(BaseDecorator(FakeTool()), SupportsCapabilityResolution)

    def test_resolves_own_capability_to_self(self):
        dec = _HealthcheckDecorator(FakeTool())
        assert DriverMeta.resolve_capability(dec, SupportsHealthcheck) is dec

    def test_resolves_inner_capability(self):
        inner = FakeHealthTool()
        dec = BaseDecorator(inner)   # bare wrapper, no healthcheck of its own
        assert DriverMeta.resolve_capability(dec, SupportsHealthcheck) is inner

    def test_self_takes_priority_over_inner(self):
        inner = FakeHealthTool()
        dec = _HealthcheckDecorator(inner)   # both provide healthcheck
        assert DriverMeta.resolve_capability(dec, SupportsHealthcheck) is dec

    def test_returns_none_when_absent(self):
        dec = BaseDecorator(FakeTool())
        assert DriverMeta.resolve_capability(dec, SupportsHealthcheck) is None


# -- Nested decorators (stack navigation) ------------------------------------

class TestNestedDecorators:
    def test_two_bare_wrappers_find_inner_capability(self):
        inner = FakeHealthTool()
        stack = BaseDecorator(BaseDecorator(inner))
        assert DriverMeta.resolve_capability(stack, SupportsHealthcheck) is inner

    def test_outer_decorator_capability_wins(self):
        stack = _HealthcheckDecorator(BaseDecorator(FakeHealthTool()))
        assert DriverMeta.resolve_capability(stack, SupportsHealthcheck) is stack

    def test_capability_on_middle_layer(self):
        middle = _HealthcheckDecorator(FakeTool())   # middle adds healthcheck
        outer = BaseDecorator(middle)                # bare outer
        assert DriverMeta.resolve_capability(outer, SupportsHealthcheck) is middle

    def test_execute_tool_chains_through_wrappers(self):
        inner = FakeTool(results={"tool_a": "A"})
        stack = _HealthcheckDecorator(_HealthcheckDecorator(inner))
        assert stack.execute_tool("tool_a", {}) == "wrapped:wrapped:A"
