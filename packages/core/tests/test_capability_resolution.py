"""Tests for capability resolution -- the core mechanism (entry point + fallback).

Only *wrappers* (decorators, orchestrators) implement
``SupportsCapabilityResolution`` -- they need it as a signal to the entry point
"search me inward instead of matching me with ``isinstance``". A plain or hybrid
``BaseDriver`` is **not** a resolution node: it has no inner layers, so the
``isinstance`` fallback in :meth:`DriverMeta.resolve_capability` is exactly the
right (and only needed) behaviour. Wrapper-side resolution lives in the decorator
and orchestrator packages.

Note: resolution is an *invocation* concern -- it locates the layer that
*satisfies* a contract via ``isinstance``, independent of what
``meta.capabilities`` advertises (that is the *detection* concern).
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any

from mcs.driver.core import (
    BaseDriver,
    DriverMeta,
    DriverBinding,
    Tool,
    MCSToolDriver,
    SupportsHealthcheck,
    SupportsNativeTools,
    SupportsCapabilityResolution,
)


@dataclass(frozen=True)
class _Meta(DriverMeta):
    id: str = "res-0000"
    name: str = "Resolution Test"
    version: str = "0.0.1"
    bindings: tuple[DriverBinding, ...] = ()
    supported_llms: tuple[str, ...] | None = None
    capabilities: tuple[str, ...] = ()


class PlainDriver(BaseDriver):
    """A plain ``BaseDriver`` -- provides ``native_tools`` via the base, nothing else."""

    meta: DriverMeta = _Meta()

    def list_tools(self) -> list[Tool]:
        return []

    def execute_tool(self, tool_name: str, arguments: dict[str, Any]) -> Any:
        return "ok"


class HealthDriver(PlainDriver, SupportsHealthcheck):
    """A ``BaseDriver`` that additionally provides the healthcheck capability."""

    def healthcheck(self) -> dict[str, Any]:
        return {"status": "OK"}


class RawToolDriver(MCSToolDriver, SupportsHealthcheck):
    """A non-``BaseDriver`` tool driver -- also matched through the fallback."""

    meta: DriverMeta = _Meta()

    def list_tools(self) -> list[Tool]:
        return []

    def execute_tool(self, tool_name: str, arguments: dict[str, Any]) -> Any:
        return "ok"

    def healthcheck(self) -> dict[str, Any]:
        return {"status": "OK"}


# -- Leaves are NOT resolution nodes -- only wrappers implement the contract --

class TestNotResolutionNodes:
    def test_basedriver_is_not_a_resolution_node(self):
        assert not isinstance(PlainDriver(), SupportsCapabilityResolution)

    def test_raw_tool_driver_is_not_a_resolution_node(self):
        assert not isinstance(RawToolDriver(), SupportsCapabilityResolution)


# -- DriverMeta.resolve_capability: the fallback resolves every leaf ----------

class TestEntryPointFallback:
    def test_basedriver_matched_via_fallback(self):
        d = HealthDriver()
        assert DriverMeta.resolve_capability(d, SupportsHealthcheck) is d

    def test_basedriver_inherited_capability(self):
        d = PlainDriver()
        assert DriverMeta.resolve_capability(d, SupportsNativeTools) is d

    def test_basedriver_absent_capability_returns_none(self):
        d = PlainDriver()
        assert DriverMeta.resolve_capability(d, SupportsHealthcheck) is None

    def test_raw_tool_driver_matched_via_fallback(self):
        d = RawToolDriver()
        assert DriverMeta.resolve_capability(d, SupportsHealthcheck) is d

    def test_raw_tool_driver_absent_capability_returns_none(self):
        d = RawToolDriver()
        assert DriverMeta.resolve_capability(d, SupportsNativeTools) is None
