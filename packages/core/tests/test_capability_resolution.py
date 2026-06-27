"""Tests for capability resolution -- the core mechanism.

Covers the leaf node (:meth:`DriverBase.resolve_capability`), the static entry
point (:meth:`DriverMeta.resolve_capability`), and the ``isinstance`` fallback
for drivers that are not resolution-aware.  Nested composition through
orchestrators is tested in the ``mcs-orchestrator-base`` package.

Note: resolution is an *invocation* concern -- it locates the layer that
*satisfies* a contract via ``isinstance``, independent of what
``meta.capabilities`` advertises (that is the *detection* concern).
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any

from mcs.driver.core import (
    DriverBase,
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


class PlainDriver(DriverBase):
    """A ``DriverBase`` leaf -- provides ``native_tools`` via the base, nothing else."""

    meta: DriverMeta = _Meta()

    def list_tools(self) -> list[Tool]:
        return []

    def execute_tool(self, tool_name: str, arguments: dict[str, Any]) -> Any:
        return "ok"


class HealthDriver(PlainDriver, SupportsHealthcheck):
    """A ``DriverBase`` leaf that additionally provides the healthcheck capability."""

    def healthcheck(self) -> dict[str, Any]:
        return {"status": "OK"}


class RawToolDriver(MCSToolDriver, SupportsHealthcheck):
    """A non-``DriverBase`` tool driver.

    It does **not** implement ``resolve_capability`` (it is not a
    ``SupportsCapabilityResolution`` node), so it can only be matched through
    the ``isinstance`` fallback in :meth:`DriverMeta.resolve_capability`.
    """

    meta: DriverMeta = _Meta()

    def list_tools(self) -> list[Tool]:
        return []

    def execute_tool(self, tool_name: str, arguments: dict[str, Any]) -> Any:
        return "ok"

    def healthcheck(self) -> dict[str, Any]:
        return {"status": "OK"}


# -- DriverBase as a leaf resolution node ------------------------------------

class TestLeafResolution:
    def test_driverbase_is_resolution_node(self):
        assert isinstance(PlainDriver(), SupportsCapabilityResolution)

    def test_leaf_resolves_own_capability_to_self(self):
        d = PlainDriver()
        assert d.resolve_capability(SupportsNativeTools) is d

    def test_leaf_returns_none_for_absent_capability(self):
        d = PlainDriver()
        assert d.resolve_capability(SupportsHealthcheck) is None

    def test_leaf_resolves_extra_capability(self):
        d = HealthDriver()
        assert d.resolve_capability(SupportsHealthcheck) is d

    def test_leaf_still_resolves_inherited_capability(self):
        d = HealthDriver()
        assert d.resolve_capability(SupportsNativeTools) is d


# -- DriverMeta.resolve_capability static entry point ------------------------

class TestEntryPoint:
    def test_dispatches_to_node_for_driverbase(self):
        d = HealthDriver()
        assert DriverMeta.resolve_capability(d, SupportsHealthcheck) is d

    def test_returns_none_when_absent(self):
        d = PlainDriver()
        assert DriverMeta.resolve_capability(d, SupportsHealthcheck) is None


# -- Fallback for non-resolution-aware drivers -------------------------------

class TestIsinstanceFallback:
    def test_raw_driver_is_not_a_resolution_node(self):
        assert not isinstance(RawToolDriver(), SupportsCapabilityResolution)

    def test_raw_driver_matched_via_fallback(self):
        d = RawToolDriver()
        assert DriverMeta.resolve_capability(d, SupportsHealthcheck) is d

    def test_raw_driver_absent_capability_returns_none(self):
        d = RawToolDriver()
        assert DriverMeta.resolve_capability(d, SupportsNativeTools) is None
