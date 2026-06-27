"""Optional contract for *wrappers* that resolve a capability through a stack.

A **leaf** driver (a plain or hybrid ``BaseDriver``) has no inner layers, so it
needs no resolution logic of its own: the ``isinstance`` fallback in
:meth:`mcs.driver.core.DriverMeta.resolve_capability` *is* the leaf behaviour.

A **wrapper** (an orchestrator or a decorator) hides its inner layers from a
direct ``isinstance`` check on the stack as a whole. By implementing
``SupportsCapabilityResolution`` it signals the entry point to call its
``resolve_capability`` instead -- which checks itself first, then searches
inward through the driver(s) it holds. That is what lets
:meth:`DriverMeta.resolve_capability` locate the layer satisfying a contract no
matter how deep it sits, so a client treats every driver the same, whether it is
a plain leaf, an orchestrator, or a decorator.
"""

from __future__ import annotations

from typing import Protocol, TypeVar, runtime_checkable

T = TypeVar("T")


@runtime_checkable
class SupportsCapabilityResolution(Protocol):
    """Opt-in contract for wrappers that resolve a capability across their inner driver(s)."""

    def resolve_capability(self, contract: type[T]) -> T | None: ...
