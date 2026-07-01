"""Optional contract for *transparent wrappers* that resolve a capability inward.

A **leaf** driver (a plain or hybrid ``BaseDriver``) has no inner layers, so it
needs no resolution logic of its own: the ``isinstance`` fallback in
:meth:`mcs.driver.core.DriverMeta.resolve_capability` *is* the leaf behaviour.

A **transparent wrapper** -- a :class:`~mcs.driver.core.BaseDecorator` -- wraps a
single inner driver and *passes its capabilities through*. It hides that inner
layer from a direct ``isinstance`` check, so by implementing
``SupportsCapabilityResolution`` it signals the entry point to call its
``resolve_capability`` instead -- which checks itself first, then searches
inward. That is what lets :meth:`DriverMeta.resolve_capability` locate the layer
satisfying a contract no matter how deep it sits.

An **orchestrator is deliberately *not* a transparent wrapper.** It bundles many
drivers into a new entity with its own identity, so a capability held by *one* of
its N drivers is not a capability of the orchestrator as a whole (which of the N,
and what would it mean?). It therefore does **not** implement this contract: it
advertises and resolves only the capabilities it provides *itself* (e.g. an
aggregate ``healthcheck``), and stays a plain ``MCSDriver`` to the outside. See
the specification's Decorators section for the transparent-vs-opaque distinction.
"""

from __future__ import annotations

from typing import Protocol, TypeVar, runtime_checkable

T = TypeVar("T")


@runtime_checkable
class SupportsCapabilityResolution(Protocol):
    """Opt-in contract for transparent wrappers (decorators) that resolve a capability inward."""

    def resolve_capability(self, contract: type[T]) -> T | None: ...
