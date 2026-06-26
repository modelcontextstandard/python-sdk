"""Optional contract for capability-resolving wrappers.

A plain driver *is* the capability holder and is matched directly. Wrappers
(orchestrators, decorators) wrap an inner driver and therefore hide the inner
layers from a direct ``isinstance`` check on the stack as a whole.

By implementing ``SupportsCapabilityResolution`` a wrapper exposes
``resolve_capability``, which searches inward (each layer checks itself, then
delegates to its inner driver). This lets
:meth:`mcs.driver.core.DriverMeta.resolve_capability` locate the layer that
satisfies a contract no matter how deep it sits in the stack -- so a client
can treat every driver the same, whether it is plain, an orchestrator, or a
decorator.
"""

from __future__ import annotations

from typing import Protocol, TypeVar, runtime_checkable

T = TypeVar("T")


@runtime_checkable
class SupportsCapabilityResolution(Protocol):
    """Opt-in contract for wrappers that resolve an inner driver's capability."""

    def resolve_capability(self, contract: type[T]) -> T | None: ...
