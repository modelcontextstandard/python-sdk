"""BaseDecorator -- reusable wrapping driver for cross-cutting concerns.

A decorator wraps a single inner ``MCSToolDriver`` and presents the same
interface, so from the outside it is indistinguishable from any other driver
("everything is a driver"). It delegates ``list_tools`` unchanged and lets a
subclass intercept ``execute_tool`` -- the seam where cross-cutting concerns
(authentication, permission/approval, lifecycle hooks) belong.

It is the **single-inner counterpart to** :class:`BaseOrchestrator` (which
wraps many): both are *pure composition mechanism* -- delegation plus
capability resolution. That is why the leaf (:class:`BaseDriver`) and this
wrapper both live in core, while the orchestrator -- which carries its own
resolution *strategy* -- ships as a separate package.

A concrete decorator declares the capability it adds via the class attribute
``CONTRACT`` and overrides only the method it intercepts::

    class AuthDecorator(BaseDecorator):
        CONTRACT = SupportsAuth

        def execute_tool(self, tool_name, arguments):
            try:
                return self._inner.execute_tool(tool_name, arguments)
            except AuthChallenge as exc:
                return describe_auth_step(exc)

Because the decorator aggregates the inner driver's ``capabilities`` and adds
its own, ``meta.capabilities`` reflects the **whole** stack, and
``resolve_capability`` finds the layer that satisfies a contract no matter how
deep it sits.
"""

from __future__ import annotations

from typing import Any, TypeVar

from .mcs_driver_interface import DriverMeta
from .mcs_tool_driver_interface import MCSToolDriver, Tool
from .mixins.capability_resolution import SupportsCapabilityResolution

T = TypeVar("T")


class BaseDecorator(MCSToolDriver, SupportsCapabilityResolution):
    """Wraps a single inner ``MCSToolDriver``; subclasses intercept one method.

    Delegation is total except for the point a subclass overrides (typically
    ``execute_tool``). The wrapper carries no tools or behaviour of its own
    beyond the capability it advertises via :attr:`CONTRACT`.
    """

    #: Optional contract whose ``CAPABILITY`` flag this decorator adds to the
    #: stack. ``None`` for the bare base, which advertises nothing of its own.
    CONTRACT: type | None = None

    def __init__(self, inner: MCSToolDriver) -> None:
        self._inner = inner
        # Aggregate: the inner driver's flags plus this decorator's own (if any).
        contract = type(self).CONTRACT
        self.meta = (
            inner.meta.with_capability(contract) if contract is not None
            else inner.meta
        )

    # -- MCSToolDriver (delegated) --------------------------------------------

    def list_tools(self) -> list[Tool]:
        return self._inner.list_tools()

    def execute_tool(self, tool_name: str, arguments: dict[str, Any]) -> Any:
        """Delegate to the inner driver.

        This is the interception seam: a concrete decorator overrides this to
        wrap the inner call (e.g. catch an ``AuthChallenge``, ask for consent,
        emit a lifecycle hook) before or after delegating.
        """
        return self._inner.execute_tool(tool_name, arguments)

    # -- Capability resolution (wrapper: self first, then the inner driver) ----

    def resolve_capability(self, contract: type[T]) -> T | None:
        """Resolve *contract* across this decorator and the driver it wraps.

        First match the decorator itself (e.g. an ``AuthDecorator`` satisfying
        ``SupportsAuth``), then search inward via
        :meth:`mcs.driver.core.DriverMeta.resolve_capability` -- so a
        capability provided by the inner driver, or by a decorator deeper in
        the stack, is found regardless of how deep it sits.
        """
        if isinstance(self, contract):
            return self
        return DriverMeta.resolve_capability(self._inner, contract)
