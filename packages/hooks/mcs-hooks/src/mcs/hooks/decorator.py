"""HooksDecorator -- lifecycle hooks around tool execution.

Wraps an ``MCSToolDriver`` (via :class:`BaseDecorator`) and emits **observability
events** around ``execute_tool``:

- ``pre`` -- before execution: ``handler(tool_name, arguments)``
- ``post`` -- after success: ``handler(tool_name, arguments, result)``
- ``on_failure`` -- after an exception (then re-raised):
  ``handler(tool_name, arguments, exc)``

Hooks are **observers**: their return values are ignored. To *gate* a call
(confirm / deny), use the ``PermissionDecorator`` from ``mcs-permission``; to
*handle auth challenges*, the ``AuthDecorator`` from ``mcs-auth``. All three stack
freely, e.g. ``Hooks(Permission(Auth(RealToolDriver)))``.

Multiple handlers per phase are supported (observer pattern): pass lists at
construction and/or manage them at runtime::

    hooks = HooksDecorator(tool_driver, pre=[audit], post=[metrics])
    hooks.add_post_hook(tracer)        # add at runtime
    hooks.remove_pre_hook(audit)
    orchestrator.add_driver(hooks, label="mail")
"""

from __future__ import annotations

from abc import ABC, abstractmethod
from typing import Any, Callable

from mcs.driver.core import BaseDecorator, MCSToolDriver

#: Called before a tool executes.
PreHook = Callable[[str, "dict[str, Any]"], None]
#: Called after a tool executes successfully (with its result).
PostHook = Callable[[str, "dict[str, Any]", Any], None]
#: Called when a tool execution raises (with the exception), before it re-raises.
FailureHook = Callable[[str, "dict[str, Any]", BaseException], None]


class SupportsHooks(ABC):
    """Contract: this layer emits lifecycle events around tool execution.

    Carries the ``"hooks"`` capability flag and lets observers be registered at
    runtime. A client that resolves the layer --
    ``DriverMeta.resolve_capability(driver, SupportsHooks)`` -- can attach hooks
    after the stack was already composed and injected.

    The contract ships with this package, not in core: any client wiring hooks
    is using ``mcs-hooks`` anyway.
    """

    CAPABILITY = "hooks"

    @abstractmethod
    def add_pre_hook(self, handler: PreHook) -> None:
        """Register an observer called before each tool execution."""
        ...

    @abstractmethod
    def add_post_hook(self, handler: PostHook) -> None:
        """Register an observer called after a successful tool execution."""
        ...

    @abstractmethod
    def add_failure_hook(self, handler: FailureHook) -> None:
        """Register an observer called when a tool execution raises (before re-raise)."""
        ...


class HooksDecorator(BaseDecorator, SupportsHooks):
    """Emits pre / post / failure events around ``execute_tool`` (observers only).

    Handlers are stored as lists -- multiple observers per phase. Supply them at
    construction and/or manage them at runtime via the ``add_`` / ``remove_``
    helpers. Overrides only ``execute_tool``; everything else is delegated by
    :class:`BaseDecorator`.
    """

    CONTRACT = SupportsHooks

    def __init__(
        self,
        inner: MCSToolDriver,
        *,
        pre: "list[PreHook] | None" = None,
        post: "list[PostHook] | None" = None,
        on_failure: "list[FailureHook] | None" = None,
    ) -> None:
        super().__init__(inner)
        self._pre: list[PreHook] = list(pre or [])
        self._post: list[PostHook] = list(post or [])
        self._failure: list[FailureHook] = list(on_failure or [])

    # -- registration: lists at construction, add/remove at runtime -----------

    def add_pre_hook(self, handler: PreHook) -> None:
        self._pre.append(handler)

    def remove_pre_hook(self, handler: PreHook) -> None:
        self._pre.remove(handler)

    def add_post_hook(self, handler: PostHook) -> None:
        self._post.append(handler)

    def remove_post_hook(self, handler: PostHook) -> None:
        self._post.remove(handler)

    def add_failure_hook(self, handler: FailureHook) -> None:
        self._failure.append(handler)

    def remove_failure_hook(self, handler: FailureHook) -> None:
        self._failure.remove(handler)

    # -- interception ---------------------------------------------------------

    def execute_tool(self, tool_name: str, arguments: dict[str, Any]) -> Any:
        for hook in self._pre:
            hook(tool_name, arguments)
        try:
            result = self._inner.execute_tool(tool_name, arguments)
        except BaseException as exc:
            for hook in self._failure:
                hook(tool_name, arguments, exc)
            raise
        for hook in self._post:
            hook(tool_name, arguments, result)
        return result
