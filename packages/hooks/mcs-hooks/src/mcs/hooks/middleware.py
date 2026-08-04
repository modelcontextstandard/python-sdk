"""HooksMiddleware -- lifecycle hooks around tool execution.

Emits **observability events** around ``execute_tool``:

- ``pre`` -- before execution: ``handler(tool_name, arguments)``
- ``post`` -- after success: ``handler(tool_name, arguments, result)``
- ``on_failure`` -- after an exception (then re-raised):
  ``handler(tool_name, arguments, exc)``

Hooks are **observers**: their return values are ignored. To *gate* a call (confirm /
deny), use ``PermissionMiddleware`` from ``mcs-permission``; to *handle auth challenges*,
``AuthMiddleware`` from ``mcs-auth``. All three are middleware -- they compose in one
ordered list, not by nesting (ADR-0002)::

    driver = MailDriver(..., middleware=[
        HooksMiddleware(pre=[audit], post=[metrics]),   # observes first, sees results last
        PermissionMiddleware(consent_handler=ask_user),
        AuthMiddleware(),
    ])
    driver.add_middleware(...)                            # or add one at runtime

Multiple handlers per phase are supported (observer pattern): pass lists at construction
and/or manage them at runtime via the ``add_`` / ``remove_`` helpers.
"""

from __future__ import annotations

from abc import ABC, abstractmethod
from typing import Any, Callable

from mcs.driver.core import ToolMiddleware, CallNext

#: Called before a tool executes.
PreHook = Callable[[str, "dict[str, Any]"], None]
#: Called after a tool executes successfully (with its result).
PostHook = Callable[[str, "dict[str, Any]", Any], None]
#: Called when a tool execution raises (with the exception), before it re-raises.
FailureHook = Callable[[str, "dict[str, Any]", BaseException], None]


class SupportsHooks(ABC):
    """Contract: this layer emits lifecycle events around tool execution.

    Carries the ``"hooks"`` capability flag (so a layer that offers this is recognisable
    with ``isinstance``) and lets observers be registered at runtime. The client keeps its
    own reference to the middleware to attach hooks after the driver was already built.
    The flag is *not* folded onto the driver's meta: ``DriverMeta`` stays a static
    description of the driver class, and which middleware an instance runs is runtime
    configuration. The contract ships with this package, not in core.
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


class HooksMiddleware(ToolMiddleware, SupportsHooks):
    """Emits pre / post / failure events around ``execute_tool`` (observers only).

    Handlers are stored as lists -- multiple observers per phase. Supply them at
    construction and/or manage them at runtime via the ``add_`` / ``remove_`` helpers.
    """

    def __init__(
        self,
        *,
        pre: "list[PreHook] | None" = None,
        post: "list[PostHook] | None" = None,
        on_failure: "list[FailureHook] | None" = None,
    ) -> None:
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

    def on_execute_tool(
        self, tool_name: str, arguments: dict[str, Any], call_next: CallNext,
    ) -> Any:
        for hook in self._pre:
            hook(tool_name, arguments)
        try:
            result = call_next(tool_name, arguments)
        except BaseException as exc:
            for hook in self._failure:
                hook(tool_name, arguments, exc)
            raise
        for hook in self._post:
            hook(tool_name, arguments, result)
        return result
