"""Tool middleware -- the interceptor chain around ``execute_tool``.

Cross-cutting concerns (lifecycle **hooks**, **permission**/consent, **auth** challenge
handling) attach to a driver's tool execution as :class:`ToolMiddleware` objects -- not by
wrapping the driver in a decorator. This is the mechanism ADR-0002 chose over object
decorators: a middleware lives *inside* the driver, so the driver keeps its full identity
(streaming, ``process_llm_response``, prompts) and clients use plain ``isinstance`` again.
See ``docs/adr/0002-tool-middleware-over-decorators.md``.

A middleware implements one around-hook,
``on_execute_tool(tool_name, arguments, call_next)``:

- **observe** -- record, log, emit an event, then ``return call_next(...)``;
- **rewrite** -- ``return call_next(tool_name, new_arguments)``;
- **short-circuit** -- ``return <payload>`` *without* calling ``call_next`` (e.g. a
  permission denial);
- **catch** -- wrap ``call_next`` in ``try/except`` to turn a domain error into a result
  (e.g. an auth challenge -> an in-band ``{"auth_required": ...}`` result).

``call_next(tool_name, arguments)`` runs the rest of the chain; the terminal is the
driver's own ``execute_tool``. Order is list order, **outermost first**: the first
middleware sees the call first and the result last. A middleware holds *configuration*
(handlers, policy), never per-call state, so **one instance may be shared across all
drivers** in a client (something a decorator, bound to its single inner, could not do).

The ``around(call, next)`` shape is port-neutral -- composition + a callback exists in
every target language, unlike multiple implementation inheritance.
"""

from __future__ import annotations

from abc import ABC, abstractmethod
from typing import Any, Callable

#: The rest of the chain: call it to continue (terminal = the driver's ``execute_tool``).
#: Not calling it short-circuits the chain (e.g. a permission denial returns its own result).
CallNext = Callable[[str, "dict[str, Any]"], Any]


class ToolMiddleware:
    """One layer around tool execution. Override the hook you need; the default passes
    through unchanged (so a middleware only states what it actually intercepts)."""

    def on_execute_tool(
        self, tool_name: str, arguments: dict[str, Any], call_next: CallNext,
    ) -> Any:
        """Wrap one tool call. Default: continue the chain unchanged.

        Return ``call_next(tool_name, arguments)`` to proceed (optionally with rewritten
        arguments); return something else *without* calling ``call_next`` to short-circuit;
        wrap ``call_next`` in ``try/except`` to catch a domain error and turn it into a
        result.
        """
        return call_next(tool_name, arguments)


class SupportsToolMiddleware(ABC):
    """Opt-in contract: this driver runs each owned tool call through a middleware chain."""

    #: Capability flag advertised in ``DriverMeta.capabilities`` when a driver accepts
    #: middleware -- a static property of the driver class. The flags the *middleware
    #: themselves* carry (``"hooks"``, ``"consent"``, ``"auth"``) are **not** folded onto
    #: the driver: which concerns an instance runs is runtime configuration the client
    #: made, not a property of the driver, and the client holds those objects already.
    CAPABILITY = "tool_middleware"

    @abstractmethod
    def add_middleware(self, middleware: ToolMiddleware) -> None:
        """Append *middleware* to the chain (innermost, closest to execution).

        Concerns known before the driver was built are passed as ``middleware=[...]`` at
        construction; this adds one afterwards (e.g. a UI that only becomes available at
        runtime). The client keeps its own reference to the middleware object to
        reconfigure it (add a hook, set a consent handler) -- no capability lookup needed,
        because the client constructed it.
        """
        ...
