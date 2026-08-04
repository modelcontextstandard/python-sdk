"""Tests for the tool-middleware chain (ADR-0002) -- the interceptor around execute_tool.

Concerns (hooks, permission, auth) live *inside* the driver as ToolMiddleware, not as
decorators wrapping it. Verified here: observe, outermost-first ordering, short-circuit
(permission-style), catch-a-domain-error (auth-style), runtime add_middleware, and that
the driver's meta stays a *static* data sheet -- a middleware's flags never leak into it.
"""

from __future__ import annotations

from abc import ABC
from dataclasses import dataclass
from typing import Any

from mcs.driver.core import (
    BaseDriver, ToolMiddleware, SupportsToolMiddleware,
    DriverMeta, DriverBinding, Tool,
)


@dataclass(frozen=True)
class _Meta(DriverMeta):
    id: str = "mw-0001"
    name: str = "Middleware Test Driver"
    version: str = "0.0.1"
    bindings: tuple[DriverBinding, ...] = ()
    supported_llms: tuple[str, ...] | None = None
    capabilities: tuple[str, ...] = ()


class GreetDriver(BaseDriver):
    """Owns ``greet``; records each real execution so a short-circuit is observable."""

    meta: DriverMeta = _Meta()

    def __init__(self, **kwargs: Any) -> None:
        super().__init__(**kwargs)
        self.executed: list[str] = []

    def list_tools(self) -> list[Tool]:
        return [Tool("greet", description="Greet someone")]

    def execute_tool(self, tool_name: str, arguments: dict[str, Any]) -> Any:
        self.executed.append(tool_name)
        return f"hello {arguments.get('who', 'world')}"


_GREET = '{"tool": "greet", "arguments": {"who": "world"}}'


class TestMiddlewareChain:
    def test_no_middleware_executes_directly(self):
        driver = GreetDriver()
        dr = driver.process_llm_response(_GREET)
        assert dr.call_executed is True
        assert dr.tool_call_result == "hello world"
        assert driver.executed == ["greet"]

    def test_middleware_observes_around_execution(self):
        seen: list = []

        class Recorder(ToolMiddleware):
            def on_execute_tool(self, name, args, call_next):
                seen.append(("pre", name, dict(args)))
                result = call_next(name, args)
                seen.append(("post", result))
                return result

        driver = GreetDriver(middleware=[Recorder()])
        dr = driver.process_llm_response(_GREET)
        assert dr.tool_call_result == "hello world"
        assert seen == [("pre", "greet", {"who": "world"}), ("post", "hello world")]

    def test_order_is_outermost_first(self):
        order: list[str] = []

        class Tag(ToolMiddleware):
            def __init__(self, tag): self.tag = tag
            def on_execute_tool(self, name, args, call_next):
                order.append(f"{self.tag}>")
                result = call_next(name, args)
                order.append(f"{self.tag}<")
                return result

        GreetDriver(middleware=[Tag("A"), Tag("B")]).process_llm_response(_GREET)
        # A wraps B wraps execute: A first in, A last out.
        assert order == ["A>", "B>", "B<", "A<"]

    def test_short_circuit_blocks_execution(self):
        class Deny(ToolMiddleware):
            def on_execute_tool(self, name, args, call_next):
                return "DENIED"                      # never calls call_next

        driver = GreetDriver(middleware=[Deny()])
        dr = driver.process_llm_response(_GREET)
        assert dr.tool_call_result == "DENIED"
        assert driver.executed == []                 # execute_tool never ran

    def test_middleware_can_rewrite_arguments(self):
        class Rewrite(ToolMiddleware):
            def on_execute_tool(self, name, args, call_next):
                return call_next(name, {**args, "who": "Alice"})

        dr = GreetDriver(middleware=[Rewrite()]).process_llm_response(_GREET)
        assert dr.tool_call_result == "hello Alice"


class _Boom(Exception):
    pass


class BoomDriver(BaseDriver):
    meta: DriverMeta = _Meta()

    def list_tools(self) -> list[Tool]:
        return [Tool("greet", description="Greet someone")]

    def execute_tool(self, tool_name: str, arguments: dict[str, Any]) -> Any:
        raise _Boom("challenge")


class TestDomainErrorHandling:
    """Auth-style: a middleware catches a domain error and turns it into a result; with
    no such middleware it degrades to call_failed -- the old decorator stack's fallback."""

    def test_catch_turns_error_into_in_band_result(self):
        class Catch(ToolMiddleware):
            def on_execute_tool(self, name, args, call_next):
                try:
                    return call_next(name, args)
                except _Boom as exc:
                    return f"caught: {exc}"

        dr = BoomDriver(middleware=[Catch()]).process_llm_response(_GREET)
        assert dr.call_executed is True and dr.call_failed is False
        assert dr.tool_call_result == "caught: challenge"

    def test_uncaught_error_is_call_failed(self):
        dr = BoomDriver().process_llm_response(_GREET)
        assert dr.call_failed is True
        assert dr.call_executed is False


class _SupportsFoo(ABC):
    CAPABILITY = "foo"


class FooMiddleware(ToolMiddleware, _SupportsFoo):
    """A concern middleware carrying a capability flag (like hooks/consent/auth)."""


class TestCapabilityStaysStatic:
    """The data sheet describes the driver *class*; middleware is runtime config."""

    def test_driver_advertises_tool_middleware(self):
        driver = GreetDriver()
        assert isinstance(driver, SupportsToolMiddleware)
        assert driver.meta.has_capability(SupportsToolMiddleware)

    def test_middleware_flag_not_folded_at_construction(self):
        driver = GreetDriver(middleware=[FooMiddleware()])
        assert not driver.meta.has_capability(_SupportsFoo)

    def test_middleware_flag_not_folded_at_runtime(self):
        driver = GreetDriver()
        before = driver.meta.capabilities
        driver.add_middleware(FooMiddleware())
        assert not driver.meta.has_capability(_SupportsFoo)
        assert driver.meta.capabilities == before

    def test_add_middleware_joins_the_chain(self):
        """What ``add_middleware`` *does*: the middleware intercepts the next call."""
        driver = GreetDriver()
        seen: list = []
        driver.add_middleware(_Appender(seen))
        driver.process_llm_response(_GREET)
        assert seen == ["greet"]


class _Appender(ToolMiddleware):
    def __init__(self, sink: list): self._sink = sink
    def on_execute_tool(self, name, args, call_next):
        self._sink.append(name)
        return call_next(name, args)
