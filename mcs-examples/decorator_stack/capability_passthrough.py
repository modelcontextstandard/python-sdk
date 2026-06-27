"""Demo: a capability on the INNER driver surfaces through the decorator.

Question: if the wrapped ToolDriver supports healthcheck, does the AuthDecorator
(a) advertise "healthcheck" in meta.capabilities, and (b) how do you call it?

Answer:
  (a) Yes -- the decorator aggregates the inner driver's flags and adds its own.
  (b) NOT on the decorator (it doesn't implement healthcheck). You ask
      DriverMeta.resolve_capability(stack, SupportsHealthcheck) for the layer
      that satisfies the contract, and call the method on *that*.

Run:  python mcs-examples/decorator_stack/capability_passthrough.py
"""

from __future__ import annotations

from dataclasses import dataclass

from mcs.driver.core import MCSToolDriver, DriverMeta, DriverBinding, Tool
from mcs.driver.core.mixins.healthcheck import (
    SupportsHealthcheck,
    HealthStatus,
    HealthCheckResult,
)
from mcs.auth.decorator import AuthDecorator, SupportsAuth


@dataclass(frozen=True)
class _Meta(DriverMeta):
    id: str = "mail-tool"
    name: str = "Mail Tool"
    version: str = "0.0.1"
    bindings: tuple[DriverBinding, ...] = (DriverBinding("mail", "imap", "Custom"),)
    supported_llms: tuple[str, ...] | None = None
    # The ToolDriver declares the capability it satisfies. (A BaseDriver would
    # auto-derive this from its interfaces; a bare ToolDriver states it here.)
    capabilities: tuple[str, ...] = ("healthcheck",)


class HealthyMailTool(MCSToolDriver, SupportsHealthcheck):
    """A ToolDriver that also implements SupportsHealthcheck."""

    meta = _Meta()

    def list_tools(self):
        return [Tool("list_messages", description="List inbox")]

    def execute_tool(self, tool_name, arguments):
        return "ok"

    def healthcheck(self) -> HealthCheckResult:
        return {"status": HealthStatus.OK}


def main() -> None:
    inner = HealthyMailTool()
    stack = AuthDecorator(inner)

    print("== (a) The decorator advertises the inner driver's capability ==")
    print("  inner.meta.capabilities       :", inner.meta.capabilities)
    print("  AuthDecorator.meta.capabilities:", stack.meta.capabilities)

    print("\n== (b) The method lives on the inner driver -- reach it via resolve ==")
    print("  hasattr(decorator, 'healthcheck'):", hasattr(stack, "healthcheck"))
    if "healthcheck" in stack.meta.capabilities:
        hc = DriverMeta.resolve_capability(stack, SupportsHealthcheck)
        print("  resolve_capability(.., SupportsHealthcheck) ->", type(hc).__name__)
        print("  hc.healthcheck() ->", hc.healthcheck())

    # auth is satisfied by the decorator itself; healthcheck by the inner driver
    auth_layer = DriverMeta.resolve_capability(stack, SupportsAuth)
    print("\n  resolve(SupportsAuth)        ->", type(auth_layer).__name__, "(the decorator)")

    # -- Verification --------------------------------------------------------
    assert stack.meta.capabilities == ("healthcheck", "auth")     # aggregated
    assert not hasattr(stack, "healthcheck")                      # NOT on the decorator
    hc = DriverMeta.resolve_capability(stack, SupportsHealthcheck)
    assert hc is inner                                            # resolves inward
    assert hc.healthcheck()["status"] is HealthStatus.OK          # callable on the resolved layer
    assert DriverMeta.resolve_capability(stack, SupportsAuth) is stack  # auth = the decorator
    print("\nVerified: capability advertised through the stack; method reached via resolve_capability.")


if __name__ == "__main__":
    main()
