"""Demo: composing Hooks + Permission + Auth decorators around one ToolDriver.

Verifies that ``BaseDecorator``-based cross-cutting concerns compose cleanly with
the core features -- three independent concerns stacked on a single ToolDriver:

  1. **Capability aggregation** through the stack (``meta.capabilities``)
  2. **Capability resolution** through the stack (``DriverMeta.resolve_capability``)
  3. **execute_tool interception order**: Hooks -> Permission -> Auth -> ToolDriver

Run:  python mcs-examples/decorator_stack/main.py
"""

from __future__ import annotations

import json
from dataclasses import dataclass

from mcs.driver.core import MCSToolDriver, DriverMeta, DriverBinding, Tool
from mcs.orchestrator.base import BaseOrchestrator
from mcs.auth.decorator import AuthDecorator, SupportsAuth
from mcs.auth.challenge import AuthChallenge
from mcs.permission.decorator import PermissionDecorator, SupportsConsent
from mcs.hooks.decorator import HooksDecorator, SupportsHooks


# -- A tiny mail-like ToolDriver ---------------------------------------------

@dataclass(frozen=True)
class _MailMeta(DriverMeta):
    id: str = "demo-mail"
    name: str = "Demo Mail ToolDriver"
    version: str = "0.0.1"
    bindings: tuple[DriverBinding, ...] = (DriverBinding("mail", "imap", "Custom"),)
    supported_llms: tuple[str, ...] | None = None
    capabilities: tuple[str, ...] = ()


class MailToolDriver(MCSToolDriver):
    """``list_messages`` works; ``send_mail`` needs auth (raises AuthChallenge)."""

    meta = _MailMeta()

    def list_tools(self):
        return [
            Tool("list_messages", description="List inbox"),
            Tool("send_mail", description="Send a mail"),
        ]

    def execute_tool(self, tool_name, arguments):
        if tool_name == "send_mail":
            raise AuthChallenge(
                "Authorize sending", url="https://auth/activate", code="AB-12", scope="gmail"
            )
        return json.dumps({"messages": ["hello", "world"]})


def main() -> None:
    # Compose the stack:  Hooks( Permission( Auth( MailToolDriver ) ) )
    def ask_user(tool_name, arguments) -> bool:
        return tool_name != "delete_all"  # allow everything except a forbidden tool

    audit: list[str] = []  # observers only record -- they never alter the flow

    real = MailToolDriver()
    stack = HooksDecorator(
        PermissionDecorator(AuthDecorator(real), consent_handler=ask_user),
        pre=[lambda n, a: audit.append(f"pre:{n}")],
        post=[lambda n, a, r: audit.append(f"post:{n}")],
    )

    orch = BaseOrchestrator()
    orch.add_driver(stack, label="mail")

    print("== 1. Capability aggregation through the stack ==")
    print("  stack meta.capabilities:", stack.meta.capabilities)

    print("\n== 2. Capability resolution through the orchestrator ==")
    hooks_layer = DriverMeta.resolve_capability(orch, SupportsHooks)
    consent_layer = DriverMeta.resolve_capability(orch, SupportsConsent)
    auth_layer = DriverMeta.resolve_capability(orch, SupportsAuth)
    print("  SupportsHooks   ->", type(hooks_layer).__name__)
    print("  SupportsConsent ->", type(consent_layer).__name__)
    print("  SupportsAuth    ->", type(auth_layer).__name__)

    print("\n== 3. execute_tool interception (Hooks -> Permission -> Auth -> driver) ==")
    r1 = orch.execute_tool("list_messages", {})   # consent ok, no challenge
    print("  list_messages ->", r1)
    r2 = orch.execute_tool("send_mail", {})        # consent ok, inner raises AuthChallenge
    print("  send_mail     ->", r2)
    print("  audit trail   ->", audit)

    # -- Verification --------------------------------------------------------
    assert set(stack.meta.capabilities) >= {"auth", "consent", "hooks"}
    assert isinstance(hooks_layer, HooksDecorator)
    assert isinstance(consent_layer, PermissionDecorator)
    assert isinstance(auth_layer, AuthDecorator)
    assert json.loads(r1)["messages"] == ["hello", "world"]
    assert json.loads(r2)["auth_required"] is True
    # Hooks observed both calls (the auth-challenge is a normal return, not an exception)
    assert audit == ["pre:list_messages", "post:list_messages",
                     "pre:send_mail", "post:send_mail"]
    print("\nAll assertions passed -- 3 decorators stack cleanly on one ToolDriver.")


if __name__ == "__main__":
    main()
