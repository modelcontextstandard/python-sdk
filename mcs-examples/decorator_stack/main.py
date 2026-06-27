"""Demo: composing Auth + Permission decorators around a ToolDriver in an Orchestrator.

Verifies that ``BaseDecorator``-based cross-cutting concerns compose cleanly with
the core features:

  1. **Capability aggregation** through the stack (``meta.capabilities``)
  2. **Capability resolution** through the stack (``DriverMeta.resolve_capability``)
  3. **execute_tool interception order**: Permission -> Auth -> real ToolDriver

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
    # Compose the stack:  Permission( Auth( MailToolDriver ) )
    def ask_user(tool_name, arguments) -> bool:
        return tool_name != "delete_all"  # allow everything except a forbidden tool

    real = MailToolDriver()
    guarded = PermissionDecorator(AuthDecorator(real), consent_handler=ask_user)

    orch = BaseOrchestrator()
    orch.add_driver(guarded, label="mail")

    print("== 1. Capability aggregation through the stack ==")
    print("  stack meta.capabilities:", guarded.meta.capabilities)

    print("\n== 2. Capability resolution through the orchestrator ==")
    consent_layer = DriverMeta.resolve_capability(orch, SupportsConsent)
    auth_layer = DriverMeta.resolve_capability(orch, SupportsAuth)
    print("  SupportsConsent ->", type(consent_layer).__name__)
    print("  SupportsAuth    ->", type(auth_layer).__name__)

    print("\n== 3. execute_tool interception (Permission -> Auth -> driver) ==")
    r1 = orch.execute_tool("list_messages", {})   # consent ok, no challenge
    print("  list_messages ->", r1)
    r2 = orch.execute_tool("send_mail", {})        # consent ok, inner raises AuthChallenge
    print("  send_mail     ->", r2)

    # -- Verification --------------------------------------------------------
    assert "consent" in guarded.meta.capabilities
    assert "auth" in guarded.meta.capabilities
    assert isinstance(consent_layer, PermissionDecorator)
    assert isinstance(auth_layer, AuthDecorator)
    assert json.loads(r1)["messages"] == ["hello", "world"]
    assert json.loads(r2)["auth_required"] is True
    print("\nAll assertions passed -- decorators compose with core + orchestrator as expected.")


if __name__ == "__main__":
    main()
