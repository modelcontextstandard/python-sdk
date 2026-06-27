"""Demo: AuthDecorator injected into a client-facing driver via the _tooldriver DI hook.

This mirrors how ``gmail_agent`` works after the AuthMixin -> AuthDecorator
migration: instead of mixing auth into the driver (inheritance), the ToolDriver
is wrapped with ``AuthDecorator`` and **injected** through the driver's
``_tooldriver`` hook. The driver stays client-facing -- it keeps its own
``process_llm_response`` loop, prompts, native tools and ``meta.bindings`` -- and
its ``execute_tool`` now routes through the decorator. No orchestrator needed.

Run:  python mcs-examples/decorator_stack/via_tooldriver.py
"""

from __future__ import annotations

import json
from dataclasses import dataclass

from mcs.driver.core import BaseDriver, MCSToolDriver, DriverMeta, DriverBinding, Tool
from mcs.auth.decorator import AuthDecorator
from mcs.auth.challenge import AuthChallenge


@dataclass(frozen=True)
class _MailMeta(DriverMeta):
    id: str = "demo-mail"
    name: str = "Demo Mail Driver"
    version: str = "0.0.1"
    bindings: tuple[DriverBinding, ...] = (DriverBinding("mail", "imap", "Custom"),)
    supported_llms: tuple[str, ...] = ("*",)
    capabilities: tuple[str, ...] = ()


class DemoMailToolDriver(MCSToolDriver):
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


class DemoMailDriver(BaseDriver):
    """Client-facing hybrid driver that delegates execute_tool to an injected ToolDriver."""

    meta = _MailMeta()

    def __init__(self, *, _tooldriver: MCSToolDriver, **kwargs):
        super().__init__(**kwargs)
        self._td = _tooldriver

    def list_tools(self):
        return self._td.list_tools()

    def execute_tool(self, tool_name, arguments):
        return self._td.execute_tool(tool_name, arguments)


def main() -> None:
    # Wrap the ToolDriver with auth, then inject it via the _tooldriver DI hook:
    driver = DemoMailDriver(_tooldriver=AuthDecorator(DemoMailToolDriver()))

    print("== Driver stays client-facing (unchanged surface) ==")
    print("  has process_llm_response:", hasattr(driver, "process_llm_response"))
    print("  meta.bindings[0]:", driver.meta.bindings[0].capability)   # works -- driver keeps its meta

    print("\n== The driver's own process_llm_response routes execute_tool through AuthDecorator ==")
    dr1 = driver.process_llm_response('{"tool": "list_messages", "arguments": {}}')
    print("  list_messages -> executed:", dr1.call_executed, "| result:", dr1.tool_call_result)

    dr2 = driver.process_llm_response('{"tool": "send_mail", "arguments": {}}')
    print("  send_mail     -> executed:", dr2.call_executed, "| result:", dr2.tool_call_result)

    # -- Verification --------------------------------------------------------
    assert driver.meta.bindings[0].capability == "mail"                 # driver kept its identity
    assert json.loads(dr1.tool_call_result)["messages"] == ["hello", "world"]
    assert json.loads(dr2.tool_call_result)["auth_required"] is True    # challenge caught
    print(
        "\nAuthDecorator injected via _tooldriver: the driver's own "
        "process_llm_response catches the challenge -- no orchestrator needed."
    )


if __name__ == "__main__":
    main()
