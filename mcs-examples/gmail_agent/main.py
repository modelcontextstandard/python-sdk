"""MCS Gmail Agent -- streaming chat client for e-mail via Auth0 Device Flow.

Demonstrates the full MCS auth stack:
- Auth0 Device Authorization (RFC 8628) for credential acquisition
- Auth0 Token Vault (RFC 8693) for token exchange
- AuthMixin for transparent auth challenges during tool execution
- MailDriver composite driver for read + send e-mail

The client has no knowledge of authentication -- when a tool needs
credentials, the AuthMixin intercepts the challenge and the LLM
presents the login URL to the user.

Usage:
    # Auth0 Device Flow (recommended):
    python main.py --auth0

    # Quick test with a static Google OAuth2 token:
    python main.py --token ya29.xxx

    # With custom model:
    python main.py --auth0 --model anthropic/claude-sonnet-4-20250514

Auth0 mode reads from environment variables:
    AUTH0_DOMAIN        e.g. my-tenant.auth0.com
    AUTH0_CLIENT_ID     your Auth0 application client ID
    AUTH0_CLIENT_SECRET your Auth0 application client secret

Requires:
    pip install mcs-driver-mail[gmail] mcs-auth-auth0 litellm rich python-dotenv
"""

from __future__ import annotations

import argparse
import os

from dotenv import load_dotenv
from litellm import completion
from rich.console import Console
from rich.panel import Panel

from mcs.auth.mixin import AuthMixin
from mcs.driver.core import DriverResponse, MCSDriver, SupportsDriverContext
from mcs.driver.mail import MailDriver

console = Console()

MAX_TOOL_ROUNDS = 10


class AuthMailDriver(AuthMixin, MailDriver):
    """MailDriver with transparent auth-challenge handling via AuthMixin."""


def _parse_args() -> argparse.Namespace:
    p = argparse.ArgumentParser(description="MCS Gmail Agent (streaming)")
    auth = p.add_mutually_exclusive_group(required=True)
    auth.add_argument("--token", help="Google OAuth2 access token (quick test)")
    auth.add_argument("--auth0", action="store_true", help="Use Auth0 Device Flow")

    p.add_argument("--model", default="gpt-4o", help="LiteLLM model identifier (default: gpt-4o)")
    p.add_argument("--sender-name", default=None, help="Display name for outgoing e-mails")
    p.add_argument("--api-base", default=None,
                   help="Custom OpenAI-compatible API base URL (e.g. http://localhost:8000/v1)")
    p.add_argument("--api-key", default=None,
                   help="API key for --api-base (default: 'no-key' when --api-base is set)")
    p.add_argument("--debug", "-d", action="store_true", help="Show DriverResponse details")
    return p.parse_args()


def _build_driver(args: argparse.Namespace) -> AuthMailDriver:
    """Build an AuthMailDriver with gmail adapters."""
    gmail_kwargs: dict = {}
    if args.sender_name:
        gmail_kwargs["sender_name"] = args.sender_name

    if args.auth0:
        from mcs.auth.auth0 import Auth0Provider

        for var in ("AUTH0_DOMAIN", "AUTH0_CLIENT_ID", "AUTH0_CLIENT_SECRET"):
            if not os.environ.get(var):
                raise SystemExit(f"Missing environment variable: {var}")

        credential = Auth0Provider(
            domain=os.environ["AUTH0_DOMAIN"],
            client_id=os.environ["AUTH0_CLIENT_ID"],
            client_secret=os.environ["AUTH0_CLIENT_SECRET"],
            audience=os.environ.get("AUTH0_AUDIENCE"),
        )
        gmail_kwargs["_credential"] = credential
    else:
        gmail_kwargs["access_token"] = args.token

    return AuthMailDriver(
        read_adapter="gmail",
        send_adapter="gmail",
        read_kwargs=gmail_kwargs,
        send_kwargs=gmail_kwargs,
    )


def _stream_one_turn(
    model: str,
    messages: list[dict],
    api_base: str | None = None,
    api_key: str | None = None,
    tools: list[dict] | None = None,
) -> dict:
    """Stream one LLM turn, display tokens live, return accumulated message dict.

    The client collects text and displays it live, but passes the full
    accumulated message dict to the driver without interpretation.
    """
    kwargs: dict = {"model": model, "messages": messages, "stream": True}
    if api_base:
        kwargs["api_base"] = api_base
        kwargs["api_key"] = api_key or "no-key"
    if tools:
        kwargs["tools"] = tools
    stream = completion(**kwargs)

    content_buffer = ""
    tool_calls_buffer: list[dict] = []
    printed_header = False

    for chunk in stream:  # type: ignore[union-attr]
        choices = getattr(chunk, "choices", None)
        delta = choices[0].delta if choices else None
        if delta is None:
            continue

        token = getattr(delta, "content", None) or ""
        if token:
            content_buffer += token
            if not printed_header:
                console.print("\n[bold blue]Assistant:[/bold blue] ", end="")
                printed_header = True
            print(token, end="", flush=True)

        tc_deltas = getattr(delta, "tool_calls", None)
        if tc_deltas:
            for tc in tc_deltas:
                idx = getattr(tc, "index", 0) or 0
                while len(tool_calls_buffer) <= idx:
                    tool_calls_buffer.append({"function": {"name": "", "arguments": ""}})
                entry = tool_calls_buffer[idx]
                fn = getattr(tc, "function", None)
                if fn:
                    if getattr(fn, "name", None):
                        entry["function"]["name"] = fn.name
                    if getattr(fn, "arguments", None):
                        entry["function"]["arguments"] += fn.arguments
                tc_id = getattr(tc, "id", None)
                if tc_id:
                    entry["id"] = tc_id
                    entry["type"] = "function"

    if printed_header:
        print()

    msg: dict = {"role": "assistant", "content": content_buffer or None}
    if tool_calls_buffer:
        msg["tool_calls"] = tool_calls_buffer
    return msg


def _print_debug_dr(dr: DriverResponse) -> None:
    parts = [f"call_executed={dr.call_executed}  call_failed={dr.call_failed}"]
    if dr.call_detail:
        parts.append(f"detail: {dr.call_detail}")
    if dr.tool_call_result is not None:
        r = str(dr.tool_call_result)
        if len(r) > 200:
            r = r[:197] + "..."
        parts.append(f"tool_call_result: {r}")
    if dr.retry_prompt:
        parts.append(f"retry_prompt: {dr.retry_prompt}")
    console.print(Panel("\n".join(parts), title="DriverResponse", border_style="dim"))


def chat_loop(driver: MCSDriver, model: str, debug: bool,
              api_base: str | None = None, api_key: str | None = None) -> None:
    native_tools: list[dict] | None = None
    if isinstance(driver, SupportsDriverContext):
        ctx = driver.get_driver_context(model)
        system_msg = ctx.system_message
        native_tools = ctx.tools
    else:
        system_msg = driver.get_driver_system_message()

    messages: list[dict] = [{"role": "system", "content": system_msg}]

    binding = driver.meta.bindings[0]
    mode = "native tools" if native_tools else "text prompt"
    info = [
        "[bold cyan]MCS Chat (streaming)[/bold cyan]\n",
        f"Driver:   {driver.meta.name}",
        f"Binding:  {binding.capability} / {binding.adapter}",
        f"Model:    {model}",
        f"Tools:    {mode}",
    ]
    if api_base:
        info.append(f"API base: {api_base}")
    info += [
        f"Debug:    {'on' if debug else 'off'}",
        "",
        "[dim]Type 'exit' or Ctrl+C to quit.[/dim]",
    ]
    console.print(Panel("\n".join(info), expand=False))

    if debug:
        console.print(Panel(system_msg, title="System prompt", border_style="dim"))

    while True:
        try:
            user_input = console.input("\n[bold green]You:[/bold green] ").strip()
        except (EOFError, KeyboardInterrupt):
            break
        if not user_input or user_input.lower() in ("exit", "quit", "q"):
            break

        messages.append({"role": "user", "content": user_input})

        for _round in range(MAX_TOOL_ROUNDS):
            llm_out = _stream_one_turn(model, messages, api_base, api_key, native_tools)
            response = driver.process_llm_response(llm_out)

            if debug and (response.call_executed or response.call_failed):
                _print_debug_dr(response)

            if response.messages:
                messages.extend(response.messages)

            if response.call_executed:
                if debug:
                    console.print("[dim]Tool executed -- streaming next LLM turn...[/dim]")
                continue

            if response.call_failed:
                if debug:
                    console.print(f"[yellow]Tool call failed: {response.call_detail}[/yellow]")
                continue

            content = llm_out.get("content", "") or ""
            messages.append({"role": "assistant", "content": content})
            break
        else:
            console.print("[yellow]Max tool rounds reached -- stopping.[/yellow]")


def main() -> None:
    load_dotenv()
    args = _parse_args()

    console.print("[dim]Building Gmail driver...[/dim]")
    driver = _build_driver(args)
    tools = driver.list_tools()
    console.print(f"[dim]Ready -- {len(tools)} tools discovered.[/dim]")

    chat_loop(driver, args.model, args.debug, args.api_base, args.api_key)
    console.print("\n[dim]Chat ended.[/dim]")


if __name__ == "__main__":
    main()
