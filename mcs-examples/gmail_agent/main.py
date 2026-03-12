"""MCS Gmail Agent -- read and send e-mail via an LLM chat loop.

Demonstrates MCS with Auth0 Token Vault for secure credential management.
The same client code works with a static token (for quick testing) or
Auth0 (for production / hackathon demo).

Usage:
    # Quick test with a static Google OAuth2 token:
    python main.py --token ya29.xxx

    # Via Auth0 Token Vault (production):
    python main.py --auth0

    # Auth0 with custom model:
    python main.py --auth0 --model anthropic/claude-sonnet-4-20250514

Auth0 mode reads from environment variables:
    AUTH0_DOMAIN        e.g. my-tenant.auth0.com
    AUTH0_CLIENT_ID     your Auth0 application client ID
    AUTH0_CLIENT_SECRET your Auth0 application client secret
    AUTH0_REFRESH_TOKEN the user's Auth0 refresh token

Requires:
    pip install mcs-driver-mail[gmail] mcs-auth-auth0 litellm rich python-dotenv
"""

from __future__ import annotations

import argparse
import os

from dotenv import load_dotenv
from litellm import completion, ModelResponse
from litellm.types.utils import Choices
from rich.console import Console
from rich.markdown import Markdown
from rich.panel import Panel

from mcs.driver.core import DriverResponse, SupportsDriverContext
from mcs.driver.mail import MailDriver

console = Console()

MAX_TOOL_ROUNDS = 10


def _parse_args() -> argparse.Namespace:
    p = argparse.ArgumentParser(description="MCS Gmail Agent")
    auth = p.add_mutually_exclusive_group(required=True)
    auth.add_argument("--token", help="Google OAuth2 access token (quick test)")
    auth.add_argument("--auth0", action="store_true", help="Use Auth0 Token Vault")

    p.add_argument("--model", default="gpt-4o", help="LiteLLM model identifier")
    p.add_argument("--sender-name", default=None, help="Display name for outgoing e-mails")
    p.add_argument("--debug", "-d", action="store_true", help="Show raw LLM output")
    return p.parse_args()


def _build_credential(args: argparse.Namespace):
    """Build a CredentialProvider or a static access_token."""
    if args.auth0:
        from mcs.auth.auth0 import Auth0Provider

        for var in ("AUTH0_DOMAIN", "AUTH0_CLIENT_ID", "AUTH0_CLIENT_SECRET", "AUTH0_REFRESH_TOKEN"):
            if not os.environ.get(var):
                console.print(f"[red]Missing environment variable: {var}[/red]")
                raise SystemExit(1)

        return Auth0Provider(
            domain=os.environ["AUTH0_DOMAIN"],
            client_id=os.environ["AUTH0_CLIENT_ID"],
            client_secret=os.environ["AUTH0_CLIENT_SECRET"],
            refresh_token=os.environ["AUTH0_REFRESH_TOKEN"],
        )

    # Static token mode
    return None, args.token


def _build_driver(args: argparse.Namespace) -> MailDriver:
    """Build the MailDriver with gmail adapter.

    MailDriver is a composite that delegates to MailreadToolDriver and
    MailsendToolDriver.  Both accept ``adapter="gmail"`` and forward
    ``**adapter_kwargs`` to ``GmailAdapter``.  We pass the same config
    to both via ``read_kwargs`` / ``send_kwargs``.
    """
    gmail_kwargs: dict = {}
    if args.sender_name:
        gmail_kwargs["sender_name"] = args.sender_name

    credential = _build_credential(args)

    if isinstance(credential, tuple):
        # Static token mode: (None, token_string)
        _, token = credential
        gmail_kwargs["access_token"] = token
    else:
        # Auth0 mode: CredentialProvider
        gmail_kwargs["_credential"] = credential

    return MailDriver(
        read_adapter="gmail",
        send_adapter="gmail",
        read_kwargs=gmail_kwargs,
        send_kwargs=gmail_kwargs,
    )


def _llm_call(model: str, messages: list[dict], tools: list[dict] | None = None) -> dict:
    kwargs: dict = {"model": model, "messages": messages}
    if tools:
        kwargs["tools"] = tools
    resp = completion(**kwargs)
    assert isinstance(resp, ModelResponse)
    choice = resp.choices[0]
    assert isinstance(choice, Choices)
    return choice.message.model_dump()


def chat_loop(driver: MailDriver, model: str, debug: bool) -> None:
    native_tools: list[dict] | None = None
    if isinstance(driver, SupportsDriverContext):
        ctx = driver.get_driver_context(model)
        system_msg = ctx.system_message
        native_tools = ctx.tools
    else:
        system_msg = driver.get_driver_system_message()

    messages: list[dict] = [{"role": "system", "content": system_msg}]

    info = [
        "[bold cyan]MCS Gmail Agent[/bold cyan]\n",
        f"Driver:   {driver.meta.name}",
        f"Model:    {model}",
        f"Tools:    {len(driver.list_tools())} available",
        f"Debug:    {'on' if debug else 'off'}",
        "",
        "[dim]Type 'exit' or Ctrl+C to quit.[/dim]",
    ]
    console.print(Panel("\n".join(info), expand=False))

    if debug:
        tool_names = [t.name for t in driver.list_tools()]
        console.print(f"[dim]Tools: {tool_names}[/dim]")

    while True:
        try:
            user_input = console.input("\n[bold green]You:[/bold green] ").strip()
        except (EOFError, KeyboardInterrupt):
            break
        if not user_input or user_input.lower() in ("exit", "quit", "q"):
            break

        messages.append({"role": "user", "content": user_input})

        for _round in range(MAX_TOOL_ROUNDS):
            console.print("[dim]Thinking...[/dim]")
            llm_out = _llm_call(model, messages, native_tools)
            response = driver.process_llm_response(llm_out)

            if debug:
                import json
                console.print(Panel(
                    json.dumps(llm_out, indent=2, ensure_ascii=False),
                    title="Raw LLM output", border_style="dim",
                ))
                parts = [f"call_executed={response.call_executed}  call_failed={response.call_failed}"]
                if response.tool_call_result is not None:
                    result_str = str(response.tool_call_result)[:200]
                    parts.append(f"result: {result_str}")
                console.print(Panel("\n".join(parts), title="DriverResponse", border_style="dim"))

            if response.messages:
                messages.extend(response.messages)

            if response.call_executed:
                continue

            if response.call_failed:
                if debug:
                    console.print(f"[yellow]Tool failed: {response.call_detail}[/yellow]")
                continue

            content = llm_out.get("content", "") or ""
            messages.append({"role": "assistant", "content": content})
            console.print("\n[bold blue]Assistant:[/bold blue] ", end="")
            try:
                console.print(Markdown(content))
            except Exception:
                console.print(content)
            break
        else:
            console.print("[yellow]Max tool rounds reached.[/yellow]")


def main() -> None:
    load_dotenv()
    args = _parse_args()

    console.print("[dim]Building Gmail driver...[/dim]")
    driver = _build_driver(args)

    tools = driver.list_tools()
    console.print(f"[dim]Ready -- {len(tools)} tools discovered.[/dim]")

    chat_loop(driver, args.model, args.debug)
    console.print("\n[dim]Chat ended.[/dim]")


if __name__ == "__main__":
    main()
