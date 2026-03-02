"""Streaming MCS chat client using the REST driver.

Streams LLM output token-by-token.  The client only buffers text and
passes the accumulated buffer to the driver.  When the driver detects
a tool call it executes it, feeds the result back, and the LLM continues.

The client has no knowledge of tool calls whatsoever -- it just collects
text and lets the driver decide.

The MCS integration loop in ``chat_loop`` is structurally identical to
the non-streaming variant -- only the LLM call differs (streaming
accumulation instead of a single request).

Default: GitHub REST API (search + repos).  Any OpenAPI spec works.

Usage:
    python chat_stream.py [--model MODEL] [--debug] [--url URL]

    # Browse GitHub repos (default):
    python chat_stream.py --debug

    # Local model via OpenAI-compatible server (vLLM, llama.cpp, etc.):
    python chat_stream.py \
        --model openai/meta-llama/Meta-Llama-3.1-8B-Instruct \
        --api-base http://localhost:8000/v1 --debug

Requires:
    pip install mcs-driver-rest litellm rich python-dotenv
"""

from __future__ import annotations

import argparse

from dotenv import load_dotenv
from litellm import completion
from rich.console import Console
from rich.panel import Panel

from mcs.driver.rest import RestDriver
from mcs.driver.core import DriverResponse, MCSDriver, SupportsDriverContext

console = Console()

MAX_TOOL_ROUNDS = 10


GITHUB_SPEC = (
    "https://raw.githubusercontent.com/github/rest-api-description"
    "/main/descriptions/api.github.com/api.github.com.json"
)
DEFAULT_TAGS = ["repos", "search"]


def _parse_args() -> argparse.Namespace:
    p = argparse.ArgumentParser(description="MCS streaming chat client (REST)")
    p.add_argument("--model", default="gpt-4o", help="LiteLLM model identifier (default: gpt-4o)")
    p.add_argument("--url", default=GITHUB_SPEC, help="OpenAPI spec URL")
    p.add_argument("--include-tags", nargs="*", default=None,
                   help="Only include operations with these OpenAPI tags (default: repos search for GitHub)")
    p.add_argument("--api-base", default=None,
                   help="Custom OpenAI-compatible API base URL (e.g. http://localhost:8000/v1)")
    p.add_argument("--api-key", default=None,
                   help="API key for --api-base (default: 'no-key' when --api-base is set)")
    p.add_argument("--debug", "-d", action="store_true", help="Show DriverResponse details")
    return p.parse_args()


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

    tags = args.include_tags if args.include_tags is not None else (
        DEFAULT_TAGS if args.url == GITHUB_SPEC else None
    )
    driver = RestDriver(url=args.url, include_tags=tags)
    tools = driver.list_tools()
    console.print(f"[dim]Tools discovered ({len(tools)}): {[t.name for t in tools]}[/dim]")
    chat_loop(driver, args.model, args.debug, args.api_base, args.api_key)

    console.print("\n[dim]Chat ended.[/dim]")


if __name__ == "__main__":
    main()
