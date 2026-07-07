"""Streaming MCS chat client using the REST driver.

Streams LLM output chunk-by-chunk. The client feeds each raw chunk to an
``LLMStreamBuffer`` (obtained via ``streamer.new_stream_buffer()`` -- a standalone
object, seeded with the driver's chain); the buffer reassembles the provider's native
message and returns the content delta for live display. Each accumulated message goes
to ``process_llm_response`` -- the client never touches ``tool_calls`` itself. When the
driver detects a complete call it executes it, ``reset()``s the buffer to hunt for the
next call, feeds the result back, and the LLM continues.

The client has no knowledge of tool calls whatsoever -- the ``LLMStreamBuffer`` does
the reassembly (once, in the SDK, per tool format, instead of in every client); the
driver does the rest. The buffer is not driver-bound: reassembly is an LLM/SDK
concern, identical for every driver.

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
from rich.markdown import Markdown
from rich.panel import Panel

from mcs.driver.rest import RestDriver
from mcs.driver.core import (
    DriverMeta, DriverResponse, MCSDriver,
    SupportsNativeTools, SupportsStreaming,
)

console = Console()

MAX_TOOL_RETRIES = 3   # consecutive *failed* call attempts before giving up (see chat_loop)
MAX_TOOL_ROUNDS = 25   # hard safety cap: total tool rounds per user message, so a model
#                        that keeps (successfully) calling a tool can never loop forever


GITHUB_SPEC = (
    "https://raw.githubusercontent.com/github/rest-api-description"
    "/main/descriptions/api.github.com/api.github.com.json"
)
DEFAULT_TAGS = ["search"]


def _parse_args() -> argparse.Namespace:
    p = argparse.ArgumentParser(description="MCS streaming chat client (REST)")
    p.add_argument("--model", default="gpt-5.5", help="LiteLLM model identifier (default: gpt-5.5)")
    p.add_argument("--url", default=GITHUB_SPEC, help="OpenAPI spec URL")
    p.add_argument("--include-tags", nargs="*", default=None,
                   help="Only include operations with these OpenAPI tags (default: repos search for GitHub)")
    p.add_argument("--api-base", default=None,
                   help="Custom OpenAI-compatible API base URL (e.g. http://localhost:8000/v1)")
    p.add_argument("--api-key", default=None,
                   help="API key for --api-base (default: 'no-key' when --api-base is set)")
    p.add_argument("--debug", "-d", action="store_true", help="Show DriverResponse details")
    p.add_argument("--native-tools", action=argparse.BooleanOptionalAction, default=True,
                   help="Use the model's native tool-calling API "
                        "(default: on; pass --no-native-tools for text-prompt mode)")
    return p.parse_args()


def _stream_one_turn(
    model: str,
    messages: list[dict],
    api_base: str | None = None,
    api_key: str | None = None,
    tools: list[dict] | None = None,
):
    """Build and return the streaming completion for one LLM turn.

    Only the LLM call lives here. The caller consumes the stream chunk by chunk
    (the *view*) and hands the accumulated message to the driver (the
    *processing*) -- keeping the two cleanly separate, exactly like the
    non-streaming variant's ``_llm_call``.
    """
    kwargs: dict = {"model": model, "messages": messages, "stream": True}
    if api_base:
        kwargs["api_base"] = api_base
        kwargs["api_key"] = api_key or "no-key"
    if tools:
        kwargs["tools"] = tools
    return completion(**kwargs)


def _print_debug_dr(dr: DriverResponse) -> None:
    parts = [f"call_executed={dr.call_executed}  call_failed={dr.call_failed}"]
    # executed_calls is the per-call report -- one line each, so a parallel batch
    # is readable (name, args, result/error) instead of one raw blob.
    for rec in dr.executed_calls or []:
        if rec.error:
            outcome = f"[red]error:[/red] {rec.error}"
        else:
            r = str(rec.result)
            outcome = "-> " + (r[:157] + "..." if len(r) > 160 else r)
        parts.append(f"  • {rec.name}({rec.arguments}) {outcome}")
    if dr.retry_prompt:
        parts.append(f"retry_prompt: {dr.retry_prompt}")
    console.print(Panel("\n".join(parts), title="DriverResponse", border_style="dim"))


def chat_loop(driver: MCSDriver, model: str, native_tools_enabled: bool, debug: bool,
              api_base: str | None = None, api_key: str | None = None) -> None:
    # This client depends on the SupportsStreaming *capability* for the
    # streaming-aware process_llm_response. The buffer is a standalone object (not
    # driver-bound, so it works in fan-out); new_stream_buffer() is a convenience that
    # seeds it with the driver's extraction chain.
    streamer = DriverMeta.resolve_capability(driver, SupportsStreaming)
    if streamer is None:
        raise SystemExit(f"{driver.meta.name} does not support streaming.")

    native_tools: list[dict] | None = None
    if (dc := DriverMeta.resolve_capability(driver, SupportsNativeTools)) and native_tools_enabled:
        ctx = dc.get_native_tool_context(model)
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

        # Agentic loop, LLM-steered: a tool call ends the model's turn (like native
        # finish_reason="tool_calls"); the harness feeds the result back and the model
        # continues on the *next* turn -- now *with* the result. It stops when a turn has
        # *no* tool call (a plain answer). Two guards: MAX_TOOL_RETRIES bounds consecutive
        # *failed* attempts; MAX_TOOL_ROUNDS is a hard cap on total rounds so a model that
        # keeps (successfully) calling a tool can never loop forever. Continuation keys on
        # MCS's ``call_executed``, not the wire's finish_reason -- format-agnostic.
        retries = 0
        rounds = 0
        
        
        while True:
            stream = _stream_one_turn(model, messages, api_base, api_key, native_tools)
            console.print("\n[bold blue]Assistant:[/bold blue] ", end="")
            # Format-agnostic: feed the chunk, let the driver work on the buffer, read
            # what it lets through. Native and text-embedded calls look identical here.
            # Per chunk: (a) a content token -> buf.text() -> print; (b) a call building
            # up -> buf.text() empty, call_pending; (c) call complete -> driver executes.
            buf = streamer.new_stream_buffer()      # seeded with the driver's chain

            content = ""
            tool_ran = tool_ok = False
            for chunk in stream:  # type: ignore[union-attr]
                buf.add(chunk)
                response = streamer.process_llm_response(buf)   # the buffer IS the signal

                if response.messages:                 # tool result -> back to the LLM
                    messages.extend(response.messages)
                if (text := buf.text()):              # (a) assistant text before the call
                    content += text
                    print(text, end="", flush=True)
                elif response.call_pending:           # (b) a tool call is building up
                    print(".", end="", flush=True)
                if response.call_executed or response.call_failed:
                    if debug:                         # a panel here breaks the line -> resume it
                        print()
                        _print_debug_dr(response)
                        console.print("[bold blue]Assistant:[/bold blue] ", end="")
                    tool_ran = True
                    tool_ok = tool_ok or response.call_executed
                    content = ""                      # pre-call text is already in the
                    #                                   assistant echo (response.messages)
                    # (c) A tool call ends the turn: STOP consuming the stream. Any text the
                    # model streams *after* the call was generated blind (before the tool
                    # ran, so without its result) -- keeping it would show a hallucinated
                    # "I got no data". The result-aware answer continues on the next turn,
                    # on the same assistant line.
                    break

            if not tool_ran:
                # No call -> the model's final answer. Record it (the driver did not) and
                # close the one assistant block.
                if content.strip():
                    messages.append({"role": "assistant", "content": content})
                print()
                break

            rounds += 1
            if rounds >= MAX_TOOL_ROUNDS:             # runaway guard (degenerate re-calling)
                print()
                console.print("[yellow]Max tool rounds reached -- stopping.[/yellow]")
                break
            if tool_ok:
                retries = 0                           # progress -> keep working (agentic)
            else:
                retries += 1                          # only failures count toward the cap
                if retries > MAX_TOOL_RETRIES:
                    print()
                    console.print("[yellow]Tool call keeps failing -- giving up.[/yellow]")
                    break


def main() -> None:
    load_dotenv()
    args = _parse_args()

    tags = args.include_tags if args.include_tags is not None else (
        DEFAULT_TAGS if args.url == GITHUB_SPEC else None
    )
    driver = RestDriver(url=args.url, include_tags=tags)
    tools = driver.list_tools()
    console.print(f"[dim]Tools discovered ({len(tools)}): {[t.name for t in tools]}[/dim]")
    chat_loop(driver, args.model, args.native_tools, args.debug, args.api_base, args.api_key)

    console.print("\n[dim]Chat ended.[/dim]")


if __name__ == "__main__":
    main()
