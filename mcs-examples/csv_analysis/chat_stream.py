"""Streaming MCS chat client using the CSV driver.

Streams LLM output token-by-token.  When the driver detects a tool call
in the accumulated output it executes the tool, feeds the result back, and
the LLM continues.  A ``--debug`` flag shows raw tool-call payloads and
DriverResponse details inline.

The MCS integration loop in ``chat_loop`` is structurally identical to
the non-streaming variant -- only the LLM call differs (streaming
accumulation instead of a single request).

Usage:
    python chat_stream.py [--model MODEL] [--debug] [--data-dir DIR]

    # Local model via OpenAI-compatible server (vLLM, llama.cpp, etc.):
    python chat_stream.py \
        --model openai/meta-llama/Meta-Llama-3.1-8B-Instruct \
        --api-base http://localhost:8000/v1 --debug

Requires:
    pip install mcs-driver-csv litellm rich python-dotenv
"""

from __future__ import annotations

import argparse
import json
from pathlib import Path

from dotenv import load_dotenv
from litellm import completion
from rich.console import Console
from rich.panel import Panel

from mcs.driver.csv import CsvDriver
from mcs.driver.core import DriverResponse, MCSDriver

console = Console()

MAX_TOOL_ROUNDS = 10


def _parse_args() -> argparse.Namespace:
    p = argparse.ArgumentParser(description="MCS streaming chat client (CSV)")
    p.add_argument("--model", default="gpt-4o", help="LiteLLM model identifier (default: gpt-4o)")
    p.add_argument("--api-base", default=None,
                   help="Custom OpenAI-compatible API base URL (e.g. http://localhost:8000/v1)")
    p.add_argument("--api-key", default=None,
                   help="API key for --api-base (default: 'no-key' when --api-base is set)")
    p.add_argument("--debug", "-d", action="store_true", help="Show tool-call payloads and DriverResponse details")
    p.add_argument("--data-dir", default=str(Path(__file__).parent / "data"),
                   help="CSV base directory for the driver")
    return p.parse_args()


def _fmt_tool_params(params: dict) -> str:
    if not params:
        return ""
    parts = []
    for key, val in params.items():
        s = str(val)
        if len(s) > 60:
            s = s[:57] + "..."
        parts.append(f"{key}={s}")
    return ", ".join(parts)


def _extract_native_tool_calls(chunk) -> list[dict] | None:
    """Collect native tool-call fragments from a single streaming chunk."""
    delta = chunk.choices[0].delta if chunk.choices else None
    if delta is None:
        return None
    calls = getattr(delta, "tool_calls", None)
    if not calls:
        return None
    result = []
    for tc in calls:
        fn = getattr(tc, "function", None)
        if fn:
            result.append({
                "id": getattr(tc, "id", None),
                "name": getattr(fn, "name", None),
                "arguments": getattr(fn, "arguments", ""),
            })
    return result or None


def _stream_one_turn(
    model: str,
    messages: list[dict],
    debug: bool,
    api_base: str | None = None,
    api_key: str | None = None,
) -> str | dict:
    """Stream one LLM turn, display tokens live, return accumulated output.

    This function is the streaming equivalent of a simple ``completion()``
    call.  It handles token display and native tool-call accumulation,
    but does **not** interact with the MCS driver at all -- that happens
    in the caller's MCS loop.

    Returns
    -------
    str
        Accumulated text when the LLM produced a text response.
    dict
        MCS tool-call dict (``{"tool": ..., "arguments": ...}``) when the
        LLM emitted a native/structured tool call via the API.
    """
    kwargs: dict = {"model": model, "messages": messages, "stream": True}
    if api_base:
        kwargs["api_base"] = api_base
        kwargs["api_key"] = api_key or "no-key"
    stream = completion(**kwargs)

    buffer = ""
    native_calls: list[dict] = []
    printed_header = False

    for chunk in stream:  # type: ignore[union-attr]
        choices = getattr(chunk, "choices", None)
        delta = choices[0].delta if choices else None
        if delta is None:
            continue

        token = getattr(delta, "content", None) or ""

        nc = _extract_native_tool_calls(chunk)
        if nc:
            for c in nc:
                existing = next(
                    (x for x in native_calls if x.get("id") == c.get("id")),
                    None,
                )
                if existing and c.get("arguments"):
                    existing["arguments"] = existing.get("arguments", "") + c["arguments"]
                elif c.get("id"):
                    native_calls.append(c)

        if token:
            buffer += token
            if not printed_header:
                console.print("\n[bold blue]Assistant:[/bold blue] ", end="")
                printed_header = True
            print(token, end="", flush=True)

    if printed_header:
        print()

    if native_calls:
        nc_item = native_calls[0]
        try:
            args = json.loads(nc_item.get("arguments", "{}"))
        except json.JSONDecodeError:
            args = {}
        if debug:
            console.print(f"  [dim]\u2699 {nc_item.get('name', '?')}({_fmt_tool_params(args)})[/dim]")
        return {"tool": nc_item.get("name"), "arguments": args}

    return buffer


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
    system_msg = driver.get_driver_system_message()
    messages: list[dict] = [{"role": "system", "content": system_msg}]

    binding = driver.meta.bindings[0]
    info = [
        "[bold cyan]MCS Chat (streaming)[/bold cyan]\n",
        f"Driver:   {driver.meta.name}",
        f"Binding:  {binding.capability} / {binding.adapter}",
        f"Model:    {model}",
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
            llm_out = _stream_one_turn(model, messages, debug, api_base, api_key)
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

            if isinstance(llm_out, str):
                messages.append({"role": "assistant", "content": llm_out})
            break
        else:
            console.print("[yellow]Max tool rounds reached -- stopping.[/yellow]")


def main() -> None:
    load_dotenv()
    args = _parse_args()

    driver = CsvDriver(base_dir=args.data_dir)
    chat_loop(driver, args.model, args.debug, args.api_base, args.api_key)

    console.print("\n[dim]Chat ended.[/dim]")


if __name__ == "__main__":
    main()
