"""Streaming MCS chat client with ToolCallSignalingMixin support.

Demonstrates how a client can use ``ToolCallSignalingMixin`` to hide
inline JSON tool calls from the user during streaming.  When the driver
signals that streamed tokens might be a tool call, the client buffers
them instead of displaying.  Once the call is confirmed and executed,
the next LLM turn streams seamlessly -- the user never sees raw JSON.

This is a copy of ``mcs_driver_minimal_client_stream.py`` with the
buffer logic added.  The separation keeps the base example simple.

Usage:
    python mcs_driver_minimal_client_stream_tcs.py [--model MODEL] [--debug] [--data-dir DIR]

    # Local model:
    python mcs_driver_minimal_client_stream_tcs.py \\
        --model openai/meta-llama/Meta-Llama-3.1-8B-Instruct \\
        --api-base http://localhost:8000/v1 --debug

Requires:
    pip install -e ".[examples]"
"""

from __future__ import annotations

import argparse
import json
import sys
import time
from pathlib import Path

from dotenv import load_dotenv
from litellm import completion
from rich.console import Console
from rich.panel import Panel

sys.path.insert(0, str(Path(__file__).parent / "reference"))

from csv_localfs_driver_tcs import CsvLocalfsDriverTcs  # type: ignore[import-not-found]

from mcs.driver.core import DriverResponse, MCSDriver
from mcs.driver.core.mixins import ToolCallSignalingMixin

console = Console()

MAX_TOOL_ROUNDS = 10
SIGNAL_TIMEOUT_MS = 3000


def _parse_args() -> argparse.Namespace:
    p = argparse.ArgumentParser(
        description="MCS streaming chat client with tool-call signaling (CSV-LocalFS)")
    p.add_argument("--model", default="gpt-4o", help="LiteLLM model identifier (default: gpt-4o)")
    p.add_argument("--api-base", default=None,
                   help="Custom OpenAI-compatible API base URL (e.g. http://localhost:8000/v1)")
    p.add_argument("--api-key", default=None,
                   help="API key for --api-base (default: 'no-key' when --api-base is set)")
    p.add_argument("--debug", "-d", action="store_true",
                   help="Show tool-call signaling, payloads, and DriverResponse details")
    p.add_argument("--data-dir", default=str(Path(__file__).parent / "reference" / "data"),
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
    """Pull native tool_calls from an OpenAI-style streaming delta."""
    choices = getattr(chunk, "choices", None)
    delta = choices[0].delta if choices else None
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
    driver: MCSDriver,
    debug: bool,
    api_base: str | None = None,
    api_key: str | None = None,
) -> tuple[str | None, DriverResponse | None]:
    """Stream one LLM turn with tool-call signaling support.

    When the driver implements ``ToolCallSignalingMixin``, the client
    buffers tokens that look like a tool call instead of printing them.
    """
    kwargs: dict = {"model": model, "messages": messages, "stream": True}
    if api_base:
        kwargs["api_base"] = api_base
        kwargs["api_key"] = api_key or "no-key"
    stream = completion(**kwargs)

    has_signaling = isinstance(driver, ToolCallSignalingMixin)

    full_buffer = ""
    display_buffer = ""
    native_calls: list[dict] = []
    printed_header = False

    buffering = False
    buffering_since: float = 0.0
    held_tokens = ""

    for chunk in stream:  # type: ignore[union-attr]
        choices = getattr(chunk, "choices", None)
        delta = choices[0].delta if choices else None
        if delta is None:
            continue

        token = getattr(delta, "content", None) or ""
        finish = choices[0].finish_reason if choices else None

        nc = _extract_native_tool_calls(chunk)
        if nc:
            for c in nc:
                existing = next((x for x in native_calls if x.get("id") == c.get("id")), None)
                if existing and c.get("arguments"):
                    existing["arguments"] = existing.get("arguments", "") + c["arguments"]
                elif c.get("id"):
                    native_calls.append(c)

        if token:
            full_buffer += token

            if has_signaling and not buffering:
                probe = (held_tokens + token).lstrip()
                if driver.might_be_tool_call(probe):  # type: ignore[union-attr]
                    buffering = True
                    buffering_since = time.monotonic()
                    held_tokens += token
                    if debug:
                        if not printed_header:
                            console.print(f"\n[bold blue]Assistant:[/bold blue] ", end="")
                            printed_header = True
                        console.print("[dim][buffering -- possible tool call][/dim]", end="")
                    continue
                else:
                    if held_tokens:
                        if not printed_header:
                            console.print(f"\n[bold blue]Assistant:[/bold blue] ", end="")
                            printed_header = True
                        print(held_tokens, end="", flush=True)
                        display_buffer += held_tokens
                        held_tokens = ""

            if buffering:
                held_tokens += token

                if has_signaling and driver.is_complete_tool_call(held_tokens):  # type: ignore[union-attr]
                    if debug:
                        print()
                        console.print(f"  [dim]\u2699 buffered tool call confirmed[/dim]")
                    dr = driver.process_llm_response(held_tokens, streaming=False)
                    if debug:
                        _print_debug_dr(dr)
                    return None, dr

                elapsed = (time.monotonic() - buffering_since) * 1000
                if elapsed > SIGNAL_TIMEOUT_MS:
                    if debug:
                        console.print(f" [yellow]timeout -- flushing buffer[/yellow]")
                    if not printed_header:
                        console.print(f"\n[bold blue]Assistant:[/bold blue] ", end="")
                        printed_header = True
                    print(held_tokens, end="", flush=True)
                    display_buffer += held_tokens
                    held_tokens = ""
                    buffering = False

                continue

            if not printed_header:
                console.print(f"\n[bold blue]Assistant:[/bold blue] ", end="")
                printed_header = True
            print(token, end="", flush=True)
            display_buffer += token

        if finish == "tool_calls" and native_calls:
            return None, _handle_native_calls(native_calls, driver, debug, printed_header)

    if native_calls:
        return None, _handle_native_calls(native_calls, driver, debug, printed_header)

    if buffering and held_tokens:
        dr = driver.process_llm_response(held_tokens, streaming=False)
        if dr.call_executed or dr.call_failed:
            if debug:
                print()
                console.print(f"  [dim]\u2699 end-of-stream tool call confirmed[/dim]")
                _print_debug_dr(dr)
            return None, dr
        if not printed_header:
            console.print(f"\n[bold blue]Assistant:[/bold blue] ", end="")
            printed_header = True
        print(held_tokens, end="", flush=True)
        display_buffer += held_tokens

    dr = driver.process_llm_response(full_buffer, streaming=False)
    if dr.call_executed or dr.call_failed:
        if debug:
            if printed_header:
                print()
            console.print(f"  [dim]\u2699 inline JSON tool call detected[/dim]")
            _print_debug_dr(dr)
        elif printed_header:
            print("\r\033[K", end="")
        return None, dr

    if printed_header:
        print()
    return full_buffer, None


def _handle_native_calls(
    native_calls: list[dict], driver: MCSDriver, debug: bool, printed_header: bool,
) -> DriverResponse:
    for nc_item in native_calls:
        try:
            args = json.loads(nc_item.get("arguments", "{}"))
        except json.JSONDecodeError:
            args = {}
        tool_payload = {"tool": nc_item.get("name"), "arguments": args}

        if debug:
            if printed_header:
                print()
            console.print(f"  [dim]\u2699 {nc_item.get('name', '?')}({_fmt_tool_params(args)})[/dim]")

        dr = driver.process_llm_response(tool_payload, streaming=False)
        if debug:
            _print_debug_dr(dr)
        return dr
    return DriverResponse()


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
    has_tcs = isinstance(driver, ToolCallSignalingMixin)
    info = [
        "[bold cyan]MCS Chat (streaming + TCS)[/bold cyan]\n",
        f"Driver:   {driver.meta.name}",
        f"Binding:  {binding.protocol} / {binding.transport}",
        f"Model:    {model}",
        f"TCS:      {'active' if has_tcs else 'not supported by driver'}",
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
            final_text, dr = _stream_one_turn(model, messages, driver, debug, api_base, api_key)

            if dr is not None:
                if dr.messages:
                    messages.extend(dr.messages)

                if dr.call_executed:
                    if debug:
                        console.print("[dim]Tool executed -- streaming next LLM turn...[/dim]")
                    continue

                if dr.call_failed:
                    if debug:
                        console.print(f"[yellow]Tool call failed: {dr.call_detail}[/yellow]")
                    continue

            if final_text is not None:
                messages.append({"role": "assistant", "content": final_text})
            break
        else:
            console.print("[yellow]Max tool rounds reached -- stopping.[/yellow]")


def main() -> None:
    load_dotenv()
    args = _parse_args()

    driver = CsvLocalfsDriverTcs(args.data_dir)
    chat_loop(driver, args.model, args.debug, args.api_base, args.api_key)

    console.print("\n[dim]Chat ended.[/dim]")


if __name__ == "__main__":
    main()
