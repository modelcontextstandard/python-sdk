"""Streaming MCS chat client using the CSV-LocalFS reference driver.

Streams LLM output token-by-token.  When the driver detects a tool call
in the accumulated buffer it executes the tool, feeds the result back, and
resumes streaming.  A ``--debug`` flag shows raw tool-call payloads and
DriverResponse details inline (similar to OctaClaw's debug mode).

Usage:
    python mcs_driver_minimal_client_stream.py [--model MODEL] [--debug] [--data-dir DIR]

    # Local model via OpenAI-compatible server (vLLM, llama.cpp, etc.):
    python mcs_driver_minimal_client_stream.py \
        --model openai/meta-llama/Meta-Llama-3.1-8B-Instruct \
        --api-base http://localhost:8000/v1 --debug

Requires:
    pip install -e ".[examples]"
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from dotenv import load_dotenv
from litellm import completion
from rich.console import Console
from rich.panel import Panel

sys.path.insert(0, str(Path(__file__).parent / "reference"))

from csv_driver import CsvDriver  # type: ignore[import-not-found]

from mcs.driver.core import DriverResponse, MCSDriver

console = Console()

MAX_TOOL_ROUNDS = 10


def _parse_args() -> argparse.Namespace:
    p = argparse.ArgumentParser(description="MCS streaming chat client (CSV-LocalFS)")
    p.add_argument("--model", default="gpt-4o", help="LiteLLM model identifier (default: gpt-4o)")
    p.add_argument("--api-base", default=None,
                   help="Custom OpenAI-compatible API base URL (e.g. http://localhost:8000/v1)")
    p.add_argument("--api-key", default=None,
                   help="API key for --api-base (default: 'no-key' when --api-base is set)")
    p.add_argument("--debug", "-d", action="store_true", help="Show tool-call payloads and DriverResponse details")
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
    driver: MCSDriver,
    debug: bool,
    api_base: str | None = None,
    api_key: str | None = None,
) -> tuple[str | None, DriverResponse | None]:
    """Stream a single LLM turn, detect tool calls, return final text or DriverResponse.

    Returns
    -------
    (final_text, None)        -- LLM finished with a text answer (no tool call).
    (None, DriverResponse)    -- A tool call was detected and executed (or failed).
    """
    kwargs: dict = {"model": model, "messages": messages, "stream": True}
    if api_base:
        kwargs["api_base"] = api_base
        kwargs["api_key"] = api_key or "no-key"
    stream = completion(**kwargs)

    buffer = ""
    native_calls: list[dict] = []
    printed_header = False
    after_tool_debug = False

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
            buffer += token
            if not printed_header:
                console.print(f"\n[bold blue]Assistant:[/bold blue] ", end="")
                printed_header = True
            print(token, end="", flush=True)

        if finish == "tool_calls" and native_calls:
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

                return None, dr

    if native_calls:
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
            return None, dr

    dr = driver.process_llm_response(buffer, streaming=False)

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
    return buffer, None


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

    driver = CsvDriver(base_dir=args.data_dir)
    chat_loop(driver, args.model, args.debug, args.api_base, args.api_key)

    console.print("\n[dim]Chat ended.[/dim]")


if __name__ == "__main__":
    main()
