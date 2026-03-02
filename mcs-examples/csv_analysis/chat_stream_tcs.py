"""Streaming MCS chat client with ToolCallSignalingMixin support.

Demonstrates how a client can use ``ToolCallSignalingMixin`` to hide
inline JSON tool calls from the user during streaming.  When the driver
signals that streamed tokens might be a tool call, the client buffers
them instead of displaying.  Once the call is confirmed and executed,
the next LLM turn streams seamlessly -- the user never sees raw JSON.

The MCS integration loop in ``chat_loop`` is structurally identical to
the non-streaming and basic streaming variants -- only the LLM call
differs (TCS-aware buffering in ``_stream_one_turn``).

Usage:
    python chat_stream_tcs.py [--model MODEL] [--debug] [--data-dir DIR]

    # Local model:
    python chat_stream_tcs.py \
        --model openai/meta-llama/Meta-Llama-3.1-8B-Instruct \
        --api-base http://localhost:8000/v1 --debug

Requires:
    pip install mcs-driver-csv litellm rich python-dotenv
"""

from __future__ import annotations

import argparse
import json
import re
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from dotenv import load_dotenv
from litellm import completion
from rich.console import Console
from rich.panel import Panel
from rich.spinner import Spinner
from rich.live import Live

from mcs.driver.csv import CsvDriver
from mcs.driver.core import DriverMeta, DriverBinding, DriverResponse, MCSDriver
from mcs.driver.core.mixins import ToolCallSignalingMixin

console = Console()

MAX_TOOL_ROUNDS = 10
SIGNAL_TIMEOUT_MS = 3000


@dataclass(frozen=True)
class _CsvTcsMeta(DriverMeta):
    id: str = "b8c3e5f1-4d9a-4b2e-a7c6-9f1d3e5a8b2c"
    name: str = "CSV Driver (TCS)"
    version: str = "0.1.0"
    bindings: tuple[DriverBinding, ...] = (
        DriverBinding(capability="csv", adapter="localfs", spec_format="Custom"),
    )
    supported_llms: tuple[str, ...] = ("*",)
    capabilities: tuple[str, ...] = ()


class CsvDriverTcs(CsvDriver, ToolCallSignalingMixin):
    """CsvDriver extended with streaming tool-call signaling.

    Shows how to add TCS to any existing driver by mixing in
    ``ToolCallSignalingMixin`` and implementing two methods.
    """

    meta: DriverMeta = _CsvTcsMeta()

    TOOL_CALL_OPENERS = ("{", "```")

    def might_be_tool_call(self, partial: str) -> bool:
        stripped = partial.strip()
        if not stripped:
            return False
        for opener in self.TOOL_CALL_OPENERS:
            if stripped.startswith(opener) or opener.startswith(stripped):
                return True
        return False

    def is_complete_tool_call(self, text: str) -> bool:
        payload = self._extract_json_obj(text)
        if payload is None:
            return False
        return "tool" in payload

    @staticmethod
    def _extract_json_obj(raw: str) -> dict[str, Any] | None:
        cleaned = raw.strip()
        if cleaned.startswith("```"):
            cleaned = re.sub(r"^```[^\n]*\n", "", cleaned)
            cleaned = re.sub(r"\n```$", "", cleaned)
        match = re.search(r"\{.*\}", cleaned, re.S)
        if not match:
            return None
        try:
            return json.loads(match.group(0))
        except json.JSONDecodeError:
            return None


def _parse_args() -> argparse.Namespace:
    p = argparse.ArgumentParser(
        description="MCS streaming chat client with tool-call signaling (CSV)")
    p.add_argument("--model", default="gpt-4o", help="LiteLLM model identifier (default: gpt-4o)")
    p.add_argument("--api-base", default=None,
                   help="Custom OpenAI-compatible API base URL")
    p.add_argument("--api-key", default=None,
                   help="API key for --api-base")
    p.add_argument("--debug", "-d", action="store_true",
                   help="Show tool-call signaling, payloads, and DriverResponse details")
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
) -> str | dict:
    """Stream one LLM turn with TCS-aware buffering, return accumulated output.

    When the driver supports ``ToolCallSignalingMixin``, tokens that look
    like the beginning of a tool call are held back instead of being
    displayed.  If they turn out to be a complete tool call the buffered
    text is returned directly (the driver will parse and execute it).
    If the buffer times out it is flushed to the screen as normal text.

    Returns
    -------
    str
        Accumulated text when the LLM produced a text response.
    dict
        MCS tool-call dict when the LLM emitted a native/structured tool call.
    """
    kwargs: dict = {"model": model, "messages": messages, "stream": True}
    if api_base:
        kwargs["api_base"] = api_base
        kwargs["api_key"] = api_key or "no-key"
    stream = completion(**kwargs)

    has_signaling = isinstance(driver, ToolCallSignalingMixin)

    full_buffer = ""
    native_calls: list[dict] = []
    printed_header = False

    buffering = False
    buffering_since: float = 0.0
    held_tokens = ""
    spinner_live: Live | None = None

    def _start_spinner() -> None:
        nonlocal spinner_live
        if spinner_live is not None:
            return
        spinner_live = Live(
            Spinner("dots", text="[dim]Calling tool...[/dim]"),
            console=console, transient=True,
        )
        spinner_live.start()

    def _stop_spinner() -> None:
        nonlocal spinner_live
        if spinner_live is None:
            return
        spinner_live.stop()
        spinner_live = None

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
                    (x for x in native_calls if x.get("id") == c.get("id")), None
                )
                if existing and c.get("arguments"):
                    existing["arguments"] = existing.get("arguments", "") + c["arguments"]
                elif c.get("id"):
                    native_calls.append(c)

        if token:
            full_buffer += token

            # --- TCS: check whether new tokens might be a tool call ---
            if has_signaling and not buffering:
                probe = (held_tokens + token).lstrip()
                if driver.might_be_tool_call(probe):  # type: ignore[union-attr]
                    buffering = True
                    buffering_since = time.monotonic()
                    held_tokens += token
                    _start_spinner()
                    if debug:
                        if not printed_header:
                            console.print("\n[bold blue]Assistant:[/bold blue] ", end="")
                            printed_header = True
                    continue
                else:
                    if held_tokens:
                        if not printed_header:
                            console.print("\n[bold blue]Assistant:[/bold blue] ", end="")
                            printed_header = True
                        print(held_tokens, end="", flush=True)
                        held_tokens = ""

            if buffering:
                held_tokens += token

                if has_signaling and driver.is_complete_tool_call(held_tokens):  # type: ignore[union-attr]
                    _stop_spinner()
                    if debug:
                        console.print("  [dim]\u2699 buffered tool call confirmed[/dim]")
                    return held_tokens

                elapsed = (time.monotonic() - buffering_since) * 1000
                if elapsed > SIGNAL_TIMEOUT_MS:
                    _stop_spinner()
                    if debug:
                        console.print(" [yellow]timeout -- flushing buffer[/yellow]")
                    if not printed_header:
                        console.print("\n[bold blue]Assistant:[/bold blue] ", end="")
                        printed_header = True
                    print(held_tokens, end="", flush=True)
                    held_tokens = ""
                    buffering = False

                continue

            # --- normal token display ---
            if not printed_header:
                console.print("\n[bold blue]Assistant:[/bold blue] ", end="")
                printed_header = True
            print(token, end="", flush=True)

    _stop_spinner()

    if printed_header:
        print()

    # Native tool calls -> MCS dict format
    if native_calls:
        nc_item = native_calls[0]
        try:
            args = json.loads(nc_item.get("arguments", "{}"))
        except json.JSONDecodeError:
            args = {}
        if debug:
            console.print(f"  [dim]\u2699 {nc_item.get('name', '?')}({_fmt_tool_params(args)})[/dim]")
        return {"tool": nc_item.get("name"), "arguments": args}

    # End-of-stream: check held buffer for complete tool call
    if buffering and held_tokens:
        if has_signaling and driver.is_complete_tool_call(held_tokens):  # type: ignore[union-attr]
            if debug:
                console.print("  [dim]\u2699 end-of-stream tool call confirmed[/dim]")
            return held_tokens
        if not printed_header:
            console.print("\n[bold blue]Assistant:[/bold blue] ", end="")
        print(held_tokens)

    return full_buffer


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
        f"Binding:  {binding.capability} / {binding.adapter}",
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
            llm_out = _stream_one_turn(model, messages, driver, debug, api_base, api_key)
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

    driver = CsvDriverTcs(base_dir=args.data_dir)
    chat_loop(driver, args.model, args.debug, args.api_base, args.api_key)

    console.print("\n[dim]Chat ended.[/dim]")


if __name__ == "__main__":
    main()
