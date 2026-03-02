"""Non-streaming MCS chat client using the CSV driver.

Usage:
    python chat_non_stream.py [--model MODEL] [--debug] [--data-dir DIR]

    # Local model via OpenAI-compatible server (vLLM, llama.cpp, etc.):
    python chat_non_stream.py \
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
from litellm import completion, ModelResponse
from litellm.types.utils import Choices
from rich.console import Console
from rich.markdown import Markdown
from rich.panel import Panel

from mcs.driver.csv import CsvDriver
from mcs.driver.core import DriverResponse, MCSDriver

console = Console()

MAX_TOOL_ROUNDS = 10


def _parse_args() -> argparse.Namespace:
    p = argparse.ArgumentParser(description="MCS non-streaming chat client (CSV)")
    p.add_argument("--model", default="gpt-4o", help="LiteLLM model identifier (default: gpt-4o)")
    p.add_argument("--api-base", default=None,
                   help="Custom OpenAI-compatible API base URL (e.g. http://localhost:8000/v1)")
    p.add_argument("--api-key", default=None,
                   help="API key for --api-base (default: 'no-key' when --api-base is set)")
    p.add_argument("--debug", "-d", action="store_true", help="Show raw LLM output and DriverResponse details")
    p.add_argument("--data-dir", default=str(Path(__file__).parent / "data"),
                   help="CSV base directory for the driver")
    return p.parse_args()


def _llm_call(model: str, messages: list[dict],
              api_base: str | None = None, api_key: str | None = None) -> str | dict:
    """Call the LLM and return its output.

    Returns a string for text responses, or an MCS tool-call dict
    (``{"tool": ..., "arguments": ...}``) for native/structured tool calls.
    """
    kwargs: dict = {"model": model, "messages": messages}
    if api_base:
        kwargs["api_base"] = api_base
        kwargs["api_key"] = api_key or "no-key"
    resp = completion(**kwargs)
    assert isinstance(resp, ModelResponse)
    choice = resp.choices[0]
    assert isinstance(choice, Choices)
    msg = choice.message

    if hasattr(msg, "tool_calls") and msg.tool_calls:
        tc = msg.tool_calls[0]
        fn = tc.function
        try:
            args = json.loads(fn.arguments)
        except (json.JSONDecodeError, TypeError):
            args = {}
        return {"tool": fn.name, "arguments": args}

    return msg.content or ""


def _print_debug_response(llm_out: str | dict, response: DriverResponse) -> None:
    raw = llm_out if isinstance(llm_out, str) else json.dumps(llm_out, indent=2)
    console.print(Panel(raw, title="Raw LLM output", border_style="dim"))
    parts = [f"call_executed={response.call_executed}  call_failed={response.call_failed}"]
    if response.call_detail:
        parts.append(f"detail: {response.call_detail}")
    if response.tool_call_result is not None:
        result_str = str(response.tool_call_result)
        if len(result_str) > 200:
            result_str = result_str[:197] + "..."
        parts.append(f"tool_call_result: {result_str}")
    if response.retry_prompt:
        parts.append(f"retry_prompt: {response.retry_prompt}")
    console.print(Panel("\n".join(parts), title="DriverResponse", border_style="dim"))


def chat_loop(driver: MCSDriver, model: str, debug: bool,
              api_base: str | None = None, api_key: str | None = None) -> None:
    system_msg = driver.get_driver_system_message()
    messages: list[dict] = [{"role": "system", "content": system_msg}]

    binding = driver.meta.bindings[0]
    info = [
        "[bold cyan]MCS Chat (non-streaming)[/bold cyan]\n",
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
            console.print("[dim]Thinking...[/dim]")
            llm_out = _llm_call(model, messages, api_base, api_key)
            response = driver.process_llm_response(llm_out)

            if debug:
                _print_debug_response(llm_out, response)

            if response.messages:
                messages.extend(response.messages)

            if response.call_executed:
                if debug:
                    console.print("[dim]Tool executed -- sending result back to LLM...[/dim]")
                continue

            if response.call_failed:
                if debug:
                    console.print(f"[yellow]Tool call failed: {response.call_detail}[/yellow]")
                continue

            if isinstance(llm_out, str):
                messages.append({"role": "assistant", "content": llm_out})
                console.print("\n[bold blue]Assistant:[/bold blue] ", end="")
                try:
                    console.print(Markdown(llm_out))
                except Exception:
                    console.print(llm_out)
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
