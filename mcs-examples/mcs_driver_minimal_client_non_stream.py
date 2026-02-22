"""Non-streaming MCS chat client using the CSV-LocalFS reference driver.

Usage:
    python mcs_driver_minimal_client_non_stream.py [--model MODEL] [--debug] [--data-dir DIR]

Requires:
    pip install litellm rich python-dotenv
    export OPENAI_API_KEY=sk-...              # for gpt-4o
    export OPENAI_API_BASE=http://localhost:11434  # for ollama (litellm routing)
"""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

from dotenv import load_dotenv
from litellm import completion
from rich.console import Console
from rich.markdown import Markdown
from rich.panel import Panel

sys.path.insert(0, str(Path(__file__).parent / "reference"))

from csv_localfs_driver import CsvLocalfsDriver  # type: ignore[import-not-found]

from mcs.driver.core import DriverResponse, MCSDriver

console = Console()

MAX_TOOL_ROUNDS = 10


def _parse_args() -> argparse.Namespace:
    p = argparse.ArgumentParser(description="MCS non-streaming chat client (CSV-LocalFS)")
    p.add_argument("--model", default="gpt-4o", help="LiteLLM model identifier (default: gpt-4o)")
    p.add_argument("--debug", "-d", action="store_true", help="Show raw LLM output and DriverResponse details")
    p.add_argument("--data-dir", default=str(Path(__file__).parent / "reference" / "data"),
                   help="CSV base directory for the driver")
    return p.parse_args()


def _llm_call(model: str, messages: list[dict]) -> str:
    resp = completion(model=model, messages=messages)
    return resp.choices[0].message.content or ""  # type: ignore[union-attr]


def _print_debug_response(llm_text: str, dr: DriverResponse) -> None:
    console.print(Panel(llm_text, title="Raw LLM output", border_style="dim"))
    parts = [f"call_executed={dr.call_executed}  call_failed={dr.call_failed}"]
    if dr.call_detail:
        parts.append(f"detail: {dr.call_detail}")
    if dr.tool_call_result is not None:
        result_str = str(dr.tool_call_result)
        if len(result_str) > 200:
            result_str = result_str[:197] + "..."
        parts.append(f"tool_call_result: {result_str}")
    if dr.retry_prompt:
        parts.append(f"retry_prompt: {dr.retry_prompt}")
    console.print(Panel("\n".join(parts), title="DriverResponse", border_style="dim"))


def chat_loop(driver: MCSDriver, model: str, debug: bool) -> None:
    system_msg = driver.get_driver_system_message()
    messages: list[dict] = [{"role": "system", "content": system_msg}]

    binding = driver.meta.bindings[0]
    info = [
        "[bold cyan]MCS Chat (non-streaming)[/bold cyan]\n",
        f"Driver:   {driver.meta.name}",
        f"Binding:  {binding.protocol} / {binding.transport}",
        f"Model:    {model}",
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
            llm_text = _llm_call(model, messages)
            dr = driver.process_llm_response(llm_text)

            if debug:
                _print_debug_response(llm_text, dr)

            if dr.messages:
                messages.extend(dr.messages)

            if dr.call_executed:
                if debug:
                    console.print("[dim]Tool executed -- sending result back to LLM...[/dim]")
                continue

            if dr.call_failed:
                if debug:
                    console.print(f"[yellow]Tool call failed: {dr.call_detail}[/yellow]")
                continue

            messages.append({"role": "assistant", "content": llm_text})
            console.print(f"\n[bold blue]Assistant:[/bold blue] ", end="")
            try:
                console.print(Markdown(llm_text))
            except Exception:
                console.print(llm_text)
            break
        else:
            console.print("[yellow]Max tool rounds reached -- stopping.[/yellow]")


def main() -> None:
    load_dotenv()
    args = _parse_args()

    driver = CsvLocalfsDriver(args.data_dir)
    chat_loop(driver, args.model, args.debug)

    console.print("\n[dim]Chat ended.[/dim]")


if __name__ == "__main__":
    main()
