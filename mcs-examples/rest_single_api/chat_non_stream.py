"""Non-streaming MCS chat client using the REST driver.

Connects to a single OpenAPI endpoint, discovers its tools, and provides
an interactive chat loop with tool execution.  The client code is
structurally identical to the CSV variant -- only the driver setup in
``main()`` differs.

Default: GitHub REST API (search + repos).  Any OpenAPI spec works.

Usage:
    python chat_non_stream.py [--model MODEL] [--debug] [--url URL]

    # Browse GitHub repos (default):
    python chat_non_stream.py --debug

    # ReqRes user API:
    python chat_non_stream.py --url https://reqres.in/openapi.json \
        --include-tags legacy

    # Local model via OpenAI-compatible server (vLLM, llama.cpp, etc.):
    python chat_non_stream.py \
        --model openai/meta-llama/Meta-Llama-3.1-8B-Instruct \
        --api-base http://localhost:8000/v1 --debug

Requires:
    pip install mcs-driver-rest litellm rich python-dotenv
"""

from __future__ import annotations

import argparse

from dotenv import load_dotenv
from litellm import completion, ModelResponse
from litellm.types.utils import Choices
from rich.console import Console
from rich.markdown import Markdown
from rich.panel import Panel

from mcs.driver.rest import RestDriver
from mcs.driver.core import DriverResponse, MCSDriver, SupportsDriverContext

console = Console()

MAX_TOOL_ROUNDS = 10


GITHUB_SPEC = (
    "https://raw.githubusercontent.com/github/rest-api-description"
    "/main/descriptions/api.github.com/api.github.com.json"
)
DEFAULT_TAGS = ["search"]


def _parse_args() -> argparse.Namespace:
    p = argparse.ArgumentParser(description="MCS non-streaming chat client (REST)")
    p.add_argument("--model", default="gpt-4o", help="LiteLLM model identifier (default: gpt-4o)")
    p.add_argument("--url", default=GITHUB_SPEC, help="OpenAPI spec URL")
    p.add_argument("--include-tags", nargs="*", default=None,
                   help="Only include operations with these OpenAPI tags (default: repos search for GitHub)")
    p.add_argument("--api-base", default=None,
                   help="Custom OpenAI-compatible API base URL (e.g. http://localhost:8000/v1)")
    p.add_argument("--api-key", default=None,
                   help="API key for --api-base (default: 'no-key' when --api-base is set)")
    p.add_argument("--debug", "-d", action="store_true", help="Show raw LLM output and DriverResponse details")
    return p.parse_args()


def _llm_call(model: str, messages: list[dict],
              api_base: str | None = None, api_key: str | None = None,
              tools: list[dict] | None = None) -> dict:
    """Call the LLM and return the full message dict.

    The client does not inspect or interpret the content -- that is the
    driver's responsibility.  The returned dict is the raw message
    from ``choices[0].message``.
    """
    kwargs: dict = {"model": model, "messages": messages}
    if api_base:
        kwargs["api_base"] = api_base
        kwargs["api_key"] = api_key or "no-key"
    if tools:
        kwargs["tools"] = tools
    resp = completion(**kwargs)
    assert isinstance(resp, ModelResponse)
    choice = resp.choices[0]
    assert isinstance(choice, Choices)
    return choice.message.model_dump()


def _print_debug_response(llm_out: dict, response: DriverResponse) -> None:
    import json
    console.print(Panel(json.dumps(llm_out, indent=2, ensure_ascii=False),
                        title="Raw LLM output", border_style="dim"))
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
    # Use get_driver_context if available, fall back to get_driver_system_message
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
        "[bold cyan]MCS Chat (non-streaming)[/bold cyan]\n",
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
            console.print("[dim]Thinking...[/dim]")
            llm_out = _llm_call(model, messages, api_base, api_key, native_tools)
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

            content = llm_out.get("content", "") or ""
            messages.append({"role": "assistant", "content": content})
            console.print("\n[bold blue]Assistant:[/bold blue] ", end="")
            try:
                console.print(Markdown(content))
            except Exception:
                console.print(content)
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
