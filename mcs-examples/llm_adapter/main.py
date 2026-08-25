"""The LLM stack in a glass case -- an interactive e2e probe for the adapter layer.

Not a chat app. One question, one answer, and everything in between made visible:
which bytes leave, which come back, what the catalogues know, what the endpoint
states, and how the adapter resolves the wire dialect from it. The fixed test suites
prove the measured cases; this is for probing the variants around them.

The whole trick is one line of MCS: a *glass* ``HttpAdapter`` is injected into every
component -- the LLM adapters AND the catalogue providers. Because MCS routes every
byte through the injected transport, ``debug on`` shows the complete truth: the
request body (is the budget spelled ``max_completion_tokens``? did
``reasoning_effort`` travel?), the describe() inquiries against ``/models/{id}`` and
``/api/show``, and the one big catalogue fetch. Nothing can talk past the glass.

Usage:
    python main.py                            # local fleet: qwen3:4b + gemma4:e4b
    python main.py --model gpt-5.5 --model gpt-5.6 \
                   --model qwen3:4b@http://localhost:11434/v1
    python main.py --model "openai/gpt-5.5@https://openrouter.ai/api/v1" \
                   --model "google/gemini-2.5-flash@https://openrouter.ai/api/v1"

    Model spec is ``ID[@BASE_URL]``; the default base URL is the local Ollama.

Commands inside the loop:
    <any text>              ask the ACTIVE model (one complete(), no history)
    use <model>             switch the active model
    models                  the fleet, its endpoints, and each resolved wire field
    info                    describe() of the active adapter: statement + knowledge
    info <model>            ask the current catalogue alone (any id, no adapter)
    catalog models.dev|litellm|off      swap the knowledge source (rebuilds fleet)
    effort none|low|...|off             reasoning_effort for new calls (rebuilds)
    budget <tokens>         max_completion_tokens per call (0 = send no budget)
    debug on|off            print every request/response on the wire
    quit

Keys (environment or .env): OPENAI_API_KEY for api.openai.com, OPENROUTER_API_KEY
for openrouter.ai, MCS_LLM_KEY as the fallback for anything else. Local servers
need none. Which key goes to which host is client configuration, spelled out in
``_key_for`` -- unlike the wire dialect, which nothing here configures: the adapter
resolves it from catalogue knowledge, and ``debug on`` is how you watch it happen.
"""

from __future__ import annotations

import argparse
import json
import os
from dataclasses import fields as dataclass_fields
from urllib.parse import urlparse

from dotenv import load_dotenv
from rich.console import Console
from rich.panel import Panel
from rich.table import Table

from mcs.adapter.http import HttpAdapter
from mcs.adapter.llm.completion import CompletionLLMAdapter
from mcs.adapter.llm.info import LiteLLMInfoProvider, ModelsDevInfoProvider
from mcs.types.llm import ContextWindowExceeded, LLMError, ModelInfo

console = Console()

DEFAULT_BASE_URL = "http://localhost:11434/v1"
DEFAULT_FLEET = ["qwen3:4b", "gemma4:e4b"]


class GlassHttp:
    """Wraps the one real HttpAdapter; prints what travels when debug is on.

    The Authorization header is masked, never printed -- the glass shows shapes,
    not secrets.
    """

    def __init__(self) -> None:
        self.inner = HttpAdapter(timeout=120)
        self.debug = False

    def request(self, method, url, *, params=None, json_body=None, headers=None,
                timeout=None):
        if self.debug:
            shown = dict(headers or {})
            if "Authorization" in shown:
                shown["Authorization"] = "Bearer ***"
            console.print(f"[cyan]-> {method} {url}[/cyan]"
                          + (f"  [dim]{shown}[/dim]" if shown else ""))
            if json_body is not None:
                console.print(f"   [cyan]{json.dumps(json_body, ensure_ascii=False)[:600]}[/cyan]")
        resp = self.inner.request(method, url, params=params, json_body=json_body,
                                  headers=headers, timeout=timeout)
        if self.debug:
            console.print(f"[cyan]<- {resp.status_code}  "
                          f"[dim]{len(resp.text or ''):,} chars[/dim][/cyan]")
        return resp


def _parse_model(spec: str) -> tuple[str, str]:
    model_id, _, url = spec.partition("@")
    return model_id, (url or DEFAULT_BASE_URL)


def _key_for(url: str) -> str | None:
    """Which key travels to which host is CLIENT configuration -- named here, once."""
    host = urlparse(url).hostname or ""
    if host == "api.openai.com":
        return os.environ.get("OPENAI_API_KEY")
    if host.endswith("openrouter.ai"):
        return os.environ.get("OPENROUTER_API_KEY")
    return os.environ.get("MCS_LLM_KEY")


def _show_info(info: ModelInfo | None, title: str) -> None:
    if info is None:
        console.print(Panel("[yellow]None[/yellow] -- no statement, no knowledge. "
                            "That is an answer: plan conservatively.", title=title))
        return
    table = Table(show_header=False, box=None, pad_edge=False)
    for f in dataclass_fields(info):
        if f.name == "meta":
            continue
        value = getattr(info, f.name)
        rendered = ("[dim]None (not stated)[/dim]" if value is None
                    else f"{value:,}" if isinstance(value, int) else str(value))
        table.add_row(f.name, rendered)
    table.add_row("meta sources", ", ".join(info.meta) or "[dim]-[/dim]")
    md = info.meta.get("models_dev") or {}
    if md.get("providers"):
        table.add_row("  served by", f"{len(md['providers'])} providers "
                                     f"({', '.join(md['providers'][:4])}, ...)"
                      if len(md["providers"]) > 4 else ", ".join(md["providers"]))
    if md.get("temperature") is False:
        table.add_row("  temperature", "[yellow]rejected by this model[/yellow] "
                                       "(models.dev exclusive)")
    for option in md.get("reasoning_options") or []:
        if option.get("type") == "effort":
            table.add_row("  effort values", ", ".join(option.get("values", [])))
    lite = info.meta.get("litellm") or {}
    if "input_cost_per_token" in lite:
        table.add_row("  price in/out",
                      f"${lite['input_cost_per_token'] * 1e6:.2f} / "
                      f"${lite.get('output_cost_per_token', 0) * 1e6:.2f} per 1M")
    console.print(Panel(table, title=title, expand=False))


def main() -> None:
    load_dotenv()
    p = argparse.ArgumentParser(description=__doc__.split("\n", 1)[0])
    p.add_argument("--model", action="append", metavar="ID[@BASE_URL]",
                   help=f"Repeatable. Default base URL: {DEFAULT_BASE_URL}. "
                        f"Unset: {' + '.join(DEFAULT_FLEET)} locally.")
    p.add_argument("--catalog", default="models.dev",
                   choices=["models.dev", "litellm", "off"],
                   help="Knowledge source injected into every adapter (default: "
                        "models.dev; swap live with the 'catalog' command)")
    p.add_argument("--effort", default=None,
                   help="reasoning_effort for every call (model-dependent values; "
                        "the 400 names the accepted set, 'info' shows models.dev's)")
    p.add_argument("--budget", type=int, default=1024,
                   help="max_completion_tokens per call (default 1024 -- deliberately "
                        "set, so the wire-field resolution is exercised on the very "
                        "first call; 0 sends none)")
    p.add_argument("--debug", action="store_true", help="start with the glass on")
    args = p.parse_args()

    glass = GlassHttp()
    glass.debug = args.debug
    specs = [_parse_model(s) for s in (args.model or DEFAULT_FLEET)]
    state = {"catalog": args.catalog, "effort": args.effort or None,
             "budget": args.budget or None}

    def build_catalog():
        # The glass goes into the catalogue too: its one big fetch is transport
        # like any other, and seeing it once demystifies where knowledge comes from.
        if state["catalog"] == "models.dev":
            return ModelsDevInfoProvider(_http=glass)
        if state["catalog"] == "litellm":
            return LiteLLMInfoProvider(_http=glass)
        return None

    catalog = build_catalog()

    def build_fleet() -> dict[str, CompletionLLMAdapter]:
        return {
            model_id: CompletionLLMAdapter(
                model_id, base_url=url, api_key=_key_for(url),
                model_info=catalog, reasoning_effort=state["effort"], _http=glass,
            )
            for model_id, url in specs
        }

    fleet = build_fleet()
    active = next(iter(fleet))

    def show_models() -> None:
        table = Table(box=None)
        table.add_column("model"), table.add_column("endpoint")
        table.add_column("wire field"), table.add_column("")
        for model_id, adapter in fleet.items():
            # A debug view of a deliberately private detail: the resolved spelling
            # only exists after the first budgeted call -- watching it appear IS
            # the point of this probe.
            resolved = adapter._max_tokens_field or "[dim]resolves on first call[/dim]"
            table.add_row(model_id, adapter.base_url, resolved,
                          "[green]<- active[/green]" if model_id == active else "")
        console.print(Panel(table, title=f"fleet  (catalog={state['catalog']}, "
                                         f"effort={state['effort'] or 'unset'}, "
                                         f"budget={state['budget'] or 'none'})",
                            expand=False))

    show_models()
    console.print("[dim]Ask anything, or: use/models/info/catalog/effort/budget/"
                  "debug/quit[/dim]\n")

    while True:
        try:
            line = input(f"{active}> ").strip()
        except (EOFError, KeyboardInterrupt):
            break
        if not line:
            continue
        cmd, _, arg = line.partition(" ")
        arg = arg.strip()

        if cmd == "quit":
            break
        elif cmd == "use":
            if arg in fleet:
                active = arg
            else:
                console.print(f"[yellow]Not in the fleet: {arg} -- see 'models'[/yellow]")
        elif cmd == "models":
            show_models()
        elif cmd == "info":
            if arg:
                if catalog is None:
                    console.print("[yellow]catalog is off -- 'catalog models.dev' "
                                  "or 'catalog litellm' first[/yellow]")
                else:
                    _show_info(catalog.describe(arg),
                               f"{state['catalog']} knows about {arg!r}")
            else:
                _show_info(fleet[active].describe(),
                           f"describe() of {active!r} -- statement, then knowledge")
        elif cmd == "catalog":
            if arg not in ("models.dev", "litellm", "off"):
                console.print("[yellow]Usage: catalog models.dev|litellm|off[/yellow]")
                continue
            state["catalog"] = arg
            catalog = build_catalog()
            fleet = build_fleet()
            console.print(f"[dim]Fleet rebuilt -- knowledge source: {arg}. Wire "
                          f"fields resolve fresh on the next budgeted call.[/dim]")
        elif cmd == "effort":
            state["effort"] = None if arg in ("off", "") else arg
            fleet = build_fleet()
            console.print(f"[dim]Fleet rebuilt -- reasoning_effort="
                          f"{state['effort'] or 'unset'}. Values are per model; a "
                          f"rejection names the accepted set.[/dim]")
        elif cmd == "budget":
            try:
                state["budget"] = int(arg) or None
            except ValueError:
                console.print("[yellow]Usage: budget <tokens>  (0 = none)[/yellow]")
                continue
            console.print(f"[dim]budget={state['budget'] or 'none'}[/dim]")
        elif cmd == "debug":
            glass.debug = arg != "off"
            console.print(f"[dim]glass {'on' if glass.debug else 'off'}[/dim]")
        else:
            try:
                answer = fleet[active].complete(
                    line, max_completion_tokens=state["budget"])
            except ContextWindowExceeded as exc:
                console.print(f"[red]ContextWindowExceeded[/red] limit={exc.limit} "
                              f"requested={exc.requested}")
                continue
            except LLMError as exc:
                console.print(f"[red]{exc}[/red]")
                continue
            console.print(answer.text or "[dim](empty text)[/dim]")
            u = answer.usage
            console.print(
                f"[dim]{answer.model or active}  in={u.prompt} out={u.completion}"
                + (f" reasoning={u.reasoning}" if u.reasoning else "")
                + (" [red]TRUNCATED[/red]" if answer.truncated else "")
                + (f"  [reasoning text in meta: "
                   f"{len(answer.meta['reasoning_text'])} chars]"
                   if answer.meta.get("reasoning_text") else "") + "[/dim]\n")


if __name__ == "__main__":
    main()
