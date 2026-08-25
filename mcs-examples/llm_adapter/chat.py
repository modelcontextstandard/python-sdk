"""One model, eyes open -- an interactive probe for the CompletionLLMAdapter.

Pick a model as ``provider/model`` (the prefix settles endpoint and key, nothing
else). Before the first question you see what ``describe()`` found -- the endpoint's
statement merged with the configured catalogue's knowledge -- and from that the
reasoning controls follow honestly, tri-state and all:

- ``supports_reasoning`` stated **False**: no effort switch is offered at all.
- Stated **True**: the switch appears, with the accepted values where models.dev
  names them (LiteLLM's JSON only says *that* a model reasons, never which levels).
- **Nothing stated**: the switch is offered as a try -- the backend is authoritative
  and its 400 names the accepted set.

Every answer is shown in two parts, independently: the reasoning (where the backend
exposes it -- ``meta["reasoning_text"]``, plus the measured token count) and the
content. A model that silently spends its whole budget thinking shows up as an empty
content panel with a red TRUNCATED -- which is the trap the adapter's ``truncated``
flag exists for.

``debug on`` prints every request and response on the injected transport -- THE way
to verify the wire: is the budget spelled ``max_completion_tokens``? Did the effort
travel? Which describe() inquiries ran? (Keys are masked.)

Not a conversation: one question, one answer, no history. The port is deliberately
that small; the client's loop owns conversations (see the other examples).

Usage (from the workspace venv -- ``uv run python ...`` or activate ``.venv`` first):
    python chat.py                              # asks for provider/model
    python chat.py --model openai/gpt-5.5
    python chat.py --model ollama/qwen3:4b --debug
    python chat.py --model openrouter/google/gemini-2.5-flash --catalog litellm

Inside the loop:
    <any text>            one complete() to the model
    effort <value|off>    reasoning_effort (offered per the tri-state above)
    budget <tokens>       max_completion_tokens per call -- caps thinking AND
                          content together (default: none, 0 = none)
    info                  show describe() again
    debug on|off          watch the wire
    quit

Keys (environment or .env): OPENAI_API_KEY, OPENROUTER_API_KEY; ollama needs none.
"""

from __future__ import annotations

import argparse
import json
import os

from dotenv import load_dotenv
from rich.console import Console
from rich.panel import Panel

from _view import show_info  # pyright: ignore[reportImplicitRelativeImport] -- a script, run from its directory

from mcs.adapter.http import HttpAdapter
from mcs.adapter.llm.completion import CompletionLLMAdapter
from mcs.adapter.llm.info import LiteLLMInfoProvider, ModelsDevInfoProvider
from mcs.types.llm import ContextWindowExceeded, LLMError

console = Console()

#: The prefix settles ENDPOINT and KEY -- client configuration, spelled out once.
#: It does not touch the wire dialect: that resolves from catalogue knowledge, and
#: ``debug on`` is how you watch it happen.
PROVIDERS = {
    "openai": ("https://api.openai.com/v1", "OPENAI_API_KEY"),
    "openrouter": ("https://openrouter.ai/api/v1", "OPENROUTER_API_KEY"),
    "ollama": ("http://localhost:11434/v1", None),
}


class GlassHttp(HttpAdapter):
    """An HttpAdapter that prints what travels when debug is on. Keys are masked."""

    def __init__(self, debug: bool) -> None:
        super().__init__(timeout=120)
        self.debug = debug

    def request(self, method, url, *, params=None, json_body=None, headers=None,
                timeout=None):
        if self.debug:
            console.print(f"[cyan]-> {method} {url}[/cyan]")
            if json_body is not None:
                console.print("   [cyan]"
                              f"{json.dumps(json_body, ensure_ascii=False)[:600]}[/cyan]")
        resp = super().request(method, url, params=params, json_body=json_body,
                               headers=headers, timeout=timeout)
        if self.debug:
            console.print(f"[cyan]<- {resp.status_code}  "
                          f"[dim]{len(resp.text or ''):,} chars[/dim][/cyan]")
        return resp


def resolve_spec(spec: str, catalog) -> tuple[str, str, str | None] | None:
    """A model spec -> (model id, base url, api key) -- or None, and ask again.

    An explicit ``provider/model`` with a known endpoint prefix is taken as is.
    Anything else goes through the CATALOGUE first: for each addressable endpoint
    the tree walk is asked whether that namespace carries the id
    (``moonshotai/kimi-k3`` -> openrouter carries it -> resolved, with a note).
    Only when no addressable endpoint carries it does the hint appear -- naming
    where the catalogue *does* know the id, so a typo and a
    not-connected-here provider read differently -- and the caller re-asks.
    """
    spec = spec.strip()
    prefix, _, rest = spec.partition("/")
    if prefix in PROVIDERS and rest:
        url, key_env = PROVIDERS[prefix]
        return rest, url, (os.environ.get(key_env) if key_env else None)

    # No endpoint prefix: let knowledge pick the endpoint. Ollama stays explicit
    # -- a local server's models are unknown to any catalogue.
    for endpoint in ("openai", "openrouter"):
        if catalog.describe(f"{endpoint}/{spec}") is not None:
            console.print(f"[dim]{spec!r} resolved to {endpoint}/{spec}[/dim]")
            url, key_env = PROVIDERS[endpoint]
            return spec, url, (os.environ.get(key_env) if key_env else None)

    known = catalog.describe(spec)
    carried = ", ".join(((known.meta.get("models_dev") or {}).get("providers") or [])
                        if known else [])
    console.print(
        f"[yellow]The catalogue knows {spec!r} at: {carried} -- none of these is "
        f"an addressable endpoint here.[/yellow]" if carried else
        f"[yellow]Nothing resolves {spec!r} to an addressable endpoint.[/yellow]")
    console.print(f"[yellow]Pick provider/model with one of {', '.join(PROVIDERS)} "
                  f"-- e.g. openrouter/moonshotai/kimi-k3, ollama/qwen3:4b.[/yellow]")
    return None


def main() -> None:
    load_dotenv()
    p = argparse.ArgumentParser(description=(__doc__ or "").split("\n", 1)[0])
    p.add_argument("--model", metavar="PROVIDER/MODEL",
                   help=f"e.g. openai/gpt-5.5 (providers: {', '.join(PROVIDERS)}); "
                        "asked interactively when omitted")
    p.add_argument("--catalog", default="models.dev",
                   choices=["models.dev", "litellm"],
                   help="knowledge source injected into the adapter (default: "
                        "models.dev -- the only one that names effort values)")
    p.add_argument("--effort", default=None, help="initial reasoning_effort")
    p.add_argument("--budget", type=int, default=0,
                   help="max_completion_tokens per call. Caps thinking AND content "
                        "together -- spec semantics, there is no content-only cap. "
                        "Default: none (the model runs free); set one to watch the "
                        "wire-field resolution and the TRUNCATED trap.")
    p.add_argument("--debug", action="store_true", help="start with the wire visible")
    args = p.parse_args()

    glass = GlassHttp(args.debug)
    catalog = (ModelsDevInfoProvider(_http=glass) if args.catalog == "models.dev"
               else LiteLLMInfoProvider(_http=glass))

    resolved = None
    while resolved is None:
        spec = args.model or input("model (provider/model)> ")
        resolved = resolve_spec(spec, catalog)
        args.model = None                      # a bad flag falls back to asking
    model_id, base_url, api_key = resolved
    # The full address for display: endpoint provider + backend model id. The
    # backend only ever sees model_id; the provider half is client addressing.
    provider_name = next((name for name, (url, _) in PROVIDERS.items()
                          if url == base_url), None)
    display = f"{provider_name}/{model_id}" if provider_name else model_id
    # Answer "did the key load?" before the first 401 can even ask it. Never the
    # key itself -- loaded-and-still-401 means the PROVIDER rejects the key.
    key_env = PROVIDERS[provider_name][1] if provider_name else None
    console.print(f"[dim]endpoint={base_url}  "
                  + (f"key=${key_env} "
                     + ("loaded" if api_key else "[red]NOT SET in env/.env[/red]")
                     if key_env else "key: none needed") + "[/dim]")

    state = {"effort": args.effort, "budget": args.budget or None}

    def build() -> CompletionLLMAdapter:
        return CompletionLLMAdapter(model_id, base_url=base_url, api_key=api_key,
                                    model_info=catalog,
                                    reasoning_effort=state["effort"], _http=glass)

    llm = build()

    # -- what is known, before anything is asked --------------------------------
    # The merge order behind the panel: the ENDPOINT's own statement about this
    # deployment first, the catalogue's knowledge only where fields stayed unknown.
    # "meta sources" in the table names who actually contributed this time.
    stated = llm.describe()
    show_info(console, stated, f"describe() of {display!r}")

    reasoning = stated.supports_reasoning if stated else None
    effort_values: list[str] | None = None
    for option in ((stated.meta.get("models_dev") or {}) if stated else {}).get(
            "reasoning_options") or []:
        if option.get("type") == "effort":
            effort_values = option.get("values")

    if reasoning is False:
        console.print("[dim]Stated as non-reasoning -- no effort switch offered.[/dim]")
    elif reasoning:
        console.print(f"[dim]Reasoning model -- 'effort <value>' with values "
                      f"{', '.join(effort_values) if effort_values else 'unknown here (catalogue names none; the backend does, in its 400)'}."
                      + (f"  Currently: {state['effort']}." if state["effort"] else "")
                      + "[/dim]")
    else:
        console.print("[dim]Reasoning not stated -- 'effort <value>' is offered as "
                      "a try; the backend's 400 names its accepted set.[/dim]")
    console.print("[dim]Ask anything. Commands: effort/budget/info/debug/quit[/dim]\n")

    while True:
        try:
            line = input(f"{model_id}> ").strip()
        except (EOFError, KeyboardInterrupt):
            break
        if not line:
            continue
        cmd, _, arg = line.partition(" ")
        arg = arg.strip()

        if cmd == "quit":
            break
        elif cmd == "info":
            show_info(console, llm.describe(), f"describe() of {display!r}")
        elif cmd == "debug":
            glass.debug = arg != "off"
        elif cmd == "budget":
            try:
                state["budget"] = int(arg) or None
                console.print(f"[dim]budget={state['budget'] or 'none'}[/dim]")
            except ValueError:
                console.print("[yellow]Usage: budget <tokens>  (0 = none)[/yellow]")
        elif cmd == "effort":
            if reasoning is False:
                console.print("[yellow]This model is stated as non-reasoning -- "
                              "the switch stays off the menu.[/yellow]")
                continue
            if effort_values and arg not in effort_values and arg != "off":
                console.print(f"[yellow]models.dev names {', '.join(effort_values)} "
                              f"for this model -- sending {arg!r} anyway would 400. "
                              f"Pick one of those, or 'effort off'.[/yellow]")
                continue
            state["effort"] = None if arg in ("off", "") else arg
            llm = build()
            console.print(f"[dim]reasoning_effort={state['effort'] or 'unset'}[/dim]")
        else:
            try:
                answer = llm.complete(line, max_completion_tokens=state["budget"])
            except ContextWindowExceeded as exc:
                console.print(f"[red]ContextWindowExceeded[/red] limit={exc.limit} "
                              f"requested={exc.requested}")
                continue
            except LLMError as exc:
                console.print(f"[red]{exc}[/red]")
                continue

            # Reasoning and content, independently -- the whole point.
            u = answer.usage
            thinking = answer.meta.get("reasoning_text")
            if thinking:
                console.print(Panel(f"[dim]{thinking}[/dim]",
                                    title=f"reasoning ({u.reasoning or '?'} tokens)",
                                    border_style="dim", expand=False))
            elif u.reasoning:
                console.print(f"[dim]({u.reasoning} reasoning tokens spent -- text "
                              f"not exposed by this backend)[/dim]")
            console.print(Panel(answer.text or "[red](empty -- see TRUNCATED)[/red]",
                                title="content", expand=False))
            console.print(
                f"[dim]{answer.model or model_id}  in={u.prompt} out={u.completion}"
                + (" [red]TRUNCATED[/red]" if answer.truncated else "") + "[/dim]\n")


if __name__ == "__main__":
    main()
