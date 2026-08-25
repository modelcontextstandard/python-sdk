"""Ask the model catalogues -- what does each knowledge source say about an id?

Both :class:`~mcs.types.llm.ModelInfoProvider` implementations are constructed up
front; each fetches its document lazily on the first question and answers from
memory after that. Switch the active one and compare: models.dev is the deliberate
schema (limits, modalities, ``temperature: false``, the accepted reasoning-effort
values), LiteLLM's JSON is the price-rich one (``supports_reasoning`` is all it says
about reasoning -- no value list, which is why the chat probe next door takes its
effort switches from models.dev).

Usage (from the workspace venv -- ``uv run python ...`` or activate ``.venv`` first):
    python catalog.py                     # start on models.dev
    python catalog.py --catalog litellm --debug

Inside the loop:
    <model-id>                ask the active catalogue (gpt-5.5, llama3, ...)
    use models.dev|litellm    switch the active catalogue
    quit
"""

from __future__ import annotations

import argparse

from dotenv import load_dotenv
from rich.console import Console

from _view import show_info  # pyright: ignore[reportImplicitRelativeImport] -- a script, run from its directory

from mcs.adapter.http import HttpAdapter
from mcs.adapter.llm.info import LiteLLMInfoProvider, ModelsDevInfoProvider

console = Console()


class GlassHttp(HttpAdapter):
    """An HttpAdapter that shows the catalogue fetches -- one per source, ever."""

    def __init__(self, debug: bool) -> None:
        super().__init__(timeout=120)
        self.debug = debug

    def request(self, method, url, *, params=None, json_body=None, headers=None,
                timeout=None):
        if self.debug:
            console.print(f"[cyan]-> {method} {url}[/cyan]")
        resp = super().request(method, url, params=params, json_body=json_body,
                               headers=headers, timeout=timeout)
        if self.debug:
            console.print(f"[cyan]<- {resp.status_code}  "
                          f"[dim]{len(resp.text or ''):,} chars[/dim][/cyan]")
        return resp


def main() -> None:
    load_dotenv()
    p = argparse.ArgumentParser(description=(__doc__ or "").split("\n", 1)[0])
    p.add_argument("--catalog", default="models.dev",
                   choices=["models.dev", "litellm"], help="starting catalogue")
    p.add_argument("--debug", action="store_true",
                   help="show the (lazy, one-time) catalogue fetches")
    args = p.parse_args()

    glass = GlassHttp(args.debug)
    catalogues = {
        "models.dev": ModelsDevInfoProvider(_http=glass),
        "litellm": LiteLLMInfoProvider(_http=glass),
    }
    active = args.catalog

    console.print(f"[dim]Active: {active}. Type a model id, "
                  f"'use models.dev|litellm', or 'quit'.[/dim]\n")
    while True:
        try:
            line = input(f"{active}> ").strip()
        except (EOFError, KeyboardInterrupt):
            break
        if not line:
            continue
        cmd, _, arg = line.partition(" ")
        if cmd == "quit":
            break
        elif cmd == "use":
            if arg.strip() in catalogues:
                active = arg.strip()
            else:
                console.print("[yellow]Usage: use models.dev|litellm[/yellow]")
        else:
            info = catalogues[active].describe(line)
            # Name the entry that actually answered: LiteLLM's suffix search may
            # have taken a prefixed key, models.dev a namespace -- the asked id and
            # the taken entry are different facts.
            resolved = None
            if info is not None:
                lite = info.meta.get("litellm") or {}
                md = info.meta.get("models_dev") or {}
                resolved = (lite.get("resolved_id")
                            or (f"{md['provider']}/{md['id']}"
                                if md.get("provider") and md.get("id") else None))
            show_info(console, info,
                      f"{active} on {line!r}"
                      + (f" -> {resolved}" if resolved and resolved != line else ""))


if __name__ == "__main__":
    main()
