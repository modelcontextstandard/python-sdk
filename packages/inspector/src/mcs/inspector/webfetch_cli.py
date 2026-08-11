"""Webfetch CLI plugin for the MCS Inspector -- see exactly what a fetch does.

Two things make this plugin more than a thin wrapper:

**Reconfigure mid-session.** The interesting questions about ``fetch_page`` are
comparative -- same URL with and without the summarizer, another strategy, another
window. Restarting the inspector per configuration would bury the comparison, so the
driver sits behind a rebuildable delegate and extra commands swap it live:

    summarizer off        -> prompt parameter disappears from the tool (check `list`)
    summarizer on
    strategy map_reduce   -> auto | stuff | map_reduce | refine
    window 32768          -> the condensation model's context window
    answer 500            -> per-call answer cap (0 = none)
    raw on                -> expose format='raw'
    config                -> show the current configuration

**A glass summarizer.** The summarizer's LLM is wrapped in a logger, so every model
call it makes is printed as it happens -- which chunk, how many characters in, what the
backend measured coming back, and whether it truncated. This is where Ollama's silent
``num_ctx`` clipping becomes visible: the mismatch between sent size and reported
prompt tokens is printed on the very call that suffers it.
"""

from __future__ import annotations

import argparse
import os
import sys
from typing import Any

from rich.console import Console
from rich.panel import Panel

console = Console()


def add_parser(subparsers: argparse._SubParsersAction) -> None:
    p = subparsers.add_parser("webfetch", help="Inspect web page fetching (+ optional summarizer)")
    p.add_argument("--allow-raw", action="store_true",
                   help="Expose format='raw' (toggle later with 'raw on|off')")
    p.add_argument("--summarize-model", default=os.environ.get("MCS_SUMMARIZE_MODEL"),
                   help="Model id for page condensation (e.g. qwen3:4b). Enables the "
                        "prompt parameter; toggle later with 'summarizer on|off'.")
    p.add_argument("--summarize-url",
                   default=os.environ.get("MCS_SUMMARIZE_URL", "http://localhost:11434/v1"),
                   help="Chat-Completions endpoint for the condensation model "
                        "(default: local Ollama)")
    p.add_argument("--summarize-window", type=int, default=None,
                   help="Context window of the condensation model. CAUTION Ollama: "
                        "the effective window is num_ctx, not the model card.")
    p.add_argument("--strategy", default="auto",
                   choices=["auto", "stuff", "map_reduce", "refine"],
                   help="Condensation strategy (default: auto)")
    p.add_argument("--max-answer-tokens", type=int, default=None,
                   help="Answer cap per model call (default: none)")
    p.add_argument("--concurrency", type=int, default=1,
                   help="Fan-out for map calls (default: 1 = sequential)")


class _GlassLLM:
    """Wraps an LLMPort; prints every call the summarizer makes, as it happens.

    The prompt *kind* is recognised by the template markers the summarizer tests
    already pin (``one part of a larger document`` and friends) -- a debug view, so
    coupling to those phrases is acceptable and self-correcting: if a marker changes,
    the label degrades to ``stuff``, nothing breaks.
    """

    def __init__(self, inner: Any) -> None:
        self.inner = inner
        self.calls = 0

    def complete(self, prompt: str, *, system: str | None = None,
                 max_completion_tokens: int | None = None, **kwargs: Any):
        self.calls += 1
        n = self.calls
        if "one part of a larger document" in prompt:
            kind = "map"
        elif "Partial answers" in prompt:
            kind = "merge"
        elif "Current answer" in prompt:
            kind = "refine"
        else:
            kind = "stuff"
        console.print(f"  [dim]llm #{n:<3} {kind:<7} -> {len(prompt):>7,} chars[/dim]")
        try:
            r = self.inner.complete(prompt, system=system,
                                    max_completion_tokens=max_completion_tokens, **kwargs)
        except Exception as exc:
            console.print(f"  [yellow]llm #{n:<3} {type(exc).__name__}: {exc}[/yellow]")
            raise
        u = r.usage
        trunc = "  [red]TRUNCATED[/red]" if r.truncated else ""
        console.print(
            f"  [dim]llm #{n:<3} {'':<7} <- {u.prompt or '?':>7} in / "
            f"{u.completion or '?'} out{trunc}[/dim]"
        )
        return r


class _RebuildableDriver:
    """Delegates to the currently configured WebfetchToolDriver.

    Duck-types the two methods the inspector loop uses, so extra commands can swap
    the inner driver -- and with it the advertised tool surface -- mid-session.
    """

    def __init__(self, inner: Any) -> None:
        self.inner = inner

    def list_tools(self):
        return self.inner.list_tools()

    def execute_tool(self, tool_name: str, arguments: dict[str, Any]):
        return self.inner.execute_tool(tool_name, arguments)


def run(args: argparse.Namespace) -> None:
    try:
        from mcs.driver.webfetch import WebfetchToolDriver
    except ImportError:
        console.print(
            "[red]mcs-driver-webfetch is not installed.[/red]\n"
            "Install it with: [bold]pip install mcs-inspector\\[webfetch][/bold]"
        )
        sys.exit(1)

    cfg = {
        "summarize": bool(args.summarize_model),
        "model": args.summarize_model,
        "url": args.summarize_url,
        "window": args.summarize_window,
        "strategy": args.strategy,
        "answer": args.max_answer_tokens,
        "concurrency": args.concurrency,
        "allow_raw": args.allow_raw,
    }

    def build_driver() -> Any:
        summarizer = None
        if cfg["summarize"]:
            if not cfg["model"]:
                console.print("[red]No summarize model configured -- pass "
                              "--summarize-model or set $MCS_SUMMARIZE_MODEL.[/red]")
                cfg["summarize"] = False
            else:
                try:
                    from mcs.adapter.llm.completion import CompletionLLMAdapter
                    from mcs.types.summarizer import LLMSummarizer
                except ImportError:
                    console.print(
                        "[red]Summarizer packages missing.[/red] Install with: "
                        "[bold]pip install mcs-inspector\\[summarize][/bold]"
                    )
                    sys.exit(1)
                llm = _GlassLLM(CompletionLLMAdapter(
                    cfg["model"], base_url=cfg["url"],
                    api_key=os.environ.get("MCS_SUMMARIZE_KEY") or os.environ.get("OPENAI_API_KEY"),
                    max_completion_tokens_field=("max_completion_tokens"
                                                 if "api.openai.com" in (cfg["url"] or "")
                                                 else "max_tokens"),
                ))
                kw: dict[str, Any] = {
                    "strategy": cfg["strategy"],
                    "concurrency": cfg["concurrency"],
                }
                if cfg["window"]:
                    kw["context_window"] = cfg["window"]
                if cfg["answer"]:
                    kw["max_answer_tokens"] = cfg["answer"]
                summarizer = LLMSummarizer(llm, **kw)
        return WebfetchToolDriver(allow_raw=cfg["allow_raw"], summarizer=summarizer)

    def show_config(_arg: str = "") -> None:
        if cfg["summarize"]:
            summ = (f"[green]on[/green]  {cfg['model']} @ {cfg['url']}\n"
                    f"            strategy={cfg['strategy']}  "
                    f"window={cfg['window'] or 'assume 4096, learn'}  "
                    f"answer_cap={cfg['answer'] or 'none'}  "
                    f"concurrency={cfg['concurrency']}")
        else:
            summ = "[yellow]off[/yellow]  (prompt parameter not advertised)"
        console.print(Panel(
            f"Summarizer: {summ}\n"
            f"Raw HTML:   {'[green]allowed[/green]' if cfg['allow_raw'] else '[yellow]not offered[/yellow]'}",
            title="fetch_page configuration", expand=False,
        ))

    holder = _RebuildableDriver(build_driver())

    def rebuild() -> None:
        holder.inner = build_driver()
        show_config()
        console.print("[dim]Driver rebuilt -- 'list' shows the current tool surface.[/dim]")

    def cmd_summarizer(arg: str) -> None:
        if arg not in ("on", "off"):
            console.print("[yellow]Usage: summarizer on|off[/yellow]")
            return
        cfg["summarize"] = arg == "on"
        rebuild()

    def cmd_strategy(arg: str) -> None:
        if arg not in ("auto", "stuff", "map_reduce", "refine"):
            console.print("[yellow]Usage: strategy auto|stuff|map_reduce|refine[/yellow]")
            return
        cfg["strategy"] = arg
        rebuild()

    def cmd_window(arg: str) -> None:
        try:
            cfg["window"] = int(arg) or None
        except ValueError:
            console.print("[yellow]Usage: window <tokens>  (0 = assume and learn)[/yellow]")
            return
        rebuild()

    def cmd_answer(arg: str) -> None:
        try:
            cfg["answer"] = int(arg) or None
        except ValueError:
            console.print("[yellow]Usage: answer <tokens>  (0 = no cap)[/yellow]")
            return
        rebuild()

    def cmd_raw(arg: str) -> None:
        if arg not in ("on", "off"):
            console.print("[yellow]Usage: raw on|off[/yellow]")
            return
        cfg["allow_raw"] = arg == "on"
        rebuild()

    show_config()

    from mcs.inspector.core import run_inspector

    run_inspector(
        holder,  # type: ignore[arg-type]  -- duck-typed delegate, see _RebuildableDriver
        title="Webfetch Inspector",
        extra_commands={
            "summarizer": ("on|off", cmd_summarizer),
            "strategy": ("auto|stuff|map_reduce|refine", cmd_strategy),
            "window": ("<tokens>", cmd_window),
            "answer": ("<tokens>", cmd_answer),
            "raw": ("on|off", cmd_raw),
            "config": ("show configuration", show_config),
        },
    )
