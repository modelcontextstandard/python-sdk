"""One question, several models, ONE summarizer -- the prompt chain, end to end.

What this example proves, visibly: **prompts follow the model at call time.** There is
a single ``LLMSummarizer`` here. It is never reconfigured. In front of it sits a
router port that switches between the models you configured -- the "agent changes
models mid-operation" case -- and for every input, the same question runs once per
model. The answers carry per-model markers from ``prompts.toml``:

    [qwen-Variante] Die Kuendigungsfrist betraegt drei Monate.   <- qwen3:4b
    [gpt-tuned] The notice period is three months.               <- gpt-5.6

If the marker matches the model, the whole chain worked for exactly that run:

    LLMPort.model  ->  PromptBundle.resolve(model)  ->  variant template  ->  answer

Nobody passed a model id to the summarizer. It asked its port -- the one party that
knows -- per run. That is the design under test.

Usage:
    python main.py                                  # qwen3:4b via local Ollama
    python main.py --model qwen3:4b --model gpt-5.6@https://api.openai.com/v1
    python main.py --file ./contract.txt            # your own document

Configuration (environment or .env):
    MCS_SUMMARIZE_KEY   API key for cloud endpoints; falls back to OPENAI_API_KEY.
                        Local servers need none.

Requires:
    pip install mcs-types-summarizer mcs-adapter-llm rich python-dotenv
"""

from __future__ import annotations

import argparse
import os
from pathlib import Path
from typing import Any

from dotenv import load_dotenv
from rich.console import Console
from rich.panel import Panel

from mcs.adapter.llm.completion import CompletionLLMAdapter
from mcs.adapter.llm.info import ModelsDevInfoProvider
from mcs.prompts import load_prompts
from mcs.types.summarizer import LLMSummarizer

console = Console()

PROMPTS = Path(__file__).with_name("prompts.toml")

#: A small document with one buried fact -- enough to ask real questions against.
DOCUMENT = "\n\n".join(
    [f"Abschnitt {i}: Der Bericht beschreibt allgemeine organisatorische Ablaeufe "
     f"und nennt keine konkreten Fristen oder Zahlen." for i in range(4)]
    + ["Abschnitt 4: Die Kuendigungsfrist des Vertrags betraegt genau drei Monate."]
    + [f"Abschnitt {i}: Der Bericht verweist auf interne Prozesse ohne besondere "
       f"Bedeutung fuer Fristen." for i in range(5, 9)]
)


class RouterLLM:
    """The "agent switches models mid-operation" pattern, minimal.

    One ``LLMPort`` over several adapters. ``model`` names whatever is *currently*
    selected -- which is all a consumer needs: anything that resolves per run (the
    summarizer's prompt variants) follows a switch without being reconfigured. This
    class is deliberately example-grade; a real router would add fallback and health
    logic, but the port surface would be exactly this.
    """

    def __init__(self, adapters: dict[str, CompletionLLMAdapter]) -> None:
        self._adapters = adapters
        self._current = next(iter(adapters))

    def switch(self, name: str) -> None:
        self._current = name

    @property
    def model(self) -> str | None:
        """LLMPort.model: the id currently behind this port."""
        return self._adapters[self._current].model

    def describe(self):
        """LLMPort.describe: whatever the CURRENT backend states."""
        return self._adapters[self._current].describe()

    def complete(self, prompt: str, *, system: str | None = None,
                 max_completion_tokens: int | None = None, **kwargs: Any):
        return self._adapters[self._current].complete(
            prompt, system=system, max_completion_tokens=max_completion_tokens, **kwargs)


def _parse_model(spec: str) -> tuple[str, str]:
    """``id[@base_url]`` -> (id, base_url); default is the local Ollama."""
    if "@" in spec:
        model_id, url = spec.split("@", 1)
        return model_id, url
    return spec, "http://localhost:11434/v1"


def main() -> None:
    load_dotenv()
    p = argparse.ArgumentParser(
        description="Run one question through one summarizer over several models -- "
                    "and watch the prompt variants follow the model.")
    p.add_argument("--model", action="append", default=None, metavar="ID[@URL]",
                   help="Model to include; repeat for several. Default URL is the "
                        "local Ollama. Example: gpt-5.6@https://api.openai.com/v1")
    p.add_argument("--file", type=Path, default=None,
                   help="Text file to question (default: a built-in document with a "
                        "buried fact)")
    p.add_argument("--effort", default=None,
                   help="reasoning_effort for ALL models. 'none' is the right call "
                        "here: condensation needs extraction, not deliberation -- "
                        "and a 4B thinker that reasons for 3,000 tokens drops "
                        "verbatim instructions on the way. Ollama's /v1 maps this "
                        "onto qwen3's thinking switch; GPT-5 accepts "
                        "none/low/medium/high/xhigh.")
    p.add_argument("--window", type=int, default=None,
                   help="Context window passed to the summarizer (applies to all "
                        "models; default: assume 4096 and learn)")
    args = p.parse_args()

    specs = [_parse_model(s) for s in (args.model or ["qwen3:4b"])]
    # ONE catalogue for every adapter: the provider caches its document, so sharing
    # the instance means one fetch -- and it settles the wire spelling of the answer
    # budget per model (knowledge, not a URL heuristic).
    catalog = ModelsDevInfoProvider()
    adapters = {
        model_id: CompletionLLMAdapter(
            model_id, base_url=url,
            api_key=os.environ.get("MCS_SUMMARIZE_KEY") or os.environ.get("OPENAI_API_KEY"),
            model_info=catalog,
            reasoning_effort=args.effort or None,
        )
        for model_id, url in specs
    }

    # ONE summarizer for every model -- that is the point. The prompts.toml next to
    # this file carries loud per-model variants; the shipped defaults cover the rest.
    router = RouterLLM(adapters)
    summarizer = LLMSummarizer(router, prompts=PROMPTS, context_window=args.window)

    text = args.file.read_text(encoding="utf-8") if args.file else DOCUMENT

    # The deterministic half of the proof: the example resolves the SAME bundle the
    # summarizer uses and reports, per answer, whether a variant or the base applied.
    # Model output (language, marker) is corroboration -- small thinking models drop
    # verbatim markers, and the harness must not depend on a model's obedience.
    bundle = load_prompts("mcs.types.summarizer", override=PROMPTS)
    base = bundle.resolve(None)

    def variant_state(model_id: str | None) -> str:
        active = bundle.resolve(model_id)
        changed = [name for name in active if active.get(name) != base.get(name)]
        return f"variant({', '.join(changed)})" if changed else "base prompts"

    console.print(Panel(
        "[bold cyan]Prompt variants, end to end[/bold cyan]\n\n"
        f"Models:   {', '.join(adapters)}\n"
        f"Prompts:  {PROMPTS.name} (markers per model -- see the file)\n"
        f"Document: {args.file or 'built-in (fact: Kuendigungsfrist, Abschnitt 4)'}\n\n"
        "[dim]One summarizer, switched per run. If an answer starts with the marker "
        "of its model, the chain LLMPort.model -> resolve -> template held.\n"
        "Empty input or 'exit' to quit.[/dim]",
        expand=False,
    ))

    while True:
        try:
            query = console.input("\n[bold green]Frage:[/bold green] ").strip()
        except (EOFError, KeyboardInterrupt):
            break
        if not query or query.lower() in ("exit", "quit", "q"):
            break

        for name in adapters:
            router.switch(name)                      # the agent changes its model...
            try:
                s = summarizer.summarize(text, query)  # ...the summarizer just runs
            except Exception as exc:
                console.print(Panel(f"[red]{type(exc).__name__}: {exc}[/red]",
                                    title=name, border_style="red"))
                continue
            meta = (f"prompts={variant_state(router.model)}  "
                    f"strategy={s.strategy}  chunks={s.chunks}  "
                    f"truncated={s.truncated}  "
                    f"tokens={s.usage.input or '?'}/{s.usage.output or '?'}")
            console.print(Panel(f"{s.text}\n\n[dim]{meta}[/dim]",
                                title=f"[bold]{name}[/bold]", border_style="cyan"))

    console.print("\n[dim]Ende.[/dim]")


if __name__ == "__main__":
    main()
