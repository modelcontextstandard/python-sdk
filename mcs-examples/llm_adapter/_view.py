"""Shared rendering: one ModelInfo, honestly -- silence shown as silence."""

from __future__ import annotations

from dataclasses import fields as dataclass_fields

from rich.console import Console
from rich.panel import Panel
from rich.table import Table

from mcs.types.llm import ModelInfo


def show_info(console: Console, info: ModelInfo | None, title: str) -> None:
    if info is None:
        console.print(Panel("[yellow]None[/yellow] -- no entry, no statement. That is "
                            "an answer too: plan conservatively.", title=title))
        return
    table = Table(show_header=False, box=None, pad_edge=False)
    for f in dataclass_fields(info):
        if f.name == "meta":
            continue
        value = getattr(info, f.name)
        rendered = ("[dim]None (not stated)[/dim]" if value is None
                    else f"{value:,}" if isinstance(value, int)
                    and not isinstance(value, bool) else str(value))
        table.add_row(f.name, rendered)
    table.add_row("meta sources", ", ".join(info.meta) or "[dim]-[/dim]")

    md = info.meta.get("models_dev") or {}
    if md.get("providers"):
        served = md["providers"]
        table.add_row("  served by", (", ".join(served) if len(served) <= 4 else
                                      f"{len(served)} providers ({', '.join(served[:4])}, ...)"))
    for option in md.get("reasoning_options") or []:
        if option.get("type") == "effort":
            table.add_row("  effort values", ", ".join(option.get("values", [])))

    lite = info.meta.get("litellm") or {}
    if "input_cost_per_token" in lite:
        table.add_row("  price in/out",
                      f"${lite['input_cost_per_token'] * 1e6:.2f} / "
                      f"${lite.get('output_cost_per_token', 0) * 1e6:.2f} per 1M")
    console.print(Panel(table, title=title, expand=False))
