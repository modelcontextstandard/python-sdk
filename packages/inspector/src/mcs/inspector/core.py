"""Generic MCS Inspector -- works with any MCSToolDriver.

Provides an interactive CLI for tool discovery, inspection, and execution.
Driver-specific CLI wrappers build the driver and pass it here.
"""

from __future__ import annotations

import json
from dataclasses import dataclass
from typing import Any, Callable

from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from rich import print_json

from mcs.driver.core import MCSToolDriver, Tool

console = Console()


@dataclass
class ExtraColumn:
    """Driver-specific column for the overview table."""
    header: str
    width: int | None = None
    justify: str = "center"
    style: str = ""
    value_fn: Callable[[Tool, Any], str] = lambda tool, info: ""


def _build_overview_table(
    td: MCSToolDriver,
    *,
    title: str,
    extra_columns: list[ExtraColumn] | None = None,
    driver_info: dict[str, Any] | None = None,
) -> Table:
    tools = td.list_tools()
    table = Table(
        title=f"[bold]{title} ({len(tools)} tools)[/bold]",
        show_lines=True,
        expand=True,
    )
    table.add_column("#", style="dim", width=4, justify="right")
    table.add_column("Tool name", style="bold cyan", no_wrap=True)
    table.add_column("Title", ratio=1)
    table.add_column("Params", width=6, justify="right")

    for col in (extra_columns or []):
        table.add_column(col.header, width=col.width, justify=col.justify, style=col.style)

    for idx, tool in enumerate(tools, 1):
        title_text = tool.title or ""
        if len(title_text) > 60:
            title_text = title_text[:57] + "..."

        row = [str(idx), tool.name, title_text, str(len(tool.parameters))]

        for col in (extra_columns or []):
            info = (driver_info or {}).get(tool.name, {})
            row.append(col.value_fn(tool, info))

        table.add_row(*row)

    return table


def _show_tool_detail(td: MCSToolDriver, tool_name: str) -> None:
    tools = {t.name: t for t in td.list_tools()}
    tool = tools.get(tool_name)
    if tool is None:
        console.print(f"[red]Tool '{tool_name}' not found.[/red]")
        return

    header = f"[bold cyan]{tool.name}[/bold cyan]"
    console.print(Panel(header, expand=False))

    if tool.title:
        console.print(f"\n[bold]{tool.title}[/bold]")
    if tool.description and tool.description != tool.title:
        console.print(f"\n{tool.description}")
    console.print()

    if not tool.parameters:
        console.print("[dim]No parameters.[/dim]")
        return

    ptable = Table(title="Parameters", show_lines=True, expand=True)
    ptable.add_column("Name", style="bold")
    ptable.add_column("Required", width=9, justify="center")
    ptable.add_column("Type / Schema", ratio=1)
    ptable.add_column("Description", ratio=2)

    for param in tool.parameters:
        req = "[green]yes[/green]" if param.required else "[dim]no[/dim]"
        schema = param.schema or {}
        type_str = schema.get("type", "")
        if "enum" in schema:
            type_str += f" enum{schema['enum']}"
        if "format" in schema:
            type_str += f" ({schema['format']})"
        if "default" in schema:
            type_str += f" [dim]default={schema['default']}[/dim]"
        ptable.add_row(param.name, req, type_str, param.description)

    console.print(ptable)


def _read_multiline() -> str:
    """Read multiline input until the user enters a single '.' on a line."""
    lines: list[str] = []
    while True:
        try:
            line = console.input("  [dim]...[/dim] ")
        except (EOFError, KeyboardInterrupt):
            break
        if line.strip() == ".":
            break
        lines.append(line)
    return "\n".join(lines)


def _prompt_arguments(tool: Tool) -> dict[str, Any]:
    """Interactively prompt for tool arguments."""
    if not tool.parameters:
        return {}

    console.print("\n[bold]Enter arguments[/bold] (empty = skip optional / use default):\n")
    args: dict[str, Any] = {}

    for param in tool.parameters:
        schema = param.schema or {}
        default = schema.get("default")
        ptype = schema.get("type", "string")
        fmt = schema.get("format", "")
        is_multiline = fmt == "multiline"
        req_marker = "[green]*[/green]" if param.required else " "

        hint_parts: list[str] = []
        if ptype:
            hint_parts.append(ptype)
        if default is not None:
            hint_parts.append(f"default={default}")
        hint = f" [dim]({', '.join(hint_parts)})[/dim]" if hint_parts else ""

        if is_multiline:
            console.print(f"  {req_marker} {param.name}{hint}: [dim](multiline -- end with '.' on its own line)[/dim]")
            raw = _read_multiline()
        else:
            raw = console.input(f"  {req_marker} {param.name}{hint}: ").strip()

        if not raw:
            if param.required and default is None:
                console.print(f"    [yellow]Required -- using empty string[/yellow]")
                args[param.name] = ""
            elif default is not None:
                args[param.name] = default
            continue

        if ptype == "integer":
            try:
                args[param.name] = int(raw)
            except ValueError:
                args[param.name] = raw
        elif ptype == "boolean":
            args[param.name] = raw.lower() in ("true", "1", "yes", "y")
        elif ptype == "number":
            try:
                args[param.name] = float(raw)
            except ValueError:
                args[param.name] = raw
        else:
            args[param.name] = raw

    return args


def _execute_tool(td: MCSToolDriver, tool_name: str) -> None:
    tools = {t.name: t for t in td.list_tools()}
    tool = tools.get(tool_name)
    if tool is None:
        console.print(f"[red]Tool '{tool_name}' not found.[/red]")
        return

    _show_tool_detail(td, tool_name)

    args = _prompt_arguments(tool)
    console.print(f"\n[dim]Executing {tool_name}({json.dumps(args)})...[/dim]\n")

    try:
        result = td.execute_tool(tool_name, args)
    except Exception as exc:
        console.print(f"[red bold]Error:[/red bold] {exc}")
        return

    if isinstance(result, str):
        try:
            json.loads(result)
            print_json(result)
        except (json.JSONDecodeError, ValueError):
            console.print(result)
    else:
        print_json(json.dumps(result, default=str, ensure_ascii=False))


def run_inspector(
    td: MCSToolDriver,
    *,
    title: str = "MCS Inspector",
    extra_columns: list[ExtraColumn] | None = None,
    driver_info: dict[str, Any] | None = None,
) -> None:
    """Run the interactive inspector loop for any MCSToolDriver.

    Parameters
    ----------
    td :
        The tool driver to inspect.
    title :
        Display title for the overview table.
    extra_columns :
        Driver-specific columns for the overview table.
    driver_info :
        Per-tool metadata dict keyed by tool name, passed to
        ``ExtraColumn.value_fn``.
    """
    tools = td.list_tools()
    if not tools:
        console.print("[yellow]No tools discovered. Check driver configuration.[/yellow]")
        return

    console.print()
    console.print(_build_overview_table(
        td, title=title, extra_columns=extra_columns, driver_info=driver_info,
    ))
    console.print(
        "\n[dim]Commands:  <number|name> = detail   "
        "run <number|name> = execute   "
        "list = show table   "
        "quit = exit[/dim]\n"
    )

    tool_names = [t.name for t in tools]

    while True:
        try:
            raw = console.input("[bold green]inspect>[/bold green] ").strip()
        except (EOFError, KeyboardInterrupt):
            break

        if not raw or raw.lower() in ("quit", "exit", "q"):
            break

        if raw.lower() in ("list", "ls", "l"):
            console.print(_build_overview_table(
                td, title=title, extra_columns=extra_columns, driver_info=driver_info,
            ))
            continue

        is_run = raw.lower().startswith("run ")
        choice = raw[4:].strip() if is_run else raw
        handler = _execute_tool if is_run else _show_tool_detail

        resolved: str | None = None

        if choice.isdigit():
            idx = int(choice) - 1
            if 0 <= idx < len(tool_names):
                resolved = tool_names[idx]
            else:
                console.print(f"[red]Invalid index. Enter 1-{len(tool_names)}.[/red]")
        elif choice in tool_names:
            resolved = choice
        else:
            matches = [n for n in tool_names if choice.lower() in n.lower()]
            if len(matches) == 1:
                resolved = matches[0]
            elif matches:
                console.print(f"[yellow]Multiple matches: {', '.join(matches)}[/yellow]")
            else:
                console.print(f"[red]No tool matching '{choice}'.[/red]")

        if resolved:
            handler(td, resolved)

    console.print("\n[dim]Inspector closed.[/dim]")
