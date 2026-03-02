"""MCS REST Inspector -- interactive tool discovery for OpenAPI specs.

Point at any OpenAPI specification and explore which tools the
``RestToolDriver`` discovers.  Supports tag and path filtering.

Run directly::

    python -m mcs.driver.rest.inspector https://reqres.in/openapi.json
    python -m mcs.driver.rest.inspector URL --include-tags repos search

Or from the workspace root::

    python -m mcs.driver.rest.inspector \\
        https://raw.githubusercontent.com/github/rest-api-description/\\
        main/descriptions/api.github.com/api.github.com.json \\
        --include-tags repos search
"""

from __future__ import annotations

import argparse
import sys

from rich.console import Console
from rich.panel import Panel
from rich.table import Table

from mcs.driver.rest.tooldriver import RestToolDriver

console = Console()


def _parse_args() -> argparse.Namespace:
    p = argparse.ArgumentParser(
        prog="mcs-rest-inspector",
        description="Inspect tools discovered from an OpenAPI spec.",
    )
    p.add_argument("url", help="OpenAPI specification URL")
    p.add_argument(
        "--include-tags", nargs="*", default=None,
        help="Only include operations whose tags match (case-insensitive)",
    )
    p.add_argument(
        "--include-paths", nargs="*", default=None,
        help="Only include these exact path strings",
    )
    return p.parse_args()


def _build_overview_table(td: RestToolDriver) -> Table:
    tools = td.list_tools()
    table = Table(
        title=f"[bold]Discovered tools ({len(tools)})[/bold]",
        show_lines=True,
        expand=True,
    )
    table.add_column("#", style="dim", width=4, justify="right")
    table.add_column("Tool name", style="bold cyan", no_wrap=True)
    table.add_column("Method", width=7, justify="center")
    table.add_column("Path", style="dim")
    table.add_column("Params", width=6, justify="right")
    table.add_column("Description", ratio=2)

    for idx, tool in enumerate(tools, 1):
        info = td._tool_map.get(tool.name, {})
        method = info.get("method", "?")
        path = info.get("path", "?")
        desc = tool.description
        if len(desc) > 80:
            desc = desc[:77] + "..."
        method_style = {
            "GET": "green", "POST": "yellow",
            "PUT": "blue", "PATCH": "magenta", "DELETE": "red",
        }.get(method, "white")
        table.add_row(
            str(idx),
            tool.name,
            f"[{method_style}]{method}[/{method_style}]",
            path,
            str(len(tool.parameters)),
            desc,
        )
    return table


def _show_tool_detail(td: RestToolDriver, tool_name: str) -> None:
    tools = {t.name: t for t in td.list_tools()}
    tool = tools.get(tool_name)
    if tool is None:
        console.print(f"[red]Tool '{tool_name}' not found.[/red]")
        return

    info = td._tool_map.get(tool_name, {})
    method = info.get("method", "?")
    path = info.get("path", "?")

    header = f"[bold cyan]{tool.name}[/bold cyan]  [dim]{method} {path}[/dim]"
    console.print(Panel(header, expand=False))
    console.print(f"\n{tool.description}\n")

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
        ptable.add_row(param.name, req, type_str, param.description)

    console.print(ptable)


def _interactive_loop(td: RestToolDriver) -> None:
    tools = td.list_tools()
    if not tools:
        console.print("[yellow]No tools discovered. Check URL and filters.[/yellow]")
        return

    console.print(_build_overview_table(td))
    console.print(
        "\n[dim]Enter a tool number or name for details. "
        "'list' to show table again. 'quit' to exit.[/dim]\n"
    )

    tool_names = [t.name for t in tools]

    while True:
        try:
            choice = console.input("[bold green]inspect>[/bold green] ").strip()
        except (EOFError, KeyboardInterrupt):
            break
        if not choice or choice.lower() in ("quit", "exit", "q"):
            break
        if choice.lower() in ("list", "ls", "l"):
            console.print(_build_overview_table(td))
            continue

        if choice.isdigit():
            idx = int(choice) - 1
            if 0 <= idx < len(tool_names):
                _show_tool_detail(td, tool_names[idx])
            else:
                console.print(f"[red]Invalid index. Enter 1-{len(tool_names)}.[/red]")
        elif choice in tool_names:
            _show_tool_detail(td, choice)
        else:
            matches = [n for n in tool_names if choice.lower() in n.lower()]
            if len(matches) == 1:
                _show_tool_detail(td, matches[0])
            elif matches:
                console.print(f"[yellow]Multiple matches: {', '.join(matches)}[/yellow]")
            else:
                console.print(f"[red]No tool matching '{choice}'.[/red]")


def main() -> None:
    args = _parse_args()

    console.print(f"\n[dim]Fetching spec from {args.url} ...[/dim]")

    td = RestToolDriver(
        args.url,
        include_tags=args.include_tags,
        include_paths=args.include_paths,
    )

    tools = td.list_tools()
    console.print(f"[dim]Parsed {len(tools)} tools (base: {td._base_url})[/dim]\n")

    _interactive_loop(td)
    console.print("\n[dim]Inspector closed.[/dim]")


if __name__ == "__main__":
    main()
