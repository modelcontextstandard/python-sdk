"""REST/OpenAPI CLI plugin for the MCS Inspector."""

from __future__ import annotations

import argparse
import sys

from rich.console import Console

console = Console()


def add_parser(subparsers: argparse._SubParsersAction) -> None:
    p = subparsers.add_parser("rest", help="Inspect a REST API via OpenAPI spec")
    p.add_argument("url", help="OpenAPI specification URL")
    p.add_argument(
        "--include-tags", nargs="*", default=None,
        help="Only include operations whose tags match (case-insensitive)",
    )
    p.add_argument(
        "--include-paths", nargs="*", default=None,
        help="Only include these exact path strings",
    )
    p.add_argument("--bearer-token", default=None, help="Bearer token for authenticated APIs")


def run(args: argparse.Namespace) -> None:
    try:
        from mcs.driver.rest import RestToolDriver
    except ImportError:
        console.print(
            "[red]mcs-driver-rest is not installed.[/red]\n"
            "Install it with: [bold]pip install mcs-inspector\\[rest][/bold]"
        )
        sys.exit(1)

    console.print(f"\n[dim]Fetching spec from {args.url}...[/dim]")

    kwargs = {}
    if args.bearer_token:
        kwargs["default_headers"] = {"Authorization": f"Bearer {args.bearer_token}"}

    try:
        td = RestToolDriver(
            args.url,
            include_tags=args.include_tags,
            include_paths=args.include_paths,
            **kwargs,
        )
    except Exception as exc:
        console.print(f"[red bold]Failed to load spec:[/red bold] {exc}")
        sys.exit(1)

    tools = td.list_tools()
    console.print(f"[green]Parsed {len(tools)} tools[/green] (base: {td._base_url})\n")

    from mcs.inspector.core import ExtraColumn, run_inspector

    method_styles = {
        "GET": "green", "POST": "yellow",
        "PUT": "blue", "PATCH": "magenta", "DELETE": "red",
    }

    extra_columns = [
        ExtraColumn(
            header="Method",
            width=7,
            justify="center",
            value_fn=lambda tool, info: (
                f"[{method_styles.get(info.get('method', ''), 'white')}]"
                f"{info.get('method', '?')}"
                f"[/{method_styles.get(info.get('method', ''), 'white')}]"
            ),
        ),
        ExtraColumn(
            header="Path",
            style="dim",
            value_fn=lambda tool, info: info.get("path", "?"),
        ),
    ]

    run_inspector(
        td,
        title="REST Inspector",
        extra_columns=extra_columns,
        driver_info=td._tool_map,
    )
