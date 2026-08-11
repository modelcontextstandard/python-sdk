"""Websearch CLI plugin for the MCS Inspector -- debug what the search returns."""

from __future__ import annotations

import argparse
import os
import sys

from rich.console import Console

console = Console()


def add_parser(subparsers: argparse._SubParsersAction) -> None:
    p = subparsers.add_parser("websearch", help="Inspect web search (Tavily-compatible)")
    p.add_argument("--base-url", default=os.environ.get("MCS_SEARCH_URL"),
                   help="Tavily-compatible service (default: $MCS_SEARCH_URL, "
                        "else hosted Tavily)")
    p.add_argument("--api-key",
                   default=os.environ.get("MCS_SEARCH_KEY") or os.environ.get("TAVILY_API_KEY"),
                   help="API key (default: $MCS_SEARCH_KEY or $TAVILY_API_KEY)")
    p.add_argument("--max-results", type=int, default=None,
                   help="Default result count the tool advertises")


def run(args: argparse.Namespace) -> None:
    try:
        from mcs.driver.websearch import WebsearchToolDriver
    except ImportError:
        console.print(
            "[red]mcs-driver-websearch is not installed.[/red]\n"
            "Install it with: [bold]pip install mcs-inspector\\[websearch][/bold]"
        )
        sys.exit(1)

    if not args.api_key:
        console.print(
            "[red]No search API key.[/red] Set $MCS_SEARCH_KEY (with $MCS_SEARCH_URL "
            "for a self-hosted service) or $TAVILY_API_KEY, or pass --api-key."
        )
        sys.exit(1)

    kwargs = {"api_key": args.api_key}
    if args.base_url:
        kwargs["base_url"] = args.base_url
    if args.max_results is not None:
        kwargs["max_results"] = args.max_results

    td = WebsearchToolDriver(**kwargs)

    from mcs.inspector.core import run_inspector

    console.print(f"[dim]Backend: {args.base_url or 'api.tavily.com (hosted)'}[/dim]")
    run_inspector(td, title="Websearch Inspector")
