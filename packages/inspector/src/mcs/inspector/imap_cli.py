"""IMAP CLI plugin for the MCS Inspector."""

from __future__ import annotations

import argparse
import getpass
import sys

from rich.console import Console

console = Console()


def add_parser(subparsers: argparse._SubParsersAction) -> None:
    p = subparsers.add_parser("imap", help="Inspect an IMAP mailbox")
    p.add_argument("--host", required=True, help="IMAP server hostname")
    p.add_argument("--user", required=True, help="Login username / e-mail")
    p.add_argument("--password", default=None, help="Password (prompted if omitted)")
    p.add_argument("--port", type=int, default=None, help="Server port (auto: 993/SSL, 143/STARTTLS)")
    p.add_argument("--no-ssl", action="store_true", help="Disable implicit SSL (use with --starttls or plaintext)")
    p.add_argument("--starttls", action="store_true", help="Upgrade plaintext connection via STARTTLS")


def run(args: argparse.Namespace) -> None:
    try:
        from mcs.driver.imap import ImapToolDriver
    except ImportError:
        console.print(
            "[red]mcs-driver-imap is not installed.[/red]\n"
            "Install it with: [bold]pip install mcs-inspector\\[imap][/bold]"
        )
        sys.exit(1)

    password = args.password or getpass.getpass(f"Password for {args.user}@{args.host}: ")

    console.print(f"\n[dim]Connecting to {args.host} as {args.user}...[/dim]")

    try:
        td = ImapToolDriver(
            host=args.host,
            user=args.user,
            password=password,
            port=args.port,
            ssl=not args.no_ssl,
            starttls=args.starttls,
        )
    except Exception as exc:
        console.print(f"[red bold]Failed to create driver:[/red bold] {exc}")
        sys.exit(1)

    import json
    try:
        folders = json.loads(td.execute_tool("list_folders", {}))
        console.print(f"[green]Connected.[/green] Found {len(folders)} folders: {', '.join(folders[:8])}")
        if len(folders) > 8:
            console.print(f"[dim]  ... and {len(folders) - 8} more[/dim]")
    except Exception as exc:
        console.print(f"[red bold]Connection check failed:[/red bold] {exc}")
        sys.exit(1)

    from mcs.inspector import run_inspector
    run_inspector(td, title="IMAP Inspector")
