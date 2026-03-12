"""Mailread CLI plugin for the MCS Inspector."""

from __future__ import annotations

import argparse
import getpass
import sys

from rich.console import Console

console = Console()


def add_parser(subparsers: argparse._SubParsersAction) -> None:
    p = subparsers.add_parser("mailread", help="Inspect a mailbox (read / organise)")
    p.add_argument("--host", required=True, help="Mailbox server hostname")
    p.add_argument("--user", required=True, help="Login username / e-mail")
    p.add_argument("--password", default=None, help="Password (prompted if omitted)")
    p.add_argument("--port", type=int, default=None, help="Server port")
    p.add_argument("--no-ssl", action="store_true", help="Disable implicit SSL")
    p.add_argument("--starttls", action="store_true", help="Upgrade plaintext connection via STARTTLS")
    p.add_argument("--adapter", default="imap", help="Adapter to use (default: imap)")


def run(args: argparse.Namespace) -> None:
    try:
        from mcs.driver.mailread import MailreadToolDriver
    except ImportError:
        console.print(
            "[red]mcs-driver-mailread is not installed.[/red]\n"
            "Install it with: [bold]pip install mcs-inspector\\[mailread][/bold]"
        )
        sys.exit(1)

    password = args.password or getpass.getpass(f"Password for {args.user}@{args.host}: ")

    console.print(f"\n[dim]Connecting to {args.host} as {args.user} (adapter: {args.adapter})...[/dim]")

    try:
        td = MailreadToolDriver(
            adapter=args.adapter,
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
    run_inspector(td, title="Mailread Inspector")
