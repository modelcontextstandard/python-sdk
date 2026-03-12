"""Mailsend CLI plugin for the MCS Inspector."""

from __future__ import annotations

import argparse
import getpass
import sys

from rich.console import Console

console = Console()


def add_parser(subparsers: argparse._SubParsersAction) -> None:
    p = subparsers.add_parser("mailsend", help="Inspect a mail-sending server")
    p.add_argument("--host", required=True, help="Mail server hostname")
    p.add_argument("--user", required=True, help="Login username / e-mail")
    p.add_argument("--password", default=None, help="Password (prompted if omitted)")
    p.add_argument("--port", type=int, default=None, help="Server port")
    p.add_argument("--ssl", action="store_true", help="Use implicit SSL (port 465)")
    p.add_argument("--no-starttls", action="store_true", help="Disable STARTTLS upgrade")
    p.add_argument("--sender", default=None, help="Sender address (default: login user)")
    p.add_argument("--adapter", default="smtp", help="Adapter to use (default: smtp)")


def run(args: argparse.Namespace) -> None:
    try:
        from mcs.driver.mailsend import MailsendToolDriver
    except ImportError:
        console.print(
            "[red]mcs-driver-mailsend is not installed.[/red]\n"
            "Install it with: [bold]pip install mcs-inspector\\[mailsend][/bold]"
        )
        sys.exit(1)

    password = args.password or getpass.getpass(f"Password for {args.user}@{args.host}: ")

    console.print(f"\n[dim]Connecting to {args.host} as {args.user} (adapter: {args.adapter})...[/dim]")

    try:
        td = MailsendToolDriver(
            adapter=args.adapter,
            host=args.host,
            user=args.user,
            password=password,
            port=args.port,
            ssl=args.ssl,
            starttls=not args.no_starttls,
            sender=args.sender,
        )
    except Exception as exc:
        console.print(f"[red bold]Failed to create driver:[/red bold] {exc}")
        sys.exit(1)

    import json
    try:
        result = json.loads(td.execute_tool("check_connection", {}))
        if result.get("status") == "ok":
            console.print(f"[green]Connected.[/green] Server: {result['server']}:{result['port']}")
        else:
            console.print(f"[red bold]Connection check failed:[/red bold] {result.get('detail', 'unknown error')}")
            sys.exit(1)
    except Exception as exc:
        console.print(f"[red bold]Connection check failed:[/red bold] {exc}")
        sys.exit(1)

    from mcs.inspector import run_inspector
    run_inspector(td, title="Mailsend Inspector")
