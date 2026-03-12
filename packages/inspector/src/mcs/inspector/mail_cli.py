"""Mail CLI plugin for the MCS Inspector (composite: read + send)."""

from __future__ import annotations

import argparse
import getpass
import sys

from rich.console import Console

console = Console()


def add_parser(subparsers: argparse._SubParsersAction) -> None:
    p = subparsers.add_parser("mail", help="Inspect a full mail setup (read + send)")

    g_read = p.add_argument_group("mailbox (read)")
    g_read.add_argument("--read-host", required=True, help="Mailbox server hostname")
    g_read.add_argument("--read-user", required=True, help="Mailbox login username")
    g_read.add_argument("--read-password", default=None, help="Mailbox password (prompted if omitted)")
    g_read.add_argument("--read-port", type=int, default=None, help="Mailbox server port")
    g_read.add_argument("--read-no-ssl", action="store_true", help="Disable implicit SSL for reading")
    g_read.add_argument("--read-starttls", action="store_true", help="Use STARTTLS for reading")
    g_read.add_argument("--read-adapter", default="imap", help="Read adapter (default: imap)")

    g_send = p.add_argument_group("mail sending")
    g_send.add_argument("--send-host", required=True, help="Mail-sending server hostname")
    g_send.add_argument("--send-user", required=True, help="Mail-sending login username")
    g_send.add_argument("--send-password", default=None, help="Send password (prompted if omitted)")
    g_send.add_argument("--send-port", type=int, default=None, help="Send server port")
    g_send.add_argument("--send-ssl", action="store_true", help="Use implicit SSL for sending")
    g_send.add_argument("--send-no-starttls", action="store_true", help="Disable STARTTLS for sending")
    g_send.add_argument("--send-sender", default=None, help="Sender address (default: send-user)")
    g_send.add_argument("--send-sender-name", default=None, help="Display name for the sender")
    g_send.add_argument("--send-adapter", default="smtp", help="Send adapter (default: smtp)")


def run(args: argparse.Namespace) -> None:
    try:
        from mcs.driver.mail import MailToolDriver
    except ImportError:
        console.print(
            "[red]mcs-driver-mail is not installed.[/red]\n"
            "Install it with: [bold]pip install mcs-inspector\\[mail][/bold]"
        )
        sys.exit(1)

    read_pw = args.read_password or getpass.getpass(f"Read password for {args.read_user}@{args.read_host}: ")
    send_pw = args.send_password or getpass.getpass(f"Send password for {args.send_user}@{args.send_host}: ")

    console.print(f"\n[dim]Setting up mail driver...[/dim]")
    console.print(f"[dim]  Read: {args.read_host} ({args.read_adapter})[/dim]")
    console.print(f"[dim]  Send: {args.send_host} ({args.send_adapter})[/dim]")

    try:
        td = MailToolDriver(
            read_adapter=args.read_adapter,
            send_adapter=args.send_adapter,
            read_kwargs=dict(
                host=args.read_host, user=args.read_user, password=read_pw,
                port=args.read_port, ssl=not args.read_no_ssl, starttls=args.read_starttls,
            ),
            send_kwargs=dict(
                host=args.send_host, user=args.send_user, password=send_pw,
                port=args.send_port, ssl=args.send_ssl, starttls=not args.send_no_starttls,
                sender=args.send_sender,
                sender_name=args.send_sender_name,
            ),
        )
    except Exception as exc:
        console.print(f"[red bold]Failed to create driver:[/red bold] {exc}")
        sys.exit(1)

    import json

    try:
        folders = json.loads(td.execute_tool("list_folders", {}))
        console.print(f"[green]Mailbox connected.[/green] Found {len(folders)} folders: {', '.join(folders[:8])}")
    except Exception as exc:
        console.print(f"[red bold]Mailbox connection failed:[/red bold] {exc}")
        sys.exit(1)

    from mcs.inspector import run_inspector
    run_inspector(td, title="Mail Inspector (read + send)")
