"""MCS Mail Inspector -- test connections and explore all mail tools interactively.

Run directly::

    python -m mcs.driver.mail.inspector \\
        --read-host imap.example.com --read-user alice@example.com \\
        --send-host smtp.example.com --send-user alice@example.com

Or preferably via the unified CLI::

    mcs-inspect mail \\
        --read-host imap.example.com --read-user alice@example.com \\
        --send-host smtp.example.com --send-user alice@example.com
"""

from __future__ import annotations

import argparse
import getpass
import json
import sys


def _parse_args() -> argparse.Namespace:
    p = argparse.ArgumentParser(
        prog="mcs-mail-inspector",
        description="Inspect a full mail setup (read + send) -- test connections, browse tools, execute calls.",
    )
    # Read (mailbox) settings
    p.add_argument("--read-host", required=True, help="Mailbox server hostname (e.g. imap.gmail.com)")
    p.add_argument("--read-user", required=True, help="Mailbox login username")
    p.add_argument("--read-password", default=None, help="Mailbox password (prompted if omitted)")
    p.add_argument("--read-port", type=int, default=None, help="Mailbox server port")
    p.add_argument("--read-no-ssl", action="store_true", help="Disable implicit SSL for reading")
    p.add_argument("--read-starttls", action="store_true", help="Use STARTTLS for reading")
    p.add_argument("--read-adapter", default="imap", help="Read adapter (default: imap)")

    # Send settings
    p.add_argument("--send-host", required=True, help="Mail-sending server hostname (e.g. smtp.gmail.com)")
    p.add_argument("--send-user", required=True, help="Mail-sending login username")
    p.add_argument("--send-password", default=None, help="Send password (prompted if omitted)")
    p.add_argument("--send-port", type=int, default=None, help="Send server port")
    p.add_argument("--send-ssl", action="store_true", help="Use implicit SSL for sending")
    p.add_argument("--send-no-starttls", action="store_true", help="Disable STARTTLS for sending")
    p.add_argument("--send-sender", default=None, help="Sender address (default: send-user)")
    p.add_argument("--send-adapter", default="smtp", help="Send adapter (default: smtp)")
    return p.parse_args()


def main() -> None:
    args = _parse_args()
    read_pw = args.read_password or getpass.getpass(f"Read password for {args.read_user}@{args.read_host}: ")
    send_pw = args.send_password or getpass.getpass(f"Send password for {args.send_user}@{args.send_host}: ")

    from mcs.driver.mail import MailToolDriver

    try:
        from mcs.inspector import run_inspector
        has_inspector = True
    except ImportError:
        has_inspector = False

    print(f"\nSetting up mail driver...")
    print(f"  Read: {args.read_host} ({args.read_adapter})")
    print(f"  Send: {args.send_host} ({args.send_adapter})")

    try:
        td = MailToolDriver(
            read_adapter=args.read_adapter,
            send_adapter=args.send_adapter,
            read_kwargs=dict(
                host=args.read_host,
                user=args.read_user,
                password=read_pw,
                port=args.read_port,
                ssl=not args.read_no_ssl,
                starttls=args.read_starttls,
            ),
            send_kwargs=dict(
                host=args.send_host,
                user=args.send_user,
                password=send_pw,
                port=args.send_port,
                ssl=args.send_ssl,
                starttls=not args.send_no_starttls,
                sender=args.send_sender,
            ),
        )
    except Exception as exc:
        print(f"Failed to create driver: {exc}", file=sys.stderr)
        sys.exit(1)

    # Test read connection
    try:
        folders = json.loads(td.execute_tool("list_folders", {}))
        print(f"Mailbox connected. Found {len(folders)} folders: {', '.join(folders[:8])}")
    except Exception as exc:
        print(f"Mailbox connection failed: {exc}", file=sys.stderr)
        sys.exit(1)

    if has_inspector:
        run_inspector(td, title="Mail Inspector (read + send)")
    else:
        print(f"\nDiscovered {len(td.list_tools())} tools:")
        for i, tool in enumerate(td.list_tools(), 1):
            params = [p.name for p in tool.parameters]
            print(f"  {i:3d}. {tool.name:20s} | {tool.title or ''} | params={params}")
        print(
            "\nInstall mcs-inspector for the full interactive experience:\n"
            "  pip install mcs-inspector[mail]"
        )


if __name__ == "__main__":
    main()
