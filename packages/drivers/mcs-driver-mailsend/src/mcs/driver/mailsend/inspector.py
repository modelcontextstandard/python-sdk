"""MCS Mailsend Inspector -- test connections and explore tools interactively.

Run directly::

    python -m mcs.driver.mailsend.inspector --host smtp.example.com --user alice@example.com

Or preferably via the unified CLI::

    mcs-inspect mailsend --host smtp.example.com --user alice@example.com
"""

from __future__ import annotations

import argparse
import getpass
import json
import sys


def _parse_args() -> argparse.Namespace:
    p = argparse.ArgumentParser(
        prog="mcs-mailsend-inspector",
        description="Inspect a mail-sending server -- test connections, browse tools, execute calls.",
    )
    p.add_argument("--host", required=True, help="Mail server hostname")
    p.add_argument("--user", required=True, help="Login username / e-mail")
    p.add_argument("--password", default=None, help="Password (prompted if omitted)")
    p.add_argument("--port", type=int, default=None, help="Server port (auto: 465/SSL, 587/STARTTLS, 25/plain)")
    p.add_argument("--ssl", action="store_true", help="Use implicit SSL (port 465)")
    p.add_argument("--no-starttls", action="store_true", help="Disable STARTTLS upgrade")
    p.add_argument("--sender", default=None, help="Sender address (default: login user)")
    p.add_argument("--sender-name", default=None, help="Display name for the sender (e.g. 'Danny Gerst')")
    p.add_argument("--adapter", default="smtp", help="Adapter to use (default: smtp)")
    return p.parse_args()


def main() -> None:
    args = _parse_args()
    password = args.password or getpass.getpass(f"Password for {args.user}@{args.host}: ")

    from mcs.driver.mailsend import MailsendToolDriver

    try:
        from mcs.inspector import run_inspector
        has_inspector = True
    except ImportError:
        has_inspector = False

    print(f"\nConnecting to {args.host} as {args.user} (adapter: {args.adapter})...")

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
            sender_name=args.sender_name,
        )
    except Exception as exc:
        print(f"Failed to create driver: {exc}", file=sys.stderr)
        sys.exit(1)

    print(f"Driver created. Ready to inspect {args.host}.")

    if has_inspector:
        run_inspector(td, title="Mailsend Inspector")
    else:
        print("\nDiscovered tools:")
        for i, tool in enumerate(td.list_tools(), 1):
            params = [p.name for p in tool.parameters]
            print(f"  {i:3d}. {tool.name:20s} | {tool.title or ''} | params={params}")
        print(
            "\nInstall mcs-inspector for the full interactive experience:\n"
            "  pip install mcs-inspector[mailsend]"
        )


if __name__ == "__main__":
    main()
