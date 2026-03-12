"""MCS Mailread Inspector -- test connections and explore tools interactively.

Run directly::

    python -m mcs.driver.mailread.inspector --host imap.example.com --user alice@example.com

Or preferably via the unified CLI::

    mcs-inspect mailread --host imap.example.com --user alice@example.com
"""

from __future__ import annotations

import argparse
import getpass
import json
import sys


def _parse_args() -> argparse.Namespace:
    p = argparse.ArgumentParser(
        prog="mcs-mailread-inspector",
        description="Inspect a mailbox -- test connections, browse tools, execute calls.",
    )
    p.add_argument("--host", required=True, help="Mail server hostname")
    p.add_argument("--user", required=True, help="Login username / e-mail")
    p.add_argument("--password", default=None, help="Password (prompted if omitted)")
    p.add_argument("--port", type=int, default=None, help="Server port (auto: 993/SSL, 143/STARTTLS)")
    p.add_argument("--no-ssl", action="store_true", help="Disable implicit SSL")
    p.add_argument("--starttls", action="store_true", help="Upgrade plaintext connection via STARTTLS")
    p.add_argument("--adapter", default="imap", help="Adapter to use (default: imap)")
    return p.parse_args()


def main() -> None:
    args = _parse_args()
    password = args.password or getpass.getpass(f"Password for {args.user}@{args.host}: ")

    from mcs.driver.mailread import MailreadToolDriver

    try:
        from mcs.inspector import run_inspector
        has_inspector = True
    except ImportError:
        has_inspector = False

    print(f"\nConnecting to {args.host} as {args.user} (adapter: {args.adapter})...")

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
        print(f"Failed to create driver: {exc}", file=sys.stderr)
        sys.exit(1)

    try:
        folders = json.loads(td.execute_tool("list_folders", {}))
        print(f"Connected. Found {len(folders)} folders: {', '.join(folders[:8])}")
        if len(folders) > 8:
            print(f"  ... and {len(folders) - 8} more")
    except Exception as exc:
        print(f"Connection check failed: {exc}", file=sys.stderr)
        sys.exit(1)

    if has_inspector:
        run_inspector(td, title="Mailread Inspector")
    else:
        print("\nDiscovered tools:")
        for i, tool in enumerate(td.list_tools(), 1):
            params = [p.name for p in tool.parameters]
            print(f"  {i:3d}. {tool.name:20s} | {tool.title or ''} | params={params}")
        print(
            "\nInstall mcs-inspector for the full interactive experience:\n"
            "  pip install mcs-inspector[mailread]"
        )


if __name__ == "__main__":
    main()
