"""Entry point for ``python -m mcs.inspector`` and ``mcs-inspect`` CLI."""

from __future__ import annotations

import argparse
import sys

from dotenv import load_dotenv

from mcs.inspector import (
    mail_cli,
    mailread_cli,
    mailsend_cli,
    rest_cli,
    webfetch_cli,
    websearch_cli,
)


def main() -> None:
    # BEFORE the parsers are built: their env-var defaults ($MCS_SEARCH_KEY,
    # $MCS_SUMMARIZE_MODEL, ...) are read at construction time. A debugging tool
    # should honour the same .env the examples do -- failing over a key that sits
    # right there in the project is the opposite of debugging. Real environment
    # variables still win; load_dotenv never overrides them.
    load_dotenv()

    parser = argparse.ArgumentParser(
        prog="mcs-inspect",
        description="Interactive MCS driver inspector -- browse tools, test connections, execute calls.",
    )
    subparsers = parser.add_subparsers(dest="driver", help="Driver to inspect")

    mailread_cli.add_parser(subparsers)
    mailsend_cli.add_parser(subparsers)
    mail_cli.add_parser(subparsers)
    rest_cli.add_parser(subparsers)
    websearch_cli.add_parser(subparsers)
    webfetch_cli.add_parser(subparsers)

    args = parser.parse_args()

    if args.driver is None:
        parser.print_help()
        sys.exit(0)

    dispatch = {
        "mailread": mailread_cli.run,
        "mailsend": mailsend_cli.run,
        "mail": mail_cli.run,
        "rest": rest_cli.run,
        "websearch": websearch_cli.run,
        "webfetch": webfetch_cli.run,
    }

    dispatch[args.driver](args)


if __name__ == "__main__":
    main()
