"""Entry point for ``python -m mcs.inspector`` and ``mcs-inspect`` CLI."""

from __future__ import annotations

import argparse
import sys

from mcs.inspector import (
    mail_cli,
    mailread_cli,
    mailsend_cli,
    rest_cli,
)


def main() -> None:
    parser = argparse.ArgumentParser(
        prog="mcs-inspect",
        description="Interactive MCS driver inspector -- browse tools, test connections, execute calls.",
    )
    subparsers = parser.add_subparsers(dest="driver", help="Driver to inspect")

    mailread_cli.add_parser(subparsers)
    mailsend_cli.add_parser(subparsers)
    mail_cli.add_parser(subparsers)
    rest_cli.add_parser(subparsers)

    args = parser.parse_args()

    if args.driver is None:
        parser.print_help()
        sys.exit(0)

    dispatch = {
        "mailread": mailread_cli.run,
        "mailsend": mailsend_cli.run,
        "mail": mail_cli.run,
        "rest": rest_cli.run,
    }

    dispatch[args.driver](args)


if __name__ == "__main__":
    main()
