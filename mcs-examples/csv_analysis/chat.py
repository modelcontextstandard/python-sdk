"""MCS CSV analysis chat launcher.

Usage:
    python chat.py                       # non-streaming
    python chat.py --stream              # streaming
    python chat.py --stream --debug
"""

from __future__ import annotations

import sys


def main() -> None:
    use_stream = "--stream" in sys.argv
    if use_stream:
        sys.argv.remove("--stream")

    if use_stream:
        from chat_stream import main as run
    else:
        from chat_non_stream import main as run
    run()


if __name__ == "__main__":
    main()
