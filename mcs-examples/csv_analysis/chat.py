"""MCS CSV analysis chat launcher.

Usage:
    python chat.py                       # non-streaming
    python chat.py --stream              # streaming
    python chat.py --stream --tcs        # streaming + tool-call signaling
    python chat.py --stream --tcs --debug
"""

from __future__ import annotations

import sys


def main() -> None:
    use_stream = "--stream" in sys.argv
    use_tcs = "--tcs" in sys.argv

    if "--stream" in sys.argv:
        sys.argv.remove("--stream")
    if "--tcs" in sys.argv:
        sys.argv.remove("--tcs")

    if use_stream and use_tcs:
        from chat_stream_tcs import main as run
    elif use_stream:
        from chat_stream import main as run
    else:
        from chat_non_stream import main as run
    run()


if __name__ == "__main__":
    main()
