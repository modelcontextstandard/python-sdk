"""MCS minimal client launcher.

Convenience entry point that delegates to the non-streaming or streaming
variant depending on the ``--stream`` flag.

Usage:
    python mcs_driver_minimal_client.py [--stream] [--model MODEL] [--debug] [--data-dir DIR]

For direct usage prefer:
    python mcs_driver_minimal_client_non_stream.py [--model MODEL] [--debug]
    python mcs_driver_minimal_client_stream.py     [--model MODEL] [--debug]
"""

from __future__ import annotations

import sys


def main() -> None:
    if "--stream" in sys.argv:
        sys.argv.remove("--stream")
        from mcs_driver_minimal_client_stream import main as run
    else:
        from mcs_driver_minimal_client_non_stream import main as run
    run()


if __name__ == "__main__":
    main()
