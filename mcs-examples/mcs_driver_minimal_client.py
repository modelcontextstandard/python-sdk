"""MCS minimal client launcher.

Convenience entry point that delegates to the appropriate variant
depending on flags.

Usage:
    python mcs_driver_minimal_client.py                       # non-streaming
    python mcs_driver_minimal_client.py --stream              # streaming
    python mcs_driver_minimal_client.py --stream --tcs        # streaming + TCS
    python mcs_driver_minimal_client.py --stream --tcs --debug
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
        from mcs_driver_minimal_client_stream_tcs import main as run
    elif use_stream:
        from mcs_driver_minimal_client_stream import main as run
    else:
        from mcs_driver_minimal_client_non_stream import main as run
    run()


if __name__ == "__main__":
    main()
