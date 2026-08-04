"""Chat over local CSV files, via the MCS CsvDriver.

The same client as the REST example -- only the driver differs. That is the point
of the driver contract: swapping a network API for local files changes one line,
not the application.

Usage:
    python chat.py                          # streaming (default)
    python chat.py --no-stream              # one assembled response per turn
    python chat.py --no-native-tools        # text-prompt mode
    python chat.py --debug                  # + system prompt, raw output, DriverResponse
    python chat.py --data-dir ./data2       # a different folder

Requires:
    pip install mcs-driver-csv litellm rich python-dotenv
"""

from __future__ import annotations

import sys
from pathlib import Path

from dotenv import load_dotenv

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
from _shared import ChatSession, ChatView, base_parser  # noqa: E402

from mcs.driver.csv import CsvDriver  # noqa: E402


def main() -> None:
    load_dotenv()
    p = base_parser("MCS chat over local CSV files (CSV driver)")
    p.add_argument("--data-dir", default=str(Path(__file__).parent / "data"),
                   help="Directory holding the CSV files (default: ./data)")
    args = p.parse_args()

    view = ChatView(debug=args.debug)
    driver = CsvDriver(base_dir=args.data_dir)
    view.tools_discovered([t.name for t in driver.list_tools()])

    ChatSession(
        driver, args.model, view=view,
        streaming=args.stream, native_tools=args.native_tools,
        api_base=args.api_base, api_key=args.api_key,
    ).run()


if __name__ == "__main__":
    main()
