"""Chat over any OpenAPI endpoint, via the MCS RestDriver.

Point it at a spec URL and the driver turns every operation into an LLM-callable
tool. Default: the GitHub REST API, filtered to its search endpoints -- which is
the whole argument for MCS: you do not need a dedicated server in front of an API
that already describes itself.

Streaming and non-streaming are **one flag**, not two programs. The MCS contract
is identical either way; only who assembles the message differs (the stream
buffer, or the provider).

Usage:
    python chat.py                          # streaming (default)
    python chat.py --no-stream              # one assembled response per turn
    python chat.py --no-native-tools        # text-prompt mode instead of the
                                            #   provider's tool-calling API
    python chat.py --debug                  # + system prompt, raw output, DriverResponse

    # A different API entirely -- same client:
    python chat.py --url https://mcsd.io/context7.json

    # Local model via an OpenAI-compatible server:
    python chat.py --model openai/meta-llama/Meta-Llama-3.1-8B-Instruct \
        --api-base http://localhost:8000/v1 --debug

Requires:
    pip install mcs-driver-rest litellm rich python-dotenv
"""

from __future__ import annotations

import sys
from pathlib import Path

from dotenv import load_dotenv

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
from _shared import ChatSession, ChatView, base_parser  # noqa: E402

from mcs.driver.rest import RestDriver  # noqa: E402

GITHUB_SPEC = (
    "https://raw.githubusercontent.com/github/rest-api-description"
    "/main/descriptions/api.github.com/api.github.com.json"
)
#: GitHub exposes 1200+ operations; without a filter the tool list dwarfs the
#: prompt. Tag filtering is the driver's answer to "which part of this API?".
DEFAULT_TAGS = ["search"]


def main() -> None:
    load_dotenv()
    p = base_parser("MCS chat over any OpenAPI endpoint (REST driver)")
    p.add_argument("--url", default=GITHUB_SPEC, help="OpenAPI spec URL")
    p.add_argument("--include-tags", nargs="*", default=None,
                   help="Only expose operations with these OpenAPI tags "
                        f"(default: {DEFAULT_TAGS} for the GitHub spec)")
    args = p.parse_args()

    view = ChatView(debug=args.debug)
    tags = args.include_tags if args.include_tags is not None else (
        DEFAULT_TAGS if args.url == GITHUB_SPEC else None
    )
    driver = RestDriver(url=args.url, include_tags=tags)
    view.tools_discovered([t.name for t in driver.list_tools()])

    ChatSession(
        driver, args.model, view=view,
        streaming=args.stream, native_tools=args.native_tools,
        api_base=args.api_base, api_key=args.api_key,
    ).run()


if __name__ == "__main__":
    main()
