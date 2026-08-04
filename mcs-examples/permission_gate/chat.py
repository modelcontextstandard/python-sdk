"""Human-in-the-loop chat: every tool call needs the user's OK.

The gate is a **tool middleware**, not client code. ``PermissionMiddleware``
lives *inside* the driver and wraps ``execute_tool``: it receives the pending
call with its arguments, asks a consent handler, and either continues the chain
or short-circuits it with a structured ``permission_denied`` result. Nothing is
executed on denial, and no exception escapes -- the model reads the denial back
as a normal tool result and can react to it.

Two things are worth noticing:

* **The client loop is unchanged.** Compare it with any other example -- same
  ``ChatSession``, same driver call. Consent is configuration, not control flow.
* **It works identically while streaming.** The middleware runs inside
  ``process_llm_response``, so the prompt appears mid-stream, right when the
  driver is about to execute -- and the answer continues afterwards.

The consent handler is the *view*: it owns the terminal and knows whether it is
mid-line, so it can interrupt a streaming answer cleanly.

Usage:
    python chat.py                     # streaming (default)
    python chat.py --no-stream         # one assembled response per turn
    python chat.py --debug             # + raw LLM output and DriverResponse
    python chat.py --allow-all         # gate open: shows the chain still runs

Requires:
    pip install mcs-driver-rest mcs-permission litellm rich python-dotenv
"""

from __future__ import annotations

import sys
from pathlib import Path

from dotenv import load_dotenv

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
from _shared import ChatSession, ChatView, base_parser  # noqa: E402

from mcs.driver.rest import RestDriver  # noqa: E402
from mcs.permission.middleware import PermissionMiddleware  # noqa: E402

GITHUB_SPEC = (
    "https://raw.githubusercontent.com/github/rest-api-description"
    "/main/descriptions/api.github.com/api.github.com.json"
)
DEFAULT_TAGS = ["search"]


def main() -> None:
    load_dotenv()
    p = base_parser("MCS chat with a consent gate on every tool call")
    p.add_argument("--url", default=GITHUB_SPEC, help="OpenAPI spec URL")
    p.add_argument("--include-tags", nargs="*", default=None,
                   help="Only expose operations with these OpenAPI tags")
    p.add_argument("--allow-all", action="store_true",
                   help="Auto-approve every call (to contrast with the interactive gate)")
    args = p.parse_args()

    view = ChatView(debug=args.debug)

    tags = args.include_tags if args.include_tags is not None else (
        DEFAULT_TAGS if args.url == GITHUB_SPEC else None
    )
    driver = RestDriver(url=args.url, include_tags=tags)
    view.tools_discovered([t.name for t in driver.list_tools()])

    # The gate. Both handlers *show* the pending call -- only one of them asks.
    # That is the contrast worth seeing: --allow-all does not switch the gate off,
    # it answers it automatically, and the middleware is in the chain either way.
    driver.add_middleware(PermissionMiddleware(
        consent_handler=view.auto_consent if args.allow_all else view.ask_consent
    ))

    ChatSession(
        driver, args.model, view=view,
        streaming=args.stream, native_tools=args.native_tools,
        api_base=args.api_base, api_key=args.api_key,
        title="MCS Chat (consent gate)",
        banner_extra=[f"Consent:  {'auto-approve' if args.allow_all else 'ask the user'}"],
    ).run()


if __name__ == "__main__":
    main()
