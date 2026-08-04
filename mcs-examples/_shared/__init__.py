"""Shared MVC scaffolding for the MCS example clients.

Every example is the same program with a different **model**: build a driver,
hand it to a :class:`ChatSession`, done. The session (controller) runs the agent
loop, the :class:`ChatView` (view) owns everything on screen, and the MCS driver
(model) owns everything about tools.

    from _shared import ChatSession, ChatView, base_parser

    args = base_parser("MCS chat over X").parse_args()
    view = ChatView(debug=args.debug)
    driver = MyDriver(...)
    ChatSession(driver, args.model, view=view, streaming=args.stream).run()

Streaming vs. blocking is one flag, not a second program -- which is the point:
the MCS contract is the same either way, so the examples should be too.
"""

from .cli import base_parser
from .llm import LLM
from .session import ChatSession, MAX_TOOL_RETRIES, MAX_TOOL_ROUNDS
from .view import ChatView

__all__ = [
    "base_parser",
    "LLM",
    "ChatSession",
    "ChatView",
    "MAX_TOOL_RETRIES",
    "MAX_TOOL_ROUNDS",
]
