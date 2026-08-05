"""MCS ToolDriver for reading web pages.

One tool, ``fetch_page``. The driver does three things the connector does not:

1. asks the connector for what the caller wants,
2. converts what came back if it is not that yet (strategies),
3. fits the result into a context window (truncation + paging).

Point 3 belongs here rather than in the connector because it is about the *model*,
not the *page*.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass
from typing import Any, Dict, List

from mcs.driver.core import (
    DriverBinding,
    DriverMeta,
    MCSToolDriver,
    Tool,
    ToolParameter,
)

from .ports import WebFetchPort
from .strategies import (
    BestOfExtractor,
    ContentStrategy,
    MarkdownExtractor,
    title_from_html,
)

logger = logging.getLogger(__name__)

#: Default ceiling on returned characters. Unbounded, a single fetch would eat
#: the context window -- a real page runs to hundreds of kilobytes.
#:
#: Why 20 000 and not the reference MCP server's 5 000: a page legitimately
#: consists mostly of navigation and filters. GitHub's trending page extracts to
#: 13 410 characters, of which the first 10 787 -- 80% -- are the language picker
#: and site furniture before the first repository appears. At 5 000 the model
#: would have seen a list of language names and nothing else.
#:
#: The tempting fix is to strip such runs. It is the wrong fix: it trades visible
#: noise for invisible loss, and a filter aggressive enough to drop a language
#: picker will eventually drop a real list. Give the model room to reach what it
#: came for, and let it continue with ``start_index``.
DEFAULT_MAX_CHARS = 20_000

#: What the tool accepts. ``markdown`` is included because it is what the
#: ecosystem converged on for agents (Jina, OpenCode, Tavily, Cloudflare's
#: "Markdown for Agents") -- it keeps headings, lists and links at a fraction of
#: the tokens the equivalent HTML would cost.
FORMATS = ("text", "markdown", "raw")


@dataclass(frozen=True)
class _WebfetchToolDriverMeta(DriverMeta):
    id: str = "b7a1c3d5-web-4001-9000-webfetchtd0001"
    name: str = "Webfetch MCS ToolDriver"
    version: str = "0.1.0"
    bindings: tuple[DriverBinding, ...] = (
        DriverBinding(capability="webfetch", adapter="*", spec_format="Custom"),
    )
    supported_llms: None = None
    capabilities: tuple[str, ...] = ("orchestratable",)


_RAW_HELP = (
    " format='raw' returns the untouched source, which is what you need to "
    "inspect the page itself: which scripts it loads, which CSS classes an "
    "element carries, what its meta tags say."
)


def _build_tools(allow_raw: bool) -> List[Tool]:
    """Build the tool spec for this driver's configuration.

    ``raw`` is advertised only when it is actually permitted. Listing a format
    the driver will refuse teaches the model to try it and get an error -- and it
    would learn that lesson once per conversation, wasting a round trip each time.
    """
    formats = ["text", "markdown"] + (["raw"] if allow_raw else [])
    return [
        Tool(
            name="fetch_page",
            title="Read a web page",
            description=(
                "Retrieve a web page by URL. format='text' (default) returns the "
                "readable content with navigation, scripts and styling removed -- "
                "use it to find out what a page says. format='markdown' keeps "
                "headings, lists and links."
                + (_RAW_HELP if allow_raw else "")
                + " Long results are cut at max_chars; continue with start_index "
                "rather than guessing what came after the cut."
            ),
            parameters=[
                ToolParameter(
                    name="url",
                    description="Absolute http(s) URL of the page to read.",
                    required=True,
                    schema={"type": "string"},
                ),
                ToolParameter(
                    name="format",
                    description=(
                        "'text' (default), 'markdown'"
                        + (", or 'raw' for untouched source." if allow_raw else ".")
                    ),
                    required=False,
                    schema={"type": "string", "enum": formats, "default": "text"},
                ),
                ToolParameter(
                    name="max_chars",
                    description=(
                        f"Maximum characters to return (default: {DEFAULT_MAX_CHARS}). "
                        "The result says whether it was truncated and how long the full "
                        "document is."
                    ),
                    required=False,
                    schema={"type": "integer", "default": DEFAULT_MAX_CHARS},
                ),
                ToolParameter(
                    name="start_index",
                    description=(
                        "Skip this many characters before returning (default: 0). Use "
                        "the next_start_index from a truncated result to continue."
                    ),
                    required=False,
                    schema={"type": "integer", "default": 0},
                ),
            ],
        ),
    ]


class RawNotAllowed(RuntimeError):
    """``format="raw"`` was requested but the driver was not permitted to serve it.

    Distinct from :class:`UnsupportedFormatError`, which means the *backend* has
    no markup to give. This one is policy: raw markup is opt-in.

    Why it is off by default: raw is the one format that hands the model
    everything a page contains -- including ``<script>`` bodies, hidden elements
    and comments. That is exactly what makes it useful for inspecting a page, and
    exactly what makes it a prompt-injection surface no sanitiser can close
    without destroying the format's purpose. A driver that only ever answers
    questions *about content* does not need it, so it should not carry the risk.
    """


class UnsupportedFormatError(RuntimeError):
    """The backend cannot produce what was asked for.

    Raised rather than silently downgrading. A caller who asked for ``raw`` wants
    the markup -- handing back extracted text instead would answer a question they
    did not ask, and the failure would be invisible.
    """


class WebfetchToolDriver(MCSToolDriver):
    """Expose one page-retrieval connector as an MCS tool."""

    meta: DriverMeta = _WebfetchToolDriverMeta()

    def __init__(
        self,
        connector: WebFetchPort | None = None,
        *,
        text_strategy: ContentStrategy | None = None,
        markdown_strategy: ContentStrategy | None = None,
        max_chars: int = DEFAULT_MAX_CHARS,
        allow_raw: bool = False,
        _connector: WebFetchPort | None = None,
        **connector_kwargs: Any,
    ) -> None:
        """
        Parameters
        ----------
        connector :
            The retrieval backend (a :class:`~.ports.WebFetchPort`). Defaults to
            plain HTTP, built from *connector_kwargs*.
        text_strategy, markdown_strategy :
            How to convert markup when the connector returned markup. Defaults to
            :class:`~.strategies.BestOfExtractor` and
            :class:`~.strategies.MarkdownExtractor`.
        allow_raw :
            Permit ``format="raw"``. **Off by default**, and when off the format
            is not even advertised in :meth:`list_tools` -- the model never learns
            the option exists, so it cannot spend a round trip discovering that it
            is refused.

            Enable it deliberately, for drivers whose job includes inspecting
            pages (which scripts, which classes, which meta tags). Leave it off
            for drivers that only answer questions about *content*: raw hands the
            model everything a page contains, including script bodies, hidden
            elements and comments, which is a prompt-injection surface no
            sanitiser can close without destroying the format's purpose.
        """
        chosen = _connector if _connector is not None else connector
        if chosen is None:
            from .http_connector import HttpPageConnector

            chosen = HttpPageConnector(**connector_kwargs)
        self._connector: WebFetchPort = chosen
        self._text = text_strategy or BestOfExtractor()
        self._markdown = markdown_strategy or MarkdownExtractor()
        self._max_chars = max_chars
        self._allow_raw = allow_raw
        self._tools = _build_tools(allow_raw)

    # -- MCSToolDriver contract ------------------------------------------------

    def list_tools(self) -> List[Tool]:
        return list(self._tools)

    def execute_tool(self, tool_name: str, arguments: Dict[str, Any]) -> Any:
        if tool_name != "fetch_page":
            raise ValueError(f"Tool '{tool_name}' not found.")

        url = arguments.get("url")
        if not url:
            raise ValueError("fetch_page requires a 'url' argument.")

        fmt = arguments.get("format") or "text"
        if fmt not in FORMATS:
            raise ValueError(f"format must be one of {FORMATS}, got {fmt!r}.")
        if fmt == "raw" and not self._allow_raw:
            # Reachable even though the format is unadvertised: a model may guess
            # it, or a client may call execute_tool directly.
            raise RawNotAllowed(
                "format='raw' is not permitted by this driver. Raw markup exposes "
                "everything on the page (script bodies, hidden elements, comments) "
                "to the model. Enable it explicitly with "
                "WebfetchToolDriver(..., allow_raw=True) if that is intended."
            )

        max_chars = arguments.get("max_chars") or self._max_chars
        start_index = arguments.get("start_index") or 0

        logger.info("fetch_page %s (format=%s, start=%s)", url, fmt, start_index)
        page = self._connector.fetch(url, want=fmt)
        content, title = self._render(page, fmt)

        total = len(content)
        if start_index:
            content = content[start_index:]
        truncated = len(content) > max_chars
        if truncated:
            content = content[:max_chars]

        result: Dict[str, Any] = {
            "url": page.url,
            "title": title,
            "format": fmt,
            "content": content,
            "truncated": truncated,
        }
        # Tell the model how to continue instead of leaving it to infer. Without
        # this it either stops early or re-fetches the same prefix.
        if truncated:
            result["total_chars"] = total
            result["next_start_index"] = start_index + len(content)
        return result

    # -- want vs. got ----------------------------------------------------------

    def _render(self, page, fmt: str) -> tuple[str, str | None]:
        """Bring what the connector returned in line with what was asked for.

        The connector announced its ``kind``; this decides whether a conversion
        is needed, possible, or already done. A service-backed connector that
        returns ``markdown`` is passed straight through -- re-extracting content
        someone else already extracted would only lose information.
        """
        kind = page.kind

        if fmt == "raw":
            if kind != "html":
                raise UnsupportedFormatError(
                    f"This backend returned {kind!r}, so raw markup is not available "
                    f"for {page.url}. Use a connector that fetches the page itself "
                    f"(e.g. plain HTTP or a browser) if you need the source."
                )
            return page.text, page.title or title_from_html(page.text)

        if kind != "html":
            # Already reduced (a service extracted it) or never markup to begin
            # with (JSON, CSV, plain text). Either way, converting again would
            # destroy structure rather than add any.
            return page.text, page.title

        strategy = self._markdown if fmt == "markdown" else self._text
        content, title = strategy.convert(page.text, page.url)
        # The document's own <title> wins over a strategy's metadata title.
        # Extractors read og:title, which is written for social sharing and is
        # frequently the *site's* tagline: on github.com/trending, trafilatura
        # reports "Build software better, together" while <title> says "Trending
        # repositories on GitHub today". The page's own answer is the better one.
        return content, title_from_html(page.text) or title or page.title
