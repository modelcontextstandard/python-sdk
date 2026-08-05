"""MCS ToolDriver for searching the web.

One tool, ``web_search``. Verticals (news, images, video) are a **parameter**,
not extra tools: four near-identical entries would bloat the prompt for a
distinction the backend already models behind one endpoint, and every extra tool
is a choice the model can get wrong.
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

from .ports import WebSearchPort

logger = logging.getLogger(__name__)

#: Hits per search unless asked otherwise. Small on purpose: a model that needs
#: more can ask, while a large default spends context on results nobody reads.
DEFAULT_MAX_RESULTS = 5
#: Hard ceiling, so one call cannot flood the context window.
MAX_RESULTS_LIMIT = 20
#: Verticals a Tavily-compatible backend understands.
TOPICS = ("general", "news")
#: Per-result cap when full page content was requested. Without it, five pages of
#: raw text arrive at once and crowd out everything else.
DEFAULT_CONTENT_CHARS = 4_000


@dataclass(frozen=True)
class _WebsearchToolDriverMeta(DriverMeta):
    id: str = "b7a1c3d5-web-4003-9000-websearchtd001"
    name: str = "Websearch MCS ToolDriver"
    version: str = "0.1.0"
    bindings: tuple[DriverBinding, ...] = (
        DriverBinding(capability="websearch", adapter="*", spec_format="Custom"),
    )
    supported_llms: None = None
    capabilities: tuple[str, ...] = ("orchestratable",)


_TOOLS: List[Tool] = [
    Tool(
        name="web_search",
        title="Search the web",
        description=(
            "Search the web and return ranked results with title, URL and a short "
            "excerpt. Use this to find sources when you do not already have a URL. "
            "Set include_content=true to get the full page text of each hit in the "
            "same call -- do that when you intend to read the results anyway, and "
            "leave it off when the excerpts are enough to decide which one matters."
        ),
        parameters=[
            ToolParameter(
                name="query",
                description="What to search for, in natural language or keywords.",
                required=True,
                schema={"type": "string"},
            ),
            ToolParameter(
                name="max_results",
                description=(
                    f"How many hits to return (default: {DEFAULT_MAX_RESULTS}, "
                    f"maximum: {MAX_RESULTS_LIMIT})."
                ),
                required=False,
                schema={"type": "integer", "default": DEFAULT_MAX_RESULTS},
            ),
            ToolParameter(
                name="topic",
                description=(
                    "'general' (default) or 'news' for recent reporting, which "
                    "ranks by recency rather than relevance alone."
                ),
                required=False,
                schema={"type": "string", "enum": list(TOPICS), "default": "general"},
            ),
            ToolParameter(
                name="include_content",
                description=(
                    "Also return the full text of each result (default: false). "
                    "Saves a separate fetch per source, but costs far more context."
                ),
                required=False,
                schema={"type": "boolean", "default": False},
            ),
            ToolParameter(
                name="include_domains",
                description="Only return results from these domains.",
                required=False,
                schema={"type": "array", "items": {"type": "string"}},
            ),
            ToolParameter(
                name="exclude_domains",
                description="Never return results from these domains.",
                required=False,
                schema={"type": "array", "items": {"type": "string"}},
            ),
            ToolParameter(
                name="time_range",
                description=(
                    "Restrict to recent results: 'day', 'week', 'month' or 'year'."
                ),
                required=False,
                schema={"type": "string"},
            ),
        ],
    ),
]


class WebsearchToolDriver(MCSToolDriver):
    """Expose one search backend as an MCS tool."""

    meta: DriverMeta = _WebsearchToolDriverMeta()

    def __init__(
        self,
        connector: WebSearchPort | None = None,
        *,
        max_results: int = DEFAULT_MAX_RESULTS,
        content_chars: int = DEFAULT_CONTENT_CHARS,
        _connector: WebSearchPort | None = None,
        **connector_kwargs: Any,
    ) -> None:
        """
        Parameters
        ----------
        connector :
            The search backend (a :class:`~.ports.WebSearchPort`). Defaults to
            :class:`~.tavily_connector.TavilySearchConnector` built from
            *connector_kwargs* (``api_key``, ``base_url``).
        content_chars :
            Per-result cap when ``include_content`` is used.
        """
        chosen = _connector if _connector is not None else connector
        if chosen is None:
            from .tavily_connector import TavilySearchConnector

            chosen = TavilySearchConnector(**connector_kwargs)
        self._connector: WebSearchPort = chosen
        self._max_results = max_results
        self._content_chars = content_chars

    # -- MCSToolDriver contract ------------------------------------------------

    def list_tools(self) -> List[Tool]:
        return list(_TOOLS)

    def execute_tool(self, tool_name: str, arguments: Dict[str, Any]) -> Any:
        if tool_name != "web_search":
            raise ValueError(f"Tool '{tool_name}' not found.")

        query = arguments.get("query")
        if not query:
            raise ValueError("web_search requires a 'query' argument.")

        topic = arguments.get("topic") or "general"
        if topic not in TOPICS:
            raise ValueError(f"topic must be one of {TOPICS}, got {topic!r}.")

        # Clamp rather than reject: an over-large number is a reasonable ask, and
        # failing the call would waste a round trip over a detail we can fix.
        requested = arguments.get("max_results") or self._max_results
        max_results = max(1, min(int(requested), MAX_RESULTS_LIMIT))

        include_content = bool(arguments.get("include_content"))
        results, answer = self._connector.search(
            query,
            max_results=max_results,
            topic=topic,
            include_content=include_content,
            include_domains=arguments.get("include_domains"),
            exclude_domains=arguments.get("exclude_domains"),
            time_range=arguments.get("time_range"),
        )

        hits: List[Dict[str, Any]] = []
        for r in results:
            hit: Dict[str, Any] = {"url": r.url, "title": r.title, "snippet": r.snippet}
            if r.published:
                hit["published"] = r.published
            if include_content and r.content:
                text = r.content
                if len(text) > self._content_chars:
                    text = text[: self._content_chars]
                    hit["content_truncated"] = True
                hit["content"] = text
            hits.append(hit)

        out: Dict[str, Any] = {"query": query, "results": hits, "count": len(hits)}
        if answer:
            # Some backends synthesise an answer. Passing it through is free; the
            # model can use it as a lead and still check the sources.
            out["answer"] = answer
        if include_content and any("content" not in h for h in hits):
            # Say so explicitly -- otherwise the model cannot tell "no content" from
            # "this source had none" and may conclude the page was empty.
            out["note"] = ("Some results carry no full text; fetch those URLs "
                           "individually if you need them.")
        return out
