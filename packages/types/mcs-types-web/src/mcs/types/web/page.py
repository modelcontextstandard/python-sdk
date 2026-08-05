"""Library-agnostic web types for MCS.

These value objects are shared by every web adapter (plain HTTP + text
extraction, a headless browser, a search API's extract endpoint, ...) and by the
drivers that consume them. Keeping them here means an adapter can be swapped
without any driver noticing.

This module has **zero** runtime dependencies.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any


@dataclass(frozen=True)
class WebPage:
    """One retrieved web page, reduced to what an LLM can actually use.

    Adapters return *readable text*, not markup: a raw HTML page is mostly
    navigation, scripts and styling, and spending context on that is waste. How
    the reduction happens is the adapter's business -- a boilerplate stripper, a
    readability algorithm, or a browser that already rendered the DOM.

    Attributes
    ----------
    url :
        The URL that was actually retrieved, after any redirects. Not
        necessarily the one that was requested -- worth reporting, because a
        redirect can change what the content is about.
    text :
        The content itself, in whatever shape :attr:`kind` announces.
    kind :
        **What this content actually is** -- ``"html"``, ``"markdown"`` or
        ``"text"``. Declared rather than assumed, because backends differ: a
        plain HTTP adapter can only ever return markup, while Tavily, Jina or
        Firecrawl return content their own extractor has already reduced.

        Assuming either one would hard-code the wrong thing. "Always raw" locks
        out the services (or wastes the extraction they already did); "always
        text" makes raw markup unreachable, and with it every question about how
        a page is *built*. So the backend states what it produced and the caller
        converts if it can and must.
    title :
        The document title, when the source offered one.
    status_code :
        HTTP status of the retrieval, when the adapter deals in HTTP at all.
    content_type :
        MIME type as reported by the source.
    truncated :
        ``True`` when :attr:`text` was cut to fit a length budget. The consumer
        (and, through it, the model) should know it is not seeing everything.
    meta :
        Adapter-specific extras (published date, author, ``og:image``, …). Kept
        open on purpose so a richer backend loses nothing, while the common
        fields above stay predictable.
    """

    url: str
    text: str
    kind: str = "text"
    title: str | None = None
    status_code: int | None = None
    content_type: str | None = None
    truncated: bool = False
    meta: dict[str, Any] = field(default_factory=dict)


@dataclass(frozen=True)
class SearchResult:
    """One hit from a web search.

    Deliberately close to what every search API returns (Tavily, Brave, SearXNG,
    Exa), so an adapter maps rather than invents.

    Attributes
    ----------
    url :
        Link to the result.
    title :
        Result headline.
    snippet :
        The short excerpt the engine returned -- enough for the model to decide
        whether the page is worth fetching.
    content :
        Full page text, when the backend supplied it with the search results.
        ``None`` means "not requested" or "not available" -- fetch it separately
        if it is needed. This is what makes one round trip possible without
        forcing it on every caller.
    score :
        Relevance as reported by the engine, when it reports one. Scales are not
        comparable across engines; use it to order, not to threshold.
    published :
        Publication date as the engine reported it (ISO 8601 when available).
    meta :
        Adapter-specific extras (thumbnail, source engine, …).
    """

    url: str
    title: str | None = None
    snippet: str | None = None
    content: str | None = None
    score: float | None = None
    published: str | None = None
    meta: dict[str, Any] = field(default_factory=dict)
