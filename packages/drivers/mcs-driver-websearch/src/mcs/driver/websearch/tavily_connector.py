"""Search over any **Tavily-compatible** API.

Sits where ``gmail_connector`` sits in the mail driver: protocol logic in the
driver package, transport delegated to an HTTP adapter.

Tavily's request/response shape has become a de-facto interface for agent search
-- Tavily itself, self-hosted services like OrioSearch, and others expose it, so
one connector reaches all of them by changing ``base_url``. That is the same
argument MCS makes for OpenAPI: when a service already describes itself in a
shape others speak, you do not need a bespoke integration.

The wire format::

    POST /search
    {"query": ..., "max_results": 5, "topic": "general",
     "include_answer": false, "include_raw_content": false,
     "include_domains": [...], "exclude_domains": [...], "time_range": ...}

    -> {"query": ..., "answer": ...|null, "results": [
         {"title", "url", "content", "score", "raw_content", ...}], ...}

Note the field names, because they are easy to get backwards: ``content`` is the
*snippet* the engine returned, while ``raw_content`` is the full page text and is
only populated when ``include_raw_content`` was requested. The MCS
:class:`~mcs.types.web.SearchResult` keeps them apart as ``snippet`` and
``content``.
"""

from __future__ import annotations

import logging
from typing import Any, Protocol, runtime_checkable

from mcs.types.web import SearchResult

logger = logging.getLogger(__name__)

#: Tavily's own endpoint. Point ``base_url`` elsewhere for a compatible service.
TAVILY_API = "https://api.tavily.com"


@runtime_checkable
class HttpPort(Protocol):
    """The slice of an HTTP adapter this connector needs."""

    def request(self, method: str, url: str, **kwargs: Any) -> Any: ...


class TavilySearchConnector:
    """Search via a Tavily-compatible endpoint.

    Implements :class:`~.ports.WebSearchPort`.
    """

    def __init__(self, api_key: str | None = None, *, base_url: str = TAVILY_API,
                 include_answer: bool = False,
                 adapter: Any | None = None, timeout: int = 60,
                 **adapter_kwargs: Any) -> None:
        """
        Parameters
        ----------
        api_key :
            Bearer token. Required by hosted services; a self-hosted instance may
            run without one.
        base_url :
            Service root. Tavily by default; set it to your own deployment
            (e.g. an OrioSearch instance) to use the same connector.
        include_answer :
            Ask the backend to synthesise an answer alongside the hits.

            Off by default, because synthesis costs the backend an LLM call and a
            caller who does not need it should not pay for it. The hits carry
            their own excerpts; an answer is a convenience on top.

            Worth sending only when you know the deployment supports it. Backends
            differ in how they behave when answer synthesis is unavailable -- the
            graceful response is ``answer: null`` alongside the normal results,
            but a stricter implementation may treat the request as unsatisfiable.
            Sending it unconditionally therefore risks a silent empty result set
            on some deployments, which is why the flag is opt-in rather than
            always-on.
        """
        self._base = base_url.rstrip("/")
        self._api_key = api_key
        self._include_answer = include_answer
        if adapter is None:
            from mcs.adapter.http import HttpAdapter

            headers = {"Content-Type": "application/json"}
            if api_key:
                headers["Authorization"] = f"Bearer {api_key}"
            adapter_kwargs.setdefault("default_headers", headers)
            adapter_kwargs.setdefault("timeout", timeout)
            adapter = HttpAdapter(**adapter_kwargs)
        self._http: HttpPort = adapter

    # -- WebSearchPort ---------------------------------------------------------

    def search(
        self,
        query: str,
        *,
        max_results: int = 5,
        topic: str = "general",
        include_content: bool = False,
        include_domains: list[str] | None = None,
        exclude_domains: list[str] | None = None,
        time_range: str | None = None,
    ) -> tuple[list[SearchResult], str | None]:
        payload: dict[str, Any] = {
            "query": query,
            "max_results": max_results,
            "topic": topic,
            "include_raw_content": include_content,
        }
        if self._include_answer:
            # Only when asked for -- see the constructor docstring: it costs the
            # backend an LLM call, and not every deployment degrades gracefully.
            payload["include_answer"] = True
        if include_domains:
            payload["include_domains"] = list(include_domains)
        if exclude_domains:
            payload["exclude_domains"] = list(exclude_domains)
        if time_range:
            payload["time_range"] = time_range

        logger.info("search %r (topic=%s, n=%s, content=%s)",
                    query, topic, max_results, include_content)
        resp = self._http.request("POST", f"{self._base}/search", json_body=payload)
        resp.raise_for_status()
        data = resp.json()

        results = [self._to_result(item) for item in (data.get("results") or [])]
        answer = data.get("answer") or None
        return results, answer

    # -- mapping ---------------------------------------------------------------

    @staticmethod
    def _to_result(item: dict[str, Any]) -> SearchResult:
        """Map one Tavily hit onto :class:`~mcs.types.web.SearchResult`.

        Unknown extras are kept in ``meta`` rather than dropped -- a richer
        backend (thumbnails, favicons, publication dates) loses nothing, while
        the common fields stay predictable for every consumer.
        """
        known = {"title", "url", "content", "score", "raw_content",
                 "published_date", "publishedDate"}
        extras = {k: v for k, v in item.items() if k not in known and v not in (None, "")}
        return SearchResult(
            url=item.get("url", ""),
            title=item.get("title"),
            snippet=item.get("content"),          # engine excerpt, not the page
            content=item.get("raw_content"),      # full text, only when requested
            score=item.get("score"),
            published=item.get("published_date") or item.get("publishedDate"),
            meta=extras,
        )
