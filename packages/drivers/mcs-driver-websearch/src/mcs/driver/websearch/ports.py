"""Adapter port for web-searching drivers.

Defines the contract any search backend must satisfy. Backends fulfil it through
structural subtyping -- they do **not** import or inherit from this module.

Search is a different capability from fetching, which is why it is a different
port and a different driver. They compose (find sources, then read one), but they
fail differently, cost differently, and are configured differently: a search
backend needs an API key and a quota, a fetch backend needs a transport. Bundling
them would mean neither can be swapped alone.
"""

from __future__ import annotations

from typing import Protocol, runtime_checkable

from mcs.types.web import SearchResult


@runtime_checkable
class WebSearchPort(Protocol):
    """Contract that any search backend must satisfy."""

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
        """Run *query* and return ``(results, answer)``.

        Parameters
        ----------
        max_results :
            Upper bound on hits. A backend may return fewer.
        topic :
            Vertical to search -- ``"general"`` or ``"news"``. A *parameter*
            rather than a separate tool on purpose: four near-identical tools
            would bloat the prompt for a distinction the backend already models
            behind one endpoint.
        include_content :
            Ask the backend to return full page text alongside the hits. Saves a
            round trip when the caller will read them anyway, and costs context
            when it will not -- so the caller decides, per call.
        include_domains, exclude_domains :
            Restrict the search. Also the natural place for a domain policy to
            take effect.
        time_range :
            Backend-specific recency filter (e.g. ``"day"``, ``"week"``).

        Returns
        -------
        tuple
            The hits, and an optional synthesised answer when the backend
            produced one (Tavily-style ``answer``). ``None`` when it did not --
            most backends only return links.
        """
        ...
