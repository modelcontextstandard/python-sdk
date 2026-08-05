"""Retrieve a page over plain HTTP.

Sits where ``gmail_connector`` sits in the mail driver: protocol logic in the
driver package, transport delegated to an adapter. This one is deliberately
thin -- it fetches and reports **what it got**, which over HTTP is always the
markup as served.

It therefore satisfies ``want="raw"`` natively and answers ``want="text"`` or
``want="markdown"`` with ``kind="html"``, leaving the conversion to the driver's
strategies. A service-backed connector (Tavily, Jina, Firecrawl) will do the
opposite: return ``kind="markdown"`` directly, because its extraction already
happened server-side, and refuse ``want="raw"`` because it never had the markup.

Neither behaviour is hard-coded anywhere. The connector states what it produced;
the driver adapts if it can.
"""

from __future__ import annotations

import logging
from typing import Any, Protocol, runtime_checkable

from mcs.types.web import WebPage

logger = logging.getLogger(__name__)

#: Browsers get served content, unknown agents get served CAPTCHAs. Identifying
#: as a real browser is what the reference implementations do too.
DEFAULT_USER_AGENT = (
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
    "(KHTML, like Gecko) Chrome/125.0 Safari/537.36"
)


@runtime_checkable
class HttpPort(Protocol):
    """The slice of an HTTP adapter this connector needs."""

    def request(self, method: str, url: str, **kwargs: Any) -> Any: ...


class HttpPageConnector:
    """Fetch a page over HTTP and return it as served.

    Implements :class:`~.ports.WebFetchPort`.
    """

    def __init__(self, adapter: Any | None = None, *,
                 user_agent: str = DEFAULT_USER_AGENT,
                 timeout: int = 30, **adapter_kwargs: Any) -> None:
        if adapter is None:
            from mcs.adapter.http import HttpAdapter

            adapter_kwargs.setdefault("default_headers", {
                "User-Agent": user_agent,
                "Accept": "text/html,application/xhtml+xml,*/*;q=0.8",
            })
            adapter_kwargs.setdefault("timeout", timeout)
            adapter = HttpAdapter(**adapter_kwargs)
        self._http: HttpPort = adapter

    #: What this connector can produce. ``html`` covers every request: the driver
    #: converts onwards. Declared so a driver can check before asking.
    provides = ("html",)

    def fetch(self, url: str, *, want: str = "text") -> WebPage:
        resp = self._http.request("GET", url)
        resp.raise_for_status()

        content_type = (resp.headers or {}).get("Content-Type", "")
        final_url = getattr(resp, "url", None) or url   # after redirects
        is_html = "html" in content_type.lower()

        # Non-HTML (JSON, CSV, plain text) is passed through untouched whatever
        # was asked for: running a text extractor over JSON only destroys the
        # structure the caller wanted.
        kind = "html" if is_html else "text"

        return WebPage(
            url=final_url,
            text=resp.text,
            kind=kind,
            title=None,                 # the strategy reads it out of the markup
            status_code=resp.status_code,
            content_type=content_type or None,
            meta={"requested": want},
        )
