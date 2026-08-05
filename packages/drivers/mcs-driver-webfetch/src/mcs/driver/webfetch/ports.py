"""Adapter port for web-fetching drivers.

Defines the contract any page-retrieval adapter must satisfy. Adapters fulfil
this protocol through structural subtyping -- they do **not** import or inherit
from this module.

The port is deliberately narrow: *give me this URL as readable text*. Everything
that differs between backends stays behind it --

* plain HTTP plus boilerplate stripping (fast, no JavaScript),
* a headless browser that renders first (slow, handles JavaScript),
* a search API's extract endpoint (someone else's cache and extraction).

That is the whole point. The LLM only ever sees ``fetch_page(url)``; which
technique answers it is a deployment decision, not a prompt decision. A driver
can even escalate -- try HTTP, and if the result looks empty because the page
builds itself in JavaScript, retry through a rendering adapter -- without the
model ever knowing.
"""

from __future__ import annotations

from typing import Protocol, runtime_checkable

from mcs.types.web import WebPage


@runtime_checkable
class WebFetchPort(Protocol):
    """Contract that any page-retrieval adapter must satisfy."""

    def fetch(self, url: str, *, want: str = "text") -> WebPage:
        """Retrieve *url*.

        Parameters
        ----------
        url :
            Absolute ``http``/``https`` URL.
        want :
            What the caller would like: ``"text"``, ``"markdown"`` or ``"raw"``.

            A **wish, not an instruction.** An implementation returns whatever it
            can and announces it in :attr:`~mcs.types.web.WebPage.kind`; the
            driver converts onwards if it can. This is what keeps both worlds
            usable: a plain HTTP connector only ever has markup, while a service
            connector (Tavily, Jina, Firecrawl) returns content its own extractor
            already reduced -- and asking it for ``raw`` is a request it cannot
            honour, because it never saw the markup.

            Prescribing either way would hard-code the wrong thing. "Always raw"
            locks the services out, or wastes the extraction they already did.
            "Always text" makes markup unreachable, and with it every question
            about how a page is *built* -- which scripts it loads, which classes
            an element carries.

        Returns
        -------
        WebPage
            With :attr:`~mcs.types.web.WebPage.kind` stating what the content
            actually is. Implementations raise on transport failure rather than
            returning an empty page -- the driver turns that into a tool error
            the model can read and react to.

        Notes
        -----
        Truncation and paging are **not** here on purpose: they are about fitting
        a context window, which is the driver's concern, not the backend's. A
        connector returns the document; the driver decides how much of it the
        model sees.
        """
        ...
