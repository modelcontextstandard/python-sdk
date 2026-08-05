# mcs-types-web

**Shared web types for the Model Context Standard (MCS).**

Contains `WebPage` and `SearchResult` -- the library-agnostic value objects
every MCS web adapter returns, whether it fetches with plain HTTP, drives a
headless browser, or calls a search API.

Zero runtime dependencies.

## Installation

```bash
pip install mcs-types-web
```

## Why these types exist

A driver should not care *how* a page was retrieved. Putting the result shape in
its own package means a `WebFetchPort` implementation can be swapped -- HTTP +
boilerplate stripping today, a rendering browser tomorrow -- without touching a
driver or a test.

```python
from mcs.types.web import WebPage, SearchResult

page = WebPage(url="https://example.com", text="Readable content...",
               title="Example", status_code=200)

hit = SearchResult(url="https://example.com", title="Example",
                   snippet="A short excerpt", score=0.91)
```

`WebPage.text` is **readable text, not markup**: raw HTML is mostly navigation
and scripts, and spending an LLM's context on that is waste. `truncated` says
whether a length budget cut the text -- the model should know when it is not
seeing everything.

`SearchResult.content` is optional on purpose. Some backends (Tavily, Exa,
Firecrawl) can return page content together with the hits, saving a round trip;
others only return links. `None` means "fetch it separately if you need it".

## Links

- **Homepage:** <https://www.modelcontextstandard.io>
- **Source:** <https://github.com/modelcontextstandard/python-sdk>

## License

Apache-2.0
