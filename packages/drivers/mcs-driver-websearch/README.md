# mcs-driver-websearch

**Web search for the Model Context Standard (MCS)** -- lets an LLM search the web
through any **Tavily-compatible** API.

```python
from mcs.driver.websearch import WebsearchDriver

driver = WebsearchDriver(api_key="tvly-...")                 # Tavily
driver = WebsearchDriver(api_key="...", base_url="https://my-search-service")
driver.execute_tool("web_search", {"query": "model context standard"})
```

## Why Tavily-compatible

Tavily's request/response shape has become a de-facto interface for agent search.
Tavily itself speaks it, self-hosted services speak it, and so do several
alternatives -- so one connector reaches all of them by changing `base_url`.

That is the same argument MCS makes for OpenAPI: when a service already describes
itself in a shape others speak, you do not need a bespoke integration per vendor.

## Tool surface

```
web_search(query, max_results=5, topic="general", include_content=false,
           include_domains, exclude_domains, time_range)
```

Returns `query`, `count`, `results[]` (`url`, `title`, `snippet`, optional
`published` and `content`) and -- when the backend synthesised one -- `answer`.

**Verticals are a parameter, not extra tools.** `topic="news"` rather than a
separate `news_search`. Four near-identical tools would bloat the prompt for a
distinction the backend already models behind one endpoint, and every extra tool
is one more choice the model can get wrong.

**`include_content` is per call, not per driver.** Some backends return full page
text with the hits, which saves a fetch per source -- and costs a great deal of
context when the excerpts would have been enough to pick one. The caller who
knows what it intends to do decides.

## Field names to get right

The wire format is easy to misread, and the mistake is quiet:

| Tavily field | Meaning | MCS field |
|---|---|---|
| `content` | the engine's **excerpt** | `SearchResult.snippet` |
| `raw_content` | the **full page text**, only when requested | `SearchResult.content` |

Mapping `content` onto `content` would silently give the model a two-line excerpt
where it expected an article.

Unknown extras (thumbnails, favicons, engine names) are kept in
`SearchResult.meta` rather than dropped, so a richer backend loses nothing while
the common fields stay predictable.

## `include_answer` is opt-in

Answer synthesis costs the backend an LLM call, so a caller who does not need it
should not pay for it -- the hits carry their own excerpts.

There is a second reason. Backends differ in how they behave when synthesis is
unavailable: the graceful response is `answer: null` alongside the normal
results, but a stricter implementation may treat the whole request as
unsatisfiable and return an empty result set with HTTP 200 -- a failure that
looks exactly like "nothing found". Sending the flag unconditionally therefore
risks silent emptiness on some deployments.

## Search and fetch are separate drivers

They compose (find sources, then read one) but they are built apart, because:

- they **fail differently** -- a search backend runs out of quota, a fetch backend
  hits a CAPTCHA; bundled, one outage takes both down
- they are **configured differently** -- search needs an API key and a service
  URL, fetch needs a transport and possibly a browser
- they are **useful alone** -- an agent with a known URL never searches

Use [`mcs-driver-web`](../mcs-driver-web/) when you want both under one driver,
the way `mcs-driver-mail` combines reading and sending.

## Installation

```bash
pip install mcs-driver-websearch
```

## Links

- **Homepage:** <https://www.modelcontextstandard.io>
- **Source:** <https://github.com/modelcontextstandard/python-sdk>

## License

Apache-2.0
