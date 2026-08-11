# mcs-driver-web

**The composite web driver for the Model Context Standard (MCS)** -- search the
web and read pages through one driver.

```python
from mcs.driver.web import WebDriver

driver = WebDriver(api_key="tvly-...")                        # Tavily
driver = WebDriver(api_key="...", base_url="https://my-search-service")

system = driver.get_driver_system_message()
# ... hand `system` to any LLM, feed its reply back:
driver.process_llm_response(llm_output)
```

The model gets the two tools it actually wants for research:

| Tool | Purpose |
|---|---|
| `web_search` | find sources when you have no URL |
| `fetch_page` | read a specific URL as text or markdown |

## The same shape as `mcs-driver-mail`

`MailDriver` combines `mailread` + `mailsend`. This is its web counterpart:
`websearch` + `webfetch`, two capabilities that are built and configured
separately, presented to the LLM as one set of tools.

Why they are separate underneath:

- They **fail differently.** A search backend runs out of quota; a fetch backend
  hits a CAPTCHA. Bundled, one outage takes both down.
- They are **configured differently.** Search needs an API key and a service URL;
  fetch needs a transport, and possibly a browser.
- They are **useful alone.** An agent with a known URL never searches; a research
  agent may only need excerpts.

Joined here, the client needs no orchestration: the model searches, picks, and
reads, all inside one driver.

## Configuration

```python
WebDriver(
    api_key="...",             # search backend
    base_url="https://...",    # any Tavily-compatible service
    allow_raw=False,           # fetch half: expose format="raw"? (see below)
    search_kwargs={...},       # forwarded to WebsearchToolDriver
    fetch_kwargs={...},        # forwarded to WebfetchToolDriver
)
```

`allow_raw` stays **off** by default, and the safety default survives
composition: while off, `format="raw"` is not advertised to the model at all.
Raw hands over everything a page contains -- script bodies, hidden elements,
comments -- which is a prompt-injection surface no sanitiser can close without
destroying the format's purpose. Turn it on for drivers whose job includes
inspecting pages. See [`mcs-driver-webfetch`](../mcs-driver-webfetch/README.md).

## Tool name collisions fail at construction

If both halves ever claimed the same tool name, dispatch would be arbitrary and
the failure would only surface at call time -- on a specific tool, in production.
The composite refuses to build instead.

## Installation

```bash
pip install mcs-driver-web            # search + fetch, including markdown
pip install mcs-driver-web[full]      # + article-grade extraction (trafilatura)
```

The one extra belongs to the fetch half: `trafilatura` for readability-grade
text. Without it `format="text"` still works -- the BestOf chain simply votes for
another extractor -- so its absence costs quality, never a capability.

Safe markdown (`nh3` + `markdownify`) is **not** an extra but a required
dependency. `format="markdown"` is advertised in the tool schema, so a model will
pick it; an optional dependency would turn that choice into a runtime error no
retry can fix. See [`mcs-driver-webfetch`](../mcs-driver-webfetch/README.md) for
the rule.

## The pieces

| Package | Role |
|---|---|
| [`mcs-driver-websearch`](../mcs-driver-websearch/README.md) | search over any Tavily-compatible API |
| [`mcs-driver-webfetch`](../mcs-driver-webfetch/README.md) | page retrieval, extraction strategies, and the research behind them |
| `mcs-types-web` | `SearchResult`, `WebPage` -- shared value objects |

The webfetch README is the long one: it documents the listing-page extraction
problem, the measured comparison between extractors, and what the reference
implementations get right and wrong.

## Links

- **Homepage:** <https://www.modelcontextstandard.io>
- **Source:** <https://github.com/modelcontextstandard/python-sdk>

## License

Apache-2.0
