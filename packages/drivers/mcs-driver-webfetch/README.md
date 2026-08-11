# mcs-driver-webfetch

**Web page fetching for the Model Context Standard (MCS)** -- lets an LLM read any
URL as text, markdown, or (opt-in) raw source.

```python
from mcs.driver.webfetch import WebfetchToolDriver

driver = WebfetchToolDriver()                 # plain HTTP; text + markdown
driver.execute_tool("fetch_page", {"url": "https://example.com"})

driver = WebfetchToolDriver(allow_raw=True)   # also exposes format="raw"
```

---

## Architecture: the adapter fetches, the driver interprets

This is the split that matters, and it is not obvious:

```
  adapter            →  always returns RAW bytes/markup
    mcs-adapter-http        plain HTTP
    (browser adapter)       renders JavaScript first, still returns markup
    (service adapter)       someone else's fetcher, still returns markup

  ToolDriver         →  turns RAW into what the model asked for
    format="raw"            hand the markup over untouched (opt-in)
    format="text"           run extraction strategies
    format="markdown"       structure-preserving conversion
```

**An adapter is transport.** It moves bytes; it does not decide what the content
*means*. Whether the page arrives over `requests`, a headless browser, or a
remote extraction service, the adapter's job ends with the markup.

**Interpretation is a strategy in the driver.** That is where MCS already keeps
this kind of decision -- `PromptStrategy` for encoding a call, `ExtractionStrategy`
for recognising one. Content extraction is the same shape of problem: several
approaches exist, none is universally right, so the choice has to be swappable.

Everything below is the evidence for why it has to be that way.

---

## Three questions, three answers

A page is not one thing. What a caller needs depends on the question:

| Question | Needs | Example |
|---|---|---|
| *What does this page say?* | text | research, summarising, Perplexity-style Q&A |
| *How is this page built?* | markup | which scripts it loads, which CSS classes a row carries |
| *Do something on this page* | a browser | click, log in, submit, paginate |

The first two are the **same capability** -- "give me this URL" -- in two
representations, which is why they are one tool with a `format` parameter and not
two tools. The third is a **different capability** (state, session, ordering) and
belongs in a separate browser driver.

Measured on `github.com/trending?since=weekly`:

| | text extraction | raw |
|---|---|---|
| „which scripts are embedded?" | **cannot answer** | 6 `script src`, 3 inline |
| „which classes on the repo rows?" | guesses wrong | `Box-row`, 13× |

A text extraction has thrown the markup away by definition. No amount of
extraction quality recovers it -- hence `format="raw"`.

---

## Why extraction is pluggable: the listing problem

Readability-style extractors look for **the one article** on a page and discard
the rest. On a listing page, the list *is* the content -- so they discard the
content. Measured, same URL, same day:

| Extractor | Characters | Repositories found |
|---|---|---|
| tag stripping (`strip`) | 13 410 | **13** ✓ |
| trafilatura (`readable`) | 371 | 1 ✗ |
| OrioSearch `/extract` (Trafilatura-based) | 481 | 1 ✗ |

Against an *article* (Cloudflare blog post) the ranking inverts -- trafilatura
returns 8 237 characters of clean prose where stripping returns 9 008 with
navigation mixed in. Neither extractor is "better". They are right about
different **page types**.

This is a known, documented problem, not a quirk of our setup:

> *"Readability mode extracts only the main article content, stripping away
> everything else. However, this approach has limitations on listing pages where
> the 'main content' IS the list of items rather than article text."*

and, from a 2025 paper on the same failure:

> *"General purpose web agents struggle to extract all data from listing pages […]
> they cannot extract all of the data."*
> — [WebLists, arXiv 2504.12682](https://arxiv.org/html/2504.12682v1)

The benchmark numbers explain *why*: trafilatura leads on **precision** (0.978,
highest mean F1 at 0.937), Readability leads on **recall** (0.929). A
precision-optimised extractor drops anything it is unsure about -- which on a
listing page is everything after the first entry.

### The default is `strip`, on an asymmetry

Stripping leaves noise in; the model sees it and can ignore it. Readability can
drop content silently, and *nobody* -- not the model, not the operator -- can tell
from the result that something is missing.

**Visible noise beats invisible loss.** That is the whole argument for the
default, and it is also why a "clean up the menus" filter was considered and
rejected: any filter aggressive enough to remove a language picker will
eventually remove a real list.

### The multi-strategy option — read from the source, not the summary

[`agent-fetch`](https://github.com/teng-lin/agent-fetch) runs eight strategies in
parallel (Readability, text density, JSON-LD, Next.js `__NEXT_DATA__`, React
Server Components, Nuxt payload, React Router hydration, CSS selectors).

Second-hand descriptions of it say *"readability wins unless another strategy
finds 2× more content"*. **That is not what the code does**, and the difference
matters. From `src/extract/content-extractors.ts`:

```javascript
if (densityLen > readLen * COMPARATOR_LENGTH_RATIO && densityLen >= GOOD_CONTENT_LENGTH) {
    effectiveReadability = null;      // disqualify, don't outvote
}
// ...then: among candidates over the good threshold, the longest wins
```

The ratio is a **veto, not a selector**. It does not ask "which result is
bigger", it asks "did readability misjudge this page so badly that it should not
be trusted at all". Only afterwards does length decide, and only among results
that cleared a quality bar.

That ordering is the whole trick. Length alone would pick raw stripping every
time, because keeping the navigation always yields more characters than removing
it.

Three further details worth copying:

- **Two thresholds**, not one: `GOOD_CONTENT_LENGTH = 500` (worth considering)
  and `MIN_CONTENT_LENGTH = 200` (fallback bar when nothing is good).
- **A priority order** for the fallback tier, so "nothing was good" still has a
  defined answer rather than an arbitrary one.
- **Metadata is composed separately** (`composeMetadata`): the strategy that wins
  on *content* need not have the best *title*. A strategy can read the title
  correctly while misreading the body.

Checked against our measurements, the real rule decides correctly both times:

| Page | strip | readable | Decision | Picked |
|---|---|---|---|---|
| GitHub trending | 13 410 | 371 | readable under 500 → vetoed | strip ✓ 13 repos |
| Cloudflare article | 9 008 | 8 237 | readable fine, 1.1× < 2× | readable ✓ clean prose |

Note what this is *not*: it never throws content away. Two complete candidates
exist and one is chosen. That is categorically different from filtering.

---

## The Python extraction landscape

For anyone implementing a strategy, the field as of 2026:

| Library | Approach | Notes |
|---|---|---|
| **trafilatura** | XPath rules + readability fallback | Highest F1/precision; powers FineWeb and RefinedWeb. Pure Python + lxml. |
| **resiliparse** | C++/Cython parser + heuristics | Fast; strong on table-rich pages. |
| **jusText** | stopword-frequency block classification | Highly tunable; generic settings underperform. |
| **goose3** | most precise algorithm | High precision, notable recall cost. |
| **boilerpy3** | sequence labeling over blocks | |
| **newspaper4k** | news-oriented | No structured text or comment extraction. |
| **readabilipy** | Mozilla Readability | **Shells out to Node.js** -- see the trap below. |

Benchmarks: [WCXB](https://webcontentextraction.org/) ·
[trafilatura evaluation](https://trafilatura.readthedocs.io/en/latest/evaluation.html) ·
[scrapinghub article-extraction-benchmark](https://github.com/scrapinghub/article-extraction-benchmark)

---

## What the reference implementations do

| Project | Extraction | Interface |
|---|---|---|
| **MCP `fetch`** | readabilipy + markdownify, hard-wired | `fetch(url, max_length=5000, start_index=0, raw=false)` |
| **OpenCode** | Turndown + htmlparser2 | `format: text \| markdown \| html` |
| **Claude Code** | markdown, then a *small model* answers a prompt against it | keeps full pages out of the main context |
| **Anthropic `web_fetch`** | server-side | `max_uses`, `allowed_domains`, `citations`, `max_content_tokens`; **no JavaScript support** |
| **Jina Reader** | service-side, renders JS | CSS selector, token budget, engine choice |
| **Tavily / Firecrawl / Exa** | service-side | search with optional content, or separate extract |

### The trap: hard-wiring an extractor

Both agents that extract *in-process with a fixed library* have open bugs from
exactly that:

- **MCP `fetch`** hard-codes `use_readability=True`, which shells out to Node.js
  -- an undeclared dependency. Without Node the subprocess hangs with no timeout;
  the user sees `"Timed out while waiting for response"` after 60 s while the HTTP
  request itself took 0.3 s. [Issue #4199](https://github.com/modelcontextprotocol/servers/issues/4199),
  still open. The issue's own conclusion: *"Hardcoding extraction library choices
  into a fetch tool couples the interface to specific implementations."*
- **OpenCode** hits the sibling problem with `HTMLRewriter` in Electron
  ([#26187](https://github.com/anomalyco/opencode/issues/26187),
  [#27305](https://github.com/anomalyco/opencode/issues/27305)).

This is the reason extraction sits behind a strategy here rather than inside the
tool: the runtime dependency moves to where it can be swapped, and a missing
optional library degrades to a working fallback instead of a hanging tool.

---

## Handling large pages

Five patterns are in use; we implement the first and leave the rest to the caller:

| Pattern | Who | Mechanism |
|---|---|---|
| **Paging** | MCP, this driver | `start_index` + `next_start_index` in the result |
| **Small-model filter** | Claude Code | page → cheap model → answer only |
| **CSS selector** | Jina Reader | caller narrows before extraction |
| **Multi-strategy** | agent-fetch | run several, pick the most complete |
| **Interaction** | Firecrawl `/interact` | paginate inside one browser session |

A driver never talks to an LLM, so the small-model filter is deliberately *not*
implemented here -- that is the client's move, and the client can always make it.

### Why `max_chars` defaults to 20 000

A page legitimately consists mostly of navigation and filters. GitHub's trending
page extracts to 13 410 characters, of which the **first 10 787 (80 %)** are the
language picker and site furniture before the first repository appears.

At the MCP server's default of 5 000, a model would have received a list of
language names and nothing else. The page is what it is; give the model enough
room to reach the part it came for, and let it continue with `start_index`.

A caution from the same research, against reaching for `raw` by default:

> *"passing raw HTML to the LLM wastes context window on div tags, CSS classes and
> navigation elements, and the LLM might hallucinate information that was in the
> HTML noise rather than the actual content."*

---

## Implementation notes

### Void elements will eat your document

`<meta>`, `<link>`, `<br>`, `<img>` and friends have **no end tag**. Treating one
as a skippable container opens a region that never closes -- and a real page
carries ~50 `<meta>` tags. Symptom: extraction returns an *empty string* while
the title still comes through correctly, which makes the parser look healthy.
Cost: two debugging rounds. There is a regression test for it.

The same applies to elements HTML lets you leave *unclosed* (`<option>`, `<li>`,
`<p>`): they have content but no guaranteed end tag.

### Links are sanitised before they reach markdown

`javascript:`, `data:` and `vbscript:` hrefs are dropped -- the link text stays,
the target does not. Whitespace evasions (`java\tscript:`) are normalised first.

The path this closes is indirect and easy to miss: markdown goes to the LLM, and
the LLM's answer is often rendered *as markdown* in a chat UI. An unsanitised
href therefore travels from an attacker's page, through the model, into a user's
browser as a clickable link. Found during a re-read of agent-fetch's
`sanitizeHtml`; our first implementation emitted
`[Click me](javascript:alert(document.cookie))` verbatim.

### Non-HTML is never extracted

JSON, CSV and plain text are handed over untouched. Running a text extractor over
JSON only destroys the structure the caller wanted.

### Inline whitespace is meaningful

`<span>alpha</span> <span>beta</span>` must not become `alphabeta`. Whitespace
between inline elements is the word boundary; dropping it as "empty" silently
corrupts the text the model reads. Both are regression-tested.

### Redirects

`WebPage.url` reports the URL that *answered*, not the one requested -- a redirect
can change what the content is about. This required adding `HttpResponse.url` to
`mcs-types-http`.

---

## Tool surface

```
fetch_page(url, format="text"|"markdown"|"raw", max_chars=20000, start_index=0)
```

Returns `url`, `title`, `format`, `content`, `truncated`, and -- when truncated --
`total_chars` and `next_start_index`, so the model can continue rather than guess
what it missed.

Asking a backend for something it cannot produce **raises** rather than
degrading quietly: a service connector that only ever sees extracted content
cannot answer `format="raw"`, and returning text instead would answer a question
the caller did not ask. Same principle as everywhere else here -- fail visibly
rather than deliver invisibly.

### `raw` is opt-in

```python
WebfetchToolDriver()                   # formats: text, markdown
WebfetchToolDriver(allow_raw=True)     # formats: text, markdown, raw
```

Without `allow_raw`, the format is **not advertised at all** -- it is absent from
the tool's `enum` and from its description, so the model never learns the option
exists. Listing a format the driver will refuse only teaches it to try and be
refused, once per conversation.

It is still refused if guessed (`RawNotAllowed`), because unadvertised is not
unreachable: a client can call `execute_tool` directly.

Why off by default: raw is the one format that hands the model *everything* a
page contains -- script bodies, hidden elements, comments. That is exactly what
makes it useful for inspecting a page, and exactly what makes it a
prompt-injection surface that no sanitiser can close without destroying the
format's purpose. A driver that only answers questions about *content* should not
carry that risk.

---

## Outlook

**Several adapters per driver.** Today one connector answers everything it can.
The natural next step is a *chain*: a markdown-capable service for reading, a
plain-HTTP or browser connector for `raw`, and the driver picks whichever can
serve the request -- instead of raising. `WebPage.kind` and the `provides`
declaration on a connector are already the machinery this would need.

That also composes with the reason services exist in the first place: CAPTCHAs,
anti-bot fingerprinting and JavaScript rendering. A deployment could route
ordinary pages over plain HTTP and fall back to a paid service only where it is
actually required, without the model or the tool surface changing at all.

**Strategies worth porting.** `agent-fetch` extracts from framework payloads
directly -- `__NEXT_DATA__`, React Server Components, Nuxt, React Router
hydration, JSON-LD. On a JavaScript-heavy site that is often *better* than
rendering the page, because the data is right there in the markup as structured
JSON. None of that needs a browser.

**TLS fingerprinting.** `agent-fetch` impersonates Chrome at the TLS layer, not
just via `User-Agent`. Modern anti-bot systems fingerprint the handshake, so a
Python HTTP client is recognisable however its headers are set. This is an
adapter concern (transport), not a strategy concern -- another reason the two are
separate.

**A browser driver.** Clicking, logging in, submitting and paginating is a
different capability, not a `format`. It belongs in its own ToolDriver, where
accessibility snapshots (~200-400 tokens versus thousands for a screenshot) are
the interesting design question.

## Installation

```bash
pip install mcs-driver-webfetch          # HTTP, tag-stripping, and markdown
pip install mcs-driver-webfetch[text]    # + trafilatura for article-quality extraction
```

### Why markdown is *not* an extra

`nh3` and `markdownify` are required dependencies. The rule we apply:

> An optional dependency is right when its absence **degrades** something. It is wrong
> when its absence **removes a capability the tool still advertises**.

`format="markdown"` is listed in the tool schema, so a model will choose it — and it
often should, because markdown is the only format that keeps links, which is exactly
what a model needs to cite what it read. Were the libraries optional, that choice would
raise a `MarkdownUnavailable` the model can neither predict nor fix; it would retry and
fail identically.

Hiding the format when the libraries are missing is not the way out either: the tool
schema would then depend on what happens to be installed, and a driver's data sheet has
to describe the driver, not one machine's environment.

The cost of requiring them is small — `nh3` pulls nothing, `markdownify` two small
pure-Python packages.

`trafilatura` stays optional, and legitimately so: without it the BestOf chain simply
votes for another extractor, so its absence costs *quality*, never a capability. It is
also the one heavy dependency here (lxml and six more).

---

## Attribution

The selection logic in `strategies.py` is derived from
**[agent-fetch](https://github.com/teng-lin/agent-fetch)** by the agent-fetch
Contributors (MIT License, © 2025) -- specifically the design in
`src/extract/content-extractors.ts`: the ratio-as-veto mechanism, the two-tier
threshold (`GOOD_CONTENT_LENGTH` / `MIN_CONTENT_LENGTH`), the priority order for
the fallback tier, and metadata composition independent of the content winner.

No code was copied -- agent-fetch is TypeScript and considerably larger in scope
(crawling, TLS fingerprinting, PDF, eight extraction strategies). What was taken
is the *design*, and it was read from the source rather than from descriptions of
it, which turned out to matter: second-hand summaries describe the ratio as a
selector ("2× more wins"), while the code uses it as a veto and lets length decide
only afterwards. Implementing the summary would have picked raw stripping on every
article.

The link sanitisation in `_safe_href` addresses the same class of risk that
agent-fetch handles in `sanitizeHtml` (`src/extract/utils.ts`), narrowed to the
one place this driver emits attacker-controlled URLs.

Worth reading in full if you work on this area.

## Further reading

- **[WebLists: Extracting Structured Information From Complex Interactive
  Websites Using Executable LLM Agents](https://arxiv.org/html/2504.12682v1)**
  (arXiv:2504.12682) -- the listing-page failure mode, measured and named:
  general-purpose web agents navigate to the right page and still fail to extract
  all of its items. Directly relevant to why `strip` is the default here.
- **[WCXB: A Multi-Type Web Content Extraction Benchmark](https://arxiv.org/html/2605.21097)**
  (arXiv:2605.21097) and the [leaderboard](https://webcontentextraction.org/) --
  where the precision/recall numbers quoted above come from.
- **[trafilatura evaluation](https://trafilatura.readthedocs.io/en/latest/evaluation.html)**
  -- the maintainer's own comparison against the other Python extractors.

## Links

- **Homepage:** <https://www.modelcontextstandard.io>
- **Source:** <https://github.com/modelcontextstandard/python-sdk>

## License

Apache-2.0
