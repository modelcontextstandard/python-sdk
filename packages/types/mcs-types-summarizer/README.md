# mcs-types-summarizer

**Query-focused summarization for the Model Context Standard (MCS)** — ask a question
of a text that does not fit a context window, and get an answer distilled from all of it.

```python
from mcs.types.summarizer import LLMSummarizer
from mcs.adapter.llm.completion import CompletionLLMAdapter

llm = CompletionLLMAdapter("qwen3:4b", base_url="http://localhost:11434/v1")
summarizer = LLMSummarizer(llm)

s = summarizer.summarize(long_document, "Wie lange ist die Kündigungsfrist?")
s.text        # the answer, distilled from the whole input
s.strategy    # what actually ran: "stuff" | "map_reduce" | "refine"
s.chunks      # how finely the input had to be cut
s.truncated   # incomplete? (see below -- this flag exists for a measured reason)
s.usage       # measured token cost, summed over every call
```

## Why this is its own package

Fetching a web page, reading a PDF and pulling a transcript differ per source.
Condensing the result under a question does not — it is the same operation every time.
So it lives here once, and any driver takes it **injected at construction**
(`WebfetchToolDriver(..., summarizer=...)`), the same way `PermissionMiddleware` is
configuration rather than architecture. No summarizer injected → the capability simply
is not offered.

The LLM arrives the same way: `LLMSummarizer(llm)` takes any `LLMPort` — an MCS adapter,
or the three-line wrapper around a client's own governed stack. This package imports
**no** model SDK and only `mcs-types-llm`, which is itself zero-dependency.

## The query is required

This is query-focused summarization, the established NLP task. "Summarise this" is not a
second operation — it is one query among many, next to "what does it say about notice
periods?" and "list every email address". A `Summary` carries its query, so a stored
result is never prose of unknown intent.

## Strategies, by their established names

| name | what happens | when |
|---|---|---|
| `stuff` | one call, whole text | it fits |
| `map_reduce` | every chunk answers independently, then merge — recursively when needed (the bottom-up tree others call `tree_summarize`) | the promotion default: order-independent, reproducible |
| `refine` | fold chunk after chunk into a running answer | cheaper, order-dependent — a choice, never the silent default |
| `auto` *(default)* | `stuff` if the estimate fits, else `map_reduce` | — |

A **pinned** strategy is honoured into failure: `strategy="stuff"` with an oversized
text raises rather than silently becoming something else. `concurrency=N` fans the map
phase out over threads; the merge is order-stable either way, so the answer does not
depend on scheduling.

## The planner remembers; the transport does not

`LLMPort` deliberately reports no context window, so the budget is discovered by
working: the summarizer starts from `chunk_tokens` (default 3000) and, when a call
returns `ContextWindowExceeded`, **learns** — the limit the backend named shrinks the
working budget for everything after. The same document never hits the same wall twice,
and the state lives here, with the component doing the planning, not on the adapter.

An overflowing chunk is **split, not dropped**: every leaf of the document gets read, or
the failure surfaces.

## `truncated` exists for a measured reason

On a local qwen3, a modest answer budget was consumed *entirely by reasoning*: the model
returned an empty string, `finish_reason="length"`, and no error anywhere. Without a
flag, "the document says nothing about this" and "the budget was swallowed" are
indistinguishable — and an incomplete summary must never look like a short one. Any
call along the way that hit its cap marks the whole `Summary` as `truncated`.

Relatedly: `text == ""` with `truncated == False` is a *legitimate answer* — the text
contained nothing relevant to the query. Map calls answer a sentinel for empty chunks,
which is filtered before merging; a document of nothing relevant costs no merge call.

## Tests

Everything above is covered offline against a scripted fake (`pytest` — no model, no
network). The live proof runs deselected by default:

```bash
pytest packages/types/mcs-types-summarizer -m e2e     # local Ollama; same MCS_E2E_* vars
```

It buries one fact mid-document between plausible filler, forces real chunking with a
small budget, and asserts the fact survives map and merge — plus the truncation flag,
live.

## Installation

```bash
pip install mcs-types-summarizer
```

## Links

- **Homepage:** <https://www.modelcontextstandard.io>
- **Source:** <https://github.com/modelcontextstandard/python-sdk>

## License

Apache-2.0
