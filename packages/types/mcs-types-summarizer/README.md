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

The summarizer thinks in the model's **context window** — the number a developer
actually has, straight off the model card (`context_window=32768` for a qwen3:4b,
`1_000_000` for gpt-5.6). Everything else is derived:

    input budget per call = context_window − answer reserve − template overhead

`LLMPort` deliberately reports no window, so unset it assumes a conservative 4096 until
the backend teaches the real number: a `ContextWindowExceeded` with a named limit
**replaces the window outright** — the backend stated its capacity — and the same
document never hits the same wall twice. That state lives here, with the component doing
the planning, not on the adapter.

An overflowing chunk is **split, not dropped**: every leaf of the document gets read, or
the failure surfaces.

### The Ollama trap: silent clipping, measured

Ollama serves models at its `num_ctx`, **not** at the model card's window — and input
beyond it is dropped **without any error**: measured locally, the *start* of the prompt
was cut, `finish_reason` said `"stop"`, and usage dutifully reported exactly the window
(32 767 for `num_ctx=32768`). The overflow exception this summarizer learns from never
fires there.

So the summarizer cross-checks the one measurement a backend cannot help giving: when
the reported prompt tokens are far below what the prompt holds (factor 2, with an
absolute floor — the estimate is ±30%), the silent clip is turned into the loud
`ContextWindowExceeded` it should have been, and the *report* becomes the window. A
1M-window claim against a 4k `num_ctx` is caught and relearned; a 10% trim is not
provable by arithmetic and stays the operator's job: set `num_ctx` to match the card.

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
