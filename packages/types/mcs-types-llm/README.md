# mcs-types-llm

**Shared LLM types for the Model Context Standard (MCS).**

Contains `LLMPort` (the protocol any LLM backend must satisfy when an MCS component needs
to ask a model something), `LLMResponse` / `TokenUsage` (what came back and what it cost),
the `ContextWindowExceeded` error, and the token estimation fallback.

This package has **zero dependencies**.

## MCS still does not own the LLM loop

The client does — it holds the conversation, the history, the streaming and the tool
rounds. Nothing here changes that.

This port is for the other case: a component that needs a model for a **bounded sub-task
of its own**, such as a summarizer condensing a document it was handed. One question, one
answer.

## One method

```python
class LLMPort(Protocol):
    def complete(self, prompt: str, *, system: str | None = None,
                 max_completion_tokens: int | None = None, **kwargs: Any) -> LLMResponse: ...
```

No streaming, no tools, no multimodality, no conversation state — those belong to the
client's loop. And no model *metadata* either: a context window and a tokenizer describe
the model, not the connection to it, so an implementation would be guessing on behalf of
whoever chose the model. What comes back instead is what the backend actually **measured**.

`prompt` / `system` / `max_completion_tokens` are the **portable core** — the things a caller can
mean without knowing which backend it was given. `max_completion_tokens` is named (not left to
kwargs) precisely because the wire disagrees on its spelling — `max_tokens` here,
`max_completion_tokens` there — and only the implementation knows which; this is the one
translation the port asks for. Everything in `**kwargs` travels **verbatim**, the call
winning over construction defaults: stop sequences, a JSON `response_format`, a
backend-specific knob. Nothing validates it — the backend is authoritative.

A reusable component (a summarizer) should lean on the core alone; per-call kwargs are a
statement about the specific backend a caller *knows* it has, and a component that
depends on them narrows which models it runs on.

Because the surface is this small, lending an LLM a client *already has* costs three
lines:

```python
class MyLLM:                      # the client's own stack -- cost tracking, PII
    def complete(self, prompt, *, system=None, max_completion_tokens=None, **kwargs):
        return LLMResponse(text=my_stack.ask(prompt, system))
```

That is the recommended path whenever a client has one. A client that has built token
accounting, cost tracking or PII filtering into its LLM calls should lend *that* rather
than let MCS open a second, ungoverned route to a provider. Adapters
(`mcs-adapter-llm-completion` and its siblings) are a convenience for clients that have
no such stack — never a silent default when nothing is passed.

## What comes back

```python
answer = llm.complete(prompt, system="Answer only from the text.", max_completion_tokens=500)

answer.text            # the assistant's text
answer.usage.prompt    # measured input tokens -- the model's own count
answer.usage.completion
answer.usage.reasoning # of the completion, how much went into thinking
answer.usage.cached    # of the prompt, how much came from a cache
answer.truncated       # finish_reason == "length"
answer.model           # which model actually answered -- a gateway may reroute
answer.meta            # the untouched usage block, and any reasoning text
```

The text alone is enough to *use* an answer. It is not enough to **plan the next one**,
and planning is the whole job of a component feeding a long document to a small model.

Every field may be `None` where a backend did not report it — which is different from
zero. A caller calibrating an estimate must skip an unreported call, not record it as
having cost nothing.

### `truncated` is not a nicety

Measured against `qwen3:4b` on a local Ollama:

| `max_tokens` | `finish_reason` | `text` | `completion` |
|---|---|---|---|
| 64 | `length` | `""` | 64 — all of it spent thinking |
| 600 | `stop` | `"Mimi"` | 319 |

A reasoning model can spend an entire answer budget on reasoning and return an **empty
string with no error at all**. A caller that only looked at `.text` would silently
produce nothing. `truncated` is the only signal that this happened, which is why it is a
property rather than something a caller has to infer from a non-standardised
`finish_reason` vocabulary.

## Estimate first, then measure

`estimate_tokens` is the *a priori* guess, for the moment before anything has been sent:

```python
from mcs.types.llm import estimate_tokens

planned = estimate_tokens(chunk)          # ~3 characters per token
```

It assumes **3 characters per token**, deliberately below the ~4 usually quoted for
English prose. The two ways of being wrong do not cost the same: underestimating
overflows the window and wastes a round trip, overestimating just makes one chunk more.
The ~4 figure is also English-prose-specific — German compounds, code, JSON and markup
all pack fewer characters per token, and those are exactly what a document summarizer
meets.

After the first call, stop guessing: `usage.prompt` is the truth for *this* model and
*this* kind of text, and the ratio it implies can be fed back in as `chars_per_token`.

## Overflow is a type, not a message

```python
from mcs.types.llm import ContextWindowExceeded
```

Every backend words "too long" differently — `"maximum context length is ... tokens"`,
`"prompt is too long"`, sometimes with an error code and sometimes not. Without a shared
type each consumer would match on English error strings and break on the next provider.
The adapter translates once; consumers branch on the type, and send less.

When the backend names the real limit it rides along on `.limit` — often the first and
only statement of a budget nothing reports up front.

## Installation

```bash
pip install mcs-types-llm
```

Most users don't need to install this directly — it is pulled in by the packages that
use it.

## Links

- **Homepage:** <https://www.modelcontextstandard.io>
- **Source:** <https://github.com/modelcontextstandard/python-sdk>

## License

Apache-2.0
