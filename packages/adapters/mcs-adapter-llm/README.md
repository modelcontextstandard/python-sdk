# mcs-adapter-llm

**The LLM adapters for the Model Context Standard**: an `LLMPort` over the Chat
Completions wire format, and `ModelInfoProvider` catalogues for model knowledge.
Siblings for other wire formats (`/v1/messages`, `/v1/responses`) will live here too.

```python
from mcs.adapter.llm.completion import CompletionLLMAdapter

llm = CompletionLLMAdapter("gpt-4o-mini", api_key="sk-...")
llm = CompletionLLMAdapter("qwen3:8b", base_url="http://localhost:11434/v1")   # Ollama

llm.complete("Summarise the text below.", system="Answer only from the text.")
```

## You may not need this

MCS does not own the LLM loop, and a client that already calls a model — with its own
cost tracking, rate limiting or PII filtering — should lend *that* rather than let MCS
open a second, ungoverned route to a provider. `LLMPort` is small enough that doing so
costs three lines; see [`mcs-types-llm`](../../types/mcs-types-llm/README.md).

This adapter is for clients that have no such stack. It is never a silent default: a
component that needs an `LLMPort` must be given one explicitly.

## One format, not three

`POST /v1/chat/completions` is the shape practically everything speaks:

| | |
|---|---|
| **local** | Ollama, vLLM, LM Studio, llama.cpp |
| **hosted** | OpenAI, Groq, Together, OpenRouter, DeepSeek, Mistral |
| **compat endpoints** | the big vendors' OpenAI-compatible routes |

The sibling formats (`/v1/responses`, `/v1/messages`) differ because of tool calls,
streaming and thinking blocks. This port has none of those — text in, text out — so
three request builders and three auth schemes would buy identical output. A model
reachable *only* natively is better served by satisfying `LLMPort` directly.

Transport is `mcs-adapter-http`, the one MCS already has, so this package adds **no** new
runtime dependency beyond it.

## Transport only, and stateless

No *guessed* context window, no tokenizer, no remembered limits. Those describe the
**model**, not the connection to it, and an adapter answering for them from its own head
would be guessing on behalf of whoever chose the model — a generic Chat Completions URL
rarely even says which model is behind it.

What it does instead is report what the backend **measured**:

```python
answer = llm.complete(prompt, system="Answer only from the text.", max_completion_tokens=500)

answer.text, answer.usage.prompt, answer.usage.completion
answer.usage.reasoning     # from completion_tokens_details, where a backend sends it
answer.usage.cached        # from prompt_tokens_details
answer.truncated           # finish_reason == "length"
answer.meta["usage"]       # the untouched block, so an unanticipated field is not lost
```

Two backend quirks are absorbed here so consumers never meet them: Ollama's native
`prompt_eval_count` / `eval_count` naming (see
[openclaw#53448](https://github.com/openclaw/openclaw/issues/53448)), and the
non-standard `message.reasoning` field, whose text is where a missing answer budget went
and which appears nowhere else — it lands in `meta["reasoning_text"]`.

### `describe()` — relaying what the endpoint states

The port's inquiry is implemented here over the **same injected `_http`** every
completion uses — the MCS transport promise holds; a type never opens a network path,
and the adapter never opens a second one. Two sources, tried in order, both measured:

1. **`GET {base_url}/models/{id}`** — the spec's route. Enriched servers (vLLM's
   `max_model_len`, gateways like OpenRouter) answer usefully and the inquiry ends
   here; a gateway's `{"data": {...}}` envelope is unwrapped, and an OpenRouter-style
   `architecture` block states modalities in **both directions**
   (`input_modalities` / `output_modalities` lists, with the older
   `"text+image->text"` string as fallback — explicit lists win). **OpenAI itself
   answers meagrely**: the route resolves `gpt-5.5`, but states only
   `id / created / owned_by` — no window, no capabilities. And the `/v1/models`
   *list* does not even contain the dated alias ids.
2. **`POST {root}/api/show`** — only when `base_url` ends in `/v1` (an Ollama
   convention) and the first source stated no window. Rich where it answers:
   `capabilities` (`completion, tools, thinking, vision, audio`) and the
   architecture's `context_length`.

| endpoint | states |
|---|---|
| OpenAI `GET /v1/models/gpt-5.5` | identity fields only → `ModelInfo` with all-`None` fields |
| vLLM `GET /v1/models/{id}` | `max_model_len` → `context_window` |
| OpenRouter-style gateways | `architecture.input_modalities: ['text', 'image', ...]` → both directions verbatim |
| Ollama `GET /v1/models/{id}` | meagre → falls through |
| Ollama `POST /api/show` | `qwen3.context_length=262144`, capabilities → window, tools, thinking, modalities |

**Modalities need one translation of direction.** Ollama names what a model
*understands* without saying which way — measured across three local models:

| model | capabilities stated | relayed as |
|---|---|---|
| qwen3:4b | `completion, tools, thinking` | in `("text",)`, out `("text",)` |
| qwen3.6 | + `vision` | in `("text", "image")` |
| gemma4:e4b | + `vision, audio` | in `("text", "image", "audio")` |

On a completions API those capabilities are **inputs** — generation is not served
here, so output stays `("text",)`. The raw capabilities list rides in `meta` for the
day that changes. Gateway `architecture` blocks need no such translation: they state
both directions themselves, including image on the *output* side for image-producing
chat models, and are relayed verbatim.

The Ollama caveat is the reason `describe()` is worded as *stating*, not *knowing*:
`262144` is the model card's architecture limit, while the server actually serves its
configured `num_ctx` (`32768` here) and silently truncates beyond it. A statement is a
planning input, not a guarantee — consumers keep their clip detectors in force.

Everything harvested lands untouched in `ModelInfo.meta` (bulk fields like tensors,
license and modelfile trimmed), so an unanticipated field is not lost. Transport
failures never raise: `describe()` answers `None` — an inquiry must not break the
component that merely wondered.

### Knowledge, where the endpoint states nothing

Some backends state nothing usable — measured, OpenAI's own models route answers
bookkeeping only. For those there are the community-maintained catalogues, wrapped as
`ModelInfoProvider` implementations in `mcs.adapter.llm.info`:

```python
from mcs.adapter.llm.info import LiteLLMInfoProvider, ModelsDevInfoProvider

catalog = ModelsDevInfoProvider()            # models.dev -- purpose-built, provider-first
catalog = LiteLLMInfoProvider()              # LiteLLM's JSON -- price-rich, flat ids

known = catalog.describe("gpt-5.6")          # standalone: ModelInfo | None
llm = CompletionLLMAdapter("gpt-5.6", api_key=..., model_info=catalog)
llm.describe()                               # endpoint first, catalogue fills the gaps
```

**Statement beats knowledge.** What this connection's backend says about itself is
ground truth for this deployment; a catalogue describes the model family and may lag
reality (it cannot know a local server's `num_ctx`). `describe()` therefore merges
field by field, endpoint first, and `meta` names every source that contributed
(`models_endpoint`, `ollama_show`, `litellm`, `models_dev`).

Both providers fetch their document **once** per instance over the injected transport
(models.dev refuses clients without a `User-Agent` — measured, handled), answer from
memory after that, and answer `None` for unknown models and every failure. The raw
entries survive in `meta` — including LiteLLM's price fields, which nothing here maps
yet but a cost tracker will want, and models.dev's exclusives (`temperature: false`,
the accepted `reasoning_options` effort values).

This is deliberately **knowledge as data, not logic** — the same split the TypeScript
ecosystem settled on: the AI SDK keeps model ids dumb strings, models.dev carries the
knowledge, the client composes. Exactly **two** request-path decisions are settled
from knowledge, both only where the caller left room:

- **The wire spelling of the budget field.** A reasoning model that `openai` serves
  takes `max_completion_tokens` (the one measured rejection); everything else keeps
  `max_tokens`. That is a membership check against data — one id sits under many
  namespaces (measured: 18 for `gpt-5.5`, the first-party provider plus every gateway
  reselling it), so the question is "does openai serve this id", never "who is the
  canonical provider". Resolved lazily on the first call that sends a budget; an
  explicit `max_completion_tokens_field` wins and skips the lookup.
- **Withholding a configured `temperature`.** models.dev states
  `supports_temperature: false` for exactly the models that 400 on any value
  (measured on GPT-5), so a construction default is withheld rather than crashing
  the call. Only stated-False withholds — silence sends — and a per-call
  `temperature` still travels: the call wins, the backend stays authoritative.
  Measured nuance: the statement describes the reasoning *mode* — gpt-5.5 rejects
  0.2 outright and under `reasoning_effort="low"`, yet accepts it under `"none"`.
  The gate stays conservative rather than encoding that moving target; `none` plus
  a wanted temperature is exactly what the per-call override is for.

One catalogue lookup serves both, fetched lazily and never in the constructor.
Compare the AI SDK, which answers the same two questions with model-id regexes and
parameter-stripping in its first-party provider — knowledge as *code*, a release per
model family.

### The trap this exists for

Measured against `qwen3:4b` on a local Ollama:

| `max_tokens` | `finish_reason` | `text` | `completion` |
|---|---|---|---|
| 64 | `length` | `""` | 64 — all of it spent thinking |
| 600 | `stop` | `"Mimi"` | 319 |

A reasoning model can spend the whole answer budget on reasoning and return an empty
string with **no error at all**. `truncated` is the only signal — which is what the live
test asserts.

### Overflow is a type, and it teaches the adapter

There is **no standard signal** for "your request did not fit". Everyone sends HTTP 400,
which equally covers a bad model name or a malformed parameter, so the status can never
confirm an overflow. OpenAI and its close clones add `error.code =
"context_length_exceeded"`; llama.cpp sends prose and nothing else. Detection therefore
goes in decreasing order of reliability:

1. **Status** — only ever to *exclude*. A rate limit is 429 and is phrased in tokens too
   (`"Limit: 30000 tokens per min"`); without this gate, a wait-and-retry would turn into
   a split-and-retry against a wall that has nothing to do with size.
2. **Error code**, when the backend sends one.
3. **Wording**, reluctantly. Unlovely, and the state of the art — see
   [openclaw#64180](https://github.com/openclaw/openclaw/issues/64180), *"context
   overflow not detected for llama.cpp server provider"*. Doing it here means it happens
   once, instead of in every consumer.

For a backend we have never met, teach the adapter rather than wait for a release:

```python
CompletionLLMAdapter("m", base_url="...", is_overflow=lambda status, msg, code: ...)
```

Translating all of this is the adapter's real job, so consumers branch on a type:

```python
try:
    llm.complete(huge)
except ContextWindowExceeded as e:
    e.limit, e.requested        # 8192, 9001 -- when the backend stated them
```

The discovered limit travels **on the exception**, not on the adapter: a transport that
cached it would be holding state about a model it does not own. Remembering belongs to
whoever plans the chunks — and the window is usually unknown up front, so an overflow is
often the first and only statement of the real budget. The planner should keep it; the
next chunk of the same document must not walk into the same wall.

## There is a spec, and it is thinner than the practice

Chat Completions is formally specified — [`openai/openai-openapi`](https://github.com/openai/openai-openapi),
OpenAPI 3.1, ~2.8 MB. It is not the case that only the Responses API has one.

What it defines:

| | |
|---|---|
| **request** | 28 fields, incl. `reasoning_effort`, `verbosity`, `max_completion_tokens` and the deprecated `max_tokens` |
| **response** | `id, choices, created, model, service_tier, system_fingerprint, object, usage, moderation` |
| **message** | `content, refusal, tool_calls, annotations, role, function_call, audio` |
| **usage** | `prompt_tokens, completion_tokens, total_tokens, prompt_tokens_details, completion_tokens_details` |

What it does **not** define, though every reasoning model sends it: the thinking text.
LiteLLM normalises it to `message.reasoning_content`, Ollama calls it `message.reasoning`,
Anthropic-compatible layers use `thinking_blocks`. All three are read here and land in
`meta` — vendor extensions, never required.

Note also `refusal`: a spec field, and the one case where a null `content` comes with a
stated reason. That reason is carried into the error rather than reported as a blank
failure.

**Nothing is validated against any of this.** Which `reasoning_effort` values a model
takes, which fields it understands — that is between the developer and the backend, and
`gpt-5.7` or a future Gemma may answer differently. The adapter passes values through and
lets the backend be authoritative; `extra_body` and `extra_headers` make sure anything
the spec grows can be sent without waiting for a release.

## The dialects it absorbs

"OpenAI-compatible" is not one wire. Three differences bite, all measured against
`gpt-5.5` / `gpt-5.6` and a local Ollama:

**`max_tokens` vs `max_completion_tokens`.** OpenAI's reasoning models reject the older
name outright — `400 unsupported_parameter`, *"Use 'max_completion_tokens' instead"* —
while older and local servers know only that one. There is no name both accept, and the
official SDK settles it without any magic: `create()` exposes **both** spellings side by
side and the developer picks. We do the same, as one constructor knob:

```python
CompletionLLMAdapter("qwen3:8b", base_url=...)                            # default: "max_tokens"
CompletionLLMAdapter("gpt-5.6", api_key=..., max_completion_tokens_field="max_completion_tokens")
CompletionLLMAdapter("gpt-5.6", api_key=..., model_info=ModelsDevInfoProvider())  # derived
```

No probe, no hidden retry, no state. Get it wrong and the failure is loud and cheap: the
backend's 400 already names the right field, and the adapter appends where to put it —
`(construct this adapter with max_completion_tokens_field='max_completion_tokens')`. A one-time
development-time discovery instead of a per-instance probing call in production. The
third form derives the spelling from **knowledge** instead (see the catalogue section
below): data application, not a probe, and an explicit choice still wins.

The port's budget parameter is `max_completion_tokens` — named after what it actually
caps, the completion including any reasoning spent inside it. The constructor's
`max_completion_tokens_field` only chooses its spelling on the wire.

**`temperature`.** Left unset by default, and not only for tidiness: GPT-5 models accept
only their default (*"'temperature' does not support 0 with this model"*). Pinning it to
0 for reproducibility works locally and fails in the cloud.

**`reasoning_effort`.** A named parameter, because it moves cost by a large factor.
Measured on a one-word question:

| effort | gpt-5.5 reasoning tokens | gpt-5.6 |
|---|---|---|
| `none` | 0 | 0 |
| `minimal` | **rejected** | **rejected** |
| `low` / `medium` / `high` | 11 / 15 / 18 | 0 |
| `xhigh` | 45 | 0 |
| `max` | **rejected** | **rejected** |

OpenAI documents `none | minimal | low | medium | high | xhigh | max` and notes that
"supported values are model-dependent" — these two accept `none, low, medium, high,
xhigh`. The value is passed through unvalidated: only the backend can be authoritative,
and it names its accepted set in the error. Note gpt-5.6 reported no reasoning tokens at
any level for this prompt, deciding adaptively where gpt-5.5 scaled with the setting.

One limit worth knowing: with `reasoning_effort` set, GPT-5.4+ refuse *tool calls* on Chat
Completions and point at `/v1/responses`. This port sends no tools, so it does not apply
here — but it is why a `mcs-adapter-llm-response` sibling is more than symmetry.

## Why not the official OpenAI SDK

We introspected it (2.24.0) rather than guessing, and the findings settle the question
both ways — its *conventions* are worth mirroring, its *dependency* is not.

What `client.chat.completions.create()` actually is: **40 typed keyword parameters**,
among them both `max_tokens` and `max_completion_tokens` side by side, plus the escape
hatches `extra_headers`, `extra_query`, `extra_body`. `reasoning_effort` is typed as a
`Literal["none", "minimal", "low", "medium", "high", "xhigh"]` — but that is **static
typing only, nothing is validated at runtime**. The SDK's philosophy is exactly the one
this adapter follows: the developer knows the parameters, the server is authoritative.
Its return object carries the same fields we read (`choices`, `usage` with both details
blocks, `service_tier`, `system_fingerprint`), keeps unknown vendor fields only in
untyped `model_extra` (we promote the reasoning text to `meta`), and types its errors by
HTTP status — there is no overflow type; that translation remains our added value.

So we mirror the conventions — `extra_body`/`extra_headers` under the same names, `None`
means "omit" like the SDK's `NOT_GIVEN`, both max-tokens spellings with the choice left
to the caller, no runtime validation of model-dependent values.

What we do not take is the dependency: `httpx`, `pydantic`, `anyio`, `jiter` and friends,
plus a second HTTP configuration surface — proxy, TLS, timeouts — beside the
`mcs-adapter-http` the rest of MCS already uses. And it would not have prevented a single
measured failure above: those are model behaviours, and they come back as the same
`400`s through any client.

A client that prefers the SDK anyway satisfies `LLMPort` with it in three lines and
injects that — the port is the contract, this adapter only the zero-dependency default.

## Configuration

```python
CompletionLLMAdapter(
    "model-id",
    base_url="https://api.openai.com/v1",   # without /chat/completions
    api_key=None,                           # local servers usually want none
    temperature=None,                       # unset by default -- GPT-5 rejects 0
    reasoning_effort=None,                  # "none" | "low" | "medium" | "high" | "xhigh"
    max_completion_tokens_field=None,       # wire spelling of the port's budget param:
                                            #   None = derive from model_info, else "max_tokens"
    model_info=None,                        # a ModelInfoProvider: fills describe() gaps,
                                            #   settles the budget spelling -- never silent
    extra_body={"num_ctx": 32768},          # backend-specific knobs the port has no room for
    timeout=120,                            # a long chunk is not a web request
    _http=my_http_adapter,                  # DPI: share a proxy, Basic-Auth, or inject a fake
)
```

`_http` is what makes this testable without a network: the offline suite runs entirely
against an injected fake transport — no key, no server, no model.

## Per-call overrides: the LangChain / LlamaIndex blend

Construction carries the defaults (LangChain-style constructor); `complete(**kwargs)`
passes anything else through verbatim and wins (LlamaIndex-style call):

```python
llm = CompletionLLMAdapter("qwen3:8b", base_url=..., temperature=0.2)

llm.complete(prompt)                                        # runs on the defaults
llm.complete(prompt, response_format={"type": "json_object"})   # this call needs JSON
llm.complete(prompt, temperature=1.0, seed=42)              # this call overrides
```

Precedence, weakest to strongest: named construction values → `extra_body` → the mapped
`max_completion_tokens` budget → per-call kwargs. Later wins, so a call can override anything —
including the mapped budget field, by naming it explicitly.

Nothing on this path is validated or renamed. The developer who wired the backend in
knows what it takes, and the backend is authoritative — that is the line that keeps this
adapter from growing into a second LiteLLM: the *only* translation it performs is the
one budget field name, and the only vocabulary it adds is the error type.

## Live tests

The offline suite proves the adapter behaves as we *assume* a backend does. A live one
proves the assumption:

```bash
pytest packages/adapters/mcs-adapter-llm -m e2e
```

Deselected by default rather than skipped — a skipped test reports as a harmless dot and
quietly stops guarding anything, while a deselected one is counted and named.

Defaults point at a local Ollama, so it costs nothing to run:

```
MCS_E2E_LLM_BASE_URL     default http://localhost:11434/v1
MCS_E2E_LLM_MODEL        default qwen3:4b -- comma-separated to run several
MCS_E2E_LLM_KEY          optional; set it for OpenAI or a gateway
MCS_E2E_LLM_MAX_TOKENS   wire field name, default "max_tokens"
```

Against OpenAI, both models in one go:

```bash
MCS_E2E_LLM_BASE_URL=https://api.openai.com/v1 \
MCS_E2E_LLM_MODEL=gpt-5.5,gpt-5.6 \
MCS_E2E_LLM_MAX_TOKENS=max_completion_tokens \
MCS_E2E_LLM_KEY=$OPENAI_API_KEY \
  pytest packages/adapters/mcs-adapter-llm -m e2e
```

Every finding in this README came from running these, not from reading a specification.

## Installation

```bash
pip install mcs-adapter-llm
```

## Links

- **Homepage:** <https://www.modelcontextstandard.io>
- **Source:** <https://github.com/modelcontextstandard/python-sdk>

## License

Apache-2.0
