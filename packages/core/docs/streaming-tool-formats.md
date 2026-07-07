# Streaming Tool-Call Formats — Locked-Down Reference

> Status: **reference / locked-down** (2026-07). Verified against official provider
> docs via research sweep. Guides the streaming `ExtractionStrategy` subclasses and
> future format additions. The reassembly/extraction *design decision* (native
> reassembly, not canonical normalisation) is recorded in
> `docs/adr/0001-streaming-extraction-native-reassembly.md` — this doc is the "how"
> (the per-format wire matrix); the ADR is the "why".

MCS is **LLM-, provider- and SDK-agnostic**. It knows **tool formats**, nothing else.
litellm/OpenAI-SDK/Anthropic-SDK are conveniences the *client* chooses; MCS never
assumes one. This document nails down every tool-call format we know of, mapped onto
the **two axes** MCS actually cares about.

## The two axes — one hierarchy

Both axes live on **`ExtractionStrategy`**; there is no separate "wire codec" type.
Each format is a subclass that owns its format end to end, **in its own native shape**:

```
raw chunk/event ─[ strategy.accumulate ]→ native message ─[ recognizes/forming/extract ]→ Tool-Call
                  (SDK stream → its shape)  (stream=false shape)   (which format / coming / call)
                   buffer delegates                                 driver calls
```

1. **Reassembly** (`accumulate` / `is_stream_complete`) — how an SDK/endpoint *streams*
   the pieces. The `LLMStreamBuffer` resolves the wire format on the first chunk and
   delegates accumulation to it; at stream end `as_dict()` equals the provider's
   `stream=false` message. SDK-specific, but a *method*, not a parallel type.
2. **Extraction** — three distinct questions on the assembled message:
   - **`recognizes(shape) -> bool`** — *which format* is this? Identification only, not
     "is a call here". Native formats claim their envelope; the text format claims any
     plain-text content.
   - **`forming(message) -> Forming`** — *is a call coming?* (`forming`, plus `tool_name`
     once it has streamed). Drives the driver's mid-stream hold and early-release.
   - **`extract(message) -> list[ExtractedCall]`** — the *finished* call(s).

The native strategies do **not** normalise onto one shared shape. Each reassembles into
**its own** native message and reads it. The axes coincide for a native call (OpenAI
chunk → OpenAI message → OpenAI extract) and diverge for a text-embedded call (an OpenAI
*wire* carrying the call as JSON in `content` → the driver resolves `TextExtractionStrategy`
on the assembled message). See `docs/adr/0001-streaming-extraction-native-reassembly.md`.

### Reassembly primitives (what a format's `accumulate` consumes)

| primitive | meaning |
|---|---|
| **content-fragment** | a text delta to display |
| **SLOT** | which tool call a fragment belongs to (reassembly key) |
| **NAME** (once) | the tool name |
| **CALL-ID** (once) | correlation id echoed back in the result |
| **ARGS-fragment** | a partial JSON-string piece of the arguments |
| **DONE** | the call/turn is complete (per-call where available, else turn-end) → `is_stream_complete` |

### Native intermediate (the reassembly target)

The message the buffer produces = **the provider's own `stream=false` shape**, not a
normalised one:

| format | assembled message | args (final) |
|---|---|---|
| OpenAI Completions | `{role, content, tool_calls:[{id, type:"function", function:{name, arguments}}]}` | JSON **string** |
| OpenAI Responses | `{output:[{type:"function_call", call_id, name, arguments}, …]}` | JSON **string** |
| Anthropic Messages | `{role, content:[{type:"tool_use", id, name, input}, …]}` | **object** (streamed as an `input_json` string, parsed by `extract`) |

`extract` turns whichever native form into the parsed `arguments` dict of an
`ExtractedCall`. This replaces the earlier *canonical-intermediate* design (every wire
normalised onto the OpenAI message shape); see ADR-0001 for why native reassembly won —
the buffer stays a buffer (no translation), each strategy stays a whole-format expert,
and the format is resolved once. A model that **leaks** a call into text is handled by
the driver's native→text fall-through (`leaks_into_text`), not by normalisation.

---

## Wire envelopes — per format

### 1. OpenAI Chat Completions (`/v1/chat/completions`)
`chat.completion.chunk`; fragments nested in `choices[0].delta.tool_calls[]`.

| primitive | field |
|---|---|
| content-fragment | `choices[0].delta.content` |
| SLOT | `delta.tool_calls[].index` (integer) |
| NAME (once) | `delta.tool_calls[].function.name` (first fragment of slot) |
| CALL-ID (once) | `delta.tool_calls[].id` (first fragment of slot) |
| ARGS-fragment | `delta.tool_calls[].function.arguments` (concatenate) |
| DONE | `choices[0].finish_reason == "tool_calls"` — **choice-level, no per-call done** |

### 2. OpenAI Responses (`/v1/responses`)
Flat `output[]` items; **semantically-typed** SSE events.

| primitive | event → field |
|---|---|
| content-fragment | `response.output_text.delta` → `delta` |
| SLOT | `output_index` (also `item_id` `fc_…`) |
| NAME (once) | `response.output_item.added` → `item.name` |
| CALL-ID (once) | `response.output_item.added` → `item.call_id` `call_…` (plus item `id` `fc_…` — **two ids**) |
| ARGS-fragment | `response.function_call_arguments.delta` → `delta` |
| DONE | **per-call** `response.function_call_arguments.done` (full args) → `response.output_item.done` → turn `response.completed` |

### 3. Anthropic Messages (`/v1/messages`)
SSE events; name/id arrive in a **separate** event from args.

| primitive | event → field |
|---|---|
| content-fragment | `content_block_delta` → `delta.text` (`text_delta`) |
| SLOT | `index` (on `content_block_start/_delta/_stop`) |
| NAME (once) | `content_block_start` → `content_block.name` |
| CALL-ID (once) | `content_block_start` → `content_block.id` (`toolu_…`) |
| ARGS-fragment | `content_block_delta` → `delta.partial_json` (`input_json_delta`) |
| DONE | **per-call** `content_block_stop` → turn `message_delta.stop_reason == "tool_use"` → `message_stop` |

Notes: final `tool_use.input` is an **object**; results return as `tool_result` blocks in a
**user** message (`tool_use_id`). Fine-grained streaming (`eager_input_streaming`) can make
the accumulated `partial_json` invalid until DONE. `thinking` blocks occupy their own indices.

### 4. AWS Bedrock Converse (`ConverseStream`)
Named events, indexed by `contentBlockIndex`.

| primitive | event → field |
|---|---|
| content-fragment | `contentBlockDelta` → `delta.text` |
| SLOT | `contentBlockIndex` |
| NAME (once) | `contentBlockStart` → `start.toolUse.name` |
| CALL-ID (once) | `contentBlockStart` → `start.toolUse.toolUseId` |
| ARGS-fragment | `contentBlockDelta` → `delta.toolUse.input` (partial JSON string) |
| DONE | `contentBlockStop` → turn `messageStop.stopReason == "tool_use"` |

Note: non-streaming `input` is an **object**, streaming is **string fragments** — the two
directions disagree.

### 5. Google Gemini (`streamGenerateContent`) — **whole, not fragmented**
`candidates[].content.parts[]`; a `functionCall` part arrives **complete in one chunk**.

| primitive | field |
|---|---|
| content-fragment | `candidates[].content.parts[].text` |
| SLOT | array order (no index field); modern `functionCall.id` for parallel calls |
| NAME (once) | `parts[].functionCall.name` (whole) |
| CALL-ID (once) | `parts[].functionCall.id` (modern) |
| ARGS-fragment | **none** — `parts[].functionCall.args` is a whole **object** |
| DONE | terminal chunk `finishReason` (e.g. `STOP`) |

### 6. Cohere v2 (`/v2/chat`) — distinct streaming, near-OpenAI payload
Named events: `message-start` → `tool-plan-delta` → `tool-call-start` (id+name once) →
`tool-call-delta` (args string fragments) → `tool-call-end` → `message-end` (DONE).

### 7. Ollama native (`/api/chat`) — **whole, not fragmented**
Emits complete `tool_calls[]` objects per chunk; `arguments` is an **object**, SLOT via
`index`, typically **no CALL-ID**; DONE via `done:true`.

---

## Compatibility matrix

| Provider / endpoint | Wire format | args (stream) | args (final) | CALL-ID | needs own `accumulate`? |
|---|---|---|---|---|---|
| OpenAI Chat Completions | **OpenAI** | string frags | string | `call_…` | — (baseline) |
| OpenAI Responses | **distinct** | string frags | string | `call_…` + item `fc_…` | **yes** |
| Anthropic Messages | **distinct** | `partial_json` frags | object | `toolu_…` | **yes** |
| AWS Bedrock Converse | **distinct** | string frags | object | `toolUseId` | **yes** |
| Google Gemini native | **distinct** | *whole* | object | `id` (modern) | **yes** |
| Cohere v2 | **distinct** | string frags | string | yes | **yes (stream)** |
| Ollama native | **distinct** | *whole* | object | none | **yes (stream)** |
| Mistral | OpenAI | string frags | string | short (non-`call_`) | no |
| xAI Grok (`/chat/completions`) | OpenAI | string frags | string | `call_…` | no (⚠ `/responses` differs) |
| Groq | OpenAI | string frags | string | `call_…` | no |
| DeepSeek | OpenAI | string frags | string | yes | no (⚠ `reasoning_content`) |
| Together | OpenAI | string frags | string | yes | no (per-model gating) |
| Fireworks | OpenAI | string frags | string | `call_…` | no |

**Genuinely distinct wire formats:** OpenAI-Responses, Anthropic, Bedrock, Gemini,
Cohere, Ollama-native. **One OpenAI Completions strategy covers** the rest. **litellm
normalizes Anthropic/Gemini/Bedrock into the OpenAI chunk shape** — so a client on
litellm needs only the OpenAI Completions strategy; raw-SDK clients need the matching one.

**Built (2026-07):** `OpenAICompletionExtractionStrategy`, `OpenAIResponseExtractionStrategy`,
`AnthropicExtractionStrategy` (Responses/Anthropic proven with synthetic fixtures). Still
open: Gemini, Bedrock Converse, Cohere v2, Ollama-native — add on demand.

---

## Load-bearing implications for the build

1. **Even one vendor has multiple wire formats** (OpenAI Completions vs Responses; Ollama
   native vs `/v1`; xAI chat vs responses). ⇒ the format **cannot be keyed by model
   alone** — the buffer selects the strategy by the chunk envelope's shape (`recognizes`).

2. **DONE is available, arg-parseability is the pragmatic completion signal.** Each native
   strategy exposes `is_done` (Anthropic `message_stop`, Responses `response.completed`,
   OpenAI `finish_reason`), surfaced as `LLMStreamBuffer.is_finished()`. But the per-chunk
   pending/execute decision stays on **arg-parseability**: a growing JSON object is only
   parseable once its braces close (i.e. at the true end), so coincidental mid-stream
   parseability essentially cannot occur, and whole-args providers (Gemini, Ollama) are
   correctly complete on first appearance. The `arguments==""` → pending rule is kept (it
   distinguishes a name-only first fragment from a genuine `"{}"` no-arg call). DONE remains
   available for stream-lifecycle needs and multi-call granularity.

3. **SLOT ≠ CALL-ID.** SLOT (index / output_index / contentBlockIndex / array order)
   demultiplexes fragments; CALL-ID (call_id / toolUseId / toolu_ / fc_) correlates the
   result. Responses even carries **two** ids. ⇒ the canonical message keeps **both**;
   multi-call result messages need the CALL-ID.

4. **args string-vs-object is real on both axes.** Wire: string fragments vs whole objects.
   Encoding: OpenAI=string, Anthropic/Gemini/Bedrock/Ollama=object. ⇒ a strategy's
   `accumulate` for an object provider `json.dumps` into the canonical string form.

5. **Name/id timing varies.** Packed in the first fragment (OpenAI Completions) vs a
   dedicated START event before args (Responses/Anthropic/Bedrock/Cohere). ⇒ the canonical
   "NAME-once, ID-once, then ARGS-fragments" handles both; a name-only slot is **not**
   complete (already covered by pending).

6. **Pragmatic path (done):** built the three most common as `ExtractionStrategy`
   subclasses; the `LLMStreamBuffer` delegates `accumulate` to the one it recognises. Add
   Bedrock/Gemini/Cohere/Ollama-native on demand. litellm covers the multi-provider case today.

---

## Text-embedded tool calls (the leak) and the fallback

Models don't always place a tool call in the native slot; it **leaks into `content`** as
text. Verified against OpenAI/vLLM/Ollama/llama.cpp/LiteLLM/LM-Studio issues (2026-07).

**Signature.** The stream carries `delta.content` text, **no `delta.tool_calls`**, and
`finish_reason` is often **`"stop"`** (sometimes `"tool_calls"` under the structured-output
conflict) — so `finish_reason` is *not* a reliable leak flag. It is **intermittent** (one
quantified case: ~10% of calls, randomly interspersed with correct ones).

**Conditions** (most→least common *real* cause):
1. **Server/proxy parser mismatch** — the model emits a correct format but the serving
   layer (vLLM/Ollama/LiteLLM) fails to extract it into `tool_calls` and passes raw text
   through; also framework serialization bugs (LangChain dropping `tool_calls` on string
   content). **Upstream of MCS.**
2. **Reasoning models** emitting the call inside `<think>…</think>` → never reaches the parser.
3. **Weaker / less tool-tuned models** (GPT-3.5, open models); an *empty* `tools` list can induce it.
4. **Tools advertised in the system prompt only**, not bound via the API `tools` param.

**No canonical text format** — ≥4 orthogonal families, inconsistent keys:

| Family | Marker | Payload | Models |
|---|---|---|---|
| JSON-in-XML | `<tool_call>…</tool_call>` | JSON `{name,arguments}` | Hermes, Qwen2.5/3, Granite |
| Control token | `[TOOL_CALLS]`, `<\|python_tag\|>`, DeepSeek `<｜tool▁call…｜>`, `<\|START_ACTION\|>` | JSON array/object | Mistral, Llama 3.x, DeepSeek, Command R7B |
| Pythonic | `[fn(arg='x')]` | Python call list | Llama 4, ToolACE |
| Nested XML | `<function=…><parameter=…>` | XML | Qwen3-Coder |
| Fenced | ` ```json {…} ``` ` | JSON (`arguments`/`parameters`) | any *prompted* model |

Key names differ (`arguments` vs `parameters` vs `<parameter=>`), array- vs object-wrapped.

**Detecting a *forming* call mid-stream splits at the delimiter:**
- **Delimited** (a fixed sentinel: `<tool_call>`, `[TOOL_CALLS]`, `<|python_tag|>`, a ```json
  fence) → **reliable**: hold back only the ambiguous suffix that could be a partial start
  tag (vLLM Hermes `partial_tag_overlap`, Ollama greedy `findTag`), emit "pending", suppress
  raw output; release as content if the tag never completes.
- **Bare JSON** (`{`) → **inherently unsafe**: `{` / fences legitimately begin answers, code
  and reasoning; a model *reasoning about* tool syntax triggers false positives and
  self-reinforcing mis-fire loops (LM Studio #1592). Safest: don't stream-detect — buffer to
  end and validate the *whole* content against the exact schema.

**MCS's stance (premise-aligned).** Per-model text parsing is the *serving layer's* job
(vLLM selects a parser by model identity) — a client/driver inspecting `content` for
arbitrary model formats is at the wrong layer and unsafe. Therefore:
- `TextExtractionStrategy` parses **only MCS's own codec format** (what MCS itself prompted
  the model to emit). It catches OpenAI's bare-JSON `{"name"…}`/`{"tool"…}` leak (via the
  `name`/`tool` alias); it does **not** and should not parse Hermes/Mistral/Llama/Qwen
  formats — those are native-mode server leaks, fixed upstream (a correct server / litellm
  reads native `tool_calls`). This is why `TextExtractionStrategy` stays load-bearing but
  bounded. See [[feedback_client_never_interprets_llm_output]].
- Reliable streaming **pending** for MCS text-mode needs a **delimited** codec (MCS controls
  its own format); bare-JSON codecs stay execute-at-end.
- **Firewall reasoning content**: never scan `<think>…</think>` for tool calls.

Reference implementations if we add delimited start-detection: Ollama `tools.Parser.Add`
(release-if-not-a-call), vLLM `ToolParser.extract_tool_calls_streaming` (per-model marker
catalog), llama.cpp PEG parser + JSON healer.

### Planned: "Streaming interface v2" — driver-side hold/release, tool-name confirmed

Target design (not built yet): the **streaming** `process_llm_response` takes the
`LLMStreamBuffer` itself (not `as_dict()`); the buffer holds a **display cursor**
(stream-state; driver stays stateless); the driver returns the **released text** in
`DriverResponse.display_text`. The client loop becomes format-agnostic — identical for
native and text-embedded calls — and just prints `display_text` + reacts to signals:

Interface shape:
- **No `streaming` flag** — the *type* is the signal. `MCSDriver.process_llm_response`
  stays `(str | dict)` (streaming-agnostic); `SupportsStreaming` *widens* it to
  `(str | dict | LLMStreamBuffer)`; a buffer argument means streaming. Liskov-safe
  (contravariant input widening). Only a stream-aware driver knows the buffer type.
- **Direct buffer API**, not `as_dict()`: `get_content() -> str|None`,
  `get_tool_calls() -> list`, `has_tool_call()`, `is_finished()`, plus the display cursor
  (`unshown()`, `release()`, `hold()`, `reset()`). `add(chunk)` returns nothing (display is
  driver-managed via the cursor, not `add`'s return). `as_dict()` becomes internal (bridges
  the buffer's fields to the `str|dict`-based `ExtractionStrategy`s, which also serve the
  non-streaming path) or is dropped if `extract` is refactored onto direct fields.


- content forms as a call (name pending/known) → **hold** (`display_text=""`, `call_pending`);
- name resolves to a **known** tool → stay pending, accumulate args, **execute** (discard held);
- name is **unknown** to the driver (or, in a chain, to *every* driver) → **release** as text;
- `is_finished()` with an unresolved call → **flush** the held content as text.

Chain: all drivers go pending initially; each releases when the name isn't its tool; the
owner stays pending and executes (orchestrator aggregates — the proactive "union of tool
names" guard). Graceful by design: a mis-configured client (no `tools`, model leaks) never
fails — the call just runs the text path.

**TODO (hardening):** a release heuristic for **malformed JSON** — a structural break / new
control marker that cancels the "call forming" assumption, so a broken JSON never holds
`pending` forever. Also: firewall reasoning (`<think>`) content from the forming-call scan.

**False-positive guard.** Text that *resembles* a call but names a tool this driver does
not own must **not** execute — and must not be treated as a *failure* either, since another
driver in the client's list may own it. So a `BaseDriver` simply **ignores** an unowned call
(`_no_owned` returns an empty response), and mid-stream **releases** a forming call whose
name is not one of its tools so it flows as text. No driver may assume an unowned call is
*nobody's*: an orchestrator is itself a composable `BaseDriver` and there may be several in
the list. A composition that knows it holds the **full** tool set (the union) and wants to
nudge the model overrides `_no_owned` — that is the orchestrator developer's concern, not
baked into `BaseDriver`. Native tool calls never hit this path (the envelope already
committed to a call); this only concerns the text codec.
