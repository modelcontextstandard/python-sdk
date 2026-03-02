# REST Single API Example

Interactive chat clients that connect to a single OpenAPI endpoint
using the **MCS RestDriver** (`mcs-driver-rest`).

Three client variants demonstrate the same MCS integration loop with
different LLM calling strategies.  The `chat_loop` function is
structurally identical across all three -- only the LLM transport and
the driver setup in `main()` differ.

## What it shows

- **Same client, different driver** -- the CSV and REST examples share
  the same `chat_loop` code; only the driver instantiation changes.
- Automatic tool discovery from an OpenAPI spec
- The full tool-call loop via `process_llm_response()`
- Native tool support via `DriverContext` (when the model supports it)
- Tool-call signaling (TCS) for clean streaming UX

## Client variants

| File | LLM call | TCS |
|---|---|---|
| `chat_non_stream.py` | Single request | -- |
| `chat_stream.py` | Token-by-token streaming | -- |
| `chat_stream_tcs.py` | Streaming + buffering | Yes |

## Prerequisites

```bash
pip install mcs-driver-rest litellm rich python-dotenv
export OPENAI_API_KEY=sk-...
```

## Quick start

```bash
# Non-streaming (default: Swagger Petstore):
python chat_non_stream.py

# Streaming:
python chat_stream.py --debug

# Streaming with tool-call signaling:
python chat_stream_tcs.py --debug

# Custom endpoint:
python chat_non_stream.py --url https://your-api.example.com/openapi.json

# Local model via vLLM:
python chat_stream.py \
    --model openai/meta-llama/Meta-Llama-3.1-8B-Instruct \
    --api-base http://localhost:8000/v1 --debug
```
