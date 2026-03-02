# REST Single API Example

Interactive chat clients that connect to **any OpenAPI endpoint**
using the **MCS RestDriver** (`mcs-driver-rest`).

Default: **GitHub REST API** (repos + search) -- no dedicated MCP
server needed; just the OpenAPI spec URL and a tag filter.

Three client variants demonstrate the same MCS integration loop with
different LLM calling strategies.  The `chat_loop` function is
structurally identical across all three -- only the LLM transport and
the driver setup in `main()` differ.

## What it shows

- **One driver, any API** -- point at any OpenAPI spec and the LLM
  can interact with it.  No custom MCP server required.
- **Tag / path filtering** -- `--include-tags` lets you pick which
  parts of a large API (like GitHub's 800+ endpoints) the LLM sees.
- **Same client, different driver** -- the CSV and REST examples share
  the same `chat_loop` code; only the driver instantiation changes.
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
# Browse GitHub repos (default -- repos + search tags):
python chat_non_stream.py --debug

# Streaming:
python chat_stream.py --debug

# ReqRes user API:
python chat_non_stream.py \
    --url https://reqres.in/openapi.json \
    --include-tags legacy --debug

# Swagger Petstore:
python chat_non_stream.py \
    --url https://petstore3.swagger.io/api/v3/openapi.json

# Any OpenAPI spec with custom tag filter:
python chat_non_stream.py \
    --url https://your-api.example.com/openapi.json \
    --include-tags users orders

# Local model via vLLM:
python chat_stream.py \
    --model openai/meta-llama/Meta-Llama-3.1-8B-Instruct \
    --api-base http://localhost:8000/v1 --debug
```
