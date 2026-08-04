# mcs-examples

Runnable examples for the Python SDK. Every folder is self-contained and has
its own README with the details.

| Folder | What it shows |
|---|---|
| [`quickstart/`](quickstart/) | The MCS idea without any SDK: a plain API + its OpenAPI spec is enough to give an LLM context |
| [`rest_single_api/`](rest_single_api/README.md) | Chat clients against **any** OpenAPI endpoint via `RestDriver` -- non-streaming and streaming |
| [`csv_analysis/`](csv_analysis/README.md) | The same clients against local CSV files via `CsvDriver` -- a driver with no network at all |
| [`gmail_agent/`](gmail_agent/README.md) | The full stack: composite driver, OAuth credentials, and the tool-middleware chain (hooks, permission, auth) |
| [`openwebui/`](openwebui/) | MCS drivers packaged as Open WebUI tools, including a multi-driver orchestrator setup |
| [`skills/`](skills/) | The Gmail agent packaged as a Claude skill |

## Prerequisites

```bash
uv sync --extra examples
```

Set the API key for your provider (e.g. `OPENAI_API_KEY`, also read from a
`.env` file). The clients route through [LiteLLM](https://docs.litellm.ai/), so
any provider works -- including a local model via `--api-base`.

## The two client shapes

Every driver folder ships the same pair, so you can compare them directly:

**`chat_non_stream.py`** -- the whole LLM answer arrives at once and goes into
`process_llm_response(text_or_dict)`. The simplest way to see the MCS loop.

```bash
python rest_single_api/chat_non_stream.py --url https://mcsd.io/context7.json --debug
```

**`chat_stream.py`** -- the client feeds each chunk into an `LLMStreamBuffer`
and hands **the buffer** to `process_llm_response`. The driver reassembles the
provider's native message, holds back the text of a tool call that is still
forming, and executes as soon as it is complete -- so raw tool-call JSON is
never displayed, whether the call arrives as a native event or as inline JSON
in the text.

```bash
# native tool-calling API (default)
python rest_single_api/chat_stream.py --url https://mcsd.io/context7.json --debug

# text-prompt mode -- the driver parses calls out of the text instead
python rest_single_api/chat_stream.py --no-native-tools --url https://mcsd.io/context7.json --debug
```

`--debug` shows the injected system prompt and the full `DriverResponse` per
round (which tools ran, with which arguments, and what came back).

### Using a local model

All clients accept `--api-base` for OpenAI-compatible servers and LiteLLM's
provider prefixes:

```bash
# Ollama (routed automatically by LiteLLM)
python csv_analysis/chat_stream.py --model ollama/llama3 --debug

# vLLM / llama.cpp / any OpenAI-compatible server
python csv_analysis/chat_stream.py \
    --model openai/meta-llama/Meta-Llama-3.1-8B-Instruct \
    --api-base http://localhost:8000/v1 --debug
```

Text-prompt mode (`--no-native-tools`) is the interesting one here: models
without a native tool-calling API write the call as JSON into their text, and
the driver extracts it from there.

## Other scripts

- `csv_analysis/chat.py` -- launcher that dispatches to the variants above
- `csv_analysis/explore_responses.py` -- sends one prompt through several API
  modes and records the raw request/response pairs, to compare how providers
  represent tool calls
