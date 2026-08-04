# REST Single API Example

Interactive chat client that connects to **any OpenAPI endpoint**
using the **MCS RestDriver** (`mcs-driver-rest`).

Default: **GitHub REST API** (search) -- no dedicated MCP server needed;
just the OpenAPI spec URL and a tag filter.

## What it shows

- **One driver, any API** -- point at any OpenAPI spec and the LLM
  can interact with it.  No custom MCP server required.
- **Tag / path filtering** -- `--include-tags` lets you pick which
  parts of a large API (like GitHub's 800+ endpoints) the LLM sees.
- **Same client, different driver** -- this example and the CSV one run the
  *identical* `ChatSession`; only the driver constructed in `main()` differs.
- Native tool support via `NativeToolContext` (when the model supports it),
  switchable with `--no-native-tools` to compare against text-prompt mode

## One client, two modes

`chat.py` is the whole client. Streaming vs. non-streaming is a flag, not a
second program -- the MCS contract is identical either way, only who assembles
the message differs.

| Flag | What changes |
|---|---|
| *(default)* | Streaming: the client feeds chunks into an `LLMStreamBuffer` and hands the buffer to the driver, which holds a forming tool call back so its JSON is never displayed |
| `--no-stream` | The provider assembles the message; the driver receives it in one piece |
| `--no-native-tools` | Text-prompt mode: tools are described in the prompt and the driver parses the call out of the model's text |
| `--debug` | System prompt, raw LLM output and the per-call `DriverResponse` report |

The loop itself lives in [`_shared/session.py`](../_shared/session.py) and is
shared with every other example.

## Prerequisites

```bash
pip install mcs-driver-rest litellm rich python-dotenv
export OPENAI_API_KEY=sk-...
```

## Quick start

```bash
# Browse GitHub (default -- search tags):
python chat.py --debug

# Non-streaming instead:
python chat.py --no-stream --debug

# Text-prompt mode rather than the provider's tool-calling API:
python chat.py --no-native-tools --debug

# A completely different API -- same client:
python chat.py --url https://mcsd.io/context7.json

# Any OpenAPI spec with a custom tag filter:
python chat.py --url https://your-api.example.com/openapi.json     --include-tags users orders

# Local model via vLLM / llama.cpp:
python chat.py --model openai/meta-llama/Meta-Llama-3.1-8B-Instruct     --api-base http://localhost:8000/v1 --debug
```
