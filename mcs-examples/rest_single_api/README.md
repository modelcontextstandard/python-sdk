# REST Single API Example

Interactive chat client that connects to a single OpenAPI endpoint
using the **MCS RestOrchestrator** (`mcs-orchestrator-rest`).

## What it shows

- How to create a `RestOrchestrator` and register an OpenAPI URL
- Automatic tool discovery from the OpenAPI spec
- The full tool-call loop via `process_llm_response()`

## Prerequisites

```bash
pip install mcs-orchestrator-rest litellm python-dotenv
export OPENAI_API_KEY=sk-...
```

## Quick start

```bash
# Default quickstart API:
python chat.py

# Custom endpoint:
python chat.py --url https://petstore3.swagger.io/api/v3/openapi.json
```
