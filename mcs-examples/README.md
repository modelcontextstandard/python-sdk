# mcs-examples

This folder contains runnable examples for the Python SDK.

## 1) Quickstart demo (idea only, no MCS driver)

Used by `docker/quickstart`:

- `quickstart/fastapi_server_mcs_quickstart.py`
- `quickstart/fastapi_rest_quickstart.py`

These scripts provide the same "2-minute quickstart" concept shown in the organization README.

## 2) Minimal client examples (with real drivers)

Both clients use the **CSV-LocalFS reference driver** and [LiteLLM](https://docs.litellm.ai/) so you can test with any provider (OpenAI, Ollama, Anthropic, ...).

### Prerequisites

```bash
pip install litellm rich python-dotenv
```

Set the API key for your provider (e.g. `OPENAI_API_KEY`) or configure LiteLLM for a local model.

### Non-streaming

```bash
python mcs_driver_minimal_client_non_stream.py --model gpt-4o --debug
```

Sends the full LLM response to `process_llm_response(llm_text, streaming=False)` in one shot.  Good for verifying the basic MCS loop and inspecting `DriverResponse` fields.

### Streaming

```bash
python mcs_driver_minimal_client_stream.py --model gpt-4o --debug
```

Streams LLM output token-by-token.  Tool calls are detected either via native provider events (OpenAI `tool_calls` deltas) or inline JSON in the text buffer.  After execution the result is fed back and streaming continues.

**Debug mode** (`--debug` / `-d`) shows:
- The system prompt injected by the driver
- Raw tool-call payloads when detected
- Full `DriverResponse` details (executed/failed, result, retry_prompt)

Without `--debug` the tool execution is invisible -- the user sees a seamless text stream.

### Convenience launcher

```bash
python mcs_driver_minimal_client.py                  # non-streaming (default)
python mcs_driver_minimal_client.py --stream          # streaming
python mcs_driver_minimal_client.py --stream --debug  # streaming + debug
```

### Using a local model (e.g. Ollama)

```bash
python mcs_driver_minimal_client_stream.py --model ollama/llama3 --debug
```

LiteLLM routes `ollama/*` models to a local Ollama instance automatically.

## 3) Orchestrator client example

- `mcs_tooldriver_minimal_client.py` -> `MCSToolDriver` + `BasicOrchestrator` usage

## 4) Reference flow example (small stdlib protocol)

`reference/` demonstrates the full flow from ToolDriver to client with a tiny protocol/transport pair:

- Protocol: `CSV`
- Transport: `LocalFS`

Files:

- `reference/csv_localfs_tooldriver.py` -> pure `MCSToolDriver`
- `reference/csv_localfs_driver.py` -> hybrid `MCSDriver` wrapping the tooldriver
- `reference/runtime_local_tooldriver.py` -> second tooldriver (for orchestration demo)
- `reference/demo_tooldriver.py` -> direct tooldriver usage
- `reference/demo_hybrid_driver.py` -> standalone hybrid driver usage
- `reference/demo_orchestrator_client.py` -> orchestrator + simulated client steps
- `reference/data/sales.csv` -> local sample dataset

Run examples from this directory:

```bash
python reference/demo_tooldriver.py
python reference/demo_hybrid_driver.py
python reference/demo_orchestrator_client.py
```
