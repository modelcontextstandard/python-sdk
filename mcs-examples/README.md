# mcs-examples

This folder contains runnable examples for the Python SDK.

## 1) Quickstart demo (idea only, no MCS driver)

Used by `docker/quickstart`:

- `quickstart/fastapi_server_mcs_quickstart.py`
- `quickstart/fastapi_rest_quickstart.py`

These scripts provide the same "2-minute quickstart" concept shown in the organization README.

The `docker/quickstart` container exists solely to host the API under a public URL so that chatbots like ChatGPT, Gemini, or Grok can access it directly via their built-in web tools -- no SDK, no driver, no setup required.  This demonstrates the core MCS idea: a standard API description is all you need to give context to an LLM.

## 2) Reference drivers (small stdlib protocol)

To demonstrate the full MCS driver stack we need a real protocol/transport pair -- but one that requires no external services, no API keys, and no network, to work as a simple reference implementation.

`reference/` uses **CSV over LocalFS** for this purpose: CSV files on disk as the "API".  This is a realistic protocol/transport pair -- a driver for giving LLMs structured access to local CSV data.  At the same time it requires no external services, making it ideal for demonstrating the full MCS stack.

| File | Role |
|---|---|
| `reference/csv_localfs_tooldriver.py` | Pure `MCSToolDriver` -- exposes CSV operations as tools |
| `reference/csv_localfs_driver.py` | Hybrid: `MCSDriver` + `MCSToolDriver` -- Default driver for the CSV reference implementation |
| `reference/csv_localfs_driver_tcs.py` | Same hybrid driver with `ToolCallSignalingMixin` (for TCS demo) |
| `reference/runtime_local_tooldriver.py` | Second tooldriver (for orchestration demo) |
| `reference/data/sales.csv` | Sample dataset |

Standalone demos that run without an LLM:

```bash
python reference/demo_tooldriver.py           # direct tooldriver usage
python reference/demo_hybrid_driver.py        # standalone hybrid driver usage
python reference/demo_orchestrator_client.py  # orchestrator + simulated client steps
```

## 3) Minimal client examples (with LLM)

The following clients connect the reference drivers from above to a real LLM via [LiteLLM](https://docs.litellm.ai/), so you can test with any provider (OpenAI, Ollama, Anthropic, ...).

### Prerequisites

```bash
pip install -e ".[examples]"
```

Set the API key for your provider (e.g. `OPENAI_API_KEY`) or configure LiteLLM for a local model.

### Non-streaming

```bash
python mcs_driver_minimal_client_non_stream.py --model gpt-5-mini --debug
```

Sends the full LLM response to `process_llm_response(llm_text, streaming=False)` in one shot.  Good for verifying the basic MCS loop and simple LLMs.

### Streaming

```bash
python mcs_driver_minimal_client_stream.py --model gpt-5-mini --debug
```

Streams LLM output token-by-token.  Tool calls are detected either via **native provider events** (e.g. OpenAI `tool_calls` deltas) or via **inline JSON** in the text buffer.

When the LLM sends native tool-call events, the execution is invisible to the user -- the stream pauses briefly and continues with the result.  When the LLM uses inline JSON instead (common with local models), the raw JSON is visible in the stream.  For a seamless experience with inline JSON, see the **TCS variant** below.

**Debug mode** (`--debug` / `-d`) shows:
- The system prompt injected by the driver
- Raw tool-call payloads when detected
- Full `DriverResponse` details (executed/failed, result, retry_prompt)

### Streaming with Tool Call Signaling (TCS)

```bash
python mcs_driver_minimal_client_stream_tcs.py --model openai\meta-llama\Llama-3.1-8B-Instruct --debug
```
Run a lokal model unter the name provided by --model parameter or use one with OpenRouter.

For models that do not support native tool-call events, or when the driver does not handle the provider's event format, inline JSON ends up visible in the user's stream.  `ToolCallSignalingMixin` solves this: the driver signals whether streamed tokens look like a tool call, the client buffers them instead of displaying, and once confirmed the tool executes invisibly.  The user never sees raw JSON that defining tool calls.

### Convenience launcher

All three variants are also available through a single entry point:

```bash
python mcs_driver_minimal_client.py                        # non-streaming
python mcs_driver_minimal_client.py --stream               # streaming
python mcs_driver_minimal_client.py --stream --tcs         # streaming + TCS
python mcs_driver_minimal_client.py --stream --tcs --debug # streaming + TCS + debug
```

### Using a local model

All clients support `--api-base` for OpenAI-compatible servers and LiteLLM's provider prefixes:

```bash
# Ollama (routed automatically by LiteLLM)
python mcs_driver_minimal_client.py --stream --model ollama/llama3 --debug

# vLLM / llama.cpp / any OpenAI-compatible server
python mcs_driver_minimal_client.py --stream --tcs \
    --model openai/meta-llama/Meta-Llama-3.1-8B-Instruct \
    --api-base http://localhost:8000/v1 --debug
```

## 4) Orchestrator client example

- `mcs_tooldriver_minimal_client.py` -> `MCSToolDriver` + `BasicOrchestrator` usage

## Implementation notes

The TCS examples (`_tcs` suffix) are intentionally separate files to keep the base examples simple.  In production you would add `ToolCallSignalingMixin` directly to your driver rather than creating a separate class.

- `mcs_driver_minimal_client_stream_tcs.py` -- streaming client with buffer logic
- `reference/csv_localfs_driver_tcs.py` -- hybrid driver with `ToolCallSignalingMixin`
