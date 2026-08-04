# mcs-examples

Runnable examples for the Python SDK. Every folder is self-contained and has its
own README with the details.

| Folder | What it shows |
|---|---|
| [`quickstart/`](quickstart/) | The MCS idea without any SDK: a plain API plus its OpenAPI spec is enough to give an LLM context |
| [`rest_single_api/`](rest_single_api/README.md) | Chat against **any** OpenAPI endpoint via `RestDriver` |
| [`csv_analysis/`](csv_analysis/README.md) | The same client against local CSV files via `CsvDriver` -- a driver with no network at all |
| [`permission_gate/`](permission_gate/README.md) | Human-in-the-loop: every tool call needs the user's OK, gated by `PermissionMiddleware` |
| [`gmail_agent/`](gmail_agent/README.md) | The full stack: composite driver, OAuth credentials, and the middleware chain (hooks, permission, auth) |
| [`openwebui/`](openwebui/) | MCS drivers packaged as Open WebUI tools, including a multi-driver orchestrator setup |
| [`skills/`](skills/) | The Gmail agent packaged as a Claude skill |

## Prerequisites

```bash
uv sync --extra examples
```

Set the API key for your provider (e.g. `OPENAI_API_KEY`, also read from a
`.env` file). The clients route through [LiteLLM](https://docs.litellm.ai/), so
any provider works -- including a local model via `--api-base`.

## One client, many drivers

Each example is the same program with a different **model**: build a driver,
hand it to a `ChatSession`, done.

```python
view   = ChatView(debug=args.debug)
driver = RestDriver(url=args.url, include_tags=tags)   # <- the only line that differs
ChatSession(driver, args.model, view=view, streaming=args.stream).run()
```

That is not a coincidence, it is the driver contract doing its job: swapping a
network API for local files, or adding a consent gate, changes the setup -- never
the loop.

The shared scaffolding lives in [`_shared/`](_shared/) and is split MVC-style:

| Module | Role |
|---|---|
| [`_shared/session.py`](_shared/session.py) | **Controller** -- the agent loop, streaming and blocking |
| [`_shared/view.py`](_shared/view.py) | **View** -- everything on screen, including the consent prompt |
| [`_shared/llm.py`](_shared/llm.py) | The LiteLLM transport; it never inspects the response |
| [`_shared/cli.py`](_shared/cli.py) | The flags every client understands |

The **model** is your MCS driver -- it owns everything about tools.

## The flags every client shares

```bash
python chat.py                     # streaming (default)
python chat.py --no-stream         # one assembled response per turn
python chat.py --no-native-tools   # text-prompt mode instead of the provider's API
python chat.py --debug             # system prompt, raw LLM output, DriverResponse
python chat.py --model ollama/llama3 --api-base http://localhost:8000/v1
```

**Streaming vs. non-streaming is one flag, not two programs.** The MCS contract
is identical either way; only who assembles the message differs. While streaming,
the client feeds each chunk into an `LLMStreamBuffer` and hands *the buffer* to
`process_llm_response` -- the driver then holds back the text of a tool call that
is still forming, so raw JSON never reaches the screen, no matter whether the
model emits a native tool-call event or writes the call into its text.

`--no-native-tools` is the interesting switch for local models: without a native
tool-calling API the model writes the call as JSON into its answer, and the
driver extracts it from there.

## Other scripts

- `csv_analysis/explore_responses.py` -- sends one prompt through several API
  modes and records the raw request/response pairs, to compare how providers
  represent tool calls
