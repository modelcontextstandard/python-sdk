> **Stage:** Alpha 0.2.0 · **not for production use (yet)** · things will break
>
> Contract v0.6 | Python >= 3.9

# Model Context Standard (MCS) -- Python SDK
> **Your LLM needs to call an API. Don't build a server. Point at the spec.**

```bash
pip install mcs-driver-rest
```

```python
from mcs.driver.rest import RestDriver

driver = RestDriver(url="https://mcsd.io/context7.json")
system_prompt = driver.get_driver_system_message()
# Pass system_prompt to any LLM. The driver handles the rest.
```

That's Context7 -- the popular MCP server that pulls fresh docs into your
LLM context -- replaced by a single driver call. No server. No transport
layer. No build step. [See the full story.](https://modelcontextstandard.io)

---

## Quick Start

### 1. Install

```bash
pip install mcs-driver-rest   # REST/OpenAPI driver (includes core + http adapter)
pip install mcs-driver-csv    # CSV driver (includes core + localfs adapter)
```

### 2. The driver loop (works with any LLM)

The driver embeds tool descriptions in the system prompt and parses the
LLM's output for structured tool calls. No `tools=` parameter needed.
Works with every model that can follow instructions.

```python
from mcs.driver.rest import RestDriver

driver = RestDriver(url="https://mcsd.io/context7.json")
system_prompt = driver.get_driver_system_message()

messages = [
    {"role": "system", "content": system_prompt},
    {"role": "user",   "content": "How do I set up JWT auth in Next.js?"},
]

while True:
    llm_out  = call_llm(messages)                        # your LLM call
    response = driver.process_llm_response(llm_out)

    if response.messages:
        messages.extend(response.messages)

    if response.call_executed:
        continue                                         # tool ran → back to LLM
    elif response.call_failed:
        continue                                         # retry
    else:
        print(llm_out)                                   # final answer
        break
```

The client doesn't know about tools. It passes LLM output to the driver
and appends what comes back. The driver handles extraction, execution,
and retry prompts.

### 3. Native tool calling (GPT-5.2, Claude, Gemini, ...)

Models with function-calling support get native `tools=[]` definitions
from the driver:

```python
from openai import OpenAI
from mcs.driver.rest import RestDriver

client = OpenAI()
driver = RestDriver(url="https://mcsd.io/context7.json")

ctx = driver.get_driver_context(model_name="gpt-5.2")

messages = [
    {"role": "system", "content": ctx.system_message},
    {"role": "user",   "content": "How do I set up JWT auth in Next.js?"},
]

while True:
    completion = client.chat.completions.create(
        model="gpt-5.2",
        messages=messages,
        tools=ctx.tools,                                 # native tools from driver
    )
    llm_message = completion.choices[0].message
    response = driver.process_llm_response(llm_message.to_dict())

    if response.messages:
        messages.extend(response.messages)

    if response.call_executed:
        continue
    elif response.call_failed:
        continue
    else:
        print(llm_message.content)
        break
```

### 4. Run the example clients

Full working chat clients for the REST driver are included:

```bash
pip install uv && uv sync --extra examples

# Non-streaming chat (simplest)
uv run python mcs-examples/rest_single_api/chat_non_stream.py \
    --model gpt-5.2 --url https://mcsd.io/context7.json

# Streaming chat
uv run python mcs-examples/rest_single_api/chat_stream.py \
    --model gpt-5.2 --url https://mcsd.io/context7.json

# Streaming with ToolCallSignaling (hides raw JSON from the user)
uv run python mcs-examples/rest_single_api/chat_stream_tcs.py \
    --model gpt-5.2 --url https://mcsd.io/context7.json
```

Source:
[`chat_non_stream.py`](mcs-examples/rest_single_api/chat_non_stream.py) ·
[`chat_stream.py`](mcs-examples/rest_single_api/chat_stream.py) ·
[`chat_stream_tcs.py`](mcs-examples/rest_single_api/chat_stream_tcs.py)

### 5. Inspect any OpenAPI spec

```bash
pip install mcs-driver-rest[inspector]

uv run python -m mcs.driver.rest.inspector https://mcsd.io/context7.json
uv run python -m mcs.driver.rest.inspector \
    https://raw.githubusercontent.com/github/rest-api-description/main/descriptions/api.github.com/api.github.com.json \
    --include-tags search repos
```

---

## How it works

```
Client                    Driver                     Backend (API)
  │                         │                           │
  │── LLM response ───────▶│                           │
  │                         │── extract tool call ──▶   │
  │                         │── execute_tool() ───────▶│
  │                         │◀── raw result ───────────│
  │◀── DriverResponse ─────│                           │
  │    .messages            │                           │
  │    .call_executed       │                           │
  │                         │                           │
  │── append messages ──▶ LLM (next turn)              │
```

1. The driver's **extraction chain** checks if the response contains a
   native tool call or a text-based call.
2. The matching **extraction strategy** parses the call.
3. The driver **executes** the tool and returns a `DriverResponse`.
4. The client appends `response.messages` and loops back.

The driver is stateless. Thread-safe by design. Swap it and every LLM
client works with a new API.

---

## What's inside?

A **uv workspace monorepo**. Each component is its own package -- install
only what you need.

### Core

| Component | PyPI | Purpose |
| --- | --- | --- |
| `packages/core` | `mcs-driver-core` | `MCSDriver` / `MCSToolDriver` interfaces, extraction & prompt strategies, mixins. Zero runtime deps. |

### Drivers

| Component | PyPI | Purpose |
| --- | --- | --- |
| `packages/drivers/mcs-driver-rest` | `mcs-driver-rest` | REST/OpenAPI driver -- parses any OpenAPI 3.x or Swagger 2.0 spec into LLM-callable tools. |
| `packages/drivers/mcs-driver-csv` | `mcs-driver-csv` | CSV driver -- list, read, query CSV files. |
| `packages/drivers/mcs-driver-filesystem` | `mcs-driver-filesystem` | Filesystem driver -- `list_directory`, `read_file`, `write_file` with pluggable adapter backend. |

### Adapters

| Component | PyPI | Purpose |
| --- | --- | --- |
| `packages/adapters/mcs-adapter-http` | `mcs-adapter-http` | HTTP transport (Bearer, Basic, proxy, SSL). |
| `packages/adapters/mcs-adapter-localfs` | `mcs-adapter-localfs` | Local filesystem I/O. Zero dependencies. |
| `packages/adapters/mcs-adapter-smb` | `mcs-adapter-smb` | SMB/CIFS network shares. |

### Orchestrators

| Component | PyPI | Purpose |
| --- | --- | --- |
| `packages/orchestrators/mcs-orchestrator-base` | `mcs-orchestrator-base` | Base orchestrator with pluggable resolution strategies. |
| `packages/orchestrators/mcs-orchestrator-rest` | `mcs-orchestrator-rest` | Dynamic REST/OpenAPI orchestrator -- manages multiple API connections. |

### Examples

| Component | Purpose |
| --- | --- |
| `mcs-examples/` | Reference clients, REST inspector, OpenAPI specs. See [`mcs-examples/README.md`](mcs-examples/README.md). |

---

## Build your own driver

Every MCS driver implements the same contract. Here's the minimum:

```python
from mcs.driver.core import DriverBase, Tool, ToolParameter

class WeatherDriver(DriverBase):
    def list_tools(self):
        return [
            Tool(
                name="get_forecast",
                title="Get weather forecast",
                description="Returns a 5-day weather forecast for the given city.",
                parameters=[
                    ToolParameter(name="city", description="City name", required=True),
                ],
            )
        ]

    def execute_tool(self, tool_name, arguments):
        if tool_name == "get_forecast":
            return call_weather_api(arguments["city"])
        raise ValueError(f"Unknown tool: {tool_name}")
```

That's it. `DriverBase` gives you:
- System prompt generation (from your tools)
- LLM response parsing (text-based and native tool calls)
- Retry handling on failed calls
- Native tool definitions for `get_driver_context()`

### Naming convention

| Level | Pattern | Example |
| --- | --- | --- |
| PyPI (Driver) | `mcs-driver-<capability>` | `mcs-driver-weather` |
| PyPI (Adapter) | `mcs-adapter-<protocol>` | `mcs-adapter-http` |
| Python import | `mcs.driver.<capability>` | `from mcs.driver.weather import WeatherDriver` |
| Class | `<Capability>Driver` | `WeatherDriver` |

### Adapter ports (structural typing)

Drivers define a `typing.Protocol` for their adapter dependency.
Adapters satisfy the protocol through structural subtyping -- no
inheritance from the driver package required. This keeps adapters
fully decoupled.

```python
# In your driver package
class WeatherPort(Protocol):
    def fetch(self, city: str) -> dict: ...

# In your adapter package -- no import from the driver needed
class OpenMeteoAdapter:
    def fetch(self, city: str) -> dict:
        return requests.get(f"https://api.open-meteo.com/...?city={city}").json()
```

---

## Development

```bash
git clone https://github.com/modelcontextstandard/python-sdk.git
pip install uv
uv sync --extra examples
uv run python -m pytest packages/core/tests/ -q
```

### Building & Publishing

```bash
python scripts/build_all.py --build --check      # build all 9 packages + twine check
uvx twine upload --repository testpypi dist_all/* # TestPyPI dry-run
uvx twine upload dist_all/*                       # production PyPI
```

---

## License

Apache-2.0. See `LICENSE`.
