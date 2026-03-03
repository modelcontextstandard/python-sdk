# `python-sdk` · Model Context Standard (MCS)

> **Stage:** alpha `v0.2` · Contract v0.6 | Python >= 3.9
>
> Reference SDK that showcases the **MCS driver contract** plus first-party
> drivers, adapters, and orchestrators.
> Every component ships as **its own wheel**. Install only what you need.

---

## The Core Concept

Large Language Models (LLMs) are powerful, but connecting them to external
data sources (APIs, databases, bus systems) is often an ad-hoc process.
The result: brittle prompts, hardcoded logic, and poor reusability.

**The Model Context Standard (MCS)** introduces a clean contract: the
`MCSDriver` interface.

Your application no longer needs to know the API specifics. Instead:

* The **driver** contains the optimised prompts and execution logic.
* Your **application** talks to the driver interface only.

> This makes the driver swappable and reusable. Prompt tuning and structured
> execution are handled in one place, not scattered across codebases.

Unlike MCP, no new protocol stack is required. At the end of the day,
function calling connects an LLM with its environment.
MCS standardises the driver contract, not the wire format. That makes this
primarily a **driver challenge**, not a protocol stack challenge.

---

## Quick Start

### 1. Installation

```bash
pip install mcs-driver-rest   # REST/OpenAPI driver (includes core + http adapter)
pip install mcs-driver-csv    # CSV driver (includes core + localfs adapter)
```

### 2. Text-based driver loop (works with any LLM)

The simplest pattern -- the driver embeds all tool descriptions in the
system prompt and parses the LLM's text output for structured tool calls.
No `tools=` parameter needed; works with every model that can follow
instructions.

```python
from mcs.driver.rest import RestDriver

driver = RestDriver(url="https://api.example.com/openapi.json")
system_prompt = driver.get_driver_system_message()

messages = [
    {"role": "system", "content": system_prompt},
    {"role": "user",   "content": "Find the top Python repos on GitHub"},
]

while True:
    llm_out  = call_llm(messages)                        # your LLM call (any model)
    response = driver.process_llm_response(llm_out)

    if response.messages:
        messages.extend(response.messages)

    if response.call_executed:
        continue                                         # tool ran -- back to LLM
    elif response.call_failed:
        continue                                         # retry
    else:
        print(llm_out)                                   # final answer
        break
```

### 3. Native tool calling (models with function-calling support)

Models like GPT-5.2, Claude, or Gemini support native `tools=[]`.
Drivers that implement the `SupportsDriverContext` mixin provide both the
system prompt **and** tool definitions in one call:

```python
from openai import OpenAI
from mcs.driver.rest import RestDriver
from mcs.driver.core import SupportsDriverContext

client = OpenAI()
driver = RestDriver(url="https://api.example.com/openapi.json")

# Get system prompt + native tool definitions from the driver
ctx = driver.get_driver_context(model_name="gpt-5.2")

messages = [
    {"role": "system", "content": ctx.system_message},
    {"role": "user",   "content": "Find the top Python repos on GitHub"},
]

while True:
    completion = client.chat.completions.create(
        model="gpt-5.2",
        messages=messages,
        tools=ctx.tools,                                 # native tools from driver
    )
    llm_message = completion.choices[0].message

    # Pass the full message to the driver -- it handles both
    # native tool_calls and text-based tool calls transparently
    response = driver.process_llm_response(llm_message.to_dict())

    if response.messages:
        messages.extend(response.messages)

    if response.call_executed:
        continue                                         # tool ran -- back to LLM
    elif response.call_failed:
        continue                                         # retry
    else:
        print(llm_message.content)                       # final answer
        break
```

The driver handles everything: it knows which extraction strategy to use
(native JSON vs text-based), executes the tool call, and returns
pre-formatted messages the client can append directly.

### 4. How tools work under the hood

The client never interprets tool calls -- it just passes the LLM response
to the driver. Internally:

1. The driver's **extraction chain** checks if the response contains a
   native tool call (e.g. OpenAI `tool_calls` field) or a text-based call.
2. The matching **extraction strategy** parses the call.
3. The driver **executes** the tool and returns a `DriverResponse` with
   pre-formatted `messages` (assistant message + tool result).
4. The client appends these messages and loops back to the LLM.

```
Client                    Driver                     Backend
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

---

## What's inside?

This SDK is a **uv workspace monorepo**. Each component is packaged
independently -- install exactly what you need.

### Core

| Component | PyPI | Purpose |
| --- | --- | --- |
| `packages/core` | `mcs-driver-core` | `MCSDriver` / `MCSToolDriver` interfaces, metadata, extraction & prompt strategies, mixins. Zero runtime dependencies. |

### Drivers

| Component | PyPI | Purpose |
| --- | --- | --- |
| `packages/drivers/mcs-driver-rest` | `mcs-driver-rest` | REST/OpenAPI driver -- parses any OpenAPI 3.x spec into LLM-callable tools. |
| `packages/drivers/mcs-driver-csv` | `mcs-driver-csv` | CSV driver -- list, read, and query CSV files. |
| `packages/drivers/mcs-driver-filesystem` | `mcs-driver-filesystem` | Filesystem driver -- `list_directory`, `read_file`, `write_file` with pluggable adapter backend. |

### Adapters

| Component | PyPI | Purpose |
| --- | --- | --- |
| `packages/adapters/mcs-adapter-http` | `mcs-adapter-http` | HTTP transport (uses `requests`). |
| `packages/adapters/mcs-adapter-localfs` | `mcs-adapter-localfs` | Local filesystem I/O. Zero dependencies. |
| `packages/adapters/mcs-adapter-smb` | `mcs-adapter-smb` | SMB/CIFS network shares (uses `smbprotocol`). |

### Orchestrators

| Component | PyPI | Purpose |
| --- | --- | --- |
| `packages/orchestrators/mcs-orchestrator-base` | `mcs-orchestrator-base` | Base orchestrator with pluggable resolution strategies. |
| `packages/orchestrators/mcs-orchestrator-rest` | `mcs-orchestrator-rest` | Dynamic REST/OpenAPI orchestrator -- manages multiple API connections. |

### Examples

| Component | PyPI | Purpose |
| --- | --- | --- |
| `mcs-examples/` | *(not on PyPI)* | Reference clients (non-streaming, streaming, TCS), REST inspector, and more. See [`mcs-examples/README.md`](mcs-examples/README.md). |

---

## Running the examples

```bash
pip install uv          # one-time: install uv
uv sync                 # install all workspace packages as editable installs
python mcs-examples/csv_analysis/chat_non_stream.py --model gpt-5.2 --debug
python mcs-examples/rest_single_api/chat_non_stream.py --model gpt-5.2 --include-tags search
```

> **Note:** `pip install -e .` does **not** work at the workspace root.
> Use `uv sync` for the full workspace, or `pip install -e packages/core`
> etc. for individual packages.

---

## Development

```bash
git clone https://github.com/modelcontextstandard/python-sdk.git
pip install uv
uv sync
```

### Building & Publishing

A cross-platform build script is included. It builds all 9 packages into
a single `dist_all/` directory and optionally validates them with `twine`.

```bash
python scripts/build_all.py --build              # build all packages
python scripts/build_all.py --build --check      # build + twine check (dry-run)
python scripts/build_all.py --check              # check existing artifacts
```

Upload to PyPI:

```bash
uvx twine upload --repository testpypi dist_all/*    # TestPyPI (optional)
uvx twine upload dist_all/*                          # production PyPI
```

---

## Architecture & Naming (PyPI Convention)

The Python SDK follows a **capability-based** naming convention. The driver
name carries the capability (what it does for the LLM), not the
protocol+transport pair. The transport is an adapter concern.

### Naming scheme

| Level | Pattern | Example |
| --- | --- | --- |
| PyPI (Driver) | `mcs-driver-<capability>[-<variant>]` | `mcs-driver-rest`, `mcs-driver-csv` |
| PyPI (Adapter) | `mcs-adapter-<protocol>[-<variant>]` | `mcs-adapter-http`, `mcs-adapter-smb` |
| PyPI (Orchestrator) | `mcs-orchestrator-<strategy>[-<variant>]` | `mcs-orchestrator-base` |
| Python import (Driver) | `mcs.driver.<capability>` | `from mcs.driver.rest import RestDriver` |
| Python import (Adapter) | `mcs.adapter.<protocol>` | `from mcs.adapter.localfs import LocalFsAdapter` |
| Python import (Orchestrator) | `mcs.orchestrator.<strategy>` | `from mcs.orchestrator.base import BaseOrchestrator` |
| Class (Driver) | `<Capability>Driver` | `RestDriver`, `CsvDriver` |
| Class (ToolDriver) | `<Capability>ToolDriver` | `RestToolDriver`, `CsvToolDriver` |

Every driver defaults to **hybrid** -- it implements both `MCSDriver`
(standalone) and `MCSToolDriver` (orchestrator-facing). This maximises
reusability: the same driver works directly with a client or as a building
block inside an orchestrator.

### Adapter protocol (ports)

Drivers define a `typing.Protocol` ("port") for their adapter dependency.
Adapters satisfy the protocol through **structural subtyping** -- no
inheritance from the driver package required. This keeps adapters fully
decoupled and independently publishable.

### Namespace packages

The SDK uses implicit namespace packages (PEP 420, Python 3.3+). Each
package installs into its own namespace (`mcs.driver.<capability>`,
`mcs.adapter.<protocol>`, ...) without conflicting with other packages.
There must be **no** `__init__.py` in `src/`, `src/mcs/`, or
`src/mcs/driver/`.

### Discovery

```
pip search mcs-driver-              # all drivers
pip search mcs-adapter-             # all adapters
pip search mcs-orchestrator-        # all orchestrators
```

---

## Benefits

* **Reliable, tested prompts** -- drivers include system prompts that clearly
  describe the available tools and expected responses.
* **Plug-and-play logic** -- add or swap drivers without rewriting your app.
* **Pluggable adapters** -- same driver, different backends (local, SMB, S3, ...).
* **Lean configuration** -- all setup is done via the driver constructor.
* **Shared ecosystem** -- standard naming makes drivers easily discoverable
  via PyPI.

---

## Contributing

We welcome new drivers and improvements:

1. `pip install mcs-driver-core`
2. Implement the `MCSDriver` interface (and optionally `MCSToolDriver` for
   orchestrator support).
3. Place your driver under `src/mcs/driver/<capability>/`.
4. Follow the naming convention: `mcs-driver-<capability>[-<variant>]`.
5. Publish to PyPI or open a PR in this repo.

---

## License

Distributed under Apache-2.0. See `LICENSE` for details.
