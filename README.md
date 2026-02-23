# `python-sdk` · Model Context Standard (MCS)

> **Stage:** alpha `v0.1` · Contract v0.6 | Python ≥ 3.9
> 
> Reference SDK that showcases the **MCS driver contract** plus two first‑party drivers.
> Every driver ships as **its own wheel**. Install only what you need.

---

## The Core Concept

Large Language Models (LLMs) are powerful, but connecting them to external data sources (APIs, databases, bus systems) is often an ad-hoc process. The result: brittle prompts, hardcoded logic, and poor reusability.

**The Model Context Standard (MCS)** introduces a clean contract: the `MCSDriver` interface.

Your application no longer needs to know the API specifics. Instead:

* The **driver** contains the optimized prompts and execution logic.
* Your **application** talks to the driver interface only.

> This makes the driver swappable and reusable. Prompt tuning and structured execution are handled in one place, not scattered across codebases.

Unlike MCP, no new protocol stack is required. At the end of the day, function calling connects a LLM with its environment. 
MCS standardizes the driver contract, not the wire format. That makes this primarily a driver challenge, not a protocol stack challenge.

If you really need features provided by MCP (Model Context Protocol), MCS complements that by providing possible drivers
or MCP using MCS compatible drivers.

But for most tool integrations, implementing a robust MCS driver is the pragmatic and efficient path.

---

## What’s inside?

Each part of the SDK is packaged independently. Install exactly what you need.

| Component | PyPI Distribution | Purpose |
| --- | --- | --- |
| **`src/`** | `mcs-driver-core` | The `MCSDriver` and `MCSToolDriver` interfaces, metadata classes, `BasicOrchestrator`, and mixins (e.g. `ToolCallSignalingMixin`). |
| **`mcs-examples/`** | *(not on PyPI)* | Reference drivers, LLM chat clients (non-streaming, streaming, TCS), orchestrator demo, and FastAPI quickstart. See [`mcs-examples/README.md`](mcs-examples/README.md) for full details. |

Drivers live in their own repositories:

| Driver | Repo | PyPI |
| --- | --- | --- |
| REST-HTTP (OpenAPI) | [mcs-driver-rest-http](https://github.com/modelcontextstandard/mcs-driver-rest-http) | `mcs-driver-rest-http` |
| Filesystem (local) | [mcs-driver-filesystem-localfs](https://github.com/modelcontextstandard/mcs-driver-filesystem-localfs) | `mcs-driver-filesystem-localfs` |

> **Why separate repos?**<br>
> The core contract is ~5 kB with zero runtime dependencies.<br>
> Drivers have their own release cadence, dependencies, and maintainers.<br>
> Install only what you need: `pip install mcs-driver-core mcs-driver-rest-http`

---

## Quick Start

### 1. Environment and Installation

```bash
python -m venv .venv && source .venv/bin/activate   # Windows: .venv\Scripts\activate
pip install mcs-driver-core mcs-driver-rest-http
```

### 2. Using a Driver

The interaction always follows this pattern:

1. **Get system prompt**: The driver provides a complete system message for the LLM.
2. **Run LLM**: Send the system prompt + user input to the LLM.
3. **Process response**: The driver checks if the LLM wants to call a tool. If so, it executes the call and returns pre-formatted `messages` the client can append directly to its history.
4. **Loop**: If a tool was called, extend the message history with `response.messages` and repeat from step 2.

```python
from mcs.driver.rest_http import RestHttpDriver

driver = RestHttpDriver(urls=["https://example.com/openapi.json"])
system_prompt = driver.get_driver_system_message()

messages = [
    {"role": "system", "content": system_prompt},
    {"role": "user",   "content": "Find the email for Danny"},
]

while True:
    llm_out  = call_llm(messages)                        # your LLM call (pseudo code)
    response = driver.process_llm_response(llm_out)

    if response.messages:                                 # driver provides pre-formatted messages
        messages.extend(response.messages)

    if response.call_executed:                            # tool was called -- loop back to LLM
        continue

    elif response.call_failed:                            # parsing/execution failed -- retry
        continue

    else:                                                 # no tool call -- final answer
        print(llm_out)
        break
```

Once perfect prompts exist for a protocol and transport, they are encapsulated inside the driver. 
This avoids the burden to come up with prompts across apps again and again, this makes the logic reusable.

For the first time, investing in the perfect prompt for a use case pays off directly -- once developed,
everyone can reuse it without even seeing the prompt itself.

With this interface using projects like DSPy to optimize prompts for different LLMs will make the effort pay off really
quickly.

### 3. Running the examples

The `mcs-examples/` folder contains runnable demos for every part of the SDK -- from standalone reference drivers (no LLM needed) to streaming chat clients with real models.  Install the example dependencies and try them out:

```bash
pip install -e ".[examples]"
python mcs-examples/mcs_driver_minimal_client_stream.py --model gpt-4o --debug
```

See [`mcs-examples/README.md`](mcs-examples/README.md) for the full list of examples, including local model usage (Ollama, vLLM) and the `ToolCallSignalingMixin` demo.

### 4. Development

git clone https://github.com/modelcontextstandard/python-sdk.git
python -m venv .venv && source .venv/bin/activate   # Windows: .venv\Scripts\activate
pip install -e ".[dev]"


#### 4.1. Development of a new driver

Create a project named `mcs-driver-<protocol>-<transport>`:

```
mcs-driver-filesystem-localfs       # Hybrid (default) -- standalone & orchestrator
mcs-driver-filesystem-localfs-toolonly   # Only via orchestrator (no LLM-facing methods)
mcs-driver-rest-http-standalone     # Only standalone (no list_tools/execute_tool)
mcs-driver-rest-http-acme           # Variant by author/vendor "acme"
```

Setup:

```bash
python -m venv .venv && source .venv/bin/activate   # Windows: .venv\Scripts\activate
pip install mcs-driver-core
```

Create the folder structure:

```
src/mcs/driver/<protocol>_<transport>/__init__.py
src/mcs/driver/<protocol>_<transport>/<protocol>_<transport>_driver.py
README.md
LICENSE
pyproject.toml   # or requirements.txt
```

Because of implicit namespace packages (Python 3.3+) there must be **no** `__init__.py` in `src/`, `src/mcs/`, or `src/mcs/driver/`.


---

## Benefits

* **Reliable, tested prompts**: Drivers include system prompts that clearly describe the available tools and expected responses.
* **Plug-and-play logic**: Add or swap drivers without rewriting your app logic.
* **Lean configuration**: All setup is done via the driver constructor. Making it easy to use by an orchestrator with dependency injection.
* **Shared ecosystem**: Standard naming makes drivers easily discoverable via PyPI.

---

## Architecture & Naming (PyPI Convention)

The Python SDK follows a **capability-based** naming convention. The driver name carries the capability (what it does for the LLM), not the protocol+transport pair. The transport is an adapter concern (see [Specification Section 4](https://github.com/modelcontextstandard/docs/blob/main/docs/Specification/4_ToolDriver_Adapter.md)).

### Naming scheme

| Level | Pattern | Example |
| --- | --- | --- |
| PyPI package (Driver) | `mcs-driver-<capability>[-<variant>]` | `mcs-driver-pdf`, `mcs-driver-csv`, `mcs-driver-openapi` |
| PyPI package (Orchestrator) | `mcs-orchestrator-<strategy>[-<variant>]` | `mcs-orchestrator-basic` |
| PyPI package (Adapter) | `mcs-adapter-<source>[-<variant>]` | `mcs-adapter-localfs`, `mcs-adapter-s3` |
| PyPI package (Bundle) | `mcs-bundle-<capability>-<source>[-<variant>]` | `mcs-bundle-pdf-localfs` |
| Python import (Driver) | `mcs.driver.<capability>` | `from mcs.driver.csv import CsvDriver` |
| Python import (Adapter) | `mcs.adapter.<source>` | `from mcs.adapter.localfs import LocalFsConnector` |
| Python import (Orchestrator) | `mcs.orchestrators.<strategy>` | `from mcs.orchestrators.basic import BasicOrchestrator` |
| Class (Driver) | `<Capability>Driver` | `CsvDriver`, `PdfDriver`, `OpenApiDriver` |
| Class (ToolDriver) | `<Capability>ToolDriver` | `CsvToolDriver`, `PdfToolDriver` |
| Files | `driver.py` / `tooldriver.py` | `src/mcs/driver/csv/driver.py` |

**Every driver defaults to hybrid** -- it implements both `MCSDriver` (standalone) and `MCSToolDriver` (orchestrator-facing). This is the recommended pattern because it maximizes reusability: the same driver works directly with a client or as a building block inside an orchestrator.

When a driver explicitly supports only one mode, the variant suffix signals this:

| Suffix | Meaning |
| --- | --- |
| *(none)* | Hybrid (default) -- standalone & orchestrator |
| `-standalone` | Standalone only -- no `list_tools()`/`execute_tool()` |
| `-toolonly` | Orchestrator only -- no LLM-facing methods |
| `-<name>` | Author/vendor variant, e.g. `-pymupdf`, `-petstore` |

### Discovery

Search PyPI with three prefixes:

```
pip search mcs-driver-              # all drivers (hybrid, toolonly, standalone)
pip search mcs-orchestrator-        # all orchestrators
pip search mcs-adapter-             # all adapters
```

The driver type (hybrid, standalone, toolonly) is also exposed programmatically via `DriverMeta.capabilities` for registries like the planned [mcs-pkg](https://github.com/modelcontextstandard/mcs-pkg).

### Import convention (IntelliSense)

The Python namespace follows a strict pattern so IDE autocompletion works predictably:

```python
from mcs.driver.csv import CsvDriver                      # MCSDriver + MCSToolDriver
from mcs.driver.pdf import PdfDriver                       # type "from mcs.driver." -> IDE lists all
from mcs.driver.openapi import OpenApiDriver               # OpenAPI-based hybrid driver
from mcs.adapter.localfs import LocalFsConnector           # adapter
from mcs.orchestrators.basic import BasicOrchestrator      # orchestrator
```

When you type `from mcs.driver.` your IDE lists all installed drivers. When you type `from mcs.driver.csv import ` you see the available classes.

### File naming inside a driver package

Each driver package follows this internal structure:

```
src/mcs/driver/<capability>/
    __init__.py          # re-exports public classes
    driver.py            # MCSDriver implementation (standalone)
    tooldriver.py        # MCSToolDriver implementation (orchestrator-facing)
```

Class names use PascalCase derived from the module path: `csv` becomes `CsvDriver` / `CsvToolDriver`. This makes the mapping from package name to import path to class name predictable.

### Namespace packages

The SDK uses implicit namespace packages (PEP 420, Python 3.3+). Each driver installs into `mcs.driver.<capability>` without conflicting with other drivers. There must be **no** `__init__.py` in `src/`, `src/mcs/`, or `src/mcs/driver/`. The same applies to adapters (`mcs.adapter.<source>`) and orchestrators (`mcs.orchestrators.<strategy>`).

---

## Contributing

We welcome new drivers and improvements:

1. `pip install mcs-driver-core`
2. Implement the `MCSDriver` interface (and optionally `MCSToolDriver` for orchestrator support).
3. Place your driver under `src/mcs/driver/<capability>/`.
4. Follow the naming convention: `mcs-driver-<capability>[-<variant>]`.
5. Publish to PyPI or open a PR in this repo.

---

## License

Distributed under Apache 2.0. See `LICENSE` for more information
