# `python-sdk` · Model Context Standard (MCS)

> **Stage:** alpha `v0.1` | Python ≥ 3.9
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
| **`mcs-drivers-core/`** | `mcs-drivers-core` | The `MCSDriver` and `MCSToolDriver` interfaces, metadata classes, `BasicOrchestrator`, and mixins. |
| **`mcs-examples/`** | *(not on PyPI)* | Minimal client examples and a FastAPI quickstart demo. |

Drivers live in their own repositories:

| Driver | Repo | PyPI |
| --- | --- | --- |
| REST-HTTP (OpenAPI) | [mcs-driver-rest-http](https://github.com/modelcontextstandard/mcs-driver-rest-http) | `mcs-driver-rest-http` |
| Filesystem (local) | [mcs-driver-filesystem-localfs](https://github.com/modelcontextstandard/mcs-driver-filesystem-localfs) | `mcs-driver-filesystem-localfs` |

> **Why separate repos?**<br>
> The core contract is ~5 kB with zero runtime dependencies.<br>
> Drivers have their own release cadence, dependencies, and maintainers.<br>
> Install only what you need: `pip install mcs-drivers-core mcs-driver-rest-http`

---

## Quick Start

### 1. Environment and Installation

```bash
python -m venv .venv && source .venv/bin/activate   # Windows: .venv\Scripts\activate
pip install mcs-drivers-core mcs-driver-rest-http
```

### 2. Using a Driver

The interaction always follows this pattern:

1. **Get system prompt**: The driver provides a complete system message for the LLM.
2. **Run LLM**: Send the system prompt + user input to the LLM.
3. **Process response**: The driver checks if the LLM wants to call a tool.
4. **Loop**: If a tool was called, feed the result back to the LLM and repeat from step 2.

```python
from mcs.drivers.rest_http import RestHttpDriver

driver = RestHttpDriver(urls=["https://example.com/openapi.json"])
system_prompt = driver.get_driver_system_message()

messages = [
    {"role": "system", "content": system_prompt},
    {"role": "user",   "content": "Find the email for Danny"},
]

while True:
    llm_out  = call_llm(messages)                        # your LLM call (pseudo code)
    response = driver.process_llm_response(llm_out)

    if response.call_executed:                            # tool was called successfully
        messages.append({"role": "assistant", "content": llm_out})
        messages.append({"role": "tool",      "content": str(response.result)})

    elif response.call_failed:                            # tool call found but could not be parsed/executed
        messages.append({"role": "assistant", "content": llm_out})
        messages.append({"role": "system",    "content": response.retry_prompt})

    else:                                                 # no tool call -- final answer
        print(response.result)
        break
```

Once perfect prompts exist for a protocol and transport, they are encapsulated inside the driver. 
This avoids the burden to come up with prompts across apps again and again, this makes the logic reusable.

For the first time, investing in the perfect prompt for a use case pays off directly -- once developed,
everyone can reuse it without even seeing the prompt itself.

With this interface using projects like DSPy to optimize prompts for different LLMs will make the effort pay off really
quickly.

### 3. Development

git clone https://github.com/modelcontextstandard/python-sdk.git
python -m venv .venv && source .venv/bin/activate   # Windows: .venv\Scripts\activate
pip install -r requirements-dev.txt


#### 3.1. Development of a new driver

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
pip install mcs-drivers-core
```

Create the folder structure:

```
src/mcs/drivers/<protocol>_<transport>/__init__.py
src/mcs/drivers/<protocol>_<transport>/<protocol>_<transport>_driver.py
README.md
LICENSE
pyproject.toml   # or requirements.txt
```

Because of implicit namespace packages (Python 3.3+) there must be **no** `__init__.py` in `src/`, `src/mcs/`, or `src/mcs/drivers/`.


---

## Benefits

* **Reliable, tested prompts**: Drivers include system prompts that clearly describe the available tools and expected responses.
* **Plug-and-play logic**: Add or swap drivers without rewriting your app logic.
* **Lean configuration**: All setup is done via the driver constructor. Making it easy to use by an orchestrator with dependency injection.
* **Shared ecosystem**: Standard naming makes drivers easily discoverable via PyPI.

---

## Architecture & Naming (PyPI Convention)

The Python SDK uses **two prefixes** for package discovery via PyPI. Other language SDKs may define their own conventions.

### Naming scheme

| Level | Pattern | Example |
| --- | --- | --- |
| PyPI package | `mcs-driver-<protocol>-<transport>[-<variant>]` | `mcs-driver-rest-http` |
| Python import | `mcs.drivers.<protocol>_<transport>` | `from mcs.drivers.rest_http import RestHttpDriver` |
| Class (Driver) | `<Protocol><Transport>Driver` | `RestHttpDriver` |
| Class (ToolDriver) | `<Protocol><Transport>ToolDriver` | `RestHttpToolDriver` |
| Files | `driver.py` / `tooldriver.py` | `src/mcs/drivers/rest_http/driver.py` |
| Orchestrator (PyPI) | `mcs-orchestrator-<strategy>[-<variant>]` | `mcs-orchestrator-basic` |
| Orchestrator (import) | `mcs.orchestrators.<strategy>` | `from mcs.orchestrators.basic import BasicOrchestrator` |

**Every driver defaults to hybrid** -- it implements both `MCSDriver` (standalone) and `MCSToolDriver` (orchestrator-facing). This is the recommended pattern because it maximizes reusability: the same driver works directly with a client or as a building block inside an orchestrator.

When a driver explicitly supports only one mode, the variant suffix signals this:

| Suffix | Meaning |
| --- | --- |
| *(none)* | Hybrid (default) -- standalone & orchestrator |
| `-standalone` | Standalone only -- no `list_tools()`/`execute_tool()` |
| `-toolonly` | Orchestrator only -- no LLM-facing methods |
| `-<name>` | Author/vendor variant, e.g. `-acme`, `-petstore` |

### Discovery

Search PyPI with just two prefixes:

```
pip search mcs-driver-              # all drivers
pip search mcs-driver-rest-http     # all REST-HTTP variants
pip search mcs-orchestrator-        # all orchestrators
```

The driver type (hybrid, standalone, toolonly) is also exposed programmatically via `DriverMeta.capabilities` for registries like the planned [mcs-pkg](https://github.com/modelcontextstandard/mcs-pkg).

### Why two prefixes instead of four?

Earlier drafts used separate prefixes for tool drivers (`mcs-tool-`), hybrid drivers (`mcs-tool-driver-`), and full drivers (`mcs-driver-`). This made discovery harder -- users had to search three different prefixes to find all drivers for a given protocol-transport pair. Since hybrid is the recommended default, a single `mcs-driver-` prefix covers all cases. The type lives in the metadata, not the name.

### Import convention (IntelliSense)

The Python namespace follows a strict pattern so IDE autocompletion works predictably:

```python
from mcs.drivers.rest_http import RestHttpDriver           # MCSDriver
from mcs.drivers.rest_http import RestHttpToolDriver       # MCSToolDriver
from mcs.drivers.filesystem_localfs import FilesystemLocalfsDriver
from mcs.orchestrators.basic import BasicOrchestrator
```

When you type `from mcs.drivers.` your IDE lists all installed drivers. When you type `from mcs.drivers.rest_http import ` you see the available classes.

### File naming inside a driver package

Each driver package follows this internal structure:

```
src/mcs/drivers/<protocol>_<transport>/
    __init__.py          # re-exports public classes
    driver.py            # MCSDriver implementation (standalone)
    tooldriver.py        # MCSToolDriver implementation (orchestrator-facing)
```

Class names use PascalCase derived from the module path: `rest_http` becomes `RestHttpDriver` / `RestHttpToolDriver`. This makes the mapping from package name to import path to class name predictable.

### Namespace packages

The SDK uses implicit namespace packages (Python 3.3+). Each driver installs into `mcs.drivers.<protocol>_<transport>` without conflicting with other drivers. There must be **no** `__init__.py` in `src/`, `src/mcs/`, or `src/mcs/drivers/`.

---

## Contributing

We welcome new drivers and improvements:

1. `pip install mcs-drivers-core`
2. Implement the `MCSDriver` interface (and optionally `MCSToolDriver` for orchestrator support).
3. Place your driver under `src/mcs/drivers/<protocol>_<transport>/`.
4. Follow the naming convention: `mcs-driver-<protocol>-<transport>[-<variant>]`.
5. Publish to PyPI or open a PR in this repo.

---

## License

Distributed under Apache 2.0. See `LICENSE` for more information
