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

Unlike MCP, no new protocol is required. At the end of the day, function calling connects a LLM with its environment. 
That makes this primarily a driver challenge, not a protocol stack challenge.

If you really need features provided by MCP (Model Context Protocol), MCS complements that by providing possible drivers
or MCP using MCS compatible drivers.

But for most tool integrations, implementing a robust MCS driver is the pragmatic and efficient path.

---

## What’s inside?

Each part of the SDK is packaged independently. Install exactly what you need.

| Sub-directory / Project     | PyPI Distribution      | Purpose                                                           |
| --------------------------- | ---------------------- | ----------------------------------------------------------------- |
| **`mcs-drivers-core/`**     | `mcs-drivers-core`     | Defines the language-agnostic `MCSDriver` interface and metadata. |
| **`mcs-driver-rest-http/`** | `mcs-driver-rest-http` | A reference driver for connecting to REST APIs (OpenAPI).         |
| **`mcs-examples/`**         | *(not on PyPI)*        | A minimal client and FastAPI demo for local development.          |

> **Why split packages?**<br> 
> The core contract is \~5 kB and has no runtime dependencies.<br> 
> Only add the drivers your app truly needs.

---

## Quick Start

### 1. Environment and Installation

```bash
python -m venv .venv && source .venv/bin/activate   # Windows: .venv\Scripts\activate
pip install mcs-drivers-core mcs-driver-rest-http
```

### 2. Using a Driver

The interaction always follows this pattern:

1. **Get system prompt**: Provided by the driver, tailored for your LLM.
2. **Run LLM**: Send prompt + input to the LLM.
3. **Process response**: The driver parses the LLM response and executes commands.

```python
from mcs.drivers.rest_http import RestHttpDriver

driver = RestHttpDriver(urls=["https://example.com/openapi.json"])

# 1) Get the system prompt for the LLM
system_prompt = driver.get_driver_system_message()

# 2) Let the LLM use that system message (pseudo code)
llm_out = get_llm_response(system_prompt, "Find the email for Danny")

# 3) The driver executes any structured command in the LLM output
final_answer = driver.process_llm_response(llm_out)
```

Once perfect prompts exist for a protocol and transport, they are encapsulated inside the driver. 
This avoids the burden to come up with prompts across apps again and again, this makes the logic reusable.

First time in history of function call it makes sense to get the perfect prompt for a use case, because once developed
everyone can use it directly, without even knowing how it looks like.

With this interface using projects like DSPy to optimize prompts for different LLMs will make the effort pay off really
quickly.

---

## Benefits

* **Reliable, tested prompts**: Drivers include system prompts that clearly describe the available tools and expected responses.
* **Plug-and-play logic**: Add or swap drivers without rewriting your app logic.
* **Lean configuration**: All setup is done via the driver constructor. Making it easy to use by an orchestrator with dependency injection.
* **Shared ecosystem**: Standard naming makes drivers easily discoverable via PyPI.

---

## Architecture & Naming

The SDK follows a consistent naming convention based on PEP 420 namespace packages. This allows multiple independently packaged 
drivers to coexist under shared namespaces like `mcs.drivers`, `mcs.tooldrivers`, and `mcs.orchestrators`.

| Component Type  | PyPI Package Name Format            | Python Namespace                     | Example                          |
| --------------- | ----------------------------------- | ------------------------------------ |----------------------------------|
| MCS Driver      | `mcs-driver-<protocol>-<transport>` | `mcs.drivers.<protocol>_<transport>` | `mcs-driver-rest-http`           |
| MCS Tool Driver | `mcs-tool-<domain>-<name>`          | `mcs.tooldrivers.<domain>_<name>`    | `mcs-tool-erp-odoo`              |
| Orchestrator    | `mcs-orchestrator-<target>`         | `mcs.orchestrators.<target>`         | `mcs-orchestrator-openai-chatml` |

If a name is already taken or the implementation is organization-specific, a custom prefix can be added 
using an underscore, for example: `mcs-driver-rest-http-<org>`.

This structure makes it easy to discover relevant packages using standard tools:

> pip search mcs-driver- <br>
> pip search mcs-tool- <br>
> pip search mcs-orchestrator-

The format ensures that new drivers can be published without requiring a central registry. At the same time, the namespace 
layout supports modular development, semantic clarity, and direct support for dependency injection in orchestrators.

---

## Contributing

We welcome new drivers and improvements:

1. pip install mcs-driver-core
2. Implement the MCSDriver Interace and follow the naming conventions above
3. Implement your driver under `mcs/drivers/<protocol>_<transport>_driver.py`.
4. Publish to PyPI (using the naming scheme) or open a PR in this repo.

---

## License

Distributed under Apache 2.0. See `LICENSE` for more information
