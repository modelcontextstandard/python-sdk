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
    llm_out = call_llm(messages)                    # your LLM call (pseudo code)
    result  = driver.process_llm_response(llm_out)

    if driver.call_executed:                         # tool was called successfully
        messages.append({"role": "assistant", "content": llm_out})
        messages.append({"role": "tool",      "content": str(result)})

    elif driver.call_failed:                         # tool call found but could not be parsed/executed
        messages.append({"role": "assistant", "content": llm_out})
        messages.append({"role": "system",    "content": driver.get_retry_prompt()})

    else:                                            # no tool call -- final answer
        print(result)
        break
```

Once perfect prompts exist for a protocol and transport, they are encapsulated inside the driver. 
This avoids the burden to come up with prompts across apps again and again, this makes the logic reusable.

For the first time, investing in the perfect prompt for a use case pays off directly -- once developed,
everyone can reuse it without even seeing the prompt itself.

With this interface using projects like DSPy to optimize prompts for different LLMs will make the effort pay off really
quickly.

---

## Benefits

* **Reliable, tested prompts**: Drivers include system prompts that clearly describe the available tools and expected responses.
* **Plug-and-play logic**: Add or swap drivers without rewriting your app logic.
* **Lean configuration**: All setup is done via the driver constructor. Making it easy to use by an orchestrator with dependency injection.
* **Shared ecosystem**: Standard naming makes drivers easily discoverable via PyPI.

---

## Architecture & Naming (PyPI Convention)

The Python SDK uses **two prefixes** for package discovery via PyPI. Other language SDKs may define their own conventions.

| Component | PyPI Package Format | Python Namespace | Example |
| --- | --- | --- | --- |
| Driver | `mcs-driver-<protocol>-<transport>[-<variant>]` | `mcs.drivers.<protocol>_<transport>` | `mcs-driver-rest-http` |
| Orchestrator | `mcs-orchestrator-<strategy>[-<variant>]` | `mcs.orchestrators.<strategy>` | `mcs-orchestrator-basic` |

Drivers default to **hybrid** (implementing both `MCSDriver` and `MCSToolDriver`). Use suffix `-standalone` or `-toolonly` when a driver explicitly supports only one mode. Author/vendor variants use a free suffix, e.g. `-acme`.

Discovery with just two prefixes:

```
pip search mcs-driver-              # all drivers
pip search mcs-driver-rest-http     # all REST-HTTP variants
pip search mcs-orchestrator-        # all orchestrators
```

Implicit namespace packages (Python 3.3+) allow multiple independently packaged drivers to coexist under `mcs.drivers.*` without conflicts. See the [python-sdk README](https://github.com/modelcontextstandard/python-sdk#architecture--naming-pypi-convention) for the full rationale.

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
