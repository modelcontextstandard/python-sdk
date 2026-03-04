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
LLM context -- replaced by a Spec. No server. No transport
layer. No build step. 
But the full power of their API is still here. 

[See the full MCS story.](https://modelcontextstandard.io)

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

From easy to complex, but always simple.

### The minimal interface

An MCS driver does exactly three things: tell the LLM what tools exist,
give it a system prompt, and handle its response. That's the entire
contract:

```python
import json
from mcs.driver.core import MCSDriver, DriverResponse

class GreetDriver(MCSDriver):
    def get_function_description(self, model_name=None):
        return '{"tools": [{"name": "greet", "description": "Say hello", "parameters": [{"name": "name", "type": "string"}]}]}'

    def get_driver_system_message(self, model_name=None):
        return f"You have tools:\n{self.get_function_description()}\nCall them as JSON."

    def process_llm_response(self, llm_response, *, streaming=False):
        try:
            call = json.loads(llm_response)
        except (json.JSONDecodeError, TypeError):
            # Not JSON -- nothing for us. Pass through.
            return DriverResponse()

        if call.get("tool") != "greet":
            # Not our tool. Drivers can be chained -- the next driver
            # in the chain will get the same response and may handle it.
            return DriverResponse()

        name = call.get("arguments", {}).get("name", "World")
        return DriverResponse(
            tool_call_result=f"Hello, {name}!",
            call_executed=True,
            messages=[
                {"role": "assistant", "content": llm_response},
                {"role": "system",    "content": f"Hello, {name}!"},
            ],
        )
```

That's it. Three methods.
You write the system prompt, you write the tool descriptions, you parse
the LLM response yourself. This is a valid MCS driver.

But you'd be writing boilerplate -- prompt templates, JSON parsing,
error handling, retry logic -- every single time. That's what
`DriverBase` and the layered architecture solve.

### The recommended workflow

The recommended MCS development workflow is bottom-up:
**Port → Adapter → ToolDriver → Driver (→ Orchestrator)**.

Each ToolDriver has exactly **one responsibility**. IMAP reads mail.
Sending is SMTP -- that would be a separate ToolDriver. Here's a
condensed IMAP inbox driver. Once built, it works with every IMAP
mailbox -- write the driver once, connect any account.

### Step 1 -- Define the port (adapter interface)

The port is a `Protocol` -- it declares what the adapter must provide.
It lives in the driver package so ToolDriver can type-hint against it.

```python
# mcs-driver-imap/src/mcs/driver/imap/ports.py
from typing import Protocol

class ImapPort(Protocol):
    def list_folders(self) -> list[str]: ...
    def list_messages(self, folder: str, limit: int = 20) -> list[dict]: ...
    def read_message(self, message_id: str) -> dict: ...
```
That allows to plugin own implemetations, that the driver should use.

### Step 2 -- Implement the adapter

The adapter satisfies the port against a concrete backend.
No import from the driver package required (structural subtyping).

```python
# mcs-adapter-imap/src/mcs/adapter/imap/adapter.py
import imaplib

class ImapAdapter:
    def __init__(self, host, user, password):
        self._imap = imaplib.IMAP4_SSL(host)
        self._imap.login(user, password)

    def list_folders(self) -> list[str]:
        _, folders = self._imap.list()
        return [f.decode().split('"')[-2] for f in folders]

    def list_messages(self, folder="INBOX", limit=20) -> list[dict]:
        self._imap.select(folder)
        _, data = self._imap.search(None, "ALL")
        # ... parse and return message summaries
        return [{"id": mid, "subject": "...", "from": "..."} for mid in ids[-limit:]]

    def read_message(self, message_id: str) -> dict: ...
```

### Step 3 -- Write the ToolDriver

Maps each adapter method to a `Tool`. No LLM knowledge needed.
Perfect for technical people that don't bother on the LLM side.

```python
# mcs-driver-imap/src/mcs/driver/imap/tooldriver.py
from mcs.driver.core import MCSToolDriver, Tool, ToolParameter
from .ports import ImapPort

class ImapToolDriver(MCSToolDriver):
    def __init__(self, adapter: ImapPort):
        self._adapter = adapter

    def list_tools(self):
        return [
            Tool(name="inbox_list_folders", title="List mail folders",
                 description="Returns all IMAP folders for the connected account."),
            Tool(name="inbox_list_messages", title="List messages in a folder",
                 description="Returns recent messages with subject and sender.",
                 parameters=[
                     ToolParameter(name="folder", description="Folder name", required=True),
                     ToolParameter(name="limit", description="Max messages", schema={"type": "integer"}),
                 ]),
            Tool(name="inbox_read", title="Read a message",
                 description="Returns the full message content including headers and body.",
                 parameters=[ToolParameter(name="message_id", description="Message ID", required=True)]),
        ]

    def execute_tool(self, tool_name, arguments):
        match tool_name:
            case "inbox_list_folders":  return self._adapter.list_folders()
            case "inbox_list_messages": return self._adapter.list_messages(**arguments)
            case "inbox_read":          return self._adapter.read_message(**arguments)
            case _: raise ValueError(f"Unknown tool: {tool_name}")
```

### Step 3b -- Compose ToolDrivers: the `-toolonly` pattern

The `ImapToolDriver` above does exactly one thing: read mail. But in
practice you'll want an LLM that can **read and send** mail. Sending
is SMTP -- a different protocol, a different responsibility, a different
ToolDriver.

So you'd (or your AI Code Assistant) writes a second smtp ToolDriver.
```python
# some code for the smtp ToolDriver
```

Now you have two independent ToolDrivers. Publish them on PyPI with the
`-toolonly` suffix to signal they are building blocks, not standalone
drivers:

| Package | Responsibility |
| --- | --- |
| `mcs-driver-imap-toolonly` | Read mail (IMAP) |
| `mcs-driver-smtp-toolonly` | Send mail (SMTP) |

Anyone who only needs inbox access installs `mcs-driver-imap-toolonly`
and is done. But if you want a full mail experience, you compose them:

### Step 4 -- Write the composite `MailDriver`

The `MailDriver` pulls in both ToolDrivers and presents them as a single
driver to the client. It depends on the `-toolonly` packages.

```python
# mcs-driver-mail/src/mcs/driver/mail/driver.py
from mcs.driver.core import DriverBase
from mcs.driver.imap.tooldriver import ImapToolDriver, SmtpToolDriver

class MailDriver(DriverBase):
    def __init__(self, **kwargs):
        super().__init__(**kwargs)
        self._imap = ImapToolDriver(*(kwargs.get(k) for k in ("imap_host", "imap_user", "imap_pass")))
        self._smtp = SmtpToolDriver(*(kwargs.get(k) for k in ("smtp_host", "smtp_user", "smtp_pass")))

    def list_tools(self):
        return self._imap.list_tools() + self._smtp.list_tools()

    def execute_tool(self, tool_name, arguments):
        for td in (self._imap, self._smtp):
            if any(t.name == tool_name for t in td.list_tools()):
                return td.execute_tool(tool_name, arguments)
```

#### What `DriverBase` does for you

The Driver itself only wires `list_tools()` and `execute_tool()`.
Everything that makes the LLM *understand* and *use* these tools lives
in `DriverBase`:

**System prompt & tool descriptions** -- `get_driver_system_message()`
takes the `Tool` objects from `list_tools()`, passes them through a
`PromptStrategy`, and renders a complete system prompt. The default
strategy loads all text from a TOML file (`default_json.toml`):

- **System message template** with `{tools}` and `{call_example}`
  placeholders -- filled automatically from the Tool definitions
- **Call format** the LLM should use (JSON by default)
- **Healing regexes** to recover from malformed LLM output
- **Retry prompts** for unknown tools or failed executions

You can swap the strategy at construction time:

```python
from mcs.driver.core import PromptStrategy

strategy = PromptStrategy.from_toml("my_prompts.toml")
driver   = MailDriver(imap, smtp, prompt_strategy=strategy)
```

Or bypass it entirely and write the prompts yourself:

```python
driver = MailDriver(
    imap, smtp,
    custom_system_message="You are a mail assistant. ...",
    custom_tool_description="... hand-crafted tool descriptions ...",
)
```

**LLM response parsing** -- `process_llm_response()` runs an extraction
chain that detects tool calls (text-based Formats, OpenAI-native
`tool_calls`, or raw dicts), executes them via `execute_tool()`, and
returns a `DriverResponse` with the result or a retry prompt.

**Native tool-call support** -- `get_driver_context()` returns a
`DriverContext` with `system_message` and, when the model supports it,
`tools` in OpenAI format -- the client just passes them through.

**HybridDriver** -- Because `DriverBase` inherits from both `MCSDriver`
(prompt generation, LLM parsing) *and* `MCSToolDriver` (`list_tools`,
`execute_tool`), every driver that extends `DriverBase` is automatically
a HybridDriver. That means `MailDriver` can talk to a client directly
**and** be used as a ToolDriver inside another driver or orchestrator.
This is the default.

Three packages, clean separation:

| Package | Depends on | Tools |
| --- | --- | --- |
| `mcs-driver-imap-toolonly` | `mcs-adapter-imap` | `inbox_list_folders`, `inbox_list_messages`, `inbox_read` |
| `mcs-driver-smtp-toolonly` | `mcs-adapter-smtp` | `mail_send` |
| `mcs-driver-mail` | both `-toolonly` packages | all of the above |

### Usage

```python
from mcs.driver.mail import MailDriver
from mcs.adapter.imap import ImapAdapter
from mcs.adapter.smtp import SmtpAdapter

mail = MailDriver(
    imap_adapter=ImapAdapter("imap.gmail.com", "user", "pass"),
    smtp_adapter=SmtpAdapter("smtp.gmail.com", "user", "pass"),
)

# Credentials stay in the adapters. The LLM never sees them.
system_prompt = mail.get_driver_system_message()
```

### Chain it -- multiple drivers, same loop

Every MCS driver implements the same interface. The client doesn't change
when you add more drivers. Just pass the LLM response through each one:

```python
from mcs.driver.rest import RestDriver
from mcs.driver.mail import MailDriver
from mcs.adapter.imap import ImapAdapter
from mcs.adapter.smtp import SmtpAdapter

# Two drivers, two completely different backends
docs = RestDriver(url="https://mcsd.io/context7.json")
mail = MailDriver(
    imap_adapter=ImapAdapter("imap.gmail.com", "user", "pass"),
    smtp_adapter=SmtpAdapter("smtp.gmail.com", "user", "pass"),
)

drivers = [docs, mail]

# Combine system prompts
system_prompt = "\n\n".join(d.get_driver_system_message() for d in drivers)

messages = [
    {"role": "system", "content": system_prompt},
    {"role": "user",   "content": "Find the Next.js auth docs and email a summary to danny@example.com"},
]

while True:
    llm_out = call_llm(messages)

    for driver in drivers:
        response = driver.process_llm_response(llm_out)
        if response.call_executed or response.call_failed:
            break

    if response.messages:
        messages.extend(response.messages)

    if response.call_executed:
        continue
    elif response.call_failed:
        continue
    else:
        print(llm_out)
        break
```

REST API + Mail in one chat loop. Same client code. The LLM decides
which tools to call -- `search_libraries`, `query_documentation`,
`inbox_read`, `mail_send` -- and each driver handles its own.
Credentials never cross boundaries.

### Or use an Orchestrator

The manual `for driver in drivers` loop works, but an Orchestrator does
it cleaner: it aggregates tools from multiple ToolDrivers, namespaces
them to avoid collisions, and looks like a single driver to the client.

And that will make it easy for users / client dev to allow change in configuration 
while the loop is running.

Add a new OpenAPI URL, or a filesystem driver.

```python
from mcs.orchestrator.base import BaseOrchestrator
from mcs.driver.rest import RestDriver
from mcs.driver.mail import MailDriver
from mcs.adapter.imap import ImapAdapter
from mcs.adapter.smtp import SmtpAdapter

orch = BaseOrchestrator()
orch.add_driver(RestDriver(url="https://mcsd.io/context7.json"), label="docs")
orch.add_driver(
    MailDriver(
        imap_adapter=ImapAdapter("imap.gmail.com", "user", "pass"),
        smtp_adapter=SmtpAdapter("smtp.gmail.com", "user", "pass"),
    ),
    label="mail",
)

# The orchestrator IS a driver -- same interface, same loop
system_prompt = orch.get_driver_system_message()

messages = [
    {"role": "system", "content": system_prompt},
    {"role": "user",   "content": "Find the Next.js auth docs and email a summary to danny@example.com"},
]

while True:
    llm_out  = call_llm(messages)
    response = orch.process_llm_response(llm_out)     # one call, routes internally

    if response.messages:
        messages.extend(response.messages)

    if response.call_executed:
        continue
    elif response.call_failed:
        continue
    else:
        print(llm_out)
        break
```

The client loop is identical to the single-driver version. The
Orchestrator handles tool namespacing (`docs__search_libraries`,
`mail__mail_send`), resolution, and routing. And because the
Orchestrator itself implements `MCSToolDriver`, it can be nested
inside another Orchestrator.

### Convention over configuration

MCS follows the principle Ruby on Rails once taught us: 
**convention over configuration**

Consistent naming lets you discover packages on
[pypi.org](https://pypi.org/search/?q=mcs-driver) by prefix -- search
for `mcs-driver-` or `mcs-adapter-` and find what you need. The
trade-off: you need to learn the conventions, and there's no system
that enforces them at runtime.

| Level | Pattern | Example |
| --- | --- | --- |
| PyPI (Driver) | `mcs-driver-<capability>` | `mcs-driver-mail`, `mcs-driver-pdf` |
| PyPI (Adapter) | `mcs-adapter-<protocol>` | `mcs-adapter-imap` |
| Python import | `mcs.driver.<capability>` | `from mcs.driver.mail import MailDriver` |
| Class | `<Capability>Driver` | `MailDriver`, `PdfDriver` |

Most packages ship **both** the ToolDriver and the full Driver (a
HybridDriver extending `DriverBase`). For example, `mcs-driver-pdf`
contains a `PdfToolDriver` and a `PdfDriver` -- there's no reason to
separate them. The `-toolonly` suffix (e.g. `mcs-driver-imap-toolonly`)
is only used when a ToolDriver is explicitly designed as a building
block that gets composed into a higher-level driver like `mcs-driver-mail`.

See the [full specification](https://modelcontextstandard.io) for
architectural details, the orchestrator pattern, and security model.

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
