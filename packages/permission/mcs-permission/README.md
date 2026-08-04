# mcs-permission

Consent / permission **middleware** for the **Model Context Standard (MCS)**.

Provides `PermissionMiddleware` -- a `ToolMiddleware` that gates tool execution behind a
consent callback. Before `execute_tool` runs, it asks the client whether the pending tool
call (name + arguments) is allowed; on denial it short-circuits the chain and returns a
structured `permission_denied` result instead of executing.

## Installation

```bash
pip install mcs-permission
```

## Usage

```python
from mcs.permission.middleware import PermissionMiddleware

def ask_user(tool_name, arguments) -> bool:
    return input(f"Run {tool_name}? [y/N] ").strip().lower() == "y"

driver = MyDriver(..., middleware=[PermissionMiddleware(consent_handler=ask_user)])
```

The middleware sits *inside* the driver, so the driver keeps its `process_llm_response`
loop and its full identity; each `execute_tool` routes through the chain. Order is list
order (outermost first), so `[PermissionMiddleware(...), AuthMiddleware()]` checks consent
first and handles auth challenges closer to execution. One instance can be shared across
many drivers.

The client keeps its own reference to the middleware to register or replace the handler at
runtime (`set_consent_handler`) -- no lookup needed, because the client constructed it.
The driver's `meta` is unaffected: it stays a static description of the driver class,
while which middleware an instance runs is runtime configuration.

## License

Apache-2.0
