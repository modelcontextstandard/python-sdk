# mcs-permission

Consent / permission decorator for the **Model Context Standard (MCS)**.

Provides `PermissionDecorator` -- a `BaseDecorator` that gates tool execution
behind a consent callback. Before `execute_tool` runs, the decorator asks the
client whether the pending tool call (name + arguments) is allowed; on denial it
returns a structured `permission_denied` result instead of executing.

## Installation

```bash
pip install mcs-permission
```

## Usage

```python
from mcs.permission.decorator import PermissionDecorator

def ask_user(tool_name, arguments) -> bool:
    return input(f"Run {tool_name}? [y/N] ").strip().lower() == "y"

guarded = PermissionDecorator(MyToolDriver(...), consent=ask_user)
orchestrator.add_driver(guarded, label="mail")
```

It wraps the **ToolDriver** layer, so the surrounding orchestrator keeps its
`process_llm_response` loop and calls `execute_tool` -- the decorator -- beneath
it. Decorators stack: `PermissionDecorator(AuthDecorator(RealToolDriver))`
checks consent first and handles auth challenges deeper down.

Advertises the `"consent"` capability and is reachable via
`DriverMeta.resolve_capability(driver, SupportsConsent)`.

## License

Apache-2.0
