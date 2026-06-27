# mcs-hooks

Tool-call lifecycle hooks decorator for the **Model Context Standard (MCS)**.

`HooksDecorator` wraps a ToolDriver and emits **observability events** around
`execute_tool`:

- `pre` -- before execution: `handler(tool_name, arguments)`
- `post` -- after success: `handler(tool_name, arguments, result)`
- `on_failure` -- after an exception (then re-raised): `handler(tool_name, arguments, exc)`

Hooks are **observers** (return values ignored). To *gate* a call (confirm/deny)
use `mcs-permission`; for auth challenges use `mcs-auth`. All three stack freely:
`Hooks(Permission(Auth(RealToolDriver)))`.

## Installation

```bash
pip install mcs-hooks
```

## Usage

```python
from mcs.hooks.decorator import HooksDecorator

def audit(name, args):
    log.info("tool %s args=%s", name, args)

hooks = HooksDecorator(MyToolDriver(...), pre=[audit])
hooks.add_post_hook(lambda n, a, r: metrics.observe(n))   # multiple observers
orchestrator.add_driver(hooks, label="mail")
```

Multiple handlers per phase (observer pattern): pass lists at construction and/or
`add_*_hook` / `remove_*_hook` at runtime. Advertises the `"hooks"` capability;
reachable via `DriverMeta.resolve_capability(driver, SupportsHooks)`.

## License

Apache-2.0
