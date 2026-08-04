# mcs-hooks

Tool-call lifecycle hooks **middleware** for the **Model Context Standard (MCS)**.

`HooksMiddleware` is added to a driver's middleware chain and emits **observability
events** around `execute_tool`:

- `pre` -- before execution: `handler(tool_name, arguments)`
- `post` -- after success: `handler(tool_name, arguments, result)`
- `on_failure` -- after an exception (then re-raised): `handler(tool_name, arguments, exc)`

Hooks are **observers** (return values ignored). To *gate* a call (confirm/deny)
use `mcs-permission`; for auth challenges use `mcs-auth`. All three are middleware and
compose in one ordered list (ADR-0002), not by nesting.

## Installation

```bash
pip install mcs-hooks
```

## Usage

```python
from mcs.hooks.middleware import HooksMiddleware

def audit(name, args):
    log.info("tool %s args=%s", name, args)

driver = MyDriver(..., middleware=[HooksMiddleware(pre=[audit])])
# or attach at runtime (the client keeps the reference to reconfigure it):
hooks = HooksMiddleware()
driver.add_middleware(hooks)
hooks.add_post_hook(lambda n, a, r: metrics.observe(n))   # multiple observers
```

Multiple handlers per phase (observer pattern): pass lists at construction and/or
`add_*_hook` / `remove_*_hook` at runtime. The client uses its own reference to the
middleware -- no lookup. The driver's `meta` is unaffected: it stays a static description
of the driver class, while which middleware an instance runs is runtime configuration.

## License

Apache-2.0
