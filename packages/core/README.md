# mcs-driver-core

Core driver contract for the **Model Context Standard (MCS)**.

This package defines the language-agnostic `MCSDriver` and `MCSToolDriver`
interfaces, metadata classes (`DriverMeta`, `DriverBinding`, `DriverResponse`),
extraction strategies, prompt strategies, and optional mixins
(`ToolCallSignaling`, `SupportsNativeTools`).

It has **zero runtime dependencies** and weighs only a few kilobytes.

## Installation

```bash
pip install mcs-driver-core
```

## Quick start

```python
from mcs.driver.core import MCSDriver, DriverMeta, DriverResponse

class MyDriver(MCSDriver):
    ...
```

## Capability detection

Optional features (health checks, native tool-calling via
`get_native_context`, streaming tool-call signaling, …) are advertised as
flags in `DriverMeta.capabilities`. Each optional contract carries its flag
as a `CAPABILITY` constant. There are two operations — **detection** ("is the
feature there?") and **invocation** ("give me the object that provides it") —
and both avoid `isinstance`:

```python
from mcs.driver.core import DriverMeta, SupportsNativeTools

# detection: a pure read over the (aggregated) capability flags
if driver.meta.has_capability(SupportsNativeTools):
    ...

# invocation: get the layer that satisfies the contract -- typed, no cast,
# works whether `driver` is a plain driver, an orchestrator, or a decorator
if (dc := DriverMeta.resolve_capability(driver, SupportsNativeTools)):
    ctx = dc.get_native_context(model)
```

**Do not rely on `isinstance` for feature detection.** Drivers are
composable: a *decorator* (auth, permission, hooks, …) wraps another driver,
satisfies the same `MCSDriver` / `MCSToolDriver` interfaces, and is injected
via dependency injection — so from the outside it just looks like a driver,
and the client cannot know what the stack contains. `isinstance` only sees
the **outermost** layer and misses capabilities provided deeper in the
stack. Each decorator aggregates the inner driver's `capabilities` and adds
its own, so `meta.capabilities` reflects the **whole** stack; `isinstance`
does not.

## Links

- **Homepage:** <https://www.modelcontextstandard.io>
- **Source:** <https://github.com/modelcontextstandard/python-sdk>
- **Specification:** <https://modelcontextstandard.io/Specification>

## License

Apache-2.0
