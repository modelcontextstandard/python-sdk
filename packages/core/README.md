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
`get_native_tool_context`, streaming tool-call signaling, …) are advertised as
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
    ctx = dc.get_native_tool_context(model)
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

## What lives in core — and what doesn't

`mcs-driver-core` holds the contracts (`MCSDriver`, `MCSToolDriver`,
`DriverMeta`) plus the reference implementations that are **pure composition
mechanism** — and nothing more:

- **`BaseDriver`** — the *leaf*. A ready-made implementation of the mandatory
  driver methods (prompt generation, response parsing). It carries no resolution
  logic of its own: a leaf has no inner layers, so the resolution entry point's
  `isinstance` fallback matches it directly.
- **`BaseDecorator`** — the *wrapping node*. It delegates every interface call
  to a single inner driver and resolves capabilities by searching inward — the
  one-inner counterpart to what the orchestrator does for many. Being nothing
  but delegation plus stack-navigation, it belongs here alongside `BaseDriver`.

Both are zero-dependency and carry no concept of their own; they are the
minimal machinery the contract already implies.

The **orchestrator** lives in its **own** package (`mcs-orchestrator-base`),
even though it is *also* a wrapping driver. The difference is decisive: it
brings an abstraction of its own — a pluggable `ResolutionStrategy` (tool
pipelines, namespacing, tool-switching layers). That is a strategy *family*
with a concept of its own, not bare mechanism, so it earns a package of its
own (and keeps the kernel free of that weight).

**Rule of thumb:** pure composition mechanism — the leaf and the wrapping
delegation — lives in the kernel; composition that carries its own strategy
becomes its own package.

## Links

- **Homepage:** <https://www.modelcontextstandard.io>
- **Source:** <https://github.com/modelcontextstandard/python-sdk>
- **Specification:** <https://modelcontextstandard.io/Specification>

## License

Apache-2.0
