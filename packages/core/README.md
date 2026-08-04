# mcs-driver-core

Core driver contract for the **Model Context Standard (MCS)**.

This package defines the language-agnostic `MCSDriver` and `MCSToolDriver`
interfaces, metadata classes (`DriverMeta`, `DriverBinding`, `DriverResponse`),
extraction strategies, prompt strategies, and the optional contracts
(`SupportsHealthcheck`, `SupportsStreaming`, `SupportsNativeTools`,
`SupportsToolMiddleware`).

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

Two questions, two moments. **"Can this object do X?"** — you hold the driver,
so ask it. **"Which driver should I pick?"** — you do not hold one yet, so read
the data sheet (`DriverMeta`).

```python
from mcs.driver.core import SupportsNativeTools

# runtime: detect and call in one step -- the driver satisfies the contract itself
if isinstance(driver, SupportsNativeTools):
    ctx = driver.get_native_tool_context(model)

# data sheet: for a consumer that has metadata but no driver object
candidates = [m for m in registry if m.has_capability(SupportsNativeTools)]
```

Optional features (health checks, native tool-calling, streaming, …) are
declared by the `Supports…` contract a driver implements; each contract carries
its flag as a `CAPABILITY` constant, and `DriverMeta.derive_capabilities` folds
those flags into `meta.capabilities`. That makes the metadata a **projection**
of the contracts rather than a second list to maintain — it cannot drift away
from the object.

Cross-cutting concerns (auth, permission, hooks) are **middleware *inside* the
driver** (`SupportsToolMiddleware`), not wrappers around it — so the driver
keeps its full identity and `isinstance(driver, SupportsX)` sees its contracts
directly (ADR-0002). Which middleware an instance runs is **not** reflected in
its `meta`: that is runtime configuration the client made, not a property of the
driver — and the client that built a middleware holds its own reference to it.

Note that `DriverBinding.capability` (`"rest"`, `"csv"`, `"mailread"`) is the
driver's *subject matter* and the primary selector — unrelated to
`meta.capabilities`, which lists optional contracts, despite the similar name.

## What lives in core — and what doesn't

`mcs-driver-core` holds the contracts (`MCSDriver`, `MCSToolDriver`,
`DriverMeta`) plus the reference implementations that are **pure composition
mechanism** — and nothing more:

- **`BaseDriver`** — the *leaf*. A ready-made implementation of the mandatory
  driver methods (prompt generation, response parsing). It also implements
  `SupportsToolMiddleware`, threading each tool call through its middleware chain.
- **`ToolMiddleware` / `SupportsToolMiddleware`** — the interceptor around
  `execute_tool`: an ordered, in-driver chain for cross-cutting concerns.
  Composition mechanism only; the concrete concerns ship in their own packages
  (`mcs-hooks`, `mcs-permission`, `mcs-auth`).

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
