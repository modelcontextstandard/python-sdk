# mcs-orchestrator-base

Base orchestrator with pluggable resolution strategies for the
**Model Context Standard (MCS)**.

Combines multiple `MCSToolDriver` instances behind a single `MCSDriver`
interface. Tool-name conflicts are resolved by configurable strategies
(e.g. prefix-based, priority-based).

## Installation

```bash
pip install mcs-orchestrator-base
```

## Quick start

```python
from mcs.orchestrator.base import BaseOrchestrator

orchestrator = BaseOrchestrator()
orchestrator.add_driver(driver_a, label="a")
orchestrator.add_driver(driver_b, label="b")
system_prompt = orchestrator.get_driver_system_message()
```

## Capabilities

The orchestrator is **opaque**: it advertises and resolves only the capabilities
it provides *itself*, not those of the drivers it holds (`resolve_capability`
matches the orchestrator, never reaches inward). It ships with an aggregate
`healthcheck` that combines its first-level drivers — worst status wins, healthy
when none report. Override it for stack-specific semantics.

## Links

- **Homepage:** <https://www.modelcontextstandard.io>
- **Source:** <https://github.com/modelcontextstandard/python-sdk>

## License

Apache-2.0
