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

orchestrator = BaseOrchestrator(drivers=[driver_a, driver_b])
system_prompt = orchestrator.get_driver_system_message()
```

## Links

- **Homepage:** <https://www.modelcontextstandard.io>
- **Source:** <https://github.com/modelcontextstandard/python-sdk>

## License

Apache-2.0
