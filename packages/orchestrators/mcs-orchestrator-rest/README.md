# mcs-orchestrator-rest

Dynamic REST/OpenAPI orchestrator for the **Model Context Standard (MCS)**.

Manages multiple OpenAPI connections, each backed by a `RestToolDriver`.
Automatically resolves tool names across APIs using the base orchestrator's
strategy system.

## Installation

```bash
pip install mcs-orchestrator-rest
```

## Quick start

```python
from mcs.orchestrator.rest import RestOrchestrator

orchestrator = RestOrchestrator(connections=[
    {"url": "https://api.github.com", "include_tags": ["repos"]},
    {"url": "https://api.stripe.com/openapi.json"},
])
system_prompt = orchestrator.get_driver_system_message()
```

## Links

- **Homepage:** <https://www.modelcontextstandard.io>
- **Source:** <https://github.com/modelcontextstandard/python-sdk>

## License

Apache-2.0
