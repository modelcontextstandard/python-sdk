# mcs-driver-rest

REST / OpenAPI driver for the **Model Context Standard (MCS)**.

Parses any OpenAPI 3.x specification and exposes every endpoint as a
structured tool that an LLM can call. Supports tag-based and path-based
filtering for large APIs (e.g. GitHub, Stripe).

## Installation

```bash
pip install mcs-driver-rest
```

## Quick start

```python
from mcs.driver.rest import RestDriver

driver = RestDriver(
    url="https://api.example.com/openapi.json",
    include_tags=["search"],
)
system_prompt = driver.get_driver_system_message()
```

## Features

- Automatic tool discovery from OpenAPI specs
- `include_tags` / `include_paths` filtering
- Tool name sanitisation for LLM compatibility
- Interactive inspector CLI: `python -m mcs.driver.rest.inspector <URL>`

## Links

- **Homepage:** <https://www.modelcontextstandard.io>
- **Source:** <https://github.com/modelcontextstandard/python-sdk>

## License

Apache-2.0
