# mcs-adapter-http

HTTP transport adapter for the **Model Context Standard (MCS)**.

Wraps the `requests` library behind a clean adapter interface so that
drivers like `mcs-driver-rest` can make HTTP calls without depending on
a specific HTTP client.

## Installation

```bash
pip install mcs-adapter-http
```

## Quick start

```python
from mcs.adapter.http import HttpAdapter

adapter = HttpAdapter()
response = adapter.get("https://api.example.com/users")
```

## Links

- **Homepage:** <https://www.modelcontextstandard.io>
- **Source:** <https://github.com/modelcontextstandard/python-sdk>

## License

Apache-2.0
