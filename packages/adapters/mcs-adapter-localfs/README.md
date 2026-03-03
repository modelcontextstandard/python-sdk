# mcs-adapter-localfs

Local filesystem adapter for the **Model Context Standard (MCS)**.

Encapsulates all local file I/O (`list_dir`, `read_text`, `write_text`, ...)
behind an adapter interface. Used by drivers like `mcs-driver-csv` and
`mcs-driver-filesystem` so they never touch `pathlib` or `os` directly.

Zero runtime dependencies.

## Installation

```bash
pip install mcs-adapter-localfs
```

## Quick start

```python
from mcs.adapter.localfs import LocalFsAdapter

adapter = LocalFsAdapter(base_dir="/data")
content = adapter.read_text("report.csv")
```

## Links

- **Homepage:** <https://www.modelcontextstandard.io>
- **Source:** <https://github.com/modelcontextstandard/python-sdk>

## License

Apache-2.0
