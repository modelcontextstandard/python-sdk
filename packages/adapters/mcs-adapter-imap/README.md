# mcs-adapter-imap

IMAP adapter for the [Model Context Standard](https://modelcontextstandard.io).

Wraps Python's built-in `imaplib` behind a clean interface so that
MCS ToolDrivers never touch IMAP internals directly.

## Installation

```bash
pip install mcs-adapter-imap
```

## Quick start

```python
from mcs.adapter.imap import ImapAdapter

adapter = ImapAdapter(
    host="imap.example.com",
    user="alice@example.com",
    password="secret",
)

folders = adapter.list_folders()
messages = adapter.list_messages("INBOX", limit=10)
```

## License

Apache 2.0
