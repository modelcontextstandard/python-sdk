# mcs-driver-mailread

Mail-reading driver for the **Model Context Standard (MCS)**.

Provides tools for listing folders, reading messages, searching, moving, and
organising e-mail. The actual I/O is delegated to a pluggable adapter, making
the same driver work with IMAP, Gmail API, Microsoft Graph, or any future
backend.

## Installation

```bash
pip install mcs-driver-mailread

# With IMAP adapter
pip install mcs-driver-mailread[imap]
```

## Quick start

```python
from mcs.driver.mailread import MailreadToolDriver

# IMAP (default adapter)
td = MailreadToolDriver(
    adapter="imap",
    host="imap.example.com",
    user="alice@example.com",
    password="...",
)

tools = td.list_tools()       # 7 tools
result = td.execute_tool("list_folders", {})
```

## Tools

| Tool               | Description                            |
|--------------------|----------------------------------------|
| `list_folders`     | List all mailbox folders               |
| `list_messages`    | List message summaries in a folder     |
| `fetch_message`    | Fetch a full message by UID            |
| `search_messages`  | Search messages by criteria            |
| `move_message`     | Move a message to another folder       |
| `set_flags`        | Add or remove flags on a message       |
| `create_folder`    | Create a new mailbox folder            |

## Adapter protocol

The driver defines a `MailboxPort` typing protocol. Any object that implements
the seven methods above satisfies the contract -- no inheritance required.

## Links

- **Homepage:** <https://www.modelcontextstandard.io>
- **Source:** <https://github.com/modelcontextstandard/python-sdk>

## License

Apache-2.0
