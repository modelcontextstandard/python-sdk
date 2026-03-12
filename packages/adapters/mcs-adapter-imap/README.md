# mcs-adapter-imap

IMAP adapter for the **Model Context Standard (MCS)**.

Encapsulates all IMAP wire-level details (`imaplib`, MIME parsing) behind a
clean adapter interface. Drivers like `mcs-driver-mailread` delegate all
mailbox I/O to this adapter so they never touch `imaplib` directly.

Zero runtime dependencies -- uses only the Python standard library.

## Installation

```bash
pip install mcs-adapter-imap
```

## Quick start

```python
from mcs.adapter.imap import ImapAdapter

adapter = ImapAdapter(host="imap.example.com", user="alice@example.com", password="...")
folders = adapter.list_folders()
messages = adapter.list_messages("INBOX", limit=10)
```

## Provided methods

| Method             | Description                                |
|--------------------|--------------------------------------------|
| `list_folders`     | List all mailbox folders                   |
| `list_messages`    | List message summaries in a folder         |
| `fetch_message`    | Fetch a full message by UID                |
| `search_messages`  | Search messages by IMAP criteria           |
| `move_message`     | Move a message to another folder           |
| `set_flags`        | Add or remove flags on a message           |
| `create_folder`    | Create a new mailbox folder                |

## Links

- **Homepage:** <https://www.modelcontextstandard.io>
- **Source:** <https://github.com/modelcontextstandard/python-sdk>

## License

Apache-2.0
