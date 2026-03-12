# mcs-driver-mail

Composite mail driver for the **Model Context Standard (MCS)**.

Combines `mcs-driver-mailread` and `mcs-driver-mailsend` into a single driver
that exposes all 9 tools (7 read + 2 send). This demonstrates the MCS driver
stacking / composition pattern -- build focused drivers, then combine them.

## Installation

```bash
pip install mcs-driver-mail

# With IMAP + SMTP adapters
pip install mcs-driver-mail[imap,smtp]

# Everything including inspector
pip install mcs-driver-mail[all]
```

## Quick start

```python
from mcs.driver.mail import MailToolDriver

td = MailToolDriver(
    read_adapter="imap",
    send_adapter="smtp",
    read_kwargs=dict(host="imap.example.com", user="alice@example.com", password="..."),
    send_kwargs=dict(host="smtp.example.com", user="alice@example.com", password="...",
                     sender_name="Alice Smith"),
)

tools = td.list_tools()       # 9 tools (7 read + 2 send)
td.execute_tool("list_folders", {})
td.execute_tool("send_message", {"to": "bob@example.com", "subject": "Hi", "body": "Hello"})
```

## Tools

| Tool                | Source       | Description                            |
|---------------------|--------------|----------------------------------------|
| `list_folders`      | mailread     | List all mailbox folders               |
| `list_messages`     | mailread     | List message summaries in a folder     |
| `fetch_message`     | mailread     | Fetch a full message by UID            |
| `search_messages`   | mailread     | Search messages by criteria            |
| `move_message`      | mailread     | Move a message to another folder       |
| `set_flags`         | mailread     | Add or remove flags on a message       |
| `create_folder`     | mailread     | Create a new mailbox folder            |
| `send_message`      | mailsend     | Send a plain-text e-mail               |
| `send_html_message` | mailsend     | Send an HTML e-mail with text fallback |

## Architecture

```
mcs-driver-mail (composite)
  ├── mcs-driver-mailread  ←  mcs-adapter-imap (or Gmail, Graph, ...)
  └── mcs-driver-mailsend  ←  mcs-adapter-smtp (or Gmail, Graph, ...)
```

Each sub-driver is protocol-agnostic -- swap adapters without changing driver code.

## Links

- **Homepage:** <https://www.modelcontextstandard.io>
- **Source:** <https://github.com/modelcontextstandard/python-sdk>

## License

Apache-2.0
