# mcs-driver-mailsend

Mail-sending driver for the **Model Context Standard (MCS)**.

Provides tools for sending plain-text and HTML e-mail. The actual I/O is
delegated to a pluggable adapter, making the same driver work with SMTP,
Gmail API, Microsoft Graph, or any future backend.

## Installation

```bash
pip install mcs-driver-mailsend

# With SMTP adapter
pip install mcs-driver-mailsend[smtp]
```

## Quick start

```python
from mcs.driver.mailsend import MailsendToolDriver

# SMTP (default adapter)
td = MailsendToolDriver(
    adapter="smtp",
    host="smtp.example.com",
    user="alice@example.com",
    password="...",
    sender_name="Alice Smith",  # optional display name
)

tools = td.list_tools()       # 2 tools
result = td.execute_tool("send_message", {
    "to": "bob@example.com",
    "subject": "Hello",
    "body": "Hi Bob!",
})
```

## Tools

| Tool                | Description                                      |
|---------------------|--------------------------------------------------|
| `send_message`      | Send a plain-text e-mail                         |
| `send_html_message` | Send an HTML e-mail with optional text fallback  |

## Adapter protocol

The driver defines a `MailsendPort` typing protocol. Any object that implements
`send_message` and `send_html_message` satisfies the contract -- no inheritance
required.

## Links

- **Homepage:** <https://www.modelcontextstandard.io>
- **Source:** <https://github.com/modelcontextstandard/python-sdk>

## License

Apache-2.0
