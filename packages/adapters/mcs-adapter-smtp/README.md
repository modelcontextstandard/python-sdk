# mcs-adapter-smtp

SMTP adapter for the **Model Context Standard (MCS)**.

Encapsulates all SMTP wire-level details (`smtplib`, MIME construction) behind
a clean adapter interface. Drivers like `mcs-driver-mailsend` delegate all
sending I/O to this adapter so they never touch `smtplib` directly.

Supports implicit SSL (port 465), STARTTLS (port 587), and plaintext (port 25).

Zero runtime dependencies -- uses only the Python standard library.

## Installation

```bash
pip install mcs-adapter-smtp
```

## Quick start

```python
from mcs.adapter.smtp import SmtpAdapter

adapter = SmtpAdapter(
    host="smtp.example.com",
    user="alice@example.com",
    password="...",
    sender_name="Alice Smith",  # optional display name
)
adapter.send_message(to="bob@example.com", subject="Hello", body="Hi Bob!")
```

## Provided methods

| Method              | Description                                      |
|---------------------|--------------------------------------------------|
| `send_message`      | Send a plain-text e-mail                         |
| `send_html_message` | Send an HTML e-mail with optional text fallback  |
| `check_connection`  | Test SMTP connectivity and authentication        |

## Links

- **Homepage:** <https://www.modelcontextstandard.io>
- **Source:** <https://github.com/modelcontextstandard/python-sdk>

## License

Apache-2.0
