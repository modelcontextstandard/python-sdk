# mcs-driver-imap

IMAP driver for the [Model Context Standard](https://modelcontextstandard.io).

Gives an LLM the ability to **read, search, and organise** e-mail via
IMAP.  Sending mail is a separate concern -- use an SMTP driver for that.

## Installation

```bash
pip install mcs-driver-imap
```

## Quick start

```python
from mcs.driver.imap import ImapDriver

# SSL (port 993, default -- most providers)
driver = ImapDriver(
    host="imap.example.com",
    user="alice@example.com",
    password="secret",
)

# STARTTLS (port 143, upgrade to TLS after connect)
driver = ImapDriver(
    host="mail.corp.local",
    user="alice",
    password="secret",
    ssl=False,
    starttls=True,
)

# Standalone usage
system_prompt = driver.get_driver_system_message()
```

Port is chosen automatically (`993` for SSL, `143` for STARTTLS / plaintext)
but can be overridden with `port=...`.

## Tools

| Tool | Description |
|------|-------------|
| `list_folders` | List all mailbox folders |
| `list_messages` | List message headers in a folder (newest first) |
| `fetch_message` | Fetch a complete message by UID |
| `search_messages` | Search messages with IMAP criteria |
| `move_message` | Move a message to another folder |
| `set_flags` | Add or remove flags (seen, flagged, ...) |
| `create_folder` | Create a new mailbox folder |

## Inspector

Test your connection and explore tools interactively:

```bash
# Via the unified MCS inspector (recommended)
pip install mcs-inspector[imap]
mcs-inspect imap --host imap.example.com --user alice@example.com

# Or directly from this package
pip install mcs-driver-imap[inspector]
python -m mcs.driver.imap.inspector --host imap.example.com --user alice@example.com
```

The inspector verifies the IMAP connection, lists all discovered tools,
and lets you execute them interactively with prompted arguments.
Password is prompted securely via `getpass` when not passed as `--password`.

## Security: credentials never reach the LLM

Credentials (`host`, `user`, `password`) are injected once at driver
construction time and stay on the client side.  The LLM only ever sees
tool names, descriptions, and execution results -- **never** the
underlying connection parameters.

That means even a successful prompt-injection attack cannot trick the
model into revealing IMAP credentials.  The worst case is that the LLM
misuses the tools it has (e.g. moving mails to the wrong folder), but
the secret material itself is architecturally out of reach.

## License

Apache 2.0
