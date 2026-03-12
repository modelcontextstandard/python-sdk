# mcs-adapter-gmail

Gmail API adapter for the **Model Context Standard (MCS)**.

Provides both mail-reading and mail-sending capabilities via the Gmail REST API.
Implements `MailboxPort` (7 methods) and `MailsendPort` (2 methods) so it works
as a drop-in replacement for `mcs-adapter-imap` + `mcs-adapter-smtp`.

Uses `mcs-adapter-http` as transport layer -- no direct `requests` dependency.

**Auth-agnostic:** receives an OAuth2 access token (or a callable that returns
one). Works with Auth0 Token Vault, manual OAuth2, service accounts, or any
future credential provider.

## Installation

```bash
pip install mcs-adapter-gmail
```

## Quick start

```python
from mcs.adapter.gmail import GmailAdapter

# Static token
adapter = GmailAdapter(access_token="ya29.a0...", sender_name="Alice Smith")

# Or with a token provider (e.g. Auth0 Token Vault)
adapter = GmailAdapter(access_token=lambda: get_fresh_token())

# Use with MCS drivers -- same tools, different backend
from mcs.driver.mailread import MailreadToolDriver
from mcs.driver.mailsend import MailsendToolDriver

td_read = MailreadToolDriver(_adapter=adapter)
td_send = MailsendToolDriver(_adapter=adapter)
```

## Gmail labels vs IMAP folders

Gmail uses **labels** instead of folders. The adapter maps them transparently:

| IMAP concept | Gmail equivalent |
|---|---|
| Folder | Label |
| `\Seen` flag | Remove `UNREAD` label |
| `\Flagged` flag | Add `STARRED` label |
| `\Deleted` flag | Add `TRASH` label |
| Move to folder | Add destination label, remove source label |

## Required OAuth2 scopes

| Scope | Purpose |
|---|---|
| `gmail.readonly` | Read messages and labels |
| `gmail.labels` | Create and manage labels |
| `gmail.send` | Send e-mail |

## Links

- **Homepage:** <https://www.modelcontextstandard.io>
- **Source:** <https://github.com/modelcontextstandard/python-sdk>

## License

Apache-2.0
