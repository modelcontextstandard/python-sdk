---
name: mcs-gmail
description: >
  Provides mail tools: list_folders, list_messages, fetch_message, search_messages, move_message, set_flags, create_folder, send_message, send_html_message.
  - list_folders: List all folders (mailboxes) available on the mail server.
  - list_messages: List message headers (subject, from, date, flags) in a folder, newest first.
  - fetch_message: Fetch the full message identified by its UID, including body text.
  - search_messages: Search messages matching criteria such as FROM "alice", SUBJECT "invoice", UNSEEN, SINCE 01-Jan-2025, etc.
  - move_message: Move a message from one folder to another.
  - set_flags: Add or remove flags on a message.
  - create_folder: Create a new folder on the mail server for organising mail.
  - send_message: Send an e-mail with a plain-text body.
  - send_html_message: Send an e-mail with an HTML body and an optional plain-text fallback.
  Use when the user asks about mail operations.
allowed-tools: Bash(python *) Bash(pip *) Bash(uv *) Read
---

# Mail MCS Driver

## Configuration

Before using this skill, configure the required parameters.
The wrapper script resolves each parameter in order:

1. **Environment variable** (highest priority)
2. **Config file** (`config.toml` or `config.json` in the skill directory)
3. **Interactive prompt** (only in a terminal session)

### Option A: Config file

Copy `config.toml.example` to `config.toml` in the skill directory and fill in the values.

### Option B: Environment variables

- `MCS_GMAIL_AUTH0_DOMAIN`
- `MCS_GMAIL_AUTH0_CLIENT_ID`
- `MCS_GMAIL_AUTH0_CLIENT_SECRET`
- `MCS_GMAIL_AUTH0_AUDIENCE`
- `MCS_GMAIL_LINKAUTH_BROKER_URL`
- `MCS_GMAIL_LINKAUTH_API_KEY`

### Parameters

| Parameter | Env Variable | Description |
|-----------|-------------|-------------|
| `auth0_domain` | `MCS_GMAIL_AUTH0_DOMAIN` |  |
| `auth0_client_id` | `MCS_GMAIL_AUTH0_CLIENT_ID` |  |
| `auth0_client_secret` | `MCS_GMAIL_AUTH0_CLIENT_SECRET` | (secret) |
| `auth0_audience` | `MCS_GMAIL_AUTH0_AUDIENCE` |  |
| `linkauth_broker_url` | `MCS_GMAIL_LINKAUTH_BROKER_URL` |  |
| `linkauth_api_key` | `MCS_GMAIL_LINKAUTH_API_KEY` | (secret) |

## Setup

```bash
pip install mcs-driver-mail>=0.1.2 mcs-driver-core>=0.2.2 mcs-driver-mailread>=0.2.0 mcs-driver-mailsend>=0.2.0 mcs-adapter-http>=0.3.0 mcs-auth>=0.3.0 mcs-auth-auth0>=0.4.1 mcs-auth-linkauth>=0.4.1 mcs-types-cache>=0.1.1
```

## Tools

### list_folders

List all folders (mailboxes) available on the mail server.

```bash
python ${CLAUDE_SKILL_DIR}/scripts/mcs_tool.py exec list_folders '{}'
```

---

### list_messages

List message headers (subject, from, date, flags) in a folder, newest first.  Returns at most `limit` entries.

| Parameter | Required | Description |
|-----------|----------|-------------|
| `folder` | no | Folder name (default: INBOX). |
| `limit` | no | Maximum number of messages to return (default: 20). |

```bash
python ${CLAUDE_SKILL_DIR}/scripts/mcs_tool.py exec list_messages '{}'
```

---

### fetch_message

Fetch the full message identified by its UID, including body text.

| Parameter | Required | Description |
|-----------|----------|-------------|
| `uid` | yes | Message UID. |
| `folder` | no | Folder containing the message (default: INBOX). |

```bash
python ${CLAUDE_SKILL_DIR}/scripts/mcs_tool.py exec fetch_message '{"uid": "<uid>"}'
```

---

### search_messages

Search messages matching criteria such as FROM "alice", SUBJECT "invoice", UNSEEN, SINCE 01-Jan-2025, etc.

| Parameter | Required | Description |
|-----------|----------|-------------|
| `criteria` | no | Search criteria string (default: "ALL"). |
| `folder` | no | Folder to search in (default: INBOX). |
| `limit` | no | Maximum number of results (default: 20). |

```bash
python ${CLAUDE_SKILL_DIR}/scripts/mcs_tool.py exec search_messages '{}'
```

---

### move_message

Move a message from one folder to another.

| Parameter | Required | Description |
|-----------|----------|-------------|
| `uid` | yes | Message UID. |
| `destination` | yes | Target folder name. |
| `folder` | no | Source folder (default: INBOX). |

```bash
python ${CLAUDE_SKILL_DIR}/scripts/mcs_tool.py exec move_message '{"uid": "<uid>", "destination": "<destination>"}'
```

---

### set_flags

Add or remove flags on a message.  Common flags: \Seen, \Flagged, \Answered, \Deleted.

| Parameter | Required | Description |
|-----------|----------|-------------|
| `uid` | yes | Message UID. |
| `flags` | yes | Space-separated flags, e.g. '\Seen \Flagged'. |
| `remove` | no | If true, remove the flags instead of adding them (default: false). |
| `folder` | no | Folder containing the message (default: INBOX). |

```bash
python ${CLAUDE_SKILL_DIR}/scripts/mcs_tool.py exec set_flags '{"uid": "<uid>", "flags": "<flags>"}'
```

---

### create_folder

Create a new folder on the mail server for organising mail.

| Parameter | Required | Description |
|-----------|----------|-------------|
| `name` | yes | Name of the folder to create. |

```bash
python ${CLAUDE_SKILL_DIR}/scripts/mcs_tool.py exec create_folder '{"name": "<name>"}'
```

---

### send_message

Send an e-mail with a plain-text body.  Supports To, CC, BCC, and Reply-To headers.

| Parameter | Required | Description |
|-----------|----------|-------------|
| `to` | yes | Comma-separated recipient addresses. |
| `subject` | yes | E-mail subject line. |
| `body` | yes | Plain-text message body. |
| `cc` | no | Comma-separated CC addresses (default: none). |
| `bcc` | no | Comma-separated BCC addresses (default: none). |
| `reply_to` | no | Reply-To address (default: none). |

```bash
python ${CLAUDE_SKILL_DIR}/scripts/mcs_tool.py exec send_message '{"to": "<to>", "subject": "<subject>", "body": "<body>"}'
```

---

### send_html_message

Send an e-mail with an HTML body and an optional plain-text fallback.  Supports To, CC, BCC, and Reply-To headers.

| Parameter | Required | Description |
|-----------|----------|-------------|
| `to` | yes | Comma-separated recipient addresses. |
| `subject` | yes | E-mail subject line. |
| `html_body` | yes | HTML message body. |
| `text_body` | no | Plain-text fallback body (default: none). |
| `cc` | no | Comma-separated CC addresses (default: none). |
| `bcc` | no | Comma-separated BCC addresses (default: none). |
| `reply_to` | no | Reply-To address (default: none). |

```bash
python ${CLAUDE_SKILL_DIR}/scripts/mcs_tool.py exec send_html_message '{"to": "<to>", "subject": "<subject>", "html_body": "<html_body>"}'
```

---
