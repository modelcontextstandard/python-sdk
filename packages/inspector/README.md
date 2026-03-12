# mcs-inspector

Interactive CLI inspector for any [MCS](https://modelcontextstandard.io) driver.

Point it at a driver, verify the connection, browse discovered tools,
and execute them interactively -- all from the terminal.

## Installation

```bash
# Core inspector (bring your own driver)
pip install mcs-inspector

# With mail-reading driver (IMAP)
pip install mcs-inspector[mailread]

# With mail-sending driver (SMTP)
pip install mcs-inspector[mailsend]

# With composite mail driver (read + send)
pip install mcs-inspector[mail]

# With REST/OpenAPI driver
pip install mcs-inspector[rest]

# Everything
pip install mcs-inspector[all]
```

## Usage

```bash
# Inspect a mailbox (read)
mcs-inspect mailread --host imap.example.com --user alice@example.com

# Inspect a mail-sending server
mcs-inspect mailsend --host smtp.example.com --user alice@example.com

# Inspect both read + send as a composite driver
mcs-inspect mail --read-host imap.example.com --read-user alice@example.com \
                 --send-host smtp.example.com --send-user alice@example.com

# Inspect a REST API via OpenAPI spec
mcs-inspect rest https://api.example.com/openapi.json

# Same via python -m
python -m mcs.inspector mailread --host imap.example.com --user alice@example.com
```

## What it does

1. **Connects** to the target system and verifies the driver works
2. **Lists** all discovered tools in a rich table
3. **Inspects** any tool in detail (parameters, types, descriptions)
4. **Executes** tools interactively -- enter arguments, see results

## Programmatic use

```python
from mcs.inspector import run_inspector
from mcs.driver.mailread import MailreadToolDriver

td = MailreadToolDriver(host="...", user="...", password="...")
run_inspector(td, title="Mailread Inspector")
```

## Links

- **Homepage:** <https://www.modelcontextstandard.io>
- **Source:** <https://github.com/modelcontextstandard/python-sdk>

## License

Apache-2.0
