# mcs-inspector

Interactive CLI inspector for any [MCS](https://modelcontextstandard.io) driver.

Point it at a driver, verify the connection, browse discovered tools,
and execute them interactively -- all from the terminal.

## Installation

```bash
# Core inspector (bring your own driver)
pip install mcs-inspector

# With IMAP driver
pip install mcs-inspector[imap]

# With REST/OpenAPI driver
pip install mcs-inspector[rest]

# Everything
pip install mcs-inspector[all]
```

## Usage

```bash
# Inspect an IMAP mailbox
mcs-inspect imap --host imap.example.com --user alice@example.com

# Inspect a REST API via OpenAPI spec
mcs-inspect rest https://api.example.com/openapi.json

# Same via python -m
python -m mcs.inspector imap --host imap.example.com --user alice@example.com
```

## What it does

1. **Connects** to the target system and verifies the driver works
2. **Lists** all discovered tools in a rich table
3. **Inspects** any tool in detail (parameters, types, descriptions)
4. **Executes** tools interactively -- enter arguments, see results

## Programmatic use

```python
from mcs.inspector import run_inspector
from mcs.driver.imap import ImapToolDriver

td = ImapToolDriver(host="...", user="...", password="...")
run_inspector(td, title="My IMAP Inspector")
```

## License

Apache 2.0
