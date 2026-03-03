# mcs-adapter-smb

SMB/CIFS filesystem adapter for the **Model Context Standard (MCS)**.

Provides the same adapter interface as `mcs-adapter-localfs` but operates
on remote SMB/CIFS network shares. Uses `smbprotocol` (SMB 2/3) internally.

Drop-in replacement for `mcs-adapter-localfs` in any MCS driver that
delegates file I/O to an adapter.

## Installation

```bash
pip install mcs-adapter-smb
```

## Quick start

```python
from mcs.adapter.smb import SmbAdapter

adapter = SmbAdapter(
    server="fileserver",
    share="data",
    username="user",
    password="secret",
)
content = adapter.read_text("reports/q1.csv")
```

## Links

- **Homepage:** <https://www.modelcontextstandard.io>
- **Source:** <https://github.com/modelcontextstandard/python-sdk>

## License

Apache-2.0
