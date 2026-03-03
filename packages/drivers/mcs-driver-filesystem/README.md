# mcs-driver-filesystem

Filesystem driver for the **Model Context Standard (MCS)**.

Provides `list_directory`, `read_file`, and `write_file` tools. The actual
I/O is delegated to a pluggable adapter, making the same driver work with
local disk, SMB shares, or any future backend (S3, SFTP, ...).

## Installation

```bash
pip install mcs-driver-filesystem
```

## Quick start

```python
from mcs.driver.filesystem import FilesystemToolDriver

# Local filesystem (default)
td = FilesystemToolDriver(adapter="localfs", base_dir="/data")

# SMB share
td = FilesystemToolDriver(adapter="smb", server="nas", share="docs",
                           username="user", password="pass")
```

## Adapter protocol

The driver defines a `FilesystemPort` typing protocol. Any object that
implements `list_dir`, `read_text`, `write_text`, `list_files`, `read_raw`,
and `exists` satisfies the contract -- no inheritance required.

## Links

- **Homepage:** <https://www.modelcontextstandard.io>
- **Source:** <https://github.com/modelcontextstandard/python-sdk>

## License

Apache-2.0
