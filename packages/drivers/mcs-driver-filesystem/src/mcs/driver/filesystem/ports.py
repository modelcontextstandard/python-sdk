"""Adapter port for filesystem drivers.

Defines the contract that any filesystem adapter must satisfy.
Adapters fulfil this protocol through structural subtyping -- they do
**not** need to import or inherit from this module.
"""

from __future__ import annotations

from typing import Protocol, runtime_checkable


@runtime_checkable
class FilesystemPort(Protocol):
    """Contract that any filesystem adapter must satisfy.

    Implementations include ``LocalFsAdapter`` (``mcs-adapter-localfs``)
    and ``SmbAdapter`` (``mcs-adapter-smb``).  Third-party adapters
    (S3, SFTP, ...) only need to implement these methods.
    """

    def list_dir(self, path: str) -> str: ...

    def read_text(self, path: str, *, encoding: str = "utf-8") -> str: ...

    def write_text(self, path: str, content: str, *, encoding: str = "utf-8") -> str: ...

    def list_files(self, path: str, pattern: str = "*") -> list[str]: ...

    def read_raw(self, path: str, *, encoding: str = "utf-8") -> str: ...

    def exists(self, path: str) -> bool: ...
