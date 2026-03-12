"""Adapter port for IMAP drivers.

Defines the contract that any IMAP adapter must satisfy.
Adapters fulfil this protocol through structural subtyping -- they do
**not** need to import or inherit from this module.
"""

from __future__ import annotations

from typing import Protocol, runtime_checkable


@runtime_checkable
class ImapPort(Protocol):
    """Contract that any IMAP adapter must satisfy.

    The reference implementation is ``ImapAdapter`` from
    ``mcs-adapter-imap``.  Alternative adapters (Exchange Web Services,
    test stubs, ...) only need to implement these methods.
    """

    def list_folders(self) -> str: ...

    def list_messages(self, folder: str = "INBOX", *, limit: int = 20) -> str: ...

    def fetch_message(self, uid: int, folder: str = "INBOX") -> str: ...

    def move_message(self, uid: int, destination: str, folder: str = "INBOX") -> str: ...

    def set_flags(self, uid: int, flags: str, *, remove: bool = False, folder: str = "INBOX") -> str: ...

    def create_folder(self, name: str) -> str: ...

    def search_messages(self, criteria: str = "ALL", folder: str = "INBOX", *, limit: int = 20) -> str: ...
