"""Adapter port for mail-reading drivers.

Defines the contract that any mailbox adapter must satisfy.
Adapters fulfil this protocol through structural subtyping -- they do
**not** need to import or inherit from this module.

The reference implementation is ``ImapAdapter`` from ``mcs-adapter-imap``.
Future adapters (Gmail API, Microsoft Graph, ...) only need to implement
these methods.
"""

from __future__ import annotations

from typing import Protocol, Union, runtime_checkable


@runtime_checkable
class MailboxPort(Protocol):
    """Contract that any mail-reading adapter must satisfy.

    ``uid`` is ``int | str`` to support both IMAP (integer UIDs) and
    REST APIs like Gmail (string message IDs).
    """

    def list_folders(self) -> str: ...

    def list_messages(self, folder: str = "INBOX", *, limit: int = 20) -> str: ...

    def fetch_message(self, uid: Union[int, str], folder: str = "INBOX") -> str: ...

    def move_message(self, uid: Union[int, str], destination: str, folder: str = "INBOX") -> str: ...

    def set_flags(self, uid: Union[int, str], flags: str, *, remove: bool = False, folder: str = "INBOX") -> str: ...

    def create_folder(self, name: str) -> str: ...

    def search_messages(self, criteria: str = "ALL", folder: str = "INBOX", *, limit: int = 20) -> str: ...
