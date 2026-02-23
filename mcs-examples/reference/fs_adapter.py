"""Step 1 -- Adapter interface for filesystem backends.

Defines the operations a filesystem backend must support.
Any concrete adapter (local disk, HTTP, S3, SMB, ...) implements
this interface so that ToolDrivers can delegate without knowing
which backend is behind it.
"""
from __future__ import annotations

from abc import ABC, abstractmethod


class FsAdapter(ABC):

    @abstractmethod
    def list_dir(self, path: str, pattern: str = "*") -> list[str]:
        """List entries under *path* that match *pattern* (glob syntax)."""

    @abstractmethod
    def read_text(self, path: str, encoding: str = "utf-8") -> str:
        """Read a file and return its content as text."""
