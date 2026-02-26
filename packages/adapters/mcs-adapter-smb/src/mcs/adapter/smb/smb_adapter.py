"""MCS SMB Adapter -- SMB/CIFS filesystem transport layer.

Encapsulates all SMB file access (list, read, write, stat) behind
the same interface as ``LocalFsAdapter`` so that ToolDrivers can
work with network shares without code changes.

Uses ``smbprotocol`` (``smbclient``) for SMB2/3 connections.
"""

from __future__ import annotations

import fnmatch
import json
import logging
from typing import Any

import smbclient
from smbprotocol.exceptions import SMBOSError

logger = logging.getLogger(__name__)


class SmbAdapter:
    """Adapter for SMB/CIFS filesystem operations.

    Parameters
    ----------
    server :
        Hostname or IP of the SMB server.
    share :
        Share name (e.g. ``"data"``).
    username :
        Authentication user.
    password :
        Authentication password.
    port :
        SMB port (default 445).
    base_path :
        Optional subdirectory within the share to use as root.
    """

    def __init__(
        self,
        *,
        server: str,
        share: str,
        username: str,
        password: str,
        port: int = 445,
        base_path: str = "",
    ) -> None:
        self._server = server
        self._share = share
        self._username = username
        self._password = password
        self._port = port
        self._base_path = base_path.strip("/\\")
        smbclient.register_session(
            server, username=username, password=password, port=port,
        )

    def _unc(self, relative_path: str = "") -> str:
        """Build a UNC path ``\\\\server\\share\\base\\relative``."""
        parts = [f"\\\\{self._server}\\{self._share}"]
        if self._base_path:
            parts.append(self._base_path)
        if relative_path and relative_path != ".":
            cleaned = relative_path.replace("/", "\\").strip("\\")
            parts.append(cleaned)
        return "\\".join(parts)

    def list_dir(self, path: str) -> str:
        """List entries in *path* and return a JSON string."""
        unc = self._unc(path)
        try:
            entries = []
            for item in sorted(smbclient.scandir(unc), key=lambda e: e.name):
                is_dir = item.is_dir()
                size = item.stat().st_size if not is_dir else None
                entries.append({
                    "name": item.name,
                    "type": "directory" if is_dir else "file",
                    "size": size,
                })
            return json.dumps({"path": unc, "entries": entries}, indent=2)
        except SMBOSError as e:
            return json.dumps({"error": str(e)})

    def read_text(self, path: str, *, encoding: str = "utf-8") -> str:
        """Read a file and return a JSON string with the content."""
        unc = self._unc(path)
        try:
            with smbclient.open_file(unc, mode="r", encoding=encoding) as f:
                content = f.read()
            return json.dumps({"path": unc, "content": content})
        except SMBOSError as e:
            return json.dumps({"error": str(e)})

    def write_text(self, path: str, content: str, *, encoding: str = "utf-8") -> str:
        """Write *content* to a file and return a JSON string."""
        unc = self._unc(path)
        try:
            with smbclient.open_file(unc, mode="w", encoding=encoding) as f:
                f.write(content)
            return json.dumps({
                "path": unc,
                "bytes_written": len(content.encode(encoding)),
            })
        except SMBOSError as e:
            return json.dumps({"error": str(e)})

    def list_files(self, path: str, pattern: str = "*") -> list[str]:
        """Return relative paths of files matching *pattern* under *path*."""
        unc = self._unc(path)
        try:
            return sorted(
                item.name
                for item in smbclient.scandir(unc)
                if item.is_file() and fnmatch.fnmatch(item.name, pattern)
            )
        except SMBOSError:
            return []

    def read_raw(self, path: str, *, encoding: str = "utf-8") -> str:
        """Return the raw text content of a file (no JSON wrapping)."""
        unc = self._unc(path)
        with smbclient.open_file(unc, mode="r", encoding=encoding) as f:
            return f.read()

    def exists(self, path: str) -> bool:
        """Return ``True`` when *path* exists on the share."""
        unc = self._unc(path)
        try:
            smbclient.stat(unc)
            return True
        except SMBOSError:
            return False
