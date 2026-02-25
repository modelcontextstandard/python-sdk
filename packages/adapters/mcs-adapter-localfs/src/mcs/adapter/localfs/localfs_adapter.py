"""MCS LocalFS Adapter -- local filesystem transport layer.

Encapsulates all direct filesystem access (list, read, write, stat)
behind a clean interface so that ToolDrivers never touch ``pathlib``
or ``os`` directly.  This keeps the adapter swappable: the same
ToolDriver can later work with an S3, SMB, or HTTP-based backend
by providing a different adapter with the same method signatures.
"""

from __future__ import annotations

import json
import logging
from pathlib import Path
from typing import Any

logger = logging.getLogger(__name__)


class LocalFsAdapter:
    """Adapter for local-disk filesystem operations.

    Parameters
    ----------
    base_dir :
        Root directory for resolving relative paths.
        Defaults to the current working directory.
    """

    def __init__(self, *, base_dir: str | None = None) -> None:
        self.base_dir = Path(base_dir) if base_dir else Path.cwd()

    def _resolve(self, path_str: str) -> Path:
        """Resolve *path_str* against ``base_dir`` when relative."""
        p = Path(path_str)
        if not p.is_absolute():
            p = self.base_dir / p
        return p.resolve()

    def list_dir(self, path: str) -> str:
        """List entries in *path* and return a JSON string with the result."""
        target = self._resolve(path)
        if not target.is_dir():
            return json.dumps({"error": f"Not a directory: {target}"})

        entries = []
        for entry in sorted(target.iterdir()):
            entries.append({
                "name": entry.name,
                "type": "directory" if entry.is_dir() else "file",
                "size": entry.stat().st_size if entry.is_file() else None,
            })
        return json.dumps({"path": str(target), "entries": entries}, indent=2)

    def read_text(self, path: str, *, encoding: str = "utf-8") -> str:
        """Read a file and return a JSON string with the content."""
        target = self._resolve(path)
        if not target.is_file():
            return json.dumps({"error": f"Not a file: {target}"})
        try:
            content = target.read_text(encoding=encoding)
            return json.dumps({"path": str(target), "content": content})
        except Exception as e:
            return json.dumps({"error": str(e)})

    def write_text(self, path: str, content: str, *, encoding: str = "utf-8") -> str:
        """Write *content* to a file and return a JSON string with the result."""
        target = self._resolve(path)
        try:
            target.parent.mkdir(parents=True, exist_ok=True)
            target.write_text(content, encoding=encoding)
            return json.dumps({"path": str(target), "bytes_written": len(content.encode(encoding))})
        except Exception as e:
            return json.dumps({"error": str(e)})

    def exists(self, path: str) -> bool:
        """Return ``True`` when *path* exists on disk."""
        return self._resolve(path).exists()
