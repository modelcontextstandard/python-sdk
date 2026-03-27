"""File-backed cache implementation for the Model Context Standard.

Stores all entries in a single JSON file.  Thread-safe for typical
single-process CLI usage; not designed for concurrent multi-process
writes.

This module has **zero** runtime dependencies.
"""

from __future__ import annotations

import json
import logging
import time
from pathlib import Path
from typing import Any

logger = logging.getLogger(__name__)


class FileCacheStore:
    """File-backed ``CachePort`` implementation.

    Each entry is stored as::

        {"key": {"v": "value", "exp": 1234567890.0}}

    where ``exp`` is an optional expiry timestamp (epoch seconds).
    Entries without ``exp`` never expire.

    Parameters
    ----------
    path :
        Path to the JSON cache file.  Parent directories are created
        on first write.
    """

    def __init__(self, path: str | Path) -> None:
        self._path = Path(path)

    def read(self, key: str) -> str | None:
        """Return the cached value, or ``None`` on miss / expiry."""
        store = self._load()
        entry = store.get(key)
        if entry is None:
            return None
        exp = entry.get("exp")
        if exp is not None and time.time() >= exp:
            self.delete(key)
            return None
        return entry.get("v")

    def write(self, key: str, value: str, *, ttl: float | None = None) -> None:
        """Persist *value*.  Optional *ttl* in seconds sets expiry."""
        store = self._load()
        entry: dict[str, Any] = {"v": value}
        if ttl is not None:
            entry["exp"] = time.time() + ttl
        store[key] = entry
        self._save(store)

    def delete(self, key: str) -> None:
        """Remove *key* (no-op if absent)."""
        store = self._load()
        if store.pop(key, None) is not None:
            self._save(store)

    # -- internal I/O --------------------------------------------------------

    def _load(self) -> dict[str, Any]:
        if not self._path.exists():
            return {}
        try:
            return json.loads(self._path.read_text(encoding="utf-8"))
        except (json.JSONDecodeError, OSError) as exc:
            logger.warning("Cache file unreadable (%s), starting fresh", exc)
            return {}

    def _save(self, store: dict[str, Any]) -> None:
        try:
            self._path.parent.mkdir(parents=True, exist_ok=True)
            self._path.write_text(
                json.dumps(store, indent=2), encoding="utf-8",
            )
        except OSError as exc:
            logger.warning("Could not write cache file: %s", exc)
