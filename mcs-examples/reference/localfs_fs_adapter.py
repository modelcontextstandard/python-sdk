"""Step 2 -- Local-filesystem implementation of FsAdapter.

Another adapter (e.g. HttpFsAdapter, S3FsAdapter) could provide the
same interface against a different backend.
"""
from __future__ import annotations

from pathlib import Path

from fs_adapter import FsAdapter


class LocalFsAdapter(FsAdapter):

    def __init__(self, base_dir: str) -> None:
        self._base = Path(base_dir).resolve()
        self._base.mkdir(parents=True, exist_ok=True)

    def list_dir(self, path: str, pattern: str = "*") -> list[str]:
        target = self._resolve(path)
        return sorted(
            str(p.relative_to(self._base)) for p in target.glob(pattern) if p.is_file()
        )

    def read_text(self, path: str, encoding: str = "utf-8") -> str:
        return self._resolve(path).read_text(encoding=encoding)

    def _resolve(self, relative_path: str) -> Path:
        resolved = (self._base / relative_path).resolve()
        if self._base not in resolved.parents and resolved != self._base:
            raise ValueError("Path escapes configured base directory.")
        if not resolved.exists():
            raise FileNotFoundError(f"Does not exist: {relative_path}")
        return resolved
