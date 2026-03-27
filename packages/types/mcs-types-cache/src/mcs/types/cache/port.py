"""Cache port contract for the Model Context Standard.

Defines the minimal interface any cache backend must satisfy.
Values are always strings; the consumer is responsible for
serialisation.

This module has **zero** runtime dependencies.
"""

from __future__ import annotations

from typing import Protocol, runtime_checkable


@runtime_checkable
class CachePort(Protocol):
    """Minimal contract for a persistent key-value cache.

    Implementations may store data in a local file, Redis, a database,
    or any other backend.  Values are always strings; the consumer is
    responsible for serialisation.
    """

    def read(self, key: str) -> str | None:
        """Return the value for *key*, or ``None`` on cache miss."""
        ...

    def write(self, key: str, value: str) -> None:
        """Persist *value* under *key*."""
        ...

    def delete(self, key: str) -> None:
        """Remove *key* from the cache (no-op if absent)."""
        ...
