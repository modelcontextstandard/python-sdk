"""Library-agnostic HTTP response types for MCS.

These value objects are shared across all MCS HTTP adapters
(``mcs-adapter-http``, ``mcs-adapter-http-httpx``, ...) and any
package that consumes HTTP responses (connectors, drivers, providers).

This module has **zero** runtime dependencies.
"""

from __future__ import annotations

import json as _json
from dataclasses import dataclass, field
from typing import Any


class HttpError(Exception):
    """Raised by :meth:`HttpResponse.raise_for_status` on non-2xx responses."""

    def __init__(self, status_code: int, reason: str, response: HttpResponse) -> None:
        self.status_code = status_code
        self.reason = reason
        self.response = response
        super().__init__(f"{status_code} {reason}")


@dataclass(frozen=True, slots=True)
class HttpResponse:
    """Immutable HTTP response returned by any MCS HTTP adapter.

    Provides a library-agnostic response interface compatible with the
    common subset of ``requests``, ``httpx``, and ``aiohttp``.
    """

    status_code: int
    text: str
    content: bytes = b""
    headers: dict[str, str] = field(default_factory=dict)
    reason: str = ""
    encoding: str | None = None

    @property
    def ok(self) -> bool:
        return 200 <= self.status_code < 300

    def json(self, **kwargs: Any) -> Any:
        """Parse *text* as JSON."""
        return _json.loads(self.text, **kwargs)

    def raise_for_status(self) -> None:
        """Raise :class:`HttpError` if the status code indicates an error."""
        if not self.ok:
            raise HttpError(self.status_code, self.reason, self)
