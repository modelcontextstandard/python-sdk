"""Adapter port for HTTP transport.

Defines the contract that any HTTP transport adapter must satisfy.
Adapters fulfil this protocol through structural subtyping -- they do
**not** need to import or inherit from this module.
"""

from __future__ import annotations

from typing import Any, Protocol, runtime_checkable


@runtime_checkable
class HttpPort(Protocol):
    """Contract for HTTP transport used by GmailAdapter.

    ``HttpAdapter`` from ``mcs-adapter-http`` satisfies this out of the box.
    A future ``HttpxAdapter``, a test stub, or any object with a matching
    ``request`` method works equally well.
    """

    def request(
        self,
        method: str,
        url: str,
        *,
        params: dict[str, Any] | None = None,
        json_body: dict[str, Any] | None = None,
        headers: dict[str, str] | None = None,
        timeout: int | None = None,
    ) -> str: ...
