"""MCS HTTP Adapter -- reusable transport layer for HTTP-based drivers.

Encapsulates HTTP request execution, proxy configuration, basic
authentication, custom headers, and SSL settings.  Any MCS driver
that communicates over HTTP can delegate transport to this adapter
instead of implementing request logic itself.
"""

from __future__ import annotations

import base64
from typing import Any

import requests


class HttpAdapter:
    """Reusable HTTP transport for MCS drivers.

    Parameters
    ----------
    default_headers :
        Headers attached to every outgoing request.
    proxy_url / proxy_port / proxy_user / proxy_password :
        Optional forward-proxy configuration.
    basic_user / basic_password :
        HTTP Basic-Auth credentials.  When supplied, an ``Authorization``
        header is set automatically (won't overwrite one already present
        in *default_headers*).
    verify_ssl :
        Pass ``False`` to disable TLS certificate verification.
    timeout :
        Default request timeout in seconds.
    """

    def __init__(
        self,
        *,
        default_headers: dict[str, str] | None = None,
        proxy_url: str | None = None,
        proxy_port: int | None = None,
        proxy_user: str | None = None,
        proxy_password: str | None = None,
        basic_user: str | None = None,
        basic_password: str | None = None,
        verify_ssl: bool = True,
        timeout: int = 15,
    ) -> None:
        self.default_headers: dict[str, str] = dict(default_headers or {})
        self.verify_ssl = verify_ssl
        self.timeout = timeout

        if proxy_url and proxy_port:
            auth_seg = (
                f"{proxy_user}:{proxy_password}@"
                if proxy_user and proxy_password
                else ""
            )
            full_proxy = f"http://{auth_seg}{proxy_url}:{proxy_port}"
            self.proxies: dict[str, str] | None = {
                "http": full_proxy,
                "https": full_proxy,
            }
        else:
            self.proxies = None

        if basic_user and basic_password:
            token = base64.b64encode(
                f"{basic_user}:{basic_password}".encode()
            ).decode()
            self.default_headers.setdefault("Authorization", f"Basic {token}")

    def request(
        self,
        method: str,
        url: str,
        *,
        params: dict[str, Any] | None = None,
        json_body: dict[str, Any] | None = None,
        headers: dict[str, str] | None = None,
        timeout: int | None = None,
    ) -> str:
        """Execute an HTTP request and return the response body as text.

        Raises
        ------
        requests.HTTPError
            On non-2xx status codes.
        """
        merged = {**self.default_headers, **(headers or {})}
        resp = requests.request(
            method.upper(),
            url,
            params=params,
            json=json_body,
            headers=merged,
            timeout=timeout or self.timeout,
            verify=self.verify_ssl,
            proxies=self.proxies,
        )
        resp.raise_for_status()
        return resp.text

    def head(self, url: str, *, timeout: int | None = None) -> int:
        """Send a HEAD request and return the HTTP status code."""
        resp = requests.head(
            url,
            headers=self.default_headers,
            timeout=timeout or self.timeout,
            verify=self.verify_ssl,
            proxies=self.proxies,
        )
        return resp.status_code
