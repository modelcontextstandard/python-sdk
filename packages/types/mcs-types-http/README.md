# mcs-types-http

**Shared HTTP types for the Model Context Standard (MCS).**

Contains `HttpResponse` and `HttpError` -- the library-agnostic value
objects returned by any MCS HTTP adapter (`mcs-adapter-http`,
`mcs-adapter-http-httpx`, ...).

This package has **zero dependencies**.  It exists so that alternative
HTTP adapter implementations can share the same response type without
depending on each other.

## Installation

```bash
pip install mcs-types-http
```

Most users don't need to install this directly -- it's pulled in
automatically by `mcs-adapter-http` and other adapter packages.

## Usage

```python
from mcs.types.http import HttpResponse, HttpError

resp = HttpResponse(status_code=200, text='{"ok": true}')
assert resp.ok
data = resp.json()
```

## Links

- **Homepage:** <https://www.modelcontextstandard.io>
- **Source:** <https://github.com/modelcontextstandard/python-sdk>

## License

Apache-2.0
