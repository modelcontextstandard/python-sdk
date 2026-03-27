# mcs-types-cache

**Shared cache types for the Model Context Standard (MCS).**

Contains `CachePort` (the protocol any cache backend must satisfy) and
`FileCacheStore` (the default file-based implementation).

This package has **zero dependencies**.  It exists so that credential
providers, drivers, and other MCS components can persist state across
process invocations without coupling to a specific storage backend.

## Installation

```bash
pip install mcs-types-cache
```

Most users don't need to install this directly -- it's pulled in
automatically by `mcs-auth` and other packages that use caching.

## Usage

```python
from mcs.types.cache import CachePort, FileCacheStore

# File-based cache (default)
cache = FileCacheStore(".mcs_token_cache")
cache.write("my_key", "my_value")
assert cache.read("my_key") == "my_value"
cache.delete("my_key")
assert cache.read("my_key") is None
```

Custom backends implement `CachePort`:

```python
class RedisCacheStore:
    def read(self, key: str) -> str | None: ...
    def write(self, key: str, value: str) -> None: ...
    def delete(self, key: str) -> None: ...
```

## Links

- **Homepage:** <https://www.modelcontextstandard.io>
- **Source:** <https://github.com/modelcontextstandard/python-sdk>

## License

Apache-2.0
