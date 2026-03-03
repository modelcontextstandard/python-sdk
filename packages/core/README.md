# mcs-driver-core

Core driver contract for the **Model Context Standard (MCS)**.

This package defines the language-agnostic `MCSDriver` and `MCSToolDriver`
interfaces, metadata classes (`DriverMeta`, `DriverBinding`, `DriverResponse`),
extraction strategies, prompt strategies, and optional mixins
(`ToolCallSignalingMixin`, `SupportsDriverContext`).

It has **zero runtime dependencies** and weighs only a few kilobytes.

## Installation

```bash
pip install mcs-driver-core
```

## Quick start

```python
from mcs.driver.core import MCSDriver, DriverMeta, DriverResponse

class MyDriver(MCSDriver):
    ...
```

## Links

- **Homepage:** <https://www.modelcontextstandard.io>
- **Source:** <https://github.com/modelcontextstandard/python-sdk>
- **Specification:** <https://modelcontextstandard.io/Specification>

## License

Apache-2.0
