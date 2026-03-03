# mcs-driver-csv

CSV driver for the **Model Context Standard (MCS)**.

Lets an LLM list, read, and query CSV files through structured tools.
Delegates all file I/O to an injected adapter (default: `mcs-adapter-localfs`).

## Installation

```bash
pip install mcs-driver-csv
```

## Quick start

```python
from mcs.driver.csv import CsvDriver

driver = CsvDriver(data_dir="./data")
system_prompt = driver.get_driver_system_message()
```

## Links

- **Homepage:** <https://www.modelcontextstandard.io>
- **Source:** <https://github.com/modelcontextstandard/python-sdk>

## License

Apache-2.0
