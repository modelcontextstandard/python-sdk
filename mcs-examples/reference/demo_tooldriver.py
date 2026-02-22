from __future__ import annotations

from pathlib import Path

from csv_localfs_tooldriver import CsvLocalfsToolDriver


def main() -> None:
    base_dir = Path(__file__).parent / "data"
    driver = CsvLocalfsToolDriver(str(base_dir))

    print("== Available tools ==")
    for tool in driver.list_tools():
        print("-", tool.name)

    print("\n== list_csv_files ==")
    print(driver.execute_tool("list_csv_files", {}))

    print("\n== read_csv_head ==")
    print(driver.execute_tool("read_csv_head", {"path": "sales.csv", "limit": 3}))

    print("\n== summarize_numeric_column ==")
    print(driver.execute_tool("summarize_numeric_column", {"path": "sales.csv", "column": "amount"}))


if __name__ == "__main__":
    main()
