from __future__ import annotations

from pathlib import Path

from csv_localfs_driver import CsvLocalfsDriver


def main() -> None:
    base_dir = Path(__file__).parent / "data"
    driver = CsvLocalfsDriver(str(base_dir))

    print("== get_function_description ==")
    print(driver.get_function_description())

    llm_call = """
    {
      "tool": "filter_csv_rows",
      "arguments": {
        "path": "sales.csv",
        "column": "region",
        "value": "EU",
        "limit": 2
      }
    }
    """
    response = driver.process_llm_response(llm_call)
    print("\n== process_llm_response ==")
    print("call_executed:", response.call_executed)
    print("tool_call_result:", response.tool_call_result)
    print("messages:", response.messages)


if __name__ == "__main__":
    main()
