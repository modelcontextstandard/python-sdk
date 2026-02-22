from __future__ import annotations

from pathlib import Path

from mcs.driver.core import BasicOrchestrator

from csv_localfs_tooldriver import CsvLocalfsToolDriver
from runtime_local_tooldriver import RuntimeLocalToolDriver


def client_step(orchestrator: BasicOrchestrator, llm_response: str) -> None:
    print("\nLLM ->", llm_response.strip())
    dr = orchestrator.process_llm_response(llm_response)
    print("call_executed:", dr.call_executed, "call_failed:", dr.call_failed)
    print("tool_call_result:", dr.tool_call_result)
    print("messages:", dr.messages)
    if dr.call_failed:
        print("retry_prompt:", dr.retry_prompt)


def main() -> None:
    base_dir = Path(__file__).parent / "data"
    csv_driver = CsvLocalfsToolDriver(str(base_dir))
    runtime_driver = RuntimeLocalToolDriver()
    orchestrator = BasicOrchestrator([csv_driver, runtime_driver])

    print("== Combined system message ==")
    print(orchestrator.get_driver_system_message())

    # Simulated LLM outputs for demonstration:
    client_step(
        orchestrator,
        '{"tool":"now_utc","arguments":{}}',
    )
    client_step(
        orchestrator,
        '{"tool":"summarize_numeric_column","arguments":{"path":"sales.csv","column":"amount"}}',
    )
    client_step(
        orchestrator,
        '{"tool":"unknown_tool","arguments":{}}',
    )


if __name__ == "__main__":
    main()
