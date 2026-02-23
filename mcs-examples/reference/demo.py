"""MCS reference demo -- walks through all four building blocks.

  Step 1: FsAdapter         (fs_adapter.py)
  Step 2: LocalFsAdapter    (localfs_adapter.py)
  Step 3: CsvToolDriver     (csv_tooldriver.py)
  Step 4: CsvDriver         (csv_driver.py)
  Bonus:  Orchestrator managing two CsvDriver instances
          (namespaced to avoid tool-name collisions)

Run from the reference/ directory:
    python demo.py
"""
from __future__ import annotations

import json
import re
from pathlib import Path
from typing import Any

from mcs.driver.core import (
    DriverBinding,
    DriverMeta,
    DriverResponse,
    MCSDriver,
    MCSToolDriver,
    Tool,
)

from csv_driver import CsvDriver


DIVIDER = "-" * 60


# ---------- minimal namespacing orchestrator ----------

class CsvMultiDirOrchestrator(MCSDriver, MCSToolDriver):
    """Tiny orchestrator that namespaces identical CsvDrivers by label.

    Registered as  label -> CsvDriver.
    Tools become   <label>__<original_tool_name>.
    Dispatch strips the prefix and routes to the right driver.
    """

    meta = DriverMeta(
        id="orch-csv-multi-dir",
        name="CSV Multi-Directory Orchestrator",
        version="0.1.0",
        bindings=(DriverBinding(capability="csv", adapter="*", spec_format="Custom"),),
        supported_llms=("*",),
        capabilities=(),
    )

    def __init__(self, drivers: dict[str, MCSToolDriver]) -> None:
        self._drivers = drivers

    def list_tools(self) -> list[Tool]:
        tools: list[Tool] = []
        for label, drv in self._drivers.items():
            for t in drv.list_tools():
                tools.append(Tool(
                    name=f"{label}__{t.name}",
                    description=f"[{label}] {t.description}",
                    parameters=t.parameters,
                ))
        return tools

    def execute_tool(self, tool_name: str, arguments: dict[str, Any]) -> Any:
        label, _, original = tool_name.partition("__")
        drv = self._drivers.get(label)
        if drv is None or not original:
            raise ValueError(f"Unknown namespaced tool: {tool_name}")
        return drv.execute_tool(original, arguments)

    def get_function_description(self, model_name: str | None = None) -> str:
        payload = []
        for t in self.list_tools():
            payload.append({
                "name": t.name, "description": t.description,
                "parameters": [
                    {"name": p.name, "description": p.description, "required": p.required, "schema": p.schema}
                    for p in t.parameters
                ],
            })
        return json.dumps({"tools": payload}, indent=2, ensure_ascii=False)

    def get_driver_system_message(self, model_name: str | None = None) -> str:
        return (
            "You have access to CSV tools across multiple directories.\n"
            "Tool names are prefixed with their source label (e.g. sales__list_csv_files).\n"
            'To call a tool answer ONLY as JSON: {"tool":"<label>__<tool>","arguments":{...}}\n\n'
            f"{self.get_function_description(model_name)}"
        )

    def process_llm_response(self, llm_response: str | dict, *, streaming: bool = False) -> DriverResponse:
        llm_text = llm_response if isinstance(llm_response, str) else json.dumps(llm_response)
        match = re.search(r"\{.*\}", llm_text, re.S)
        if not match:
            return DriverResponse()
        try:
            parsed = json.loads(match.group(0))
        except json.JSONDecodeError:
            return DriverResponse()

        tool_name = parsed.get("tool", "")
        arguments = parsed.get("arguments", {})
        if not tool_name:
            return DriverResponse()

        known = {t.name for t in self.list_tools()}
        if tool_name not in known:
            return DriverResponse()

        try:
            result = self.execute_tool(tool_name, arguments)
            return DriverResponse(
                tool_call_result=result, call_executed=True,
                messages=[
                    {"role": "assistant", "content": llm_text},
                    {"role": "system", "content": str(result)},
                ],
            )
        except Exception as exc:
            retry = f"Tool execution failed: {exc}"
            return DriverResponse(
                call_failed=True, call_detail=str(exc), retry_prompt=retry,
                messages=[
                    {"role": "assistant", "content": llm_text},
                    {"role": "system", "content": retry},
                ],
            )


# ---------- demo functions ----------

def demo_adapter() -> None:
    from localfs_fs_adapter import LocalFsAdapter

    print(f"\n{'=' * 60}")
    print("STEP 1+2 -- FsAdapter / LocalFsAdapter")
    print(f"{'=' * 60}")
    adapter = LocalFsAdapter(str(Path(__file__).parent / "data"))
    print("list_dir('.', '*.csv'):", adapter.list_dir(".", "*.csv"))
    preview = adapter.read_text("sales.csv")
    print("read_text('sales.csv') (first 120 chars):", preview[:120])


def demo_tooldriver() -> None:
    from localfs_fs_adapter import LocalFsAdapter
    from csv_tooldriver import CsvToolDriver

    print(f"\n{'=' * 60}")
    print("STEP 3 -- CsvToolDriver (adapter injected)")
    print(f"{'=' * 60}")
    adapter = LocalFsAdapter(str(Path(__file__).parent / "data"))
    td = CsvToolDriver(adapter)

    print("Available tools:")
    for tool in td.list_tools():
        print(f"  - {tool.name}: {tool.description}")

    print(f"\n{DIVIDER}")
    print("execute_tool('list_csv_files'):")
    print(td.execute_tool("list_csv_files", {}))

    print(f"\n{DIVIDER}")
    print("execute_tool('read_csv_head', path='sales.csv', limit=2):")
    print(td.execute_tool("read_csv_head", {"path": "sales.csv", "limit": 2}))


def demo_driver() -> None:
    print(f"\n{'=' * 60}")
    print("STEP 4 -- CsvDriver (MCSDriver + MCSToolDriver)")
    print(f"{'=' * 60}")
    driver = CsvDriver(base_dir=str(Path(__file__).parent / "data"))

    print("System message (first 200 chars):")
    print(driver.get_driver_system_message()[:200], "...")

    llm_call = '{"tool":"summarize_numeric_column","arguments":{"path":"sales.csv","column":"amount"}}'
    print(f"\n{DIVIDER}")
    print(f"Simulated LLM output: {llm_call}")
    resp = driver.process_llm_response(llm_call)
    print(f"  call_executed: {resp.call_executed}")
    print(f"  tool_call_result: {resp.tool_call_result}")

    unknown_call = '{"tool":"unknown_tool","arguments":{}}'
    print(f"\n{DIVIDER}")
    print(f"Simulated unknown tool: {unknown_call}")
    resp2 = driver.process_llm_response(unknown_call)
    print(f"  call_executed: {resp2.call_executed} (pass-through, no flags set)")


def demo_orchestrator() -> None:
    print(f"\n{'=' * 60}")
    print("BONUS -- CsvMultiDirOrchestrator (two directories, namespaced)")
    print(f"{'=' * 60}")

    orchestrator = CsvMultiDirOrchestrator({
        "sales": CsvDriver(base_dir=str(Path(__file__).parent / "data")),
        "inventory": CsvDriver(base_dir=str(Path(__file__).parent / "data2")),
    })

    print("Namespaced tools:")
    for t in orchestrator.list_tools():
        print(f"  - {t.name}: {t.description}")

    call1 = '{"tool":"sales__list_csv_files","arguments":{}}'
    print(f"\n{DIVIDER}")
    print(f"LLM -> {call1}")
    r1 = orchestrator.process_llm_response(call1)
    print(f"  call_executed: {r1.call_executed}")
    print(f"  tool_call_result: {r1.tool_call_result}")

    call2 = '{"tool":"inventory__read_csv_head","arguments":{"path":"inventory.csv","limit":2}}'
    print(f"\n{DIVIDER}")
    print(f"LLM -> {call2}")
    r2 = orchestrator.process_llm_response(call2)
    print(f"  call_executed: {r2.call_executed}")
    print(f"  tool_call_result: {r2.tool_call_result}")

    call3 = '{"tool":"sales__summarize_numeric_column","arguments":{"path":"sales.csv","column":"amount"}}'
    print(f"\n{DIVIDER}")
    print(f"LLM -> {call3}")
    r3 = orchestrator.process_llm_response(call3)
    print(f"  call_executed: {r3.call_executed}")
    print(f"  tool_call_result: {r3.tool_call_result}")


if __name__ == "__main__":
    demo_adapter()
    demo_tooldriver()
    demo_driver()
    demo_orchestrator()
