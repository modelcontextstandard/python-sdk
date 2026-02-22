# TODO -- Python SDK

> **Prerequisite:** Verify that the v0.5 `DriverResponse.messages` and `process_llm_response(str | dict, streaming=...)` changes work correctly with and without streaming before proceeding.

---

## 1. BasicMCSDriver -- Abstract Base Class

**Goal:** Eliminate the ~70 lines of boilerplate that every `MCSDriver` implementation currently duplicates (JSON extraction, `str | dict` normalization, `DriverResponse` construction with `messages`).

**Design:** Template Method pattern. `BasicMCSDriver` implements the full `process_llm_response` pipeline and delegates only the execution logic to subclasses via one abstract hook.

```python
class BasicMCSDriver(MCSDriver, ABC):

    # Concrete: full pipeline
    def process_llm_response(self, llm_response: str | dict, *, streaming: bool = False) -> DriverResponse:
        llm_text = llm_response if isinstance(llm_response, str) else json.dumps(llm_response)
        result = self._parse_llm_json(llm_text)
        if result is None:
            return DriverResponse()
        if isinstance(result, DriverResponse):
            return result
        return self._execute_parsed_call(llm_text, result)

    # The one hook subclasses MUST implement
    @abstractmethod
    def _execute_parsed_call(self, llm_text: str, parsed: dict) -> DriverResponse:
        ...

    # Default system message (overridable)
    def get_driver_system_message(self, model_name: str | None = None) -> str:
        return (
            "You are a helpful assistant with access to these tools:\n\n"
            f"{self.get_function_description(model_name)}\n\n"
            'When you need to use a tool, respond with ONLY a JSON object:\n'
            '{"tool": "tool-name", "arguments": {"param": "value"}}\n\n'
            "After receiving a tool result, summarize it for the user.\n"
            "Do not use tools that are not listed above.\n"
        )

    # Helpers for consistent DriverResponse construction
    @staticmethod
    def _success_response(llm_text: str, result: Any) -> DriverResponse: ...
    @staticmethod
    def _failed_response(llm_text: str, detail: str, retry: str) -> DriverResponse: ...

    # JSON extraction + parsing (concrete, shared by all drivers)
    def _parse_llm_json(self, llm_text: str) -> dict | DriverResponse | None: ...
    @staticmethod
    def _extract_json(raw: str) -> str | None: ...
```

**Subclass contract:** Implement `meta`, `get_function_description`, and `_execute_parsed_call`. Everything else is inherited.

**Location:** New file `src/mcs/driver/core/mcs_basic_driver.py`, exported via `__init__.py`.

---

## 2. Message-Role Fix -- `"system"` to `"user"`

**Problem:** All drivers currently use `{"role": "system", "content": str(result)}` for tool-call results in the `messages` list. This is semantically wrong:

- `"system"` is meant for system-level instructions (typically one at conversation start).
- Many LLMs ignore or deprioritize additional system messages mid-conversation.
- Tool results are dynamic data the LLM should process, not system instructions.

**Fix:** Change the default role for tool results from `"system"` to `"user"`:

```python
# Before
{"role": "system", "content": str(result)}

# After
{"role": "user", "content": f"[Tool Result]\n{result}"}
```

`"user"` is the most portable choice -- every LLM handles multiple user messages reliably. Specialized drivers (e.g. for OpenAI native function calling) can override and use `"role": "tool"` with `tool_call_id`.

**Affected files:**
- `python-sdk/src/mcs/driver/core/mcs_base_orchestrator.py`
- `mcs-driver-rest-http/src/mcs/driver/rest_http/driver.py`
- `mcs-driver-filesystem-localfs/src/mcs/driver/filesystem_localfs/driver.py`
- `python-sdk/mcs-examples/reference/csv_localfs_driver.py`
- All docs that show `messages` examples (Driver_Contract.md, Minimal_Driver_Contract.md, 2_Core_Idea.md, README files)

Once `BasicMCSDriver` exists, the fix only needs to happen in `_success_response` / `_failed_response` -- one place instead of four.

---

## 3. Driver Migration to BasicMCSDriver

Migrate all existing `MCSDriver` implementations to extend `BasicMCSDriver` instead.

| Driver | Current base | After migration | Reduction |
|---|---|---|---|
| `FilesystemLocalfsDriver` | `MCSDriver` | `BasicMCSDriver` | ~100 -> ~35 lines |
| `CsvLocalfsDriver` | `MCSDriver` | `BasicMCSDriver` | ~115 -> ~40 lines |
| `RestHttpDriver` | `MCSDriver` | `BasicMCSDriver` | ~265 -> ~235 lines (HTTP logic stays) |
| `BasicOrchestrator` | `MCSDriver, ABC` | `BasicMCSDriver, ABC` | ~265 -> ~200 lines |

Each migration: remove `_extract_json`, remove `process_llm_response` body, implement `_execute_parsed_call`, optionally remove `get_driver_system_message` if default suffices.
