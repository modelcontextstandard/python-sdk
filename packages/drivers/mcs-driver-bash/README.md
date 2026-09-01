# mcs-driver-sandbox

Sandbox driver for the **Model Context Standard (MCS)**.

Gives AI agents an isolated compute environment with shell access and file
transfer.  The actual execution backend is **freely exchangeable** -- the same
driver works with a local Docker container, an SSH connection to a remote
server, or any future backend, without changing a single line of agent code.

## Why a separate driver and adapter?

Most sandbox solutions (E2B, llm-sandbox, CodeSandbox, open-terminal) ship as
monolithic packages tightly coupled to a single runtime.  MCS takes a different
approach:

```
mcs-driver-sandbox          ← backend-agnostic driver (this package)
  uses SandboxPort (Protocol)
    ├── mcs-adapter-docker   ← local Docker containers
    ├── mcs-adapter-ssh      ← any Linux server via SSH
    └── (your own adapter)   ← implement 6 methods, done
```

Because the driver only talks to a **Protocol** (structural typing), you can
swap the backend by changing one config line -- not by rewriting your agent.

## Installation

```bash
# Driver + Docker backend
pip install mcs-driver-sandbox mcs-adapter-docker

# Driver + SSH backend
pip install mcs-driver-sandbox mcs-adapter-ssh
```

## Quick start

### As a ToolDriver (inside an Orchestrator)

```python
from mcs.driver.sandbox import SandboxToolDriver

# Local Docker container with a persistent volume
td = SandboxToolDriver(
    adapter="docker",
    image="ubuntu:24.04",
    container_name="my-agent-ws",
    volume="agent-workspace",
)

# Or: remote server via SSH
td = SandboxToolDriver(
    adapter="ssh",
    host="49.12.xxx.xxx",
    user="deploy",
    key_path="~/.ssh/id_ed25519",
)
```

### As a standalone Driver (LLM-facing)

```python
from mcs.driver.sandbox import SandboxDriver

driver = SandboxDriver(adapter="docker", image="python:3.12")
print(driver.get_driver_system_message())
```

### Inside an Orchestrator

```python
from mcs.orchestrator.base import BaseOrchestrator
from mcs.driver.sandbox import SandboxDriver

orch = BaseOrchestrator()
orch.add_driver(SandboxDriver(adapter="ssh", host="..."), label="sandbox")
```

## Tools

The driver exposes tools **dynamically**.  When the sandbox is stopped only
lifecycle tools are visible.  After `sandbox_start` the full set appears, so
the LLM learns it must start the sandbox before running commands.

### Lifecycle tools (always visible)

| Tool | Description |
|------|-------------|
| `sandbox_start` | Start or resume the sandbox environment |
| `sandbox_stop` | Stop the sandbox (state is preserved) |
| `sandbox_status` | Check whether the sandbox is running |

### Runtime tools (visible after start)

| Tool | Description |
|------|-------------|
| `shell_exec` | Execute a shell command, returns stdout/stderr/exit_code |
| `file_put` | Upload a file into the sandbox (text or base64) |
| `file_get` | Download a file from the sandbox |

## The SandboxPort protocol

Any object that implements these six methods satisfies the contract -- no
inheritance required:

```python
class SandboxPort(Protocol):
    def start(self) -> dict[str, Any]: ...
    def stop(self) -> dict[str, Any]: ...
    def status(self) -> dict[str, Any]: ...
    def exec(self, command: str, *, timeout: int = 30) -> ExecResult: ...
    def put_file(self, path: str, content: bytes) -> None: ...
    def get_file(self, path: str) -> bytes: ...
```

To add a new backend (e.g. E2B, Coolify, Kubernetes), implement these six
methods and pass the adapter directly:

```python
td = SandboxToolDriver(_adapter=my_custom_adapter)
```

## Persistence

The sandbox is designed as a **workstation**, not a throwaway container.
State survives restarts:

- **Docker**: Named volumes persist across container stop/start cycles
- **SSH**: The remote filesystem is persistent by nature

An agent can install tools on day 1, write scripts on day 2, and find
everything exactly where it left off on day 30.

## Links

- **Homepage:** <https://www.modelcontextstandard.io>
- **Source:** <https://github.com/modelcontextstandard/python-sdk>

## License

Apache-2.0
