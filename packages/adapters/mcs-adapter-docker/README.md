# mcs-adapter-docker

Docker adapter for the **MCS Sandbox Driver**.

Implements the `SandboxPort` protocol using the Docker Engine API.  Commands
run inside an isolated container, files are transferred via the Docker
`put_archive` / `get_archive` API, and a named volume provides persistence
across container restarts.

## Installation

```bash
pip install mcs-adapter-docker
```

Requires a running Docker daemon (Docker Desktop on Windows/macOS, or the
Docker Engine on Linux).

## Usage

The adapter is typically used through `mcs-driver-sandbox`, not directly:

```python
from mcs.driver.sandbox import SandboxToolDriver

td = SandboxToolDriver(
    adapter="docker",
    image="ubuntu:24.04",
    container_name="agent-workspace",
    volume="agent-data",
)
```

### Direct usage

```python
from mcs.adapter.docker import DockerAdapter

adapter = DockerAdapter(
    image="python:3.12",
    container_name="my-sandbox",
    volume="my-volume",
    working_dir="/workspace",
    resources={"mem_limit": "2g"},
)

adapter.start()
result = adapter.exec("echo hello")
print(result.stdout)  # "hello\n"

adapter.put_file("/workspace/script.py", b"print('hi')")
adapter.exec("python /workspace/script.py")

data = adapter.get_file("/workspace/output.txt")
adapter.stop()
```

## Configuration

| Parameter | Default | Description |
|-----------|---------|-------------|
| `image` | `"ubuntu:24.04"` | Docker image to use |
| `container_name` | `"mcs-sandbox"` | Container name (must be unique) |
| `volume` | `None` | Named Docker volume for persistence |
| `working_dir` | `"/workspace"` | Default working directory inside the container |
| `resources` | `{}` | Resource constraints (e.g. `mem_limit`, `nano_cpus`) |
| `environment` | `{}` | Environment variables passed into the container |
| `docker_base_url` | `None` | Custom Docker daemon URL (e.g. `tcp://remote:2375`) |

## How it works

- **Start**: Creates a new container (or resumes a stopped one).  The named
  volume is mounted at `working_dir`.
- **Exec**: Runs commands via `docker exec` with `/bin/sh -c`.
- **File transfer**: Uses Docker's tar-based `put_archive` and `get_archive`
  API -- no bind mounts or volume drivers needed.
- **Stop**: Stops the container gracefully.  The volume (and all its data)
  survives.

## Links

- **Homepage:** <https://www.modelcontextstandard.io>
- **Source:** <https://github.com/modelcontextstandard/python-sdk>
- **Driver package:** [mcs-driver-sandbox](../../../drivers/mcs-driver-sandbox/)

## License

Apache-2.0
