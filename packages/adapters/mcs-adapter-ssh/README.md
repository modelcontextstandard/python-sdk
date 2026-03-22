# mcs-adapter-ssh

SSH adapter for the **MCS Sandbox Driver**.

Implements the `SandboxPort` protocol over SSH + SFTP using
[paramiko](https://www.paramiko.org/).  Turns **any reachable Linux server**
into a sandbox environment -- no Docker, no cloud vendor, no special runtime.
Just an SSH server.

## Installation

```bash
pip install mcs-adapter-ssh
```

## Usage

The adapter is typically used through `mcs-driver-sandbox`, not directly:

```python
from mcs.driver.sandbox import SandboxToolDriver

# Hetzner VPS
td = SandboxToolDriver(
    adapter="ssh",
    host="49.12.xxx.xxx",
    user="deploy",
    key_path="~/.ssh/id_ed25519",
)

# Password auth
td = SandboxToolDriver(
    adapter="ssh",
    host="192.168.1.100",
    user="agent",
    password="s3cret",
)
```

### Direct usage

```python
from mcs.adapter.ssh import SSHAdapter

adapter = SSHAdapter(
    host="49.12.xxx.xxx",
    user="deploy",
    key_path="~/.ssh/id_ed25519",
    working_dir="/home/deploy/workspace",
    known_hosts_policy="reject",  # secure default
)

adapter.start()
result = adapter.exec("uname -a")
print(result.stdout)

adapter.put_file("/home/deploy/workspace/data.csv", csv_bytes)
adapter.exec("python process.py")
output = adapter.get_file("/home/deploy/workspace/result.json")

adapter.stop()
```

## Configuration

| Parameter | Default | Description |
|-----------|---------|-------------|
| `host` | *(required)* | Hostname or IP of the SSH server |
| `user` | *(required)* | SSH username |
| `password` | `None` | Password authentication |
| `key_path` | `None` | Path to private key (e.g. `~/.ssh/id_ed25519`) |
| `key_passphrase` | `None` | Passphrase for encrypted private keys |
| `port` | `22` | SSH port |
| `working_dir` | `"/workspace"` | Default working directory (created on start) |
| `connect_timeout` | `10` | Connection timeout in seconds |
| `known_hosts_policy` | `"reject"` | Host key policy: `"reject"`, `"auto_add"`, or `"warn"` |

## Why SSH?

The SSH adapter is the most versatile backend for the MCS Sandbox Driver:

- **No Docker needed on the target** -- works with any Linux server that has
  sshd running
- **Persistent by nature** -- the remote filesystem *is* the state; nothing
  to snapshot or mount
- **Works everywhere** -- Hetzner VPS, AWS EC2, DigitalOcean, Raspberry Pi,
  Coolify host, on-premise server, WSL2
- **Key-based auth** -- no passwords in config files
- **Battle-tested protocol** -- SSH has been securing remote access since 1995

## How it works

- **Start**: Opens an SSH connection and creates the working directory if
  needed.  The connection is kept alive for subsequent operations.
- **Exec**: Runs commands via `ssh exec_command` with automatic `cd` to the
  working directory.
- **File transfer**: Uses SFTP (over the same SSH connection) for
  `put_file` and `get_file`.  Parent directories are created automatically.
- **Stop**: Closes the SSH connection.  The remote filesystem is untouched.

## Links

- **Homepage:** <https://www.modelcontextstandard.io>
- **Source:** <https://github.com/modelcontextstandard/python-sdk>
- **Driver package:** [mcs-driver-sandbox](../../../drivers/mcs-driver-sandbox/)

## License

Apache-2.0
