# mcs-adapter-local

The **run-it-right-here execution modality** for the MCS Bash Driver.

Satisfies the bash driver's `ExecutorPort` with a plain subprocess on the
machine the client itself runs on -- which is what every coding harness does
with its bash tool, and exactly what a consent gate exists for.

**No isolation, on purpose, and never a silent default:** a client that wants
an ungated local shell has to construct one, visibly. Pair it with
`PermissionMiddleware` unless the environment is disposable anyway (then
Docker is the better modality).

## Installation

```bash
pip install mcs-adapter-local
```

No dependencies -- stdlib only.

## Usage

```python
from mcs.adapter.local import LocalAdapter, find_shell
from mcs.driver.bash import BashToolDriver

spec = find_shell()                       # detection as a CHOICE, called visibly
td = BashToolDriver(LocalAdapter(shell=spec))
```

`find_shell()` states which shell this machine offers, best first -- the
measured practice of the harnesses (Claude Code and pi locate Git Bash the
same way; Gemini CLI is the precedent for the declared PowerShell fallback):

1. an explicit `override` path (your settings, your env variable),
2. Git Bash at `C:\Program Files\Git\bin\bash.exe`,
3. `bash` on PATH (Cygwin, MSYS2, WSL, any Unix),
4. `pwsh`, then `powershell` (started with pi's measured flags),
5. `COMSPEC` -- cmd.exe, the honest last resort no harness *chooses*.

The returned `ShellSpec` carries **argv, tool name and a syntax note**
together, and the bash driver advertises all of it: on a machine with Git Bash
the model gets the trained `bash` tool ("Commands run in Git Bash (POSIX sh)
-- use its syntax."), on a bare Windows box it honestly gets a `powershell`
tool instead. The tool name must never contradict what the shell speaks -- a
`bash` tool with PowerShell behind it would lure the model into POSIX syntax.

### Construction facts

```python
LocalAdapter(
    shell=find_shell(),          # or ["bash", "-c"], or None for the platform shell
    cwd="/path/to/workspace",    # working directory for every command
    env={"MY_FLAG": "1"},        # ADDED to the inherited environment
)
```

State does **not** persist between calls -- each `exec` is its own process. A
timeout is an answer, not an exception: the command is killed and reported
with exit code 124 (the `timeout(1)` convention) plus a note.

## Links

- **Homepage:** <https://www.modelcontextstandard.io>
- **Source:** <https://github.com/modelcontextstandard/python-sdk>
- **Driver package:** [mcs-driver-bash](../../../drivers/mcs-driver-bash/)

## License

Apache-2.0
