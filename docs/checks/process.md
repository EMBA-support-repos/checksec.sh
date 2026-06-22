# Process checks

When you scan a running process (`checksec proc <pid>`, `procAll`) checksec runs
all the [binary hardening checks](binary.md) against the process's executable
**and** adds runtime-only information from `/proc`.

## Seccomp

**Key:** `seccomp`

**Protects against:** a compromised process making arbitrary syscalls — seccomp
restricts the syscalls a process may use.

**How checksec detects it:** reads the `Seccomp` field from
`/proc/<pid>/status`.

| Value | Color | Meaning |
|-------|:-----:|---------|
| `Strict` | green | Strict mode — only `read`/`write`/`exit`/`sigreturn` allowed. |
| `Filter` | green | A BPF seccomp filter is installed. |
| `Disabled` | red | No seccomp restriction. |
| `Unknown` | yellow | The status couldn't be read or parsed. |

**Enable:** seccomp is a **runtime** property — it's applied by the program
itself (via `prctl`/`seccomp()`) or by a sandbox/container runtime, not a
compiler flag. Containers can apply a seccomp profile (e.g. Docker's default
profile, or `--security-opt seccomp=profile.json`).

!!! note "Process-scope only"
    Seccomp only appears when scanning a process; it has no meaning for an
    on-disk file, so `checksec file …` does not include it.

## Related process commands

| Command | What it adds |
|---------|--------------|
| `checksec proc <pid>` | Hardening checks for the process binary + Seccomp. |
| `checksec procAll` | The above for every readable process. Kernel threads and non-ELF entries are skipped. |
| `checksec procLibs <pid>` | Hardening checks for each shared library mapped into the process (via `/proc/<pid>/maps`). |
| `checksec fortifyProc <pid>` | The [FORTIFY](fortify.md) breakdown for a running process. |

!!! tip "Permissions"
    Reading another user's process details usually requires elevated privileges.
    Run with `sudo` to scan processes you don't own; otherwise `procAll` reports
    only what you can read.
