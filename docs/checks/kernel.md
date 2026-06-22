# Kernel checks

`checksec kernel` surveys the hardening configuration of the **running kernel**
(or a supplied config). Instead of one row per binary, it prints one row per
kernel feature, each with a description and a verdict.

```bash
checksec kernel                     # running kernel
checksec kernel -o json             # machine-readable
```

## How it's detected

checksec reads the kernel configuration from the first available of:

- `/proc/config.gz`
- `/boot/config-$(uname -r)`
- a config file you point it at

Each feature maps to one or more `CONFIG_*` options. The result is:

| Value | Color | Meaning |
|-------|:-----:|---------|
| `Enabled` | green | The hardening option is on. |
| `Disabled` | red | The option is off or absent. |

Each row also carries a **Type** (`Kernel Config`, or `SELinux` for SELinux
boot settings) and a human-readable **description**.

## What it covers

The survey spans the major kernel-hardening categories. Representative options:

=== "Memory protection"

    - Restrict Kernel/Module RWX (`CONFIG_STRICT_KERNEL_RWX`, `CONFIG_STRICT_MODULE_RWX`)
    - Make rodata strictly non-executable (`CONFIG_DEBUG_RODATA` / `CONFIG_DEBUG_WX`)
    - Hardened Usercopy (`CONFIG_HARDENED_USERCOPY`)
    - Restrict kernel memory permissions (`CONFIG_ARM_KERNMEM_PERMS`)

=== "ASLR / randomization"

    - Randomize address of kernel image — KASLR (`CONFIG_RANDOMIZE_BASE`)
    - Kernel heap randomization (`CONFIG_COMPAT_BRK` off)
    - Randomize module region (`CONFIG_RANDOMIZE_MODULE_REGION_FULL`)

=== "Stack protection"

    - Stack Protector / Strong (`CONFIG_CC_STACKPROTECTOR*`)
    - Virtually-mapped kernel stack (`CONFIG_VMAP_STACK`)
    - Detect stack corruption on calls to schedule (`CONFIG_SCHED_STACK_END_CHECK`)

=== "Sandboxing / LSM"

    - Secure computing — seccomp (`CONFIG_SECCOMP`, `CONFIG_SECCOMP_FILTER`)
    - Security Landlock / Yama support (`CONFIG_SECURITY_LANDLOCK`, `CONFIG_SECURITY_YAMA`)
    - Kernel lockdown LSM (`CONFIG_SECURITY_LOCKDOWN_LSM*`)
    - SELinux boot settings

=== "Speculative execution"

    - Speculative store bypass disable (`CONFIG_ARM64_SSBD`)
    - Harden branch predictor (`CONFIG_HARDEN_BRANCH_PREDICTOR`)
    - Unmap kernel in userspace — KAISER/KPTI (`CONFIG_UNMAP_KERNEL_AT_EL0`)

=== "Access restrictions"

    - Restrict `/dev/mem` and `/dev/kmem` access (`CONFIG_DEVKMEM`, `CONFIG_STRICT_DEVMEM`, `CONFIG_IO_STRICT_DEVMEM`)
    - Disable TTY line-discipline autoload (`CONFIG_LDISC_AUTOLOAD`)

=== "Integrity / debug"

    - Full reference count validation (`CONFIG_REFCOUNT_FULL`)
    - Check/debug linked-list manipulation (`CONFIG_LIST_HARDENED`, `CONFIG_DEBUG_LIST`)

!!! note "Remediation is distro-dependent"
    Kernel hardening is changed by building/booting a kernel with the relevant
    `CONFIG_*` options (or selecting a hardened kernel package from your
    distribution). Many options are architecture-specific — ARM-only or
    x86-only entries that don't apply to your platform are expected to be
    absent.
