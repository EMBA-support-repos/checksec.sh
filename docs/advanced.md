# Advanced

## FORTIFY breakdown

`fortifyFile` and `fortifyProc` print the per-function FORTIFY picture: which
fortifiable libc calls the binary uses, and which were routed through the
bounds-checked `*_chk` variants.

```bash
$ checksec fortifyProc 1
* Process name (PID)                         : init (1)
* FORTIFY_SOURCE support available (libc)    : Yes
* Binary compiled with FORTIFY_SOURCE support: Yes

------ EXECUTABLE-FILE ------- . -------- LIBC --------
FORTIFY-able library functions | Checked function names
-------------------------------------------------------
read                           | __read_chk
memcpy                         | __memcpy_chk
...

SUMMARY:
* Number of checked functions in libc                : 78
* Number of FORTIFY-able functions in the executable : 13
* Number of checked functions in the executable      : 7
```

!!! note "Determining the FORTIFY level"
    There is no fully reliable way to recover whether a binary was compiled at
    `_FORTIFY_SOURCE` level 1, 2, or 3 unless it carries
    [annobin](https://sourceware.org/annobin/) notes (see
    [FORTIFY Lvl](checks/fortify.md#fortify-lvl)). Some binaries embed the
    compile command in a string, which you can grep for:

    ```bash
    $ strings /usr/bin/vim | grep FORTIFY
    ... -D_FORTIFY_SOURCE=1
    ```

    Most binaries don't include this, which is why `FORTIFY Lvl` reports
    `Unknown` so often outside annobin toolchains.

## Cross-compiled / offline filesystems

checksec can inspect a cross-compiled target's filesystem offline, with two
caveats:

- **Kernel checks** read live kernel resources, so they must run on the target
  system — or you must point checksec at the target's kernel config file.
- **FORTIFY** resolves libc from the *running* system by default. For an offline
  rootfs, point checksec at the target's libc:

    ```bash
    checksec file /mnt/target/usr/bin/app --libc /mnt/target/lib/libc.so.6
    ```

  Alternatively run inside a `chroot` of the target rootfs. All other checks
  work directly against the offline files.

## OSX and BSD

Most checks target ELF binaries and the Linux kernel. They do **not** work on
Mach-O binaries or the macOS/BSD kernels. checksec may run on some BSD systems
but those platforms are not officially supported.

## Verifying a release signature

Releases are signed. To verify a downloaded `checksec` binary against its
published signature and public key:

```bash
openssl dgst -sha256 -verify checksec.pub -signature checksec.sig checksec
```

A successful check prints `Verified OK`.
