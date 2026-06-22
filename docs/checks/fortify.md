# FORTIFY checks

`_FORTIFY_SOURCE` replaces unbounded libc calls (`memcpy`, `sprintf`, `strcpy`,
…) with bounds-checked variants (`__memcpy_chk`, …) when the compiler can infer
a buffer size. checksec reports this from several angles, so they get their own
section.

See [Understanding output](../output.md) for color meanings. The **key** under
each heading is the report key used in JSON/YAML and with
[`--fail-if`](../usage.md#ci-gating).

!!! tip "Two different sources"
    `FORTIFY` (and its counts) is derived by comparing the binary's imported
    libc functions against the fortifiable set — it works on any binary.
    `FORTIFY Lvl` and `GLIBCXX Assert` come from
    [annobin](https://sourceware.org/annobin/) compiler notes, which are only
    present on annobin-enabled toolchains (RHEL/Fedora and derivatives). On
    other toolchains they report `Unknown` — see
    [Unknown vs N/A](../output.md#unknown-vs-na).

---

## FORTIFY

**Key:** `fortify_source`

**Protects against:** buffer overflows in common libc string/memory functions,
by routing them through bounds-checked `*_chk` variants.

**How checksec detects it:** resolves the target's libc, builds the set of
fortifiable functions and their fortified (`*_chk`) counterparts, and checks
whether the binary imports any fortified variants.

| Value | Color | Meaning |
|-------|:-----:|---------|
| `Yes` | green | At least one fortified (`*_chk`) function is used. |
| `No` | red | No fortified functions, though fortifiable ones are imported. |
| `N/A` | plain | Nothing fortifiable (e.g. a static binary with no libc imports). |

**Enable:**
```bash
gcc -O2 -D_FORTIFY_SOURCE=2     # or =3 for stricter checks (glibc 2.34+)
```

!!! note
    `_FORTIFY_SOURCE` requires optimization (`-O1` or higher) to take effect.

---

## Fortified / Fortifiable

**Keys:** `fortified`, `fortifiable`

These two informational counts accompany the `FORTIFY` result:

| Column | Meaning |
|--------|---------|
| `Fortified` | Number of fortified (`*_chk`) functions the binary uses. |
| `Fortifiable` | Number of functions that *could* be fortified. |

Both render as plain (informational) counts. A healthy binary has
`Fortified` close to `Fortifiable`. Use `checksec fortifyFile <file>` for the
per-function breakdown.

---

## FORTIFY Lvl

**Key:** `fortify_level`

**Protects against:** the same overflows as FORTIFY — this reports the *level*
the code was compiled at, which annobin records per translation unit.

**How checksec detects it:** reads the `_FORTIFY_SOURCE` numeric note from the
`.gnu.build.attributes` (annobin) section and reports the **lowest** level
across all translation units.

| Value | Color | Meaning |
|-------|:-----:|---------|
| `Level 2` _(or higher)_ | green | All units built with `-D_FORTIFY_SOURCE=2`+. |
| `Level 1` | yellow | Built at level 1 — weaker checks. |
| `Level 0` | red | Explicitly built with fortification off. |
| `Unknown` | yellow | **No annobin notes** — the level can't be determined. |

!!! question "Why does this say `Unknown`?"
    `FORTIFY Lvl → Unknown` is the most-asked-about value (it prompted
    [issue #346](https://github.com/slimm609/checksec/issues/346)). It means the
    binary was built **without annobin**, so the per-unit level wasn't recorded.
    It is *not* a failure — check the `FORTIFY` column for the symbol-based
    verdict, which works without annobin.

**Enable:**
```bash
# On an annobin-enabled toolchain (RHEL/Fedora):
gcc -O2 -D_FORTIFY_SOURCE=2 -fplugin=annobin
```

---

## GLIBCXX assertions

**Key:** `glibcxx_assert`

**Protects against:** out-of-bounds and invalid-argument bugs in the C++
standard library, by enabling libstdc++ precondition assertions.

**How checksec detects it:** reads the `GLIBCXX_ASSERTIONS` annobin note.

| Value | Color | Meaning |
|-------|:-----:|---------|
| `Enabled` | green | Built with `-D_GLIBCXX_ASSERTIONS`. |
| `Disabled` | red | annobin notes show it was off. |
| `Unknown` | yellow | No annobin notes — can't determine (see above). |

**Enable:**
```bash
g++ -D_GLIBCXX_ASSERTIONS
```
