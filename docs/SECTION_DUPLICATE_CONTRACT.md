# Section duplication and Chromium read-only regions

Section access expansion follows the object's current security descriptor. A
NULL or absent DACL permits expansion; an empty DACL refuses new section rights.
`DUPLICATE_SAME_ACCESS` copies the actual source grant. `MAXIMUM_ALLOWED` preserves
that grant and still checks any explicitly requested additional rights.
`DUPLICATE_CLOSE_SOURCE` closes the original on success and failure.

This follows the object-dependent behavior described by
[Microsoft](https://learn.microsoft.com/windows/win32/api/handleapi/nf-handleapi-duplicatehandle)
and Chromium's actual
[Windows shared-memory creation and transfer code](https://chromium.googlesource.com/chromium/src/+/HEAD/base/memory/platform_shared_memory_region_win.cc).
Chromium installs an empty DACL when it creates a protected region. A universal
cap based only on the source handle incorrectly rejects legitimate NULL-DACL
expansion and descriptor updates.

`T_SEC_ACCESS` now creates an actual empty ACL/security descriptor through
Advapi32. Its read-only fixture retains `READ_CONTROL`, so the existing generic
read check asks only for granted rights. `T_CHROME_SECTION` retains its exact
read/query-only transfer and independent NULL-DACL/current-descriptor tests.
All previous guest checks remain; no programs or checks are skipped.

`SECTION_MAP_EXECUTE_EXPLICIT` (`0x20`) is classified with the other section
rights when an empty DACL refuses new rights. Under empty/nonempty descriptor
evaluation, unknown rights and token-dependent nonempty ACL evaluation keep
their existing unsupported behavior. NULL/absent DACL early allowance is
preserved. This change
does not implement an owner/token ACL evaluator.

The host fixture compiles actual production duplicate, handle/refcount, generic
mapping and descriptor-evaluation bodies. It checks all 64 combinations of six
section rights against every source grant under absent, empty and NULL DACLs,
current descriptor changes, generic requests, explicit execute, unsupported
evaluation, cross-process handles, and failure/source-close cleanup. It also
compiles the complete production IPC and legacy fallback objects using the real
native and standalone build commands.

After a fresh kernel build, run from the repository root:

```sh
python3 -B tests/run_duplicate_access_host.py --repo "$PWD" --proc-stage "$PWD" --out build/section-contract-host
```

The output path must be new. The earlier cap-policy host success is superseded
by the real VM counterexample and preserved as evidence. Host success and a
linked guest fixture do not prove Windows 98 replacement or real Chromium
execution. The full enabled runtime, fresh coherent kernels/loader, and complete
GOP VM suite still require a new source-bound run.
