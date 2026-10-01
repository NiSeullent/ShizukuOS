# Explicit mapped Win32 resource adapter

`win32_adapter.c` provides the Win32 resource calling convention to an explicitly
registered mapped PE32 image. Its registry uses the real mapped base as HMODULE,
and NULL selects an explicitly registered root. The existing native loader,
hooks, registry, budgets and runtime admission remain untouched. This is a
concrete adapter for a future module manager, not Chromium execution readiness.

Registration borrows a successful immutable `nr_resources` context and original
file. It proves mapped headers, resource metadata and every payload match that
file before publishing the module. Mappings must be 64 KiB aligned and exactly
SizeOfImage bytes; verification is explicitly bounded to 64 MiB of resource
bytes. Headers/resource data remain immutable. Relocated code outside those
ranges is permitted. Payloads may be outside `.rsrc`, shared or zero sized.
The trusted range callback proves live readability, returns the same address,
and preserves the caller thread's LastError on every return. The native probe
saves/restores it around VirtualQuery and records 12 native sentinel observations
immediately before report I/O. Those observations require genuine guest execution.

HRSRC is a found information-block identity. LoadResource accepts only a found
identity belonging to the supplied module and returns mapped-base plus data RVA.
LockResource accepts only an already loaded data identity. SizeofResource keeps
zero size distinct from an invalid handle through last error. FreeResource
returns FALSE and releases nothing for PE resources; repeated calls do not
invalidate borrowed data. The adapter has no GlobalAlloc/GlobalFree ownership.
Foreign, interior, unissued and unregistered identities are refused without
dereferencing them. Successful calls preserve last error.

The caller serializes calls and registration, retains contexts/files/mappings
through all borrowed uses, unregisters before unmapping, and discards every
borrowed handle before reusing storage. Pointer identities cannot detect ABA.
One explicitly bound process facade is supported; calls before binding are
outside its contract. No thread locks, synthetic module numbers or fake native
database registration are provided.

The internal counted API preserves 31-bit PE IDs and arbitrary counted UTF16,
including NUL and unpaired surrogates. Win32 A/W entry points support WORD
MAKEINTRESOURCE values, bounded `#decimal` IDs and ASCII case-insensitive names.
Non-ASCII ACP conversion/case folding and ambiguous folded names return
ERROR_CALL_NOT_IMPLEMENTED. Exact nonneutral FindResourceEx matches work.
FindResource and special/neutral Ex selectors select a sole language variant;
multiple variants and missing-language fallback are explicitly unsupported.
The full Win98 thread/user/system/default-language policy, MUI and 16-bit NE
resources are deferred. See `adapter_contracts.json` for primary sources;
the pinned 2001 Wine sources supply semantic evidence, not copied code or a
blanket compatibility claim. Genuine Win98 comparison is still pending.

`build_adapter.py --out build/<new-directory>` freezes the complete source,
compiler and original Chromium corpus provenance before compiling. Normal GCC
and Clang ASan/UBSan controls use the same closed fixture and all 159 original
Chromium resources. They exercise malformed metadata, guarded reads, ownership,
last errors, actual shared/zero payloads, counted names and case ambiguity.
The original Chromium runtime profile must continue to refuse admission.

The three classic guest inputs are `RRFIX.DLL`, `RRPROBE.EXE`, `RRWAIT.EXE`.
The DLL has no entry, TLS or OS imports. The probe verifies its whole hash and
first compares selected semantics using original OEM Kernel32 exports. It then
calls only this own mapped fixture's exported stdcall consumer through the
adapter. The outer observer guards original Win98, hashes the entire probe,
requires a fresh readable log, waits at most 30 seconds plus a forced 5 second
reap, and observes the probe's real OS exit separately from report text. Report
I/O and handle-close failures cannot select success. The observer's own OS exit
still needs an independent host/guest observation. The emitted manifest is a
plan only: no staging, disk mutation, VM launch, target callback or application
execution occurs during this build. Chromium application success remains false.
