# Actual WTF Win9x memory port

This patch targets WebKit 2.54.0 commit
`5220e80b97a253c60ed899361654142ab5021998`. The original Apple notices remain
in every modified upstream translation unit. New helper and probe code use MIT.
`core_memory_pin.json` records original/final hashes and the added shared header.

The normal JavaScriptCore heap constructor calls `ramSize()` and therefore
`availableMemory()`. Its original Windows implementation directly imports
`GlobalMemoryStatusEx`, which the pinned Windows 98 SE export baseline lacks.
GC also references the real memory-pressure singleton, whose timer callback
retains notification and PSAPI calls. Compiling an archive or a caller of one
unrelated archive section does not verify these dependencies.

The explicit `IEWEBKIT_WIN9X` branch uses `GlobalMemoryStatus` for physical total,
physical availability and current-process virtual address capacity. Output is
validated because the API returns void. The existing 512 MiB upstream estimate
remains the physical-total fallback when a measurement is invalid; that estimate
is not a measured guest value. Invalid pressure measurements preserve the last
pressure status.

Process accounting walks the range returned by `GetSystemInfo`, capped at the
exclusive lower-process limit `0x80000000`, using `VirtualQuery`. Win9x upper
shared/system mappings are excluded. It sums the overlapping `MEM_COMMIT` +
`MEM_PRIVATE` ranges.
The walk validates metadata size, page alignment, region state, forward progress,
address endpoints and accumulation overflow, with an independent iteration bound.
This is **committed private virtual memory**, not resident private working set.
The public `memoryFootprint()` branch uses this conservative proxy and returns
zero when the measurement fails, matching the existing unavailable-measurement
convention. The handler separately tests query success before applying its
process limit.

The real WTF Windows memory-pressure handler remains selected. Installation is
idempotent, arms its existing main-loop timer at 60 seconds, then polls once.
Arming first means a callback can uninstall without a later start resurrecting
the monitor. A scoped guard prevents nested initial polls from recursing into
callbacks. Uninstallation stops that timer and is idempotent. Modern Windows
notification calls are excluded from this Win9x branch, not emulated.

The documented polling policy treats remaining physical memory or process
virtual address capacity at or below one eighth as Warning, and at or below
one sixteenth as Critical. At 128 MiB physical memory these are 16 MiB and 8 MiB.
Warning calls the existing noncritical release path; Critical calls its critical
path. Committed private virtual bytes above 0.9 GiB also trigger the existing
process-limit callback and critical release path. These are explicit Win9x
polling thresholds, not an assertion of equivalence to NT notification policy.
The existing low-memory handler and allocator scavenging contract remain intact.
Modern source branches retain their original code.

`core_memory_native.c` includes the exact shared helper used by patched WTF.
It requires native Win9x 4.10, accepts a fresh nonce and a frozen `MEMPROV.TXT`
containing source/header/binary/receipt hashes, and writes a bounded fresh
`C:\GOPLAB\MEM9X.LOG`. The command remains short enough for COMMAND.COM.
It validates physical and virtual measurements, checks shared policy boundaries,
reserves/commits/touches 2 MiB, requires committed-byte growth of at least that
amount, frees the block and requires the corresponding reduction. The recorded
expected hashes are supplied provenance; the host receipt and frozen manifest
verify actual input bytes. They are not self-computed executable hashes.

`core_memory_fixture.py` freezes four short-name inputs and four possible
outputs under `C:\GOPLAB`, without launching a guest. It binds `MEM9X.EXE` to
its build receipt and sources, and includes the exact-target `IETARGET.EXE` from
`build/iewebkit-win98-ie5-83bd/bundle`. The runner must require every declared
guest path to be absent on a new cold clone. Acceptance needs fresh target OS/IE
and nonce evidence, all MEM9X provenance fields with `exit=0`, the matching
completion nonce, and no failure marker.

The native probe verifies the shared API/accounting/policy backend. It does not
execute the actual WTF timer lifecycle, JSC, a provider DLL, DOM/layout or TLS.
Actual source object compiles, complete linkage/import closure, callback lifecycle
tests and digest-bound native guest execution remain separate gates.
