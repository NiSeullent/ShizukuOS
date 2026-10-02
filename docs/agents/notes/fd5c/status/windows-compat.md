# Windows / NT compatibility lead status

## Assignment and ownership

Implement concurrency and epoch safety in the existing NTWRAP9X transport while
preserving SHZ ABI 1.1, the DIOC controls and genuine Windows VMM ownership.
Owned changes: `ntwrapper/vxd/bridge.c`, `bridge.h`, `README.md`, `test.py`,
`tests/test_vxd.py`, `tests/test_w64vxd.c`, new
`tests/test_w64_admission.c`, and this status document.

No changes to scheduler, GOP, native Windows media, historical receipts,
`kernel64/subsys64.c`, or the common capability manifest. The latter two are
assigned to the coordinated external chats, not this lead.

Current checkout HEAD when reporting: `f8dafa6be91df0bd123c3903c1d7676be6c6a299`.
This scoped implementation is uncommitted; the master owns scoped integration
and must record its eventual commit SHA. No shared index mutation was performed.

## Implemented decisions

- An atomic nonblocking token owns W64 scratch, SPSC endpoints and pending pool
  metadata for one DIOC. Reentrant/parallel callers receive `ERROR_BUSY` before
  page callbacks. Normal success/error returns release the token. Dynamic
  shutdown refuses an admitted operation; reset leaves its state intact.
- OPEN captures a validated bounded layout. Header/owner table, both rings and
  pool are aligned, disjoint and in the mapped window; ring/header slot counts
  agree. Operations reject changed geometry with error 31 and changed epoch with
  error 55 until explicit reset/reopen.
- Incoming frames must match Kernel64 source, Win98 destination and live epoch,
  with a supported reply/one-way flag combination and no incoming pool reference.
  A pool completion must match both request ID and opcode. Invalid responses are
  dropped and counted without releasing pending buffers. A duplicate outstanding
  pool request ID returns BUSY before dispatch.
- RECV drains at most the captured ring depth. Nonconsumable corrupt indices
  return error 31 instead of looping forever. No queue indices are fabricated or
  repaired to create a passing result.
- Reset does not reclaim peer-visible allocations: a still-queued request may
  consume them. Cancellation/timeout/process-rundown acknowledgement is not
  implemented by this slice. Outstanding allocations require terminal replies
  or proven Supervisor-owned channel teardown.
- Admission precedes page pinning; the existing short IRQ-masked metadata/copy
  intervals occur within admission. Admission never spins, sleeps, or masks IRQs.
  Native VMM page-service assumptions remain single-vCPU Windows 98 assumptions.

Scheduling remains separate: Supervisor selects domain execution; VMM selects
Win16/Win32 threads and preserves its critical sections/callbacks; Kernel64
selects native workers. This change adds no VMM service number, scheduler hook,
wire structure, opcode, fabricated event wait, or new VxD.

## Test-first evidence

The original native build and twelve original host groups passed before edits.
The sanitizer regression binary then failed on the old implementation for
reentrant and actual pthread overlap, invalid layout, stale epoch, changed live
layout, duplicate pool IDs and foreign responses. The corrupt-head case timed
out after two seconds. Recorded failures remain in the ignored artifact
`build/pma-win98-vxd-baseline/regressions-red.json` with the old binaries and
baseline receipt; no historical evidence was overwritten.

All eight regression cases subsequently passed under ASan/UBSan, including seven
distinct invalid response variants and eight invalid layouts. Actual pthread
overlap passed under ASan/UBSan and TSan.

## Reproducible final checks

Executed from the integration worktree:

```sh
python3 -B ntwrapper/vxd/build.py --out build/pma-win98-vxd
python3 -B ntwrapper/vxd/test.py --out build/pma-win98-vxd
git diff --check -- ntwrapper/vxd
```

All exited 0. The fresh strict freestanding i486 build retains exact LE RX/RW
flags, documented VMM thunk constants, a single guarded VMCALL and no undefined
imports. The complete current suite reports **13 tests, OK**: original core
bridge 234 assertions; existing WIN64 bridge 2504 assertions; eight additional
regression cases (101, 169, 156, 57, 104, 375, 57, 57 assertions); actual pthread
admission under both ASan/UBSan and TSan; native i386 control-dispatch harness;
independent LE relocation/container and PE probe checks.

`build/pma-win98-vxd/host-tests.json` reports `passed: true` and
`inputs_unchanged_during_test: true`. Source, tests, docs and build artifacts were
unchanged throughout the final test command. It also keeps `guest_loaded`,
`native_vmm_calls_verified` and `win64_bridge_supervisor_run` false.

- Refreshed `NTWRAP9X.VXD`: 18161 bytes,
  SHA-256 `c11ecc0f890d1c3e41fd898f6ee36417777cb46e19ea8c240146f513065038f5`.
- Final host receipt SHA-256:
  `55d00ff4443b40825a56abf40c58f91f17d7a7a2f537b8fc1b35683cf3160705`.
- Final test log SHA-256:
  `b8dfd6d230f5f9ebe9128cdbd5a7871aa43d63553964f49e55f0a8f8f0a5ff57`.

## Dependencies, review and genuine Windows gates

Ready for independent master review and scoped integration. The Kernel64 owner
was separately notified about its analogous corrupt-head drain and missing
source-domain validation; this lead did not edit that shared service file.
The common manifest owner must distinguish serialized transport admission from
end-to-end concurrent Windows clients. NTW32 still requires caller serialization
and there is no per-process response broker in this slice. Caller request IDs
must remain unique in a live channel epoch; this slice only detects IDs still
holding pending pool allocations.

Frozen prior native production load/query/absent-Supervisor reject-50 evidence
is preserved in the application campaign. It does not validate this refreshed
artifact. Actual Windows load/VMM page-service/paging-lifetime validation, live
Supervisor channel2 exchange, VMM/PMA wait/signal/timeout/cancellation/rundown,
DOS-to-VMM replacement and a real Windows application-to-worker round trip
remain runtime gates. Host sanitizers and native linkage are component evidence
only. No positive Windows/PMA completion or broader SMP compatibility is claimed.

## Review correction F2 — lifecycle readiness race

The independent review found that the first W64 readiness read still accessed
plain `live` before admission while shutdown wrote it under admission. A new
actual pthread regression runs shutdown against W64 entry across 128 rounds;
each round initializes externally before creating the two threads and joins
both before any later lifecycle operation. The regression also explicitly
asserts shutdown refuses the existing paused admitted owner.

RED on the pre-correction code: TSan exited **66** and reported the exact
`bridge.c:533` readiness read versus `bridge.c:67` shutdown write. The log and
binary are retained at
`build/pma-win98-vxd-baseline/lifecycle-red-tsan.log` and
`test_w64_lifecycle_red_tsan`; the standalone corrected check exits 0, recorded
as `lifecycle-green-tsan.log` and `test_w64_lifecycle_green_tsan` in that same
component output directory.

Every access to `live` and `selftest` is now atomic, including pre-admission
readiness and QUERY payload flags. Release publication and acquire observation
remove the conflicting plain accesses; transport work still requires admission.
Context initialization remains an externally serialized operation. QUERY's
controls, payload layout and ordinary behavior are unchanged, as exercised by
the existing 234-assertion query/page/lifecycle suite.

Fresh F2 checks, with the preceding candidate artifacts preserved:

```sh
python3 -B ntwrapper/vxd/build.py --out build/pma-win98-vxd-f2
python3 -B ntwrapper/vxd/test.py --out build/pma-win98-vxd-f2
git diff --check -- ntwrapper/vxd docs/agents/status/windows-compat.md
```

All exited 0. Strict freestanding i486 compilation/linkage passes. The complete
suite still reports **13 tests, OK**, including the new shutdown-versus-entry
case under both ASan/UBSan and TSan and all earlier bridge regressions. The F2
host receipt reports `passed: true` and `inputs_unchanged_during_test: true`;
actual guest/VMM/Supervisor bridge fields remain false.

Refreshed F2 VxD: 18161 bytes, SHA-256
`4b58e25bd4e19c111bb0a5fac760db19bf3ce6d604b44e230511168717c8e2ca`.
F2 is ready for independent review and master-scoped commit; no index or commit
mutation was performed by this lead.
