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

## Receipt correction — external and transitive project inputs

The cross-subsystem review reproduced a receipt attribution gap: the build
manifest checked external ABI headers initially, but the test receipt's final
source-stability check omitted them. Persistent changes to either `shz_ipc.h`
or `shz_abi.h` could therefore publish a passing receipt with older build
attribution. This correction changes only `ntwrapper/vxd/test.py`, its
source-stability fixtures in `tests/test_vxd.py`, and this status file. The
production bridge and actual project headers are untouched. The separate
copied-channel integration fix belongs to c957 and awaits root's import.

The driver now binds every manifest source plus the project dependency closure
reported by the native i486 compiler, MinGW probe compiler, host ASan/UBSan and
TSan variants, and NASM. The preprocessing flags match those variants. Receipt
hashes record the initial contents; a changed or removed input prevents success
and is named in `changed_inputs`. External ABI headers are pinned before
dependency discovery and checked again before tests. System/toolchain headers
are explicitly outside this project-source receipt's scope. Existing receipt
and log bytes are copied to `host-test-history/previous-*` before starting a new
test run, with the archive directory recorded in the new receipt.

RED with the previous driver: the isolated fixtures failed five assertions
across three test groups. Either external-header mutation was still accepted,
an added transitive include was absent from the recorded hashes, and previous
receipt/log bytes were overwritten. Evidence is retained at
`build/pma-win98-vxd-receipt-binding/receipt-fixtures-red.log`.

Fresh bounded check:

```sh
python3 -B -m unittest discover -s ntwrapper/vxd/tests -p test_vxd.py -k SourceStabilityTests -v
```

Exit 0: **3 tests, OK**. Controls succeed; independent persistent mutations to
each ABI header and to a nested header absent from the fixture manifest are
rejected. The nested header is present in both native and host dependency lists.
The fixtures exercise temporary paths containing spaces and preserve prior
receipt/log bytes exactly. They run the real receipt driver against copied
project sources and dummy artifacts, emit no native or guest binary, and do not
execute the compiled C tests. Before/after hashes confirm the actual project
ABI headers remained unchanged. GREEN log and header-hash evidence are retained
at `build/pma-win98-vxd-receipt-binding/receipt-fixtures-green.log` and
`receipt-fixtures-green.json`.

The existing 13 VxD groups were not repeated during the pending ABI/bridge
import. Root must rebuild and run the complete combined suite after importing
that fix; the three new fixture groups will make the complete suite 16 groups.
This receipt correction adds source attribution evidence, with no new claim of
Windows loading, real VMM calls or a positive Supervisor/PMA round trip. No Git
index or commit mutation was performed by this lead.

## Receipt follow-up — manifest capture and initial snapshot

Independent fd5c commit `04fb9dfd968b0d0c0f6a798cde1d13ab0acac2cc`
identified a separate capture race. The driver parsed the manifest from one read
and then hashed its path in the initial snapshot. A persistent replacement
between those operations could bind the receipt to different bytes than those
used to select and validate its build inputs.

An additional fixture replaces only a private manifest immediately after its
first read, adding an external dependency present only in the replacement. RED
on the previously reviewed driver: exit **0**, `passed: true` and
`inputs_unchanged_during_test: true`. The new assertion correctly failed;
`build/pma-win98-vxd-receipt-binding/manifest-capture-red.log` preserves it.

The narrow correction captures manifest bytes once, parses those bytes and
compares their SHA-256 to the initial snapshot before dependency discovery or
the test child. The compiler-derived closure, external initial/final hashes and
previous-receipt archive remain intact. The fixture requires refusal before any
compiler scan or test subprocess and before publishing a receipt. It adapts the
independent capture scenario to the existing copied-project fixtures rather
than replacing the newer driver with fd5c's earlier manifest-only variant.

Fresh bounded `SourceStabilityTests` command above: exit **0**, **4 tests, OK**.
The original unchanged/header/nested-include/archive cases remain green alongside
the controlled manifest replacement. Actual ABI-header hashes match before and
after. GREEN log and source evidence are saved as `manifest-capture-green.log`
and `manifest-capture-green.json` in the same output directory. The full suite's
current source has the original 13 VxD groups plus these four receipt groups;
combined full acceptance remains root's responsibility after source integration.

## Native Windows PMA QUERY endpoint successor (2026-10-01)

Status: production endpoint and real Win32 PE probe implemented, **host component
verification passed; native Windows VMM execution pending**. Windows VMM remains
scheduler owner. No kernel/ABI/subsys source, media, index or commit was changed
by this lane. Root owns integration and the private boot lane.

The original `pma_endpoint.c/h` and `vmm_callbacks.asm` use the existing channel2
and PMA QUERY/PROCESS_EXIT service. REGISTER authenticates trusted DIOC
VM/device/process plus current VMM thread; the VxD issues nonwrapping lifetimes
and monotonic IDs. Its temporary exclusive channel lease rejects legacy W64
OPEN overlap deterministically, including legacy OPEN preceding REGISTER.
Restricted System-VM callbacks use pinned Win98 service ordinals, no DOS call,
no PEF timeout bypass and no PEF_RING0_EVENT promise. Owned Win32 event signaling
runs after admission/IRQ protection ends. Finite local timeout keeps an old
backend query tracked; exact real query/rundown acknowledgements are required
before transport release. TAKE and CLOSE commit only after successful checked
output copy/unpin. Native page locks cover independently relocated code/data;
failed unlock records survive exit retries. Thread and VM notices use their
separate documented EDI/EBX identity contracts.

Temporary limitation approved by root: after any backend PMA admission the image
stays resident and dynamic unload is refused, even after owner CLOSE. The wire
ABI has no persistent VxD incarnation allocator; BSS reset would reuse identity.
A backend STALE rejection poisons further QUERY/REGISTER admission. Never-used
legacy unload remains supported. A source-backed successor design requests a
backend-issued nonwrapping incarnation and request-ID range plus verified
Supervisor domain-restart/epoch binding; it is published to Fada's original
service owner in `MESSAGE-163f-FADA-PERSISTENT-NATIVE-INCARNATION-DESIGN.md`.
No guessed timestamp generation or canonical ABI change was made.

RED evidence remains in `build/pma-native-endpoint-red/` and
`build/pma-native-endpoint-controls/`: old native REGISTER unsupported;
header-only backend rejection never retiring query; failed VMM event close
losing owned reference; failed image unlock losing retry record; CLOSE copy
failure losing acknowledgement; reload fence absent; thread notification wrongly
requiring an unspecified current VM. Bounded corrected controls pass. The COPY
failure cases prove two output writes occurred before failed unpin; replies and
close acknowledgement remain retained afterward.

Fresh final commands (all exit0):

```text
python3 -B ntwrapper/vxd/build.py --out build/pma-native-endpoint-final
python3 -B ntwrapper/vxd/test.py --out build/pma-native-endpoint-final
python3 -B ntwin32/pma/test.py --endpoint-root /root/Win98-Modern-pma-20261002 --out build/pma-client-canonical-current
```

Strict freestanding i486 native build and all **21 VxD host test groups** passed;
17 actual broker/bridge/service/ring cases each under GCC and Clang ASan/UBSan,
5 modeled native image/lifetime modes, emitted service constants, original i386
control/lifecycle harness, existing W64 and TSan shutdown/admission regressions,
and receipt mutation/archive controls are included. Final receipt reports no
input drift. Frozen VxD/client source hashes are in
`build/pma-native-endpoint-controls/frozen-source-sha256.json`; independent
post-test comparison matches every entry.

- VxD 30,897 bytes SHA-256: `9df6679026c86e2bb372e7588f14ef76059aefee69fc653b58279238234744d3`.
- VxD host receipt SHA-256: `6f191b9f6b0265c691dcb136d5f4ba4384a51cfbbdb8c39c30332cc74dc3786e`.
- Endpoint header SHA-256: `b97af958dbd1edd352e88f35071f98423946593e4ee397ffd0751164a7c35281`.
- Endpoint C SHA-256: `913b3f858768b1fd7ce3439ae2b50d40f3328ba5d258dee2f4ee3a9920274177`.
- Native C SHA-256: `27e6409af8b9946b2fcde7d12074d2d1a7436006c632a48f0d1a8051a27dda4c`.
- Bridge C SHA-256: `a3a1e5c4e484ea93de15fe205f5efdad6c1c1f8483581877c2f821138137e76b`.

The exact seven frozen Fada `ntwin32/pma/` files were copied with source/target
before/after hashes unchanged. Prior peer receipt and copy provenance are
preserved under the controls directory. Fresh canonical client verification
passed **245 GCC +245 Clang ASan/UBSan assertions**. Its real i486 PE32 has only
20 old KERNEL32 imports, no CRT, OS/subsystem4.0 and reproducible timestamp0.
PMAQUERY.EXE SHA-256 is
`90e426d430f96afdd3c2d1ffa0f2cce72793a9892c02c2fc545d2ed7fe85e725`.
The VxD build now emits/binds that probe, and its test receipt includes its
compiler-discovered project closure. These tests model privileged VMM/page/
hypercall or Win32 OS boundaries and are not live Windows proof.

Actual gates: successful matched production VxD load on ShizukuDOS-backed live
Windows98; real owned-event conversion; real restricted callback scheduling and
WaitForSingleObject wake; matched Kernel64 QUERY and PROCESS_EXIT; paging/VM/
thread teardown behavior and truthful close logs. Full DOS executor, unified
multi-owner/legacy demultiplexing and final dynamic reload lifecycle remain
separate implementation work. The endpoint milestone does not complete the
user's boot/SMP/installer goal.

## Kernel32 IPC runner transitive binding correction

Only `shizukudos/tests/test_k32_ipc.py` and the new private-copy Python receipt
control fixture changed; no production IPC/kernel/header source changed. The
old runner's fixed seven inputs missed a newly included transitive project
header. A private copy adds a harmless nested include; mutating that private
header at the actual i486 compiler boundary made the old runner falsely return
PASS with `source_compiler_binary_before_after_match=true`. The preserved RED
log is `build/pma-native-endpoint-controls/k32-receipt-red.log`.

The runner now obtains separate actual compiler `-MM` closures for GCC host,
Clang ASan/UBSan host and freestanding i486. Initial project header bytes are
captured before discovery; each discovered input uses that initial snapshot,
then source/compiler/helper/binary stability gates remain active through final
receipt. GCC cc1/collect2/as/ld and Clang's linker helper are pinned too. System
headers are explicitly outside the `-MM` receipt scope; an unbound project
include fails closed and is listed. No hardcoded future service_policy/deadline
header list is required. The current native closure is recorded exactly from
the actual checked-out translation unit.

Fresh commands (exit0):

```text
K32_RECEIPT_CONTROL_OUT=build/pma-native-endpoint-controls/k32-receipt-cases python3 -B -m unittest discover -s shizukudos/tests -p test_k32_ipc_controls.py -v
python3 -B shizukudos/tests/test_k32_ipc.py --out build/k32-ipc-closure-final2
```

The private control runs the actual existing seven IPC cases under GCC and
Clang ASan/UBSan and builds the real i486 IPC object. Unchanged control passes;
persistent nested-header drift during native object compilation and during
compiler dependency discovery both produce FAIL, preserve the original header
hash and list the changed input. All three case receipts are retained in the
controls directory. No real project header is mutated.

Fresh current-source receipt status is
`PASS_HOST_KERNEL32_IPC_RECEIVE_CONTRACT`; seven cases per GCC/Clang sanitizers
and strict i486 object passed, source/compiler/helper/binary before/after match.
These are component host/compile checks, no compiled whole-kernel build or
native guest. Existing transmit backpressure and endpoint authority limitations
are unchanged by this runner-only correction.

## Native endpoint original-owner fix round: F4 / F5

The preceding native endpoint receipts are historical and were withheld by
independent review. This successor corrects the reported failed-user-alias
ownership and notification-handle lifetime defects; it does not change the
shared ABI, Kernel32 runner or canonical kernel source.

F4: every successful user-page lock now enters one of three bounded records
with its original unlock function, alias page and page count. A failed unlock
leaves that record live across calls, including partial pin unwind and an
invalid returned alias. Buffered DIOC entry drains retained records before
checking/pinning fresh buffers or admitting backend work. Each drain attempts
at most three releases. Lease release, reset and shutdown refuse unresolved
ownership. An owner-death callback retries retained records after the real
matching PROCESS_EXIT acknowledgement; successful release can finish rundown
without another user DIOC. A failed registration defers its lease rollback
until its user aliases actually release.

The legacy QUERY/W64 and native PMA fixtures now model failed unlock as a
still-held lock, preserving ownership across calls instead of resetting or
decrementing it on failure. RED controls against the previous implementation
failed on partial-unwind shutdown and lease release. A separate controlled
interleaving proved that release also needs to refuse an actively unpinning
alias, before its native unlock returns. Preserved evidence is under
`build/pma-native-fix-round1/`, including `unlock-retention-red.json`,
`unlock-inflight-red.json` and the exact RED production/fixture source copies.

F5: selecting a notification under broker admission now acquires an in-flight
notification hold before saving the event handle. Actual VMM signaling remains
outside broker/SPSC admission and the IRQ interval. CLOSE, owner release and
shutdown cannot close or reuse the owned event until signaling returns. The
controlled signal fixture reenters CLOSE, processes a real cleanup reply, tries
CLOSE again and then REGISTER while the old signal is suspended; all attempts
to close/reuse remain BUSY. CLOSE and same-value handle reuse succeed only after
the signal returns. `signal-race-red.json` preserves the previous failure.
This is modeled source-interleaving coverage; native VMM preemption reachability
has not been established.

Fresh successor commands (all exit 0):

```text
python3 -B ntwrapper/vxd/build.py --out build/pma-native-endpoint-fix-round1-final
python3 -B ntwrapper/vxd/test.py --out build/pma-native-endpoint-fix-round1-final
python3 -B ntwin32/pma/test.py --endpoint-root /root/Win98-Modern-pma-20261002 --out build/pma-client-fix-round1-final
```

The strict freestanding i486 build passed. All **21 VxD host test groups**
passed, now including **25 production broker/bridge/service/ring cases under
GCC and 25 under Clang ASan/UBSan**, five modeled native image lifetime modes,
legacy bridge/W64 ownership controls, TSan shutdown/admission, emitted thunk,
LE, PE and receipt controls. The actual client again passed **245 GCC +245
Clang ASan/UBSan checks** against the combined canonical public header. The
53-entry owned-source/client freeze map is
`build/pma-native-fix-round1/final-frozen-source-sha256.json`; post-test hashes
match every entry. Host and client receipts report unchanged inputs.

- VxD: 30,977 bytes, SHA-256 `57f9517af89175efbec66391099317cbc42f0fc12bc616ae66360b249ad2b94d`.
- Build manifest SHA-256: `b488d14cb11bab95a21c47c84f8bea5aee6f2f0614e649c303a7a4740b8dadb7`.
- Host receipt SHA-256: `12a6a91402d045198cec42bf602cc47702b7ced1ea516c3339293fc69f7b10db`.
- Client receipt SHA-256: `587ba5e428571f6ad8578bc97b869cbb0e22f82c85261f44f2fc10898d4ab177`.
- PMAQUERY.EXE remains 14,752 bytes, SHA-256 `90e426d430f96afdd3c2d1ffa0f2cce72793a9892c02c2fc545d2ed7fe85e725`.

The first full fix-round run failed only a GCC misleading-indentation warning
in the new fixture; its failed receipt/log remain in the earlier output
directory. The successor split that statement and reran the entire frozen
epoch. No failed run is promoted to PASS.

The exclusive lease and resident-after-backend-admission policy remain
temporary limitations. Production VxD load, genuine Win98 owned-event wake,
native paging/teardown, actual Windows app-to-Kernel64 reply, real DOS executor,
AP/SMP and the final installable ISO remain live integration work. These
component fixes establish no native Windows or full-goal completion claim.
