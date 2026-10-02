# Kernel32 allocator prerequisite — review candidate

Isolated root-owned branch codex/k32-memory-163f-20261002, based d91e1bc.
Production source is uncommitted and held for independent review. Windows98
VMM/USER/GDI/Explorer stay the OS; native Windows stays one virtual CPU.

The existing PMM bitmap/hint/free count and heap list/used count now use
separate ownership through existing pma_ticketlock_t. Local IRQ masking
precedes ticket admission; release precedes original IF restoration. PMM
zeroing remains outside its lock after unique allocation ownership is reserved.
PMM/heap locks are never nested and cannot be used by NMI, recursive allocator
calls, callbacks, waits or context transfer. Initialization is exclusive before
concurrent use. Generic page-table mutation and address-space reclamation are
unchanged and not certified for AP execution.

Zero/overflow/oversized heap allocations refuse before mutation. Invalid frees
retain the existing fatal assertion contract, while validating the heap span
and real allocated block boundary before altering allocation metadata. A forged
header inside valid payload bytes cannot release a real heap allocation.

Actual original production RED, captured source and exact helper before entry:
build/k32-memory-red-4/result.json SHA
e70eb6e5e41dca719a701ca4736580e3b885e084d4306bf58b2ecc9b12b266e7.
Six actual host threads perform1200 held-allocation epochs. Original PMM
reports66 GCC and1295 Clang failures in34800 checks per run. Both original
heap runs reach their unchanged60s deadline and are killed/reaped by the
subprocess runner; the exact cause of those timeouts is not separately proven.
Sources/compiler drivers remain unchanged. Earlier low-address host mapping
collision and Clang dependency-only linker flag failures are infrastructure,
not behavioral RED, and remain in their original directories.

Deterministic size/pointer RED: build/k32-memory-guards-red-5/result.json SHA
9e067ab5d0a895ce8a7d0777ff09d4ff246e13546c2d6ddcf79b2416f6c86fc8.
GCC and Clang each12 checks/8 failures against original source. The invalid
outside-header read causes the original Clang child sanitizer fault; this is
retained. Child assertion observation is an explicit host fatal-path boundary.

Final GREEN: build/k32-memory-green-2/result.json SHA
e931be6fe8ad9afc89742646d8647d1a8bbe19bc273e75302b4f1a62c57923a1.
GCC and Clang ASan/UBSan each pass42000 PMM,34800 heap concurrency/content
checks and162204 guard/exhaustion/reuse checks. Six host actors hold distinct
allocations before checking and freeing, all caller IF states are preserved,
complete exhaustion returns zero and full PMM/heap conservation follows reuse.
All actual project dependencies are copied before compilation and those copied
production/test bytes execute. The helper's exact captured bytes execute through
compile/exec with no project .pyc reuse; separate pre-entry records bind them.
Host IRQ and contiguous low private mappings substitute the actual guest's
architecture/RAM. Host hblock uses host pointer width; this does not establish
32-bit runtime layout or physical AP execution. System headers/support programs
and sanitizer libraries remain the declared host compiler environment.

Real freestanding i486 compilation: build/k32-memory-i486-compile-1/result.json
SHA0cfa05364928596968c51755be44178b54d8c4bbf712858acd64a557872f257c.
Both actual Supervisor and standalone K32 flag profiles compile the frozen
production C. Nine source/header/recipe inputs and five compiler/subtool
identities are pinned before compilation and remain unchanged; actual object
disassembly/undefined symbols contain no out-of-line atomic support calls.
Dependency discovery's earlier environment consumption is not a full toolchain
attestation. This is compile-only, no full kernel link or native guest.

Own outputs before final source/evidence seal are10656556 bytes, below64MiB.
No commit/index/canonical/peer source change, VM, private media, network service
or global configuration change occurred. Independent review, canonical source
adoption, fresh full kernel build/native regression and genuine K32 AP
architecture/timer/scheduler/MM/objects/waits remain required.

## Overlapping free successor — pending independent review

The prerequisite implementation above is now root commit370643cdf209acbc8519e94b88c653abff725e5b.
Its earlier review is historical and remains valid for the unchanged production
mem.c; it does not approve this new fixture or inherit a successor PASS. This
uncommitted successor changes only the C/Python fixture and these appended docs.
Current mem.c stays8159bfead58a4db9a860b308d3b2c44386a2c521d73e68f57b53cc966ba04e23.

Targeted actual-original mixed RED: build/k32-memory-mixed-red-1/result.json SHA
7828cf99a12322e84140d42ef7e4fdef5bfa7f188be3dda9560b386d61773a17.
The new fixture C executes against copied original mem.c hash4e299d1364d35484ab6d61b8de06a3321bc5f965456281b76b5f1d7b6c03649e,
identical to original base source. GCC mixed-PMM hits the original allocation-bit
assertion(exit3); GCC mixed-heap reports a live overlap before exiting by SIGSEGV
(-11). Clang mixed-PMM/mixed-heap report live overlaps, partial lifecycles and
exit1. These are new phase behavioral failures, not infrastructure or successful
full-epoch results. Earlier producer failures66/1295, original60s heap timeouts,
guard RED and old infrastructure outcomes remain preserved unchanged.

Successor actual-C GREEN: build/k32-memory-mixed-green-1/result.json SHA
42c8b1219a09799544f1236348b55fda465ac768367140b5f0739a2e2d219908.
Both GCC and Clang ASan/UBSan pass all five phases. Existing PMM42000/heap34800/
guards162204 checks remain. Mixed PMM: GCC134859 and Clang137824 checks; mixed
heap: GCC115941 and Clang129736 checks, all zero failures. Every mixed run has
six actual actors,1200 epochs each,7200 independent allocations AND frees,
varied heap sizes/payloads, complete PMM zero checks, IFon/off preservation after
each call/query, requested live-span uniqueness/content, and final conservation.
Observed allocation/free host-boundary overlap counts518/5382/474/369 and peak
inflight4/6/4/4 in GCC-PMM/GCC-heap/Clang-PMM/Clang-heap order. Longest passing
allocator run18.054s remains within the unchanged60s bound; this is not timing
or scheduler fairness acceptance.

All allocator calls occur outside the separate checker ledger lock; each actor
writes/checks/frees its own payload. Ledger retirement precedes actual free, so
it checks active payload ownership before release and leaves a short blind
interval. It is not exhaustive allocation/free linearizability or race-absence
proof. Fixture ledger/stop state is mutex-owned, per-owner totals single-writer
and consumed after join, call metrics atomic; no fixture allocator serialization.

The exact helper executes from captured pre-entry bytes with no project pyc.
Quoted local include snapshots precede even dependency discovery; actual compiler
-MM consumes and identifies only copied captured project files. Both chosen
source and copied-source hashes stay stable; external SDK/support/sanitizer
inputs remain declared host environment, not fully sealed. The helper requires
one complete summary per expected phase and compiler, exact owner/epoch/check
accounting, zero failures, full7200 lifecycles, observed host-call overlap and
IF/ledger statements, alongside all process terminal outcomes. Missing/duplicate/
truncated/wrong-count or failure summaries cannot pass via exit0 alone. Twenty-five
receipt controls from actual successful logs pass at
build/k32-memory-mixed-summary-controls.json. A real sleeping Python child hits
its1s deadline through the same subprocess kill/reap boundary; both original and
successor timeout controls pass. All allocator processes remain bounded60s.

Independent review must bind build/k32-memory-mixed-frozen-2/result.json and its
archive/manifest to these exact successor test/doc bytes plus unchanged mem.c.
No production, index, canonical/peer source or global configuration changes;
no commit, SDK/tool copies, full kernel build or VM. Host IRQ adapters, fixed
low private mappings and host-width heap headers remain explicit. No NMI,
actual Windows, physical AP, page-table SMP or generic MM acceptance follows.

Seal1 was rejected because its own actively written console log was captured
as empty before it received sealing output. Its archive/result are preserved;
this is evidence assembly error, not allocator/fixture execution failure. The
authoritative successor is frozen2, emitted without an active captured log.

## Successor3: descendant cleanup corrected, pending review

Root independently found P2 in frozen2's helper: a real inherited-pipe grandchild
survived the direct-child timeout. Exact retained RED result is copied at
build/k32-memory-mixed-timeout-descendant-red-root/result.json SHA
2b944dc887111cc58e6485fdf5e7b8b728821b8f319d4579fc7b7c93202824b1.
Old frozen2/allocator/summary-control artifacts stay untouched. The prior scalar
timeout PASS is insufficient for resource-lifecycle acceptance; it does not
turn any original allocator failure into infrastructure attribution.

Revised helper SHAadcf9a70767541d6fdeb47146bce72f3e3e349a05595d539091d2a7627e2fe4f
uses start_new_session, local Linux subreaping and only its owned group/session.
All terminal boundaries run bounded TERM/KILL, pipe drain and direct/adopted
child reaping; a successful parent may pass only after owned-group emptiness.
Cleanup failure rejects the invocation. The work bound remains60s plus an
explicit separate2s cleanup bound (TERM grace0.15s); group identity is checked
before signals. Descendants that deliberately create a different session are
outside this same-group lifecycle proof. External host environment remains
unsealed; no SDK/tool copies or system-global configuration are introduced.

Actual same guarded caller controls executed captured helper bytes with all
seven current local dependency guards and no project pyc:
PYTHONDONTWRITEBYTECODE=1 python3 build/k32-memory-mixed-process-controls-2.py
Nine controls PASS: timeout, exit0/exit7 retaining inherited pipes, exit0/exit7
without retained pipes, TERM-ignoring grandchild requiring KILL, real SIGUSR1
handler exception after spawn, missing executable before spawn, and unrelated
session survives. Every observed grandchild is absent and explicitly reaped;
cleanup reports group empty, direct child reaped and drain complete. Receipt:
build/k32-memory-mixed-process-controls-2/result.json SHA
c76ae4052cd5c3d20b6858c24adeeaa857778d3a0c39a02b6b11d34457b45a58.
The first eight-control run is retained separately, not overwritten.

Fresh exact helper whole-suite command:
PYTHONDONTWRITEBYTECODE=1 python3 build/k32-memory-mixed-launcher.py --out build/k32-memory-mixed-green-2
All ten GCC/Clang-ASan-UBSan phases PASS, all actual caller cleanup states PASS,
current/copied local sources and compiler driver hashes stable. Result SHA
 dd11a408e518d851de584ab6c8788b8e1c8e1089e385fa2a2afbe4b82ae8fd2e.
Existing42000 PMM/34800 heap/162204 guard checks each remain; six owners and1200
epochs produce7200 independent mixed allocations/frees each with no failure.
GCC mixed-PMM137643 checks/248 overlaps/peak3; heap128231/195/3.
Clang mixed-PMM134817/201/3; heap134618/249/3. Active requested-payload ledger
still retires before free with the declared short checker blind interval;
host call intervals are not physical allocator-critical-section concurrency.
All four mixed phases preserve IF on/off after each operation/query and end
conservation. The body run timeouts remain60s; this is no timing/fairness proof.

PYTHONDONTWRITEBYTECODE=1 python3 build/k32-memory-mixed-summary-controls-2.py
Fresh25 summary controls PASS, bound to the revised helper and green2 logs;
receipt SHA b07098a2e30533ca001f4435a53c650b519f359c8873f4710c0a5362f86ae5ea.
The earlier original-source mixed RED remains exactly copied original mem.c
plus the same C fixture and its earlier helper; no retroactive new-helper claim.
C remainsff167c96e268258f63dd844f6291739a3a929accc70517014a955bf8d2622186.
Production mem.c remains8159bfead58a4db9a860b308d3b2c44386a2c521d73e68f57b53cc966ba04e23.

Bind current four owned files and unchanged mem.c to frozen3's manifest/archive.
END pending independent review: no commit/index change, production edits, full
kernel/native Windows/VM/physical AP/page-table SMP or generic MM acceptance.

## Successor4: private capture P2 closed, pending review

Review found a private harness capture mismatch in process-controls-2.py:
its executed byte buffer and separately reread path digest/snapshots could
refer to different persistent versions. This is a private evidence-binding
failure; the allocator runner helper/C/production and green2 execution remain
unchanged. Controls2/frozen3/earlier greens are retained, not overwritten.

Fresh private process-controls-3 hashes the exact captured byte buffer before
entry, compares the current path bytes immediately before actual compile/exec,
publishes the same captured helper bytes into its local source snapshots, and
requires current-versus-captured equality again in its final guard. The actual
same loader also receives an exact local copy of the real helper and a persistent
replacement between capture and consumer. It refuses before execution entry;
the changed copied path remains retained. No canonical/helper path is mutated.
Replacement-control receipt SHA
670a1aa202945584b243279edaba3efd6e4ad3e230fd35cbcbbe427ed60fcff4.

Actual command:
PYTHONDONTWRITEBYTECODE=1 python3 build/k32-memory-mixed-process-controls-3.py
All nine fresh real process lifecycle controls PASS, with capture/final-current
identity and persistent replacement refusal PASS. Controls3 result SHA
6959cfe338654c41508dc1f90e3a96776e2f860f747712a9c4e249cfdc324e82.
Source helper remainsadcf9a70767541d6fdeb47146bce72f3e3e349a05595d539091d2a7627e2fe4f,
C remainsff167c96e268258f63dd844f6291739a3a929accc70517014a955bf8d2622186,
and production mem.c remains8159bfead58a4db9a860b308d3b2c44386a2c521d73e68f57b53cc966ba04e23.
Thus the earlier actual ten-phase green2 receipt remains historical and bound
to identical current helper/C/production bytes:dd11a408e518d851de584ab6c8788b8e1c8e1089e385fa2a2afbe4b82ae8fd2e.
No ten-phase rerun or retroactive controls3 execution claim is made.

Freeze4 carries these exact current four test/doc paths plus unchanged production,
new controls3/replacement control and preserved earlier source-bound artifacts.
Scope remains owned same-session/group cleanup and host adapter execution;
external environment, active-ledger retirement blind interval and no AP/Windows/
page-table SMP acceptance are unchanged. END pending independent rereview;
no commit/index/global configuration or production change.
