# Core Kernel Lead

Scope: extend the existing Kernel64 preemptive scheduler; actual Windows 98
retains VMM/USER/GDI scheduling and desktop authority.

Owned files: `shizukudos/kernel64/sched.c`, `k64.h`, new `pma_tests.c`, the PMA
test hook and approved counter correction in `tests.c`, and focused guest
runner `shizukudos/tests/run_k64_pma.py`. This status record is also owned here.

Baseline: `a648e9baa1c57289d50e58d3380827bd9239bc52` on
`codex/pma-integration-20261002`. No worker commit; root serializes the shared
index. Root owns the final combined full build and broad component regressions.

Decisions:

- Reuse the existing stack/SSE/CR3/GS/CR8 context switching and lifecycle paths.
- Thirty-two priority FIFO ready queues; higher numerical priority selects
  first until an oldest queue head has waited 32 scheduler ticks.
- Default quantum remains one tick; accepted quantum range is 1..16 ticks.
- A policy update cannot renew the running slice: increasing the quantum takes
  effect on the next dispatch; reducing it clamps the remaining slice. An aged
  ready head overrides even the highest priority thread on the timer path.
- CPU affinity accepts mask 1 only. This is UP policy; integrated SMP is not
  implemented or claimed.
- Keep the existing `thread.next` semaphore/mutex wait link separate from
  runnable links. Wake and resume must never enqueue the same thread twice.
- Retain short interrupt-disabled UP state transitions. Atomic ticket locks
  under the peer c957 lane do not by themselves make the kernel SMP-safe.

Implemented interfaces in existing `k64.h`:

`thread_set_sched_policy(thread_t *, unsigned priority, unsigned quantum_ticks,
uint64_t cpu_mask)` validates every argument before applying an atomic update;
return 0 on success, -1 on unsupported/invalid input or dead/foreign TCB.
`thread_get_sched_policy(thread_t *, sched_policy_t *)` reports actual policy.
`sched_get_stats(sched_stats_t *)` takes a bounded IRQ-protected diagnostic
snapshot. `sched_validate()` validates queue membership and lifecycle state.

Dependencies: existing PMM, timer ISR and kernel object dispatcher. The focused
profile needs no archive or disk; the broad profile uses root's immutable
WIN64.IMG fixture. No Supervisor/VMM ABI changes.

Interfaces are implemented as declared above. Default priority is 16 and default
quantum one tick. Idle is excluded from runnable queues and cannot have its
policy changed. The bound applies with stable policies to preemption-eligible
ticks; IRQ-disabled regions and hosted driver IRQL deferral remain explicit.

Test-first execution:

- Isolated single-profile build in `build/shizukudos/pma-red-core`: exit 0.
- `python3 shizukudos/tests/run_k64_pma.py --qemu /usr/libexec/qemu-kvm
  --accel kvm --build-dir build/shizukudos/pma-red-core/kernel64s
  --out build/shizukudos/pma-red-core/run --timeout 120`: expected RED, exit 1.
  Actual guest exit 1, QEMU exit 3, evidence slot 18 `0x504d0003`. Both large-ms
  wait assertions failed after arithmetic wrap into one tick; missing policy
  interfaces also failed. This red run occurred before scheduler implementation;
  its log and old artifacts remain intact.
- Root's separate broad baseline caught non-atomic `many_started/many_done`
  test accounting under preemption. With root approval these two counters now
  use atomic increments. This corrects test instrumentation, not scheduler
  behavior; root preserves the original failure.

Meaningful guest assertions exercise actual CPU-bound preemption, priority
reversal, FIFO entry, one/four tick quantums, duplicate wakes, finite/infinite
deadline separation, semaphore token conservation, manual-event races, bounded
starvation under repeated policy changes, and 1000 concurrent real kernel
threads returning every stack page. `sched_validate()` checks queue/state
membership and the final snapshot contains only main and idle on CPU0.

Evidence preservation and follow-up:

- The first isolated green compile linked, but its pre/post source check
  rejected a concurrent root import of display commit `f6d12ee` (main.c and
  gfx_fb.c). It produced no acceptance receipt and was not treated as green.
  Artifacts and build rejection remain under
  `build/shizukudos/pma-green-core-rejected-f6d12ee` and its build log.
- A fresh full standalone compilation in `pma-green-core` captured identical
  pre/post source maps and produced a source-bound receipt. Its initial KVM
  guest reported no assertion failure, but the host evaluator rejected a
  gap printed after the priority reversal. The test now captures both stable
  phases with IRQ guards, swaps both priorities atomically, and prints after
  stopping workers. The original rejected run remains in
  `pma-green-core/run-before-refresh-test`; the bound was not relaxed.
- Subordinate read review identified policy updates renewing the running
  quantum and thereby bypassing aging. A new real guest test before the fix
  reproduced RED in `pma-refresh-red/run`: 3,217,271 updates postponed the low
  priority worker until tick 80 with zero CPU loops. Guest failure count 1,
  evidence slot 18 `0x504d0001`, QEMU exit 3. The running-slice clamp and aged
  timer override fix that case.
- Final incremental compilation in `pma-final-core` rebuilds the changed
  production unit from the source-bound base. It verifies copied object hashes,
  permits only recorded changed sources, captures identical pre/post closure
  maps, and records its base-receipt and driver hashes. The focused runner
  rejects missing/stale kernel, stub or source receipts before execution.

Initial source-bound KVM command (exit 0, eight checks PASS; superseded below):

```sh
python3 shizukudos/tests/run_k64_pma.py --qemu /usr/libexec/qemu-kvm --accel kvm --build-dir build/shizukudos/pma-final-core/kernel64s --out build/shizukudos/pma-final-core/run-kvm --timeout 120
```

Results: priority gap 33 ticks; one/four tick workers received 22/84 CPU ticks
with 44 preemptions; 3,624,856 policy updates still allowed the low priority
worker to start at tick 32 and execute 825,529 loops. All 48 semaphore races
conserved their token. All 1000 workers started and finished; free pages were
60937 before and after. Final snapshot: ready 0, live 2, CPUs 1, guest failures 0.
Receipt: `build/shizukudos/pma-final-core/kernels-build-result.json`.
Guest log/evaluation: `pma-final-core/run-kvm/{serial.log,result.json}`.

The exact same source-bound kernel/stub also passed all eight checks under TCG
(runner exit 0):

```sh
python3 shizukudos/tests/run_k64_pma.py --qemu /usr/libexec/qemu-kvm --accel tcg --build-dir build/shizukudos/pma-final-core/kernel64s --out build/shizukudos/pma-final-core/run-tcg --timeout 120
```

TCG results: priority gap 33 ticks; quantum CPU ticks 21/80 with 41 preemptions;
123,805 policy updates with low thread starting at tick 32 and executing 9,764
loops; 48 conserved semaphore races; 1000/1000 threads returned all stack pages.
Both executions recorded the exact artifact hashes and build receipt hash.
`git diff --check` passed after these changes.

Preserved initial artifact SHA-256:

- `KERNEL64S.BIN`: `fc31ce7c11a36484c66cf0026b06d0d0decbba070ae13b55b2e40b265c9e2df5`
- `kernel64s.elf`: `7232e242a12c5abaa9d592c0fe0185e9037cce6855da73ec11fe47482249bbb6`
- `boot.elf`: `b9746b523b7b6f125acf256fb8ad7ef3d98f83dd5bf0a03f15d19ab654a3ff97`

Subordinate `/root/core_kernel_lead/k32_publication` completed the disjoint
Kernel32 `user.c` publication fix and actual-production-C regression; see
`docs/agents/status/k32-publication.md`. It preserved baseline KVM fatal ring-3
RED and deterministic host RED; GCC and Clang ASan/UBSan each passed 17 checks,
and two fresh KVM plus one TCG complete standalone runs passed nine checks.
Root independently reran sanitizer validation and committed that slice as
`8671fba`. It did not touch peer6970's sched.c/k32.h lane.

Root independent repeat and measurement correction:

- The unchanged initial binary failed root's fresh KVM repeat. Preserved
  `pma-final-core/run-root-kvm/{serial.log,result.json}` and
  `build/pma-core-root-console.log` show raw observation gap 66, policy CPU
  ticks 156/4 then 4/156, guest failures 1 and evidence `0x504d0001`. Previous
  PASS runs did not resolve this failure.
- The old spinner read the tick clock and later updated `last_tick` with
  interrupts enabled. A context switch between those operations leaves a
  stale timestamp even after the thread received service. The old metric also
  counted useful loop observations rather than READY-to-dispatch residence.
- A passive per-thread `max_ready_wait_ticks` diagnostic now records actual
  residence immediately before dequeue in the existing IRQ-off dispatch path.
  It changes no selection or context-switch decision. Phase 2 resets the
  diagnostic and observation baseline inside the policy-swap IRQ guard.
- The dedicated actual-guest sampler forces both interrupted-update points.
  It deterministically measures raw gap 64 while each serviced interval is 32
  and actual ready residence is 32. This reproduces the false raw-gap violation
  without changing the 40-tick threshold. The cumulative CPU-loop gate remained;
  review subsequently found it did not isolate each low-policy interval.
  The next follow-up fixes that coverage gap. Raw observation gaps remain.
- The diagnostic TCG run additionally exposed clock-reset interference:
  an old local clock value subtracted the new phase baseline and underflowed.
  Its log remains in `pma-observation-core/run-tcg`. The spinner now shares a
  short IRQ guard around clock read/last/max update with the phase reset; its
  CPU workload runs outside that guard.
- Because the diagnostic enlarged the TCB, all C units were freshly rebuilt
  in `pma-observation-core`. Compilation, linking and unchanged pre/post source
  checks completed; the local driver then failed serializing Path values in
  the JSON receipt. That failure remains in its build log. A separate finalizer
  verified the saved/current closure, exact complete compile-command source
  list, unresolved-symbol checks and object hashes and wrote a transparent
  receipt recording the driver failure. The final sampler-only change was
  rebuilt from that verified base in `pma-observation-final` (exit 0), with
  copied object hashes and unchanged source maps verified.

Final acceptance commands (each exit 0, all ten evaluator checks PASS):

```sh
python3 shizukudos/tests/run_k64_pma.py --qemu /usr/libexec/qemu-kvm --accel kvm --build-dir build/shizukudos/pma-observation-final/kernel64s --out build/shizukudos/pma-observation-final/run-kvm --timeout 120
python3 shizukudos/tests/run_k64_pma.py --qemu /usr/libexec/qemu-kvm --accel tcg --build-dir build/shizukudos/pma-observation-final/kernel64s --out build/shizukudos/pma-observation-final/run-tcg --timeout 120
python3 shizukudos/tests/test_k64_pma_provenance.py --build-dir build/shizukudos/pma-observation-final/kernel64s --serial build/shizukudos/pma-observation-final/run-kvm/serial.log --out build/shizukudos/pma-observation-final/provenance-tests
```

Both real guest runs report actual ready residence 32, protected observation
gap 33, forced-interruption raw gap 64 with serviced gaps 32/32, and zero
computed failures. Equal-priority workers receive 21/80 ticks with 41
preemptions. KVM executes 4,110,002 repeated policy updates; TCG 148,570;
both dispatch the low worker at tick 32 and show useful loop progress.
All 48 semaphore races conserve their token. Both runs start and complete
1000 real threads and return every stack page (60933 before and after).
Final ready/live/CPU counts are 0/2/1.

The focused runner captures artifact, receipt and source hashes before launch,
retains those identities in the result, checks artifacts/receipt/source/runner
again afterward and fails any drift. Seven host gate controls pass: unchanged
inputs, missing receipt, mismatched artifact, stale scheduler source, replaced
artifact after loading, removed artifact after loading, and replaced receipt.
Missing/mismatched/stale inputs reject before launching; mutations reject
afterward. These gate controls use mocked QEMU and claim no native execution.

Final `pma-observation-final` artifact SHA-256:

- `KERNEL64S.BIN`: `e03db93d175d49a647004e8e0dfd515915bb257239e500dc364c26e9836f3c6e`
- `kernel64s.elf`: `395267c16f1c2377cba8415907a20e26ede71dbedb4f30b83f53d723025e2b67`
- `boot.elf`: `b9746b523b7b6f125acf256fb8ad7ef3d98f83dd5bf0a03f15d19ab654a3ff97`

Final narrow task-review follow-up (supersedes the previous acceptance checkpoint):

- Phase 1 now snapshots the low worker's loop count under its ending IRQ guard.
  The newly low worker's baseline is captured at the atomic policy swap; its
  phase 2 delta is captured under the ending guard. Both must exceed 1000 loops.
  The cumulative original loop gate, CPU allocation checks and actual ready
  residence bound of 40 remain. `K64 PMA progress` prints both low-phase counts.
- The runner reads receipt bytes once and derives both parsed JSON and SHA-256
  from those exact bytes. Its post-run digest therefore detects replacement
  between the initial read and digest computation, instead of attaching old
  parsed data to a newly read digest.
- Before fixing the gate, controlled receipt replacement after the initial
  read and synthetic zero low-phase progress each incorrectly returned PASS.
  Both RED controls are preserved in `pma-review-round2-red`; exact old runner
  and control-test source snapshots were reconstructed and verified against
  their recorded SHA-256 before saving under `source-snapshot`.
- Only `pma_tests.c` changed in the kernel build. The source-bound incremental
  compile in `pma-reviewed-final` passed; scheduler policy and header stayed
  unchanged. KVM and TCG each passed all 11 checks. Low-phase useful loop counts
  were 324351/215073 under KVM and 16973/12136 under TCG. Both reported actual
  ready residence 32, protected observation gap 33, and 1000 real threads
  returning all 60933 free pages. Their artifact/receipt/source/runner hashes
  stayed unchanged during execution.
- Ten host gate controls passed, including the between-read receipt replacement
  and independent rejection of zero phase-1 or zero phase-2 low-worker progress.
- Independent final narrow re-review accepted both corrections and reconciled
  current source/runner hashes with the KVM 11/11, TCG 11/11 and ten-control
  receipts. No remaining scoped finding was reported; the scheduler/header
  were confirmed unchanged in this review round.

Latest verified commands (all exit 0):

```sh
python3 shizukudos/tests/run_k64_pma.py --qemu /usr/libexec/qemu-kvm --accel kvm --build-dir build/shizukudos/pma-reviewed-final/kernel64s --out build/shizukudos/pma-reviewed-final/run-kvm --timeout 120
python3 shizukudos/tests/run_k64_pma.py --qemu /usr/libexec/qemu-kvm --accel tcg --build-dir build/shizukudos/pma-reviewed-final/kernel64s --out build/shizukudos/pma-reviewed-final/run-tcg --timeout 120
python3 shizukudos/tests/test_k64_pma_provenance.py --build-dir build/shizukudos/pma-reviewed-final/kernel64s --serial build/shizukudos/pma-reviewed-final/run-kvm/serial.log --out build/shizukudos/pma-reviewed-final/provenance-tests
```

Latest artifact SHA-256:

- `KERNEL64S.BIN`: `d423dcbfd9e6ffb8cf0871ad827c6f97443e4d308b419f1afce40ad8e0134ed1`
- `kernel64s.elf`: `58a1a068f9f5a158a8d4594804e8e6a705c180f3eb914c4f509e65d1e6e3f101`
- `boot.elf`: `b9746b523b7b6f125acf256fb8ad7ef3d98f83dd5bf0a03f15d19ab654a3ff97`

Subordinate follow-up repairs the Kernel32 reused-build provenance gate and
adds its own negative controls: all 12 host control cases PASS, a fresh K32-only
build with real KVM execution passes 12 checks, and TCG reuse with the mandatory
matching v2 receipt passes 12 checks. The 32-source map and source/artifact/
receipt pre/post hashes match; the kernel remains `381b831a49835fca9efc596c6b50192730fd8ed01b15abdaca7a9406f8e5e274`.
Evidence: `build/pma-k32-provenance/source-bound/{kvm,tcg}/result.json` and
`build/pma-k32-provenance/negative-green-reviewed/result.json`. Its separate
status retains the original missing/stale receipt RED controls and exact
commands. Root's task reviewer independently accepted these mandatory
source/build/artifact validation changes. The subordinate files are frozen.

Remaining work: root's combined full build/regressions after peer imports and
independent cross-subsystem review. Owned Kernel64 sources, tests and runner
are frozen after the final KVM/TCG/provenance executions. Root may resume peer
imports; the disjoint Kernel32 follow-up has also finished.
No native SMP, Windows VMM integration or Win64 priority facade completion claim.

Post-merge Python-only receipt closure corrections:

- Independent peer controls showed that the focused runner could accept
  receipts omitting `sched.c`, all four core files or `main.c`. The canonical
  runner now requires the exact complete current `kbuild.source_hashes()` map
  before launch, and derives that complete map again afterward so additions,
  omissions, deletions and digest drift are detected. Same-byte receipt parsing
  and all prior semantic/artifact controls remain.
- The evaluator, QEMU helper, shared host utility and kbuild helper are hashed
  before importing their modules, rechecked before launch and after the run,
  recorded in the result and included in the immutable-input gate. A persistent
  copied-helper drift control avoids changing the real helper files.
- The prior 10 gate controls remain; scheduler/all-core/main omissions and an
  unexpected source-map key are rejected before modeled QEMU launch. Persistent
  copied-helper drift is rejected after the modeled guest computation. Exact
  old runner/control sources are SHA-verified and saved with both RED folders.

Verified host-semantic fixture commands (no new native execution claim):

```sh
python3 -B shizukudos/tests/test_k64_pma_provenance.py --build-dir build/shizukudos/kernel64s --serial build/shizukudos/pma-reviewed-final/run-root-kvm/serial.log --out build/pma-k64-receipt-closure/red
python3 -B shizukudos/tests/test_k64_pma_provenance.py --build-dir build/shizukudos/kernel64s --serial build/shizukudos/pma-reviewed-final/run-root-kvm/serial.log --out build/pma-k64-receipt-closure/green
python3 -B shizukudos/tests/test_k64_pma_provenance.py --build-dir build/shizukudos/kernel64s --serial build/shizukudos/pma-reviewed-final/run-root-kvm/serial.log --out build/pma-k64-helper-binding/red
python3 -B shizukudos/tests/test_k64_pma_provenance.py --build-dir build/shizukudos/kernel64s --serial build/shizukudos/pma-reviewed-final/run-root-kvm/serial.log --out build/pma-k64-helper-binding/green
```

The omitted/extra-membership RED suite exited 1 with four expected failures;
its GREEN passed 14/14. The copied-helper drift RED suite exited 1 with its
single expected failure; final GREEN passed 15/15. All controls use the fresh
normal build's actual 211-source map and artifacts; the earlier successful
serial is explicitly a mocked semantic fixture. No kernel/header changes or
kernel compilation occurred in this follow-up.

Final runner SHA-256:
`15c7973afd26fec11e10fbafff314a7cef6ffbe40931b57bd28869c6ad820426`.
Final control SHA-256:
`75c9dff94cea490ab69e599a3c6cfef080d286204cfdb51651b54b7b1563c00a`.

New combined native failure remains an open acceptance gate: root's fresh
normal four-profile build completed, but the KVM service guest in
`build/pma-integrated-native-service/serial.log` computed one PMA failure:
873019 policy updates, low worker first useful body at tick 98 and zero loops
inside the unchanged 80-tick window. Earlier phase observations reached gap 99
despite completed ready residence 32. Application/bridge successes do not
resolve this failure. The earlier interrupted-sampler proof established a
measurement distinction; this integrated run demonstrates a separate useful
execution starvation problem requiring native diagnosis. Candidate cause is
queued timer delivery after interrupt restoration before useful thread-body
execution; IRQ-boundary trace/probe is pending root's production freeze release.
The failing log remains intact. No thresholds are relaxed and no production
edits/builds are permitted while root's ramfb guest is still executing.


## Reviewed fixture import for the isolated native SMP consumer

Root approved b5c49d873990bebdf7611fbccb03f3757dbbf874 before the next own native build.
Only its exact Kernel64 pma_tests.c correction is imported: the coordinator
blocks on finite completion while the isolated aging arrival is measured;
first dispatch and body observation remain distinct. The fixed four-tick
policy, scheduler, architecture and shared header are unchanged. Root reviewed
actual KVM/TCG17/17 evidence. This preserves the existing historical ledger
rather than importing unrelated later canonical status claims. Original SMP
219/221 source epochs, failed gates and their actual receipts remain unchanged.
