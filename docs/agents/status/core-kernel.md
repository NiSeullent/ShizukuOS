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

## Controlled interrupt-boundary diagnosis (2026-10-01, open)

The original combined KVM failure remains preserved at
`build/pma-integrated-native-service`: refresh first C-body observation 98,
zero useful loops inside the unchanged 80-tick window. Root preserved all normal
build inputs/artifacts under `build/pma-pre-diagnostic-epoch`. RAMfb TCG completed,
then root authorized exactly sched.c/arch.c/pma_tests.c for passive diagnostics;
all unrelated C imports remain held.

Stage 1 adds a 64-entry memory ring, enabled only by explicit `shz.pma=trace`.
The hooks observe the refresh worker's own lifetime: selection immediately
before dequeue, timer frame RIP/RFLAGS before EOI, accounting before tick charge,
first C entry and body end. They do not print, allocate, block, or enable IRQs.
Tracing stops before serial flush. The sampler separately keeps one caller IRQ
guard across its two intended yields/captures, so another interrupt cannot insert
an unintended third observed interval; other contexts restore their own IF.
No scheduler policy, header, assembly or acceptance threshold changes occurred.

Fresh single-profile source compile via the existing kbuild API (all normal
extra C units, no reused objects):
`python3 build/pma-irq-trace/build_profile.py`, exit 0, 49.03 s, complete 211-source
map unchanged before/after. BIN SHA256
`4cff34511f0497c6b64cfa543fd4f0f3dccc9e168c01fc1d37b527f41402b3b7`;
ELF `2fa17dd1918321db3e22e98b819a5f9fd052261a3b608931cbe7f2c3b20d27d0`.
Natural KVM trace (`run-natural-kvm`) passed all 12 retained native/identity/trace
checks in 1.22 s. Refresh own wait 32, run ticks 2, three dispatches, C entry 32,
885334 useful loops, zero injected interrupts/overflow. Dispatches 32/65/98;
first IRQ RIP belongs to refresh_low_worker's real loop, second to ticks_now.
This successful observation does not reproduce or close the historical failure.

Stage 2 explicitly models adversarial timer delivery: a test-only naked entry
wrapper executes exactly two `INT 0x20` instructions before entering the C body.
It records wrapper entry and each resumed continuation separately; the trace
explicitly states `hardware_burst_claim=0`. This is not evidence that natural
PIT hardware generated two queued interrupts in the failing KVM run.
Fresh single-profile compile (`build/pma-irq-injected/build_profile.py`) exited 0
in 64.31 s with all 211 inputs stable. BIN
`7c508a58e5f8a3cc4dec41a38c09f4a607fd80f76db4a932ccc5c1aafea93653`;
ELF `87bddb7046157ecb331fdb6514c8719d59ee88987bc78e0b121dbe9434e68944`.
The exact tested 211-source closure is archived in `sources-tested.zip`.

Actual KVM modeled RED (`run-modeled-red-kvm`) exited 1 as expected: dispatch and
wrapper entry at 32; first software timer frame RIP `ffffffff8016c811`, saved IF1,
then charge/requeue; dispatch and first continuation at 65; second frame RIP
`ffffffff8016c825`, IF1, charge/requeue; third dispatch, second continuation and
C entry at 98; useful loops 0. Own completed ready residence is 32, run ticks 2,
three dispatches, two completed injected continuations, 12 events, no overflow.
This demonstrates that the existing aging policy can repeatedly charge and
requeue a thread before its body, exactly producing the observed 98/zero-work
shape under the declared delivery control. Production grace policy is proposed
for root review; no policy fix has been implemented or accepted yet. Original
40-tick arrival, 80-tick window and >1000 useful-loop gates stay intact.

## Normative finite aging service and corrected credit controls

Root and the independent whole reviewer accepted a fixed scheduling policy:
true `pick_aged()` selections receive a separate, unrenewable per-TCB budget of
four dispatchable timer ticks. The first three eligible ticks cannot revoke the
grant for base expiry, a higher READY priority or another aged FIFO head. On the
fourth eligible tick ordinary scheduling rules resume; a remaining larger base
quantum can continue when no competitor requires preemption. Ordinary dispatch
keeps its configured quantum/default one. Setters can clamp the base remainder
but never refill aging credit. Every scheduling transition relinquishes unused
credit, and all READY transitions clear it. The validator rejects credit on a
non-RUNNING TCB or credit above four. IRQL>=2 retains existing accounting but
spends neither base quantum nor the dispatchable credit.

Four is the declared minimum aging allocation and a priority-latency tradeoff,
not an inferred count of pending PIT interrupts. One current grant adds at most
three eligible timer deferrals; other older aged heads can then consume their
own grants, so this is not a population-independent response bound. This policy
cannot promise a useful body instruction before an arbitrary burst of delivered
interrupts. The allocation must not be raised merely to fit a later failure.
The per-TCB field remains an UP backend policy; future SMP work must provide
per-CPU queue/current ownership. No Windows VMM scheduling completion is claimed.

Native test-first RED (`build/pma-grant-controls-red/run-native-kvm`) used the
original no-grant scheduler and failed the five new assertions: zero observed
credit, no independent credit/setter/IRQL/lifecycle proof, and three aged workers'
body entries at 65/66/67. The exact 211-source build closure is archived. The
new FIFO fixture's useful work was then changed from a one-tick observer window
to 2048 actual barrier-protected CPU loop iterations; the RED had already executed
more than 299000 loops per worker, so its failures were absence of credit and late
entry, not lack of useful work.

The first four-tick candidate (`build/pma-aged-service-green`) was freshly built
with 211 unchanged inputs, BIN `4b0dfe9422ec996522904891e89abf44e6ac79695c1a54f2b1fc373453f8440b`.
Natural KVM and TCG passed all original/native assertions. The original isolated
refresh remained first<=40, window80 and useful>1000. Its fixed-two-INT IF-enabled
adversarial KVM probe nevertheless failed and is preserved, including the exact
source/driver archive and full trace:

- Result SHA256 `dd4e937fc6f6f5552fa0c33ddca1f9846dd71dad70e4c1f267a9ae2cc51d4c0b`.
- Serial SHA256 `2176d022d004768a3952bfc38b37a489c102f86c658c267c65d84325501e3bf7`.
- Four total pre-body IRQs exhausted the declared four-tick grant: two declared
  software interrupts and two uncontrolled natural deliveries. C entry 69,
  useful loops355394; it still failed the untouched first<=40 assertion.
- The new three-aged fixture's body entries34/38/42 also exceeded its initially
  chosen global40 body limit. That limit was unjustified under three-worker
  contention and did not measure first selection. Original isolated limits are
  retained. TCG's adversarial probe passed separately; it does not erase KVM RED.

The native scheduler reviewer then accepted a correction limited to test
measurement/accounting, plus a dedicated gated selection observer. The observer
records only bounded first matching-TCB selection counters; IRQ/RIP ring tracing
remains off unless explicit `shz.pma=trace` enables it. Current production policy
is unchanged at four.

The corrected credit fixture snapshots actual remaining credit1..4 under its
caller IF0 guard and delivers remaining-1 software timer interrupts at dispatchable
IRQL. After EACH, it checks exact tick/run increments, same TCB, decrement by one,
and setter nonrenewal. The final software interrupt must exhaust the remaining
credit. A competitor first acquires its own IF0 guard, then publishes the target,
and sleeps with that guard across context switches so other contexts receive PIT
ticks. Its actual C context observes target READY/zero before the terminal
interrupt continuation returns. Labels state savedIF0 and software-only; no
hardware-burst equivalence is asserted. A separate one-tick probe publishes an
equal-priority peer and observes selection after exactly one eligible interrupt.

For the stable three-worker cohort, first selection order is0/1/2, grant at each
first selection is4, and first READY residence is bounded by32+4*i. Body entry
order/time is diagnostic; 2048 eventual CPU iterations establish eventual useful
work, not useful work before grant reclamation. The original isolated refresh
and IF-enabled adversarial probe remain unchanged.

Final corrected sources are frozen for a fresh single-profile compile:
sched `3c3081a437779649dfeef720e22972daf8b038dd7fa5f98d1014edf206de8556`,
header `7ce8d1eff6784f21f9e7d7d7d38e23a29cb2254fbef0fc6967860aae0569df0f`,
tests `2cef7cc5827fee78d3149a6b2ca7843c12af751a3749695f3d579dfd25872eef`,
arch `4a8c8b29484c07b14f517dc6bf018e433251d68ab01947fb9e70f53d4465176d`.
Root's K32 IPC import adds its dedicated host C test to the complete kbuild map:
current closure212, canonical map SHA256
`8a5c6b511a9a104e52e7abc1ea943c74a657d9aa20c09f4b277a06f54f6b853c`.
Fresh compile/run evidence is pending in `build/pma-credit-final`; no completion
claim or broader Windows98/SMP/full-boot admission follows this component work.

## Final corrected focused checkpoint: frozen, ready for independent review

Fresh single-profile compile (all normal standalone extra C units, no reused
objects) exited0 in134.37s. Its212-source map exactly equals the announced frozen
map before and after compilation. Build receipt:
`build/pma-credit-final/kernels-build-result.json`, SHA256
`d0daf35465f8372bbddf2695a67a38eb5abc9b0a6fe55fbb82adcd2dab48e8a1`.
BIN `37fd31608ddc509dba1ddf086adc011f2eb0b4c57c9b30b6fad322190b0e8446`;
ELF `d522338e92c99bbbe5cb4fe6b24ddcdeb29cb906424031be9b4eac1c774b9d91`;
loader `b9746b523b7b6f125acf256fb8ad7ef3d98f83dd5bf0a03f15d19ab654a3ff97`.
Exact source/driver snapshot: `build/pma-credit-final/sources-tested.zip`.

Actual executed commands:

```
python3 build/pma-credit-final/build_profile.py
python3 build/pma-credit-final/run_natural.py --accel kvm --out build/pma-credit-final/run-natural-kvm
python3 build/pma-credit-final/run_natural.py --accel tcg --out build/pma-credit-final/run-natural-tcg
```

Both native runs pass16/16 focused checks, including explicit parsed credit,
ordinary-q1, lifecycle and first-selection controls in addition to the original
native gates. Both retain full artifact/ELF/fixture/driver/evaluator/helper,
receipt and complete212-source before/after identity checks. Same source/binary
under KVM1.85s and TCG2.89s, computed guest failures0.

- KVM original refresh: first32, useful2143538, updates2577728; source-bound result
  `dc303b741a36ef8d7306a6d84a326e5fc207bc9f77975f5319dd0d9b8ed47d60`,
  serial `4c62ef33f8373adea5d568c14507a951c12614d39cd81d8672c441ada6251dda`.
- TCG original refresh: first32, useful99690, updates220025; result
  `c23558b5adec1ce77695ec6e7ee4b07263a640406f531abe0aa5b600a8ac73d3`,
  serial `2547013c80b4f5e9185965eda15c82f14a65b6ad613e1c9e8444942c9edc5b77`.
- Both controlled remaining-credit fixtures: initial4, issued4, exact per-step
  accounting/setter/terminal checks1, actual peer observation before continuation1;
  savedIF0/software-only labels retained. These four delivered software ticks
  include the terminal expiry; this is not a two-interrupt hardware-burst proof.
- Both lifecycle controls: observed4, setters/IRQL2/yield-clear/wait-clear1,
  new higher-ready own READY residence4 with remaining grant4, terminal1.
- Both three-aged first selections: order0/1/2, READY residence32/33/34,
  grant4/4/4; each worker eventually performs2048 real CPU loop iterations.
  Body timestamps are diagnostic and do not gate an invented global bound.

All four owned source hashes remain the frozen values above. No production
allocation increase or original40/80/>1000 change. Earlier natural98/zero and
IF-enabled adversarial mixed-delivery FAIL receipts remain separate and intact.
The final candidate is ready for independent source review and root's fresh
four-profile build/full combined KVM checkpoint; those broader steps are not
claimed complete by this focused component result. No shared index/commit action.

## Reopened combined successor: grant-arrival coordinator contention

Root's fresh canonical combined KVM run failed at the unchanged isolated grant
arrival assertion: arrival READY residence 5 with remaining credit 4. All 151 app
runs, W64 loopback 48 and PMA bridge 16 passed; the original natural refresh also
passed (first 33, useful 1015770). Overall acceptance remains FAIL. Original
`build/pma-integrated-native-successor-20261001/{serial.log,result.json}` and the
root source/binary archive 94b4bb097de24b84a3db87a03b9eeb6d39a75a69d707ba88ad0bfc7c7669832b
remain historical failure evidence. Earlier 37fd component passes do not replace it.

The fixture's coordinator used `thread_join`, which keeps it READY. At low grant
expiry it can be another aged head and receive its own four tick allocation
before the newly READY high-priority arrival. The previously documented bound is
additional deferral by one current grant, not a global arrival bound across
other aged contenders. The supposedly isolated fixture did not enforce that
precondition.

Meaningful source and native controls preceded correction:

- `build/pma-arrival-diagnosis/actual_sched_probe.c` includes the actual production
  scheduler. 32 scheduler ticks obtain a real low grant 4; after four eligible
  charges a READY coordinator receives its own aged grant. One modeled eligible
  coordinator tick followed by its join-like yield dispatches arrival at wait 5.
  RED exits1. Blocking that coordinator in the same production C dispatches the
  arrival at wait 4, GREEN exits0. Privileged/context operations are host models;
  source/compiler/executable pre/post pins are in the adjacent result.json.
- Fresh native diagnostic build 68.16 s, kernel 3cc63de2ce2996a5a12062550d847fa58c048e255be4dd9f5f3795c5dee1a183,
  receipt b9e66fb4f26e2e4c38114aa0fec1036c81ef6adfef0352e5f8429f547ea76d90.
  Its explicitly injected real ISR/context control exits QEMU 3 / guest FAIL 1 in 1.63 s.
  At tick 1079 coordinator id 1 has READY wait 38, grant 4, low charges 4. Exactly one
  eligible coordinator delivery precedes arrival id 429 at tick 1080, wait 5, low
  charges 4, body delay 0. 32 IRQL2 deliveries and 4 low eligible deliveries are
  separately labeled software controls, IF 0, hardware_claim0. Only the unchanged
  <=remaining arrival assertion fails. Result and full serial are preserved in
  `build/pma-arrival-native-red/run-native-red`; result SHA d00cb2506118ee0f2916c729ae68e21f9e07923de1bf4f9df5421a02f98c82dd.
- The native injected control proves a reachable production ISR/context sequence
  matching the failed observation. The original natural run did not record
  first selection, so this does not claim attribution of its exact PIT sequence.
  All 212 diagnostic source bytes plus drivers are archived in
  `build/pma-arrival-diagnosis/native-red-source.zip`, SHA 6246cb5fb9e2a8607a305c34a7c750ef58c34e343c066c80ee05b0a8583927f8.

The corrected fixture blocks its coordinator on a completion semaphore during
measurement, with a finite 512 tick timeout. A passive bounded selection hook
captures the arrival's first dispatch, low charged ticks and actual coordinator
BLOCKED/wait-sem identity; C-body timing is recorded separately. The original
arrival <=remaining test remains, with an added verified-isolation precondition.
A 16 record passive dispatch diagnostic is flushed only after observation stops.
The forced control branches are removed from the candidate and remain only in
the archived native RED source/binary. No production scheduler/header/arch change,
allocation increase, setter renewal or original 40/80/>1000 gate change.

Frozen test source 6761e4cd35de1672406e01dc356303fa84773baf71096fe3fd3a15391f9fed3b;
complete 212 source canonical-map SHA b4d66f59927b422fc5afdef4cd8fae4aeb575c6bec4e2e054b1dd9073674d0bf.
Fresh single-profile compile 81.53 s passes with identical pre/post source maps.
Receipt `build/pma-arrival-final/kernels-build-result.json` SHA
cadc5a4a35cb4157d5616a018d6705d14d7470aae8c28ccbc4e203674c9f025c.
BIN 6518d6787834687829f2fe162c2d4083a89c8ae99f63be4c3210b5bea8c95bde,
ELF 54a97685cada7978f814c9956b5aa3671f7de238c03ac7854df0636d6c5f1331.
Exact sources/driver/evaluator archive `build/pma-arrival-final/sources-tested.zip`
SHA d76758e60eb5604f0377413f88091846a765ec9f75b4431262f3f2cfb3ab51de.

Both natural focused runs PASS 17/17, including all previous 16 gates and an
independent parsed first-selection/isolation gate:

```
python3 build/pma-arrival-final/run_natural.py --accel kvm --out build/pma-arrival-final/run-natural-kvm
python3 build/pma-arrival-final/run_natural.py --accel tcg --out build/pma-arrival-final/run-natural-tcg
```

KVM 2.45 s: original refresh first 32/useful 2444330; arrival firstwait 4/remaining 4,
low charges 4, coordinator BLOCKED 1, completion 1, body delay 0. Result SHA
e0206cc00673120c746c595846e9deba506380c658938722ae4e55a270c6b1ae.
TCG 3.02 s: original refresh first 32/useful 70358; same arrival4/4/4, BLOCKED 1,
completion 1 and body delay 0. Result SHA
f14831ce19e251c751f6f18064dcd0aa5832a3c03f2c07810696d8f424588832.
Both bind full 212 sources, BIN/ELF/loader, runtime fixture, receipt, evaluator and
loaded helpers before/after. Final handoff is `build/pma-arrival-final/handoff.json`.
No live build/guest handles or canonical index changes. Ready for independent
review and root's new full-profile/combined native checkpoint; the failed combined
successor is not promoted by these focused results.

Kernel32 SMP work was paused at root's request before production edits. Its new
linked worktree`/root/Win98-Modern-k32-smp-163f-20261002`, branch
`codex/k32-smp-163f-20261002`, remains clean at 3cbc1f8. Registration/online identity,
GDT/TSS, virtual AP/IPI and context handoff contracts still require the coordinated
next stage. USB P2 remains unapplied pending authoritative NAS recovery and valid
race RED. Actual Windows98 VMM integration/full boot/SMP/final media remain open.
