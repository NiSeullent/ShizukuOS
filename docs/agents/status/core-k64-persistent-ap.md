# Persistent restricted K64 AP service: source/host checkpoint

This isolated branch is based on `660194da44fe40df88ac67151a7aab79213353d7`.
The candidate implements a persistent, explicitly native, fixed digest work
service through the existing scheduler. Root owns main.c integration, canonical
adoption, independent review, full linking and future guest validation. Nothing
here accepts Windows, generic AP user/process/object/IPC/MM/driver scheduling,
full SMP, hardware NMI isolation, or a final ISO. No guest or full kernel build
ran in this lane. Windows remains one vCPU.

## Production contract

`shz.smp=workers` is opt-in; default and `smp=off` retain UP. The early prepare
path discovers/prepares resources but defers FIRST INIT. Root's later main hook
must finish unchanged UP QA with the tiny reviewed five-member image, then call
`shz_cpu_workers_start()`. Start verifies actual BSP ready/live/outgoing/blocked
and wait owners, kernel root, no prior AP architecture lifetime, owned full
spans and overlap exclusion before INIT. Returning from QA alone is insufficient.

Preallocation contains sixteen 4096-byte copied payload slots and two restricted
worker TCBs/stacks plus an idle per actual AP. The closed operation is FNV-1a over
exactly 256 traversals; no caller opcode/function/shared payload is admitted.
BSP submit/poll/release/stop use exact nonwrapping cookies. Actual AP identity,
per-CPU queues, stack-completion ownership and IRQ-off short tickets are retained.
Descriptor and queue transitions share the same ticket; computation, callbacks,
MSR/FX transfer and stack switches do not hold it. A wake between conditional park
and stack save never queues an on_cpu TCB; destination completion publishes it.

Class2 is immutable before AP start. BSP timeout scans, visitors, lookup/slot
exposure, generic creator/wake/reap and GS/driver policy refuse or skip it before
reading mutable restricted state. General creation is closed while its resources
are retained. AP exit bypasses process/object callbacks. Workers inherit Q1;
existing class1 migration, UP Q1..16, 32-tick aging and fixed four-tick aged service
allocation are unchanged. Finite jobs alone do not guarantee both lanes execute
useful work or accumulate sixteen hardware ticks; future native records must
measure that without weakening the old assertions.

The private `sched_ap_work_migrate(origin,slot,destination)` moves only a fully
saved BLOCKED class2 worker with no live/current/outgoing/queued reference and no
RUNNING or retained DONE job reference. Origin retains one stack/lifetime; actual
owner supplies execution and wake targets. Both workers may move off one source.
A move that strands a queued job and a submission to zero worker coverage refuse
before publication. Physical entered/private task-gate/ONLINE facts are sampled
before the ticket; RUNNING plus locked scheduler ONLINE excludes normal stop,
not asynchronous hardware failure. Generic thread policy remains closed.
`K64_AP_WORK_BUSY=-3` is pre-mutation and permits only bounded wait/retry. Other
negative migration results may follow committed movement and must not be blindly
retried; failure closes admission and retains all resources.

Per-origin completed_count/completed_cpu_mask update only after successful exact
cookie/actual CPU/current worker completion under the ticket. They distinguish
useful completed work from mere context presence and refuse overflow/double
completion. BSP prints them only after actual withdrawal before freeing.

Stop closes admission and drains. Unreleased DONE results return -2 and keep the
pool/stacks online for poll/release and a drain retry. Final stop requires real
F0 request==ACK, inactive terminal workers, bootstrap-stack withdrawal and each
AP's release-published trace done. Timeouts/failed sends retain resources. Empty
intervals leave the successful service online. No AP runtime allocator, arbitrary
callback, process VM, driver, object, semaphore, IPC or user path is opened.

AP-owned bounded raw records capture physical APIC/CR3/GDT/IDT/TR/TSS.RSP0,
ordinary GS/KERNEL_GS/EFER.SCE and actual entry/frame/stack/EOI/destination epochs.
BSP cannot copy a live ring. The retained private table stays four PMM pages;
F1 IST1/body/generation, DF IST2 and dedicated NMI IST3 are unchanged. Vector2
remains an emergency fatal guard. Host frames and privileged adapters are not
hardware AP/NMI proof; no QMP inject or software INT2 occurred.

## Actual evidence

Final GCC strict receipt:
`build/k64-persistent-ap-gcc7/result.json`
SHA256 `44bf53023da4033703499d6c672ff7a6d328376cb7c318693621025c0ebd3cc2`.
Final Clang ASAN/UBSAN receipt:
`build/k64-persistent-ap-clang4/result.json`
SHA256 `e653957d15ca1d4f3441c4a8d0de4b59049a57715e97ff08fa16719de0ddab3e`.
Each has 191 checks with zero failures: pool/queue45, service28, raw architecture
trace17, private migration34, unchanged cohort10, unchanged AP architecture17,
unchanged UP CPU API27 and unchanged six-owner runqueue13. Actual pool owners
submitted/completed/released300 with no duplicate/corruption; the original six
owners conserved all48 TCBs across12000 attempts. Each also compiled four actual
changed units in standalone and Supervisor configurations, eight units total;
these are unit objects, not kernel links.

Each final run has47 bounded actual command receipts: 30 seconds plus2-second
owned process-group cleanup, direct reaped/group empty/drain complete, no timeout
or infrastructure error. Eight host executables and eight unit objects are pinned.
Actual compiler-derived closure has131 GCC and144 Clang dependency files;
44 local source/helper inputs match before/after and current bytes. Tool/runtime,
CRT/schema, generated bodies and artifact maps are pinned before consumption and
checked afterward. System-header/runtime inventories preceded compiler use;
-M consumed closure must be a subset. The outer standard-library entry captured
runner bytes before same-buffer execution; approved adcf owner bytes were saved
before loading the two actual owner functions. No .pyc/global repair/download.
Current helper SHA256:
`be5673e9c4a7c1f86db5bab23892b4b14111ae75de6bc6ce260b44169ce28e6a`.

Meaningful pristine behavior RED is unchanged:
`build/k64-persistent-ap-red3/result.json`, SHA256
`5161dcd3917dda907a6a2740c60a3a9375534aaf33b02d47c764d20929227438`.
Actual original finish returned0, withdrew mask1, retained_count0 and freed3,
failing second-generation empty-interval persistence. The new workers path is
separate; historical class1 finish continues to withdraw normally.
Meaningful parked migration RED is unchanged:
`build/k64-persistent-ap-migration-red/result.json`, SHA256
`c9df5c5d42555a32ad143a372b7e07cee6d3bb12901ffcc1824f1eca128d48cb`.
Actual old generic policy returned-1 for saved BLOCKED/liveNONE/online7, leaving
source_mask2 and failing the private-movement behavior assertion.

All earlier failed evidence remains. Initial RED adapter compile/member mistakes
and nonzero finish-bad adapter are not valid production RED. GCC ASAN failed to
link absent installed GCC runtime targets; required scope is GCC strict plus
installed Clang sanitizer, with no repair. The initial 4000-iteration role fixture
stopped its producer after16 accepted jobs; actual diagnosis showed16 completed/
released, occupied0/bad0. The bounded corrected fixture waits for all300 jobs.
Clang initial dependency flags and then runtime-schema inventory guard rejected
before programs; those logs/available raw receipts remain. The first such Clang
exception has no final result and no complete per-child PID receipt; no invented
lifecycle claim is made for it. Final47-command records are complete. Historical
UP concurrency timeouts, old broad outer-P2/PMA361 and no-ACPI low-phase failure
are not cleared by these host controls.

## Freeze and handoff

Exact17 candidates: the seven declared existing production files; new
kernel_ap_work.c/.h; test_k64_persistent_ap_red.c, test_k64_persistent_ap.c,
test_k64_persistent_ap_service.c, test_k64_persistent_ap_trace.c,
test_k64_persistent_ap_migration.c and run_k64_persistent_ap_host.py; this status
and docs/agents/plans/core-k64-persistent-ap.md. Original fixtures are unchanged.
The ignored `build/k64-persistent-ap-final/` manifest records exact current hashes,
raw patch, tested source ZIP, complete evidence archive, artifact/tool/source
reconciliation and budget. Root must obtain independent source/evidence review
before adoption/main consumption. No branch or canonical commit was made.
