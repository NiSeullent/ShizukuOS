# Persistent restricted native AP work service

Base: 660194da44fe40df88ac67151a7aab79213353d7. Implementation is authorized
only in this isolated worktree. Windows remains one vCPU. No VM, full kernel
build, media, network, canonical/index/commit, or peer source writes.

Use the existing queues, ticket and destination-stack completion. Keep the
old cohort and all policy bounds unchanged. Add a distinct immutable restricted
worker class, 16 descriptors with owned 4096-byte buffers, exact nonwrapping
cookies, a closed finite digest operation and queue-owned conditional park/wake.
Only BSP submits/polls/releases/stops. No runtime AP allocation or arbitrary
callback, process, object, driver, IPC, VM or user access. Stop closes admission,
drains finite work and waits for real inactive workers, F0 ACK and owner stack
withdrawal before freeing. Failure retains all resources.

Pre-flight: pool/mailbox transitions and park/wake share the scheduler ticket;
unlock must retain IF clear through schedule. Existing completion alone may
publish a woken outgoing stack. Physical architecture ONLINE and scheduler
ONLINE remain separate. Root owns the main.c hook; the new start API refuses
unless actual BSP queues/live/outgoing/blocked owners are quiescent after UP QA.
Future validation uses the reviewed tiny five-member image and 120 seconds,
not the historical broad image. No general BSP NT/IPC coexistence is admitted.

Own existing kernel64/{sched.c,sched_cpu.h,k64.h,cpu_bringup.c,cpu_bringup.h,
cpu_arch_bringup.c,cpu_arch_bringup.h}; new kernel_ap_work.c/.h; unique
shizukudos/tests/{test_k64_persistent_ap_red.c,test_k64_persistent_ap.c,test_k64_persistent_ap_service.c,test_k64_persistent_ap_trace.c,
run_k64_persistent_ap_host.py}; this plan and unique status.
No main.c/arch.c/start.asm/F1/TLB/NT/Supervisor changes. Private AP tables retain
four pages, F1 IST1, DF IST2 and NMI IST3. AP-owned bounded records capture real
entry/frame/EOI/completion facts; BSP flushes after owner withdrawal only.

## Disclosed commands and effects

1. `python3 shizukudos/tests/run_k64_persistent_ap_host.py --out build/k64-persistent-ap-red --cc gcc --baseline-red`
2. `python3 shizukudos/tests/run_k64_persistent_ap_host.py --out build/k64-persistent-ap-gcc2 --cc gcc --compile-units`
3. `python3 shizukudos/tests/run_k64_persistent_ap_host.py --out build/k64-persistent-ap-clang --cc clang --sanitize --compile-units`

Each command captures its own Python and approved adcf owner bytes before
loading owner functions. Capture actual source/header/ASM/schema, selected
compiler/subtool binaries, system-header inventory and generated adapters
before compiling; compiler -M/-MM verifies the consumed closure. Each child
has 30 seconds plus owned-group TERM/KILL/drain/reap bounded to two seconds.
Writes stay in the fresh named build leaf, with aggregate lane <=96 MiB. No
download, network, service start, VM, global/client configuration or shared cache.
Only these bounded commands and equivalent private controlled variants are
authorized. No repository script executes before this plan is present.

Task 1: RED actual pristine sched_ap_cohort_finish body with real queue and
handoff primitives. Adapt only architecture completion delivery; record that
successful finish withdraws mask1 and frees stacks, failing second-generation
persistence. This is a lifetime witness, not AP/preemption execution.
Task 2: tests first for job/cookie/claim/park/wake/stop conservation and failure
retention; implement smallest closed service, preserving old cohort.
Task 3: actual GCC/Clang ASAN controls, original dispatcher controls and changed
freestanding units/MM; freeze exact source/helpers/tool maps and raw receipts.
Root dispatches independent review before main hook, adoption or native proof.

Ruling: inline execution and parent-owned final review replace skill helper
bookkeeping/commits, because this task expressly forbids those side effects.
The preserved initial GCC sanitizer link failed on absent installed GCC runtime
targets. Parent clarified ordinary GCC plus Clang ASAN/UBSAN is the required
scope; no library repair or download is authorized or performed.
A covering private `--only-pool` variant may use a fresh `build/k64-persistent-ap-*`
leaf to record bounded actual owner counters when a concurrency control fails;
it runs only that same real C pool unit, with unchanged 30+2 lifecycle bounds.
Future runs use a standard-library outer entry that reads this runner once,
saves those exact bytes and SHA before executing that same buffer (not a later
path reread), then the runner captures the approved owner before loading it.
The outer entry writes only its fresh named ignored build leaf.
Read-only original actual-C gates included in the same source-bound owner:
test_k64_cpu_api (27), test_k64_runqueue (13), existing AP context (10) and
architecture (17). Existing fixture sources and prior timeouts are unchanged.
Successor commands may use fresh gcc3/clang/gcc4/clang2 leaves to preserve any
failed compile/evaluator receipts; every child still has the same 30+2 bound.

Approved migration successor: private BSP-only `sched_ap_work_migrate(origin,
slot,destination)` for saved BLOCKED class2 workers. No current/outgoing/live
owner or RUNNING/DONE job reference may migrate. Source/destination must be
actual scheduler and private architecture online; generic policy remains closed.
Origin retains one stack/stop/reap lifetime; actual queue ownership determines
execution and wake/IPI targets. Refuse a move stranding any queued job and refuse
submission to an eligibility mask with zero actual workers before publication.
Meaningful migration RED command is a fresh equivalent runner variant
`--migration-red --cc gcc --out build/k64-persistent-ap-migration-red`; it consumes
the existing real generic policy body and actual saved queue state. Fresh full
GCC/Clang successor leaves run the new private API controls and the same old
300-job/six-owner12k/eight-unit gates, unchanged 30+2 owned bounds.

Migration reports `K64_AP_WORK_BUSY=-3` only before owner/queue/IPI mutation for
a worker not yet fully saved and parked. A bounded caller may wait for BUSY;
all other negative results must not be blindly retried, because the owner may
have moved before F0 or ACK failed. Such committed failure retains everything.
Origin-owned completed_count/completed_cpu_mask update only after successful
exact cookie/CPU/worker completion under the ticket, separate from seen context.
They are reported only after withdrawal. Architecture pre-ticket snapshot plus
locked ONLINE/state excludes normal stop, not asynchronous hardware failure.
