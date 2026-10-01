# Kernel64 CPU queue foundation — 163f

Candidate is isolated in `/root/Win98-Modern-k64-cpu-163f-20261002`, branch
`codex/k64-cpu-foundation-163f-20261002`, base4bd5de1. Root owns canonical
integration; no canonical, boot, NAS/media or global configuration changes occur
here. This is a backend component of actual Windows98 ShizukuDOS. AP scheduling,
Supervisor virtualAPs and WindowsVMM integration remain open.

## Implemented contract

The existing scheduler consumes32 CPU records with32 priority FIFO queues,
queue membership/mask/count, current/idle/outgoing and accounting state. A common
fair ticket admits bounded queue/policy transitions with local IRQs disabled.
No ticket crosses a stack switch, allocation, wait or external object callback.
The existing32-tick aging, independent fixed4 eligible-tick allocation, quantum
1..16, defaultpriority16/quantum1 and all native useful-work thresholds remain.

TCB `ready_cpu` and `on_cpu` distinguish inactive queue membership from a live
context. Outgoing READY state is withheld from queues until destination-stack
`sched_switch_complete()` runs after saving RSP, before restoring incoming IF.
A wake in the handoff window defers admission; terminal live contexts cannot be
joined/reaped. The virtual outgoing arrival preserves UP selection ordering.
The assembly call follows SysV alignment and preserves saved callee registers;
kernel C uses general registers only, preserving restored FX/userGS state.

`sched_cpu_identity()` consumes the strong existing physical identity provider.
Known BSP0, mappedAP and unknownUINT32_MAX are distinct. `sched_cpu_register()`
rejects invalidCPU with-1 and all APactivation with-2. Online affinity remains
mask1 and rejects unsupported masks without policy/queue mutation. CPU0 globals
remain explicit UP compatibility for syscall/process consumers. Unsupported
physical owners cannot charge the BSP clock, change policy, wake/allocate threads
or borrow its current TCB. GS_BASE continues to hold per-thread TEB/KPCR state.

Only already-reviewed new backend files from55b684c/981debb were imported under
root authorization (own commits2a1de80/34dd621). No main/AP-start/arch/pci/memory
hooks were added. Their dormant old page-table guard must be superseded by the
SMP owner's reviewed full-PMM-reader/resource successor during final integration.
ArchitectureONLINE is not schedulerONLINE. Wait/object/allocator/TLB/syscall and
Supervisor seams are not certified for concurrent AP execution by this slice.

## Evidence and scope

`build/k64-cpu-red/host/result.json` retains runtime RED against actual original
scheduler C: absent production CPU/queue interfaces. Its receipt pins pre/post
inputs; original untracked test bytes were not separately archived before later
test edits. This is component TDD evidence, not a native AP result.

Final `build/k64-cpu-final/host-gcc` and `host-clang` each PASS27 actual scheduler C
checks plus13 production queue checks. Clang uses ASAN/UBSAN. The API fixture
executes the actual CPUID provider against a private immutable topology and pins
its process to one allowed host CPU to avoid host migration. Privileged hardware
operations/actual stack switching are substituted only at declared boundaries.
Checks cover unsupported identity, affinity rejection, FIFO/policy conservation,
no ticket at switch, deferred semaphore wake, inactive-only zombie join and no
running quantum/grant refill. Six pthread owners make12,000 attempts on the same
production queue helper, conserving all48 identities. Logical host owners are
not physical AP execution. TSAN was not run.

The earlier Clang30-second queue timeout is retained under
`build/k64-cpu-green/host-clang-v1/infrastructure-failure.json`; no completed
concurrency pass was claimed for it. The runner now captures bounded60-second
host timeout failures and stdout/posthashes. Kernel timing limits were unchanged.
Final host receipts use compiler-MM transitive project closure, compiler driver
and executable hashes before/after. Four private actual-C defect controls PASS
under `negative-controls-v2`: offline affinity, unknown identity, live-stack
admission and disabled aging are rejected at runtime. First control attempt
compile/string-selection infrastructure failures are preserved separately.

Fresh normal single-profile kbuild compiled every Kernel64 source plus original
standalone/AHCI/libsfs/dead-screen extras, without reused objects. Frozen normal
219-input map digest is
`dd5a6172148685834c4f3337aab6cf1151f5d97ca1b83b224437decadcc8dad9`.
Sources-before/after match. KernelSHA is
`a62461c99880cfa4b1b62d3b2b9752d95cc64836afe9dd36522fedd023091629`,
ELFSHA `d8ba889b0e2c9590202982c79b4ddc6cc5a41041b1325b92c15f661c15654f59`,
stubSHA `6f673d443bddb447b7f26ba3dbbb6234db256a48e8a9006a90ec7292fb687b11`.
Native focused KVM17/17 (2.35s) and TCG17/17 (2.89s) PASS. These include original
phase useful>1000, readywait40, isolated refresh40/>1000, finite credit4 and
arrival/FIFO controls. Source/artifact/receipt/runner/helpers/QEMU hashes match
before/after. PMAfixture remains exact6761e4cd. Completed broad KVM native regression passed all original38 checks (219.75s),
151 app records exit0/faulted0, W64loopback48 and PMAservice16. The optional
focused evaluator was wrongly applied to broad slot18, so the original run's
combined driver status remainsFAIL. Original executed driver bytes and receipts
are retained. `broad-scope-reconciliation-kvm.json` separately derives PASS for
all original38 plus10 applicable policy checks from unchanged original inputs:
broad mode emits no focused marker, and tests.c338 incorporates returnedPMA
failures into finalslot28. Five controls reject missing/failedPMA summary, failed
finalaggregate and abnormalexit. First incorrect interpretation and encoding
error are preserved as host-evaluator errors; no KVM guest rerun occurred.

Broad TCG timed out at the declared360s while progressing through IPCstress:
rc-9, no final whole-suite completion. All pinned sources/artifacts/helpers/receipt
and QEMU stayed stable. This incomplete run is not38-check TCG acceptance and
was not retried or granted a longer timeout. FocusedTCG17/17 remains valid.
The executedTCG driver also retains the auxiliary focused-marker assumption;
its bytes are saved separately, and the future broad driver now uses the source-
verified aggregate contract. No new loaded-helper claim is made for that edit.
Normal non-standalone freestanding scheduler C compilation PASS with stable
source closure/compiler, without a Supervisor execution claim.

## Private producer identity limitation (F6)

The retained private `build/k64-cpu-final/build_profile.py` imports kbuild at
line5, including its shzlib dependency, before taking the initial source map at
line9. Persistent helper replacement between execution and that first capture
could bind replacement file hashes to previously loaded helper logic. Matching
the219-file maps and generated artifacts does not close this execution-identity
gap; no race is alleged to have occurred in these retained runs.

The old219-input results remain historical component behavior evidence, without
claiming equivalence to the accepted F6 captured-helper producer. Neither the
private producer nor these old receipts were changed to manufacture that claim.
Root will perform the integrated fresh all-profile build and native composite
with captured helper execution. BroadTCG360-second/63-app incompletion and the
separate no-ACPI lowloops242 failure remain open.

## Separate preserved no-ACPI failure

SMP tree `build/smp-normal-ap-noacpi-1/serial.log` has a genuine unchanged6761
native FAIL: phase1 lowloops168827, phase2 lowloops242, chargedticks16/144,
completedreadywait32. Arrival4/4/terminal1 and isolated refreshfirst32/useful1562519
PASS. No AP execution or resources were initialized in that no-ACPI fallback.
Neither current foundation gates nor other passing peer runs erase this result.

Policy setters and phase loop baselines publish under one IRQ guard. The existing
phase has no first-selection/IRQ-location observer;16 charged ticks prove that
TCB became current but not useful instruction execution. The spinner enables IF
before incrementing its loop counter, a reachable preemption boundary after
protected timestamp sampling. Attribution of the natural242 result requires an
actual dedicated phase dispatch/precharge/saved-RIP trace; no fixture or policy
threshold was changed here and no general useful-instruction guarantee is claimed.

## Remaining handoff

Highest independent source review approved the exact nine-file foundation,
committed as `cbdd766b63e0e7a47504cfd5e3a8186b3c3f17d6`. Root-owned integration
is still required. Native UP
context/SSE/ring3/service checks do not prove AP runnable contexts, load balancing,
IPI/TLB reclamation, object/wait concurrency, Supervisor or actual Windows98 boot.
