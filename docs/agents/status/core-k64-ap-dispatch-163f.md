# Native Kernel64 AP dispatcher cohort status

Frozen source candidate in isolated codex/k64-ap-dispatch-163f-20261002,
base 2b3eb1665b2b6cc42cb5af01ab3fbd31ac94b8e3. Nine production files and four
unique host fixtures/helper plus own plan/status; no canonical, peer, index,
NAS, media, process/NT, allocator, Supervisor or Kernel32 mutation. No commit,
full kernel link, guest or actual AP dispatch run has occurred in this epoch.
Windows98 remains the product OS; native Windows remains one vCPU. This is a
source prerequisite for a bounded native kernel-thread cohort, not full SMP.

## Implemented entry and ownership contracts

Explicit standalone shz.smp=dispatch delays INIT until the existing scheduler
preallocates one idle/current and two kernel worker TCBs/stacks per AP. The
normal pre-INIT resource callback validates their PMM-owned full stack spans.
Actual strong shz_smp_this_cpu is authoritative: unknown32 and unentered or
unallocated private owners refuse. Architecture ONLINE alone does not open
public AP scheduling: sched_cpu_register(AP) still returns -2. Supervisor AP
entry still returns unsupported, and normal threads remain CPU0 affinity.

Each AP binds KERNEL_GS_BASE to the existing private anchor with IF clear and
EFER.SCE disabled; ordinary NT GS_BASE is preserved. Only F0/reschedule and
F2/timer become common full-register-frame IST0 task-stack gates. F1 remains
its original private IST1 invalidate/generation handler, and DF remains IST2.
The AP NMI vector2 still uses the fatal invariant guard on IST1, shared with F1;
no separate AP NMI resource/isolation or real hardware NMI proof is claimed.

The actual assembly destination idle stack precedes scheduler-online
publication. The assembly return destination bootstrap stack precedes revoking
online and clearing idle on_cpu. Existing normal thread switches release the
queue ticket before MSR/FX/stack transfer; only destination completion releases
outgoing live-stack ownership. No suspended scheduler context is left on F1 or
another IST. Completed worker stacks are joined/reclaimed by BSP only after
all outgoing ownership is gone and every AP has withdrawn from its idle stack.

LAPIC F2 calibration uses bounded PIT2 on BSP before INIT, requires the local
timer previously masked/inactive, restores the BSP LAPIC registers and port61,
and stores measured counts rather than inferred TSC values. AP arm/mask is
owning IF-off only. F0/F2 acknowledge local APIC before context transfer. Masking
an LVT does not retract IRR: after stop F2 retains a non-scheduling private EOI
drain gate. AP interrupt resources and F1 remain alive on retained bootstrap
stacks after scheduler withdrawal. Calibration and physical delivery are not
executed by these host controls and require the later native epoch.

Only BSP advances wall jiffies and shared UP timeout/object/device/entropy paths.
APs charge private CPU service counters and running cohort TCBs. Cohort payloads
perform arithmetic without voluntary yield and terminate through a private exit
path without allocator/process/NT-object callbacks. Normal waits, user entry,
process roots, drivers, IPC and full object lifetime are not admitted on APs.
32-wall-tick aging, fixed4 service credit, Q1..16 and original UP gates remain
unchanged. No new scheduler is introduced.

Migration changes only a saved READY tagged worker under the existing queue
ticket. Policy rejects a mask removing a live current CPU; rejection preserves
ownership. Native cohort sends actual F0 after unlocking. Request/ACK is the
owning F0 handler's latest processed request generation, not proof that a
worker has executed. The future native gate separately requires the worker's
real CPU seen bitmap, charged ticks, useful loops and inactive terminal stack.
No host logical-owner fixture counts as AP execution or migration acceptance.

## Test-first evidence and preserved failures

Baseline actual architecture C compiled and failed 5/11 checks for private
owner publication and schedulable gates: red-gcc-1 and red-clang-2. Missing
cohort admission was separately preserved in cohort-red-gcc-1. The actual
pending-timer gate check failed in pending-timer-red-gcc-1 before the private
drain gate fix. First changed standalone architecture compile rejected missing
pci.h for the existing port helpers in owned-gcc-final; adding the include
passed the same captured-source compiler closure. Early fixture/link/compiler
warning failures remain separate infrastructure records; none is rewritten.

Final captured-helper runs (build/k64-ap-dispatch-*):

| Run | Actual scope | Result receipt SHA256 |
| --- | --- | --- |
| owned-gcc-final2 | 17 architecture C + 10 queue C + 7 real ASM stack checks; 8 actual freestanding changed-unit compiles | 361fd7020fcaf6ef13ba16f2aab24aa5613a5a78b68dcd14f1a19f38a7b6a2b0 |
| owned-clang-final | Same checks with C ASan/UBSan; same 8 changed-unit compiles | d6ae9b51fefe0ece4a7c28d75a22944c59cc7614ea975a535c0832e58fa89b78 |
| up-gcc | Unmodified original dispatcher fixture/helper, captured private closure | 5e6aa98bd0d32470f3f005e791f7df1b4216418377d9eb07d83970056893ce54 |
| up-clang | Same original suite with ASan/UBSan | 26ec7a0f633f4cfe70c1dc3586ef8f44314c75353120ee12c1cd1359aa64b765 |

Original suites each pass 33 actual context, 12 actual architecture, 7 queue and
8 ASM classifier checks, singleton relocation/three barrier gates and the
unchanged watchdog control. Six owners complete 12,000 saved-stack handoffs in
13.241s GCC and 21.442880s Clang, under unchanged 60s bounds. Old historical GCC
60s timeout belongs to the earlier dispatcher epoch and remains historical;
these runs do not erase it. The controlled watchdog exit124 remains an expected
negative diagnostic, not an allocator/kernel/native pass.

All four final runs capture local C/H/ASM/helper bytes before dependency/compile
consumers, pin compiler and executed subtools, bind executable/object bytes
before subsequent consumption, and compare current/source/tool/artifact hashes
afterward. The changed units use actual -M compiler dependencies for sched,
arch, cpu_arch_bringup and cpu_bringup, in standalone and Supervisor profiles.
External compiler headers are pinned; the entire host environment is not sealed.
No project pyc is loaded. The approved adcf9a707675... owned-session/group helper
is reused verbatim for bounded TERM/KILL/drain/subreaper cleanup; every final
command records reaping and an empty owned group. No unrelated process is
signaled. Pre-entry records bind exactly the helper bytes executed via compile.

## Remaining admission gates

Independent source/evidence review, merged normal kernel builds and actual
2/4 CPU component VMs are still required. Native tests must cover explicit
cohort, forced-UP/default-UP, private current/EOI/timer counts, useful preemption
without voluntary yield, saved-context affinity/migration plus F0 ACK and exact
queue/live-stack conservation; all original UP/native bounds must remain.
Dedicated AP NMI isolation and true hardware NMI injection are unqualified.
Kernel-only cohort admission does not qualify full user/NT/MM/waits/driver/AP
runtime allocation or Supervisor virtual APs, Windows runtime or final ISO.
