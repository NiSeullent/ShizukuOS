# Native Kernel64 preallocated AP dispatcher cohort

Worktree codex/k64-ap-dispatch-163f-20261002, base2b3eb1665b2b6cc42cb5af01ab3fbd31ac94b8e3.
Windows98 VMM/USER/GDI remain the OS and native Windows remains one vCPU.
This is an explicit native component admission, not completion of full SMP.

## Exact owned scope and entry contract

Production: sched.c, sched_cpu.h, k64.h, arch.c, start.asm,
cpu_arch_bringup.c/.h, cpu_bringup.c/.h. Unique tests and this plan/status.
No main/proc/sysk32/mem/provider/Supervisor/Kernel32 edits; no VM, NAS, four-profile
rebuild or commit until parent grants that epoch. Aggregate outputs <=96MiB.
Actual shz_smp_this_cpu is the only identity provider; unknown32 refuses.

The default UP/private-worker boot path is unchanged. Explicit standalone
shz.smp=dispatch discovers firmware and allocates private architecture before
sched_init, but defers INIT until shz_cpu_bringup_verify. At that point existing
sched_init has established the one BSP scheduler, so BSP preallocates exactly
one idle/current TCB and two suspended kernel-worker TCBs/stacks per real AP
through the existing scheduler table. No AP runtime allocator, user/process VM,
NT object/wait, IPC, driver or device callback is admitted. Kernel cohort code
uses only own payload arithmetic/atomics and reviewed yield/exit; general
public sched_cpu_register stays unsupported for APs.

The normal owner resource check must verify all cohort stack pages before INIT.
The physical backend still owns its immutable APIC map, bootstrap stacks and
protected F1 TLB generation/lifetime. Because backend start resets the existing
anchor array, BSP explicitly rebinds its actual current stack while IF remains
off immediately after backend start, before any user entry.

AP enter verifies actual identity, private GDT/IDT/TSS, current shared kernel CR3,
architecture ONLINE, IF-off and a prepared idle stack. It installs F0/F2 common
full-register-frame entries on IST0 only for this mode. F1 remains its existing
private IST1 handler and actual invalidate/generation ACK; faults/DF never
schedule. Ordinary GS_BASE remains NT KPCR/TEB; only KERNEL_GS_BASE binds the
existing CPU anchor and each stack switch updates the owning private TSS RSP0.
Scheduler ONLINE publishes only after assembly has transferred to the actual
preallocated idle stack. No ticket spans stack/MSR/FX/context/C observer work.

A native LAPIC periodic F2 source uses a bounded actual PIT2 calibration before
INIT, not nominal TSC guesses. Only BSP increments wall jiffies and invokes UP
object/timeouts/entropy/device/user recovery. AP F0/F2 validate their private
kernel task frame and EOI before schedule. They charge their actual CPU/thread
and consume unchanged32-wall-tick aging, finite4 service grant and Q1..16.

Cohort-tagged READY contexts alone may balance/migrate among admitted AP masks;
on_cpu NONE and the queue ticket are mandatory. Running contexts cannot be
remotely removed. Reschedule request/ACK generation is recorded under ticket;
IPI sends occur after unlock and actual F0 acknowledges its owning request.
Normal threads remain CPU0 affinity and shared BSP compatibility APIs.

On controlled stop, workers terminate without shared object/process callbacks.
BSP observes completed outgoing-stack ownership before reclamation. AP idle
masks its local timer and assembly returns to the retained bootstrap stack;
only destination-stack completion revokes scheduler ONLINE and clears that idle
TCB's live ownership. The AP then remains in its existing private interrupt
lifetime with F1 intact; root can run unchanged UP regressions after cohort.

## Test-first sequence and evidence

1. Capture helper/source bytes before compiler-MM or compile. Actual architecture
   C RED must show valid mapped private-owner stack publication unsupported and
   current schedulable F0/F2 gates unsuitable (IST1), separately from any missing
   new interface. Actual scheduler C RED must show preallocated cohort admission
   denied; architecture ONLINE by itself must still fail normal AP registration.
2. Implement minimal production admission/stack/gate/ownership seams. Actual C
   controls cover invalid/unmapped identity, unprepared/IF-on/incorrect root or
   stack rejection without mutation; private F1 preservation; saved READY only
   migration/conservation; publication only on destination stack; wake/exit
   handoff; finite credit/no refill/Q1 behavior; no external callback under ticket.
3. Assemble real start.asm and inspect/call unprivileged boundary classifiers;
   real destination-stack code and SysV alignment must be pinned. These controls
   do not execute hardware interrupts or prove native AP preemption.
4. Fresh GCC and Clang sanitized controls plus original UP host regressions and
   actual freestanding changed-unit compilation, with complete local compiler-MM
   source dependencies and tool/helper/artifact pre/post hashes. Preserve every
   unexpected failure and unchanged time/check bounds. No guest until VM slot.
5. Freeze exact source/tests/docs and receipts for independent review. Later real
   2/4 CPU VM epoch must prove timer preemption on distinct task stacks, useful
   work, affinity/migration/IPI ACK, guard/ownership and terminal conservation;
   full user/NT/MM/Supervisor SMP remains separately unqualified.

## Source epoch refinement

The final host candidate retains AP vector2 as a fatal guard on existing IST1;
a dedicated AP NMI stack/resource successor is explicitly deferred. F1 remains
byte-identical at its gate/body. No INT2 or host classifier is hardware NMI proof.
Stopping a LAPIC timer retains a private non-scheduling F2 drain gate because
an already-pending IRR delivery survives masking. Request/ACK records F0 handling;
actual migration acceptance also requires useful worker execution on both CPUs.
Final source/host/unit receipts are listed in the status; no guest/full link has
been run and general AP registration remains unsupported.
