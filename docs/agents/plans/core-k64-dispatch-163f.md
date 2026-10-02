# Kernel64 dispatcher and entry foundation implementation plan

> For agentic workers: implement this plan task by task using the executing-plans and test-driven-development skills. Parent approval precedes production edits; independent review precedes any commit.

**Goal:** Convert the existing Kernel64 dispatcher and syscall entry to CPU-owned context without enabling unsafe AP execution, then hand off the exact private interrupt and kernel-only admission requirements for real 2/4 CPU scheduling.

**Architecture:** Keep the existing priority/FIFO scheduler and common short IRQ-off ticket. Its CPU record owns current, idle, outgoing and accounting. The strong `shz_smp_this_cpu()` provider supplies logical identity; `KERNEL_GS_BASE` points to the existing `shz_smp_cpus[cpu]` entry anchor, while ordinary GS remains the thread's NT KPCR/TEB. Destination-stack completion alone releases outgoing live-stack ownership.

**Tech stack:** Freestanding x86-64 C, NASM, existing ticket primitives, GCC/Clang host controls and existing source-bound native runners.

**Spec:** Root task for isolated `codex/k64-dispatch-163f-20261002`, base `0fffd07dd22bd23a6005731e8c3a1f5118106066`; Windows 98 remains the product OS and remains one virtual CPU.

## Constraints and evidence scope

- Keep 32 priorities, FIFO, aging at 32 ticks, base quantum 1..16 and the fixed independent aged allocation of 4 eligible ticks. Preserve all original 40/80/>1000 and native 17/38 gates.
- Do not add a scheduler, topology parser, CPUID identity implementation or Supervisor CPU protocol.
- Do not change `cpu_bringup.c`, `main.c`, `mem.c`, TLB code, Kernel32, Supervisor or canonical sources/index.
- Architecture ONLINE is not scheduler ONLINE. Until admission is implemented and independently reviewed, mask remains 1 and every AP registration returns unsupported without mutation.
- No ticket spans allocation, callbacks, wait/object operations, MSR/CR3/FX context transfer or `switch_stacks`. Local IRQ masking precedes the ticket.
- Initial output budget is 64 MiB; no kernel rebuild, guest or private media until the parent grants the corresponding epoch/VM slot. Host controls cannot establish AP execution or native preemption.
- No commit until independent review. Historical native failures remain immutable.

## Existing execution and hazards

`sched_cpu.h` already has bounded per-CPU ready queues, current/idle/outgoing and accounting, but `sched.c` dispatches CPU0 and uses singleton current/idle mirrors. `start.asm` selects the SYSCALL stack through globals. `proc.c:user_thread_main` directly writes `g_kstack_top`, bypassing the declared but unimplemented `sched_set_current_kstack()`.

The physical provider is strong and maps immutable APIC IDs; unknown identity returns 32. No-ACPI UP fallback does not establish an AP domain. `smp_boot.h` reserves anchor offsets 0 and 8 for `syscall_kstack` and `syscall_user_rsp`; native topology preparation finishes before `sched_init`, so scheduler entry initialization must occur after the provider's possible array reset.

Private AP IDTs currently route ordinary faults and F0/F1 to IST1, DF to IST2, and disable EFER.SCE. Their shared interrupt stack cannot retain multiple suspended timer contexts. The BSP currently has DF IST1 only; a syscall's IF-off SWAPGS window still admits NMI before trusted RSP and while ordinary GS is temporarily replaced.

## Design choice

Use the existing anchor and a short paired SWAPGS syscall prologue. Do not keep GS pointing at CPU state through C: hosted NT drivers and user code already consume thread GS. Do not infer CPU identity from GS or CPUID counts. Keeping global syscall scratch would leave the AP blocker intact; dedicating GS to CPU state would break the NT contract.

The prologue performs `swapgs`, stores user RSP at anchor offset 8, loads trusted RSP from offset 0, pushes the saved user RSP into the existing synthetic frame, then `swapgs` back before calling C. Existing SFMASK clears IF/DF/TF/AC. Static assertions bind the offsets to the producer's real structure. Entry initialization verifies canonical kernel address/alignment and runs IF-off after `sched_init` knows the active stack.

Give BSP NMI a separate retained IST (never used for scheduling). In `isr_common`, after all registers are saved, compare interrupted RIP against the exact short SWAPGS window. If inside, restore ordinary GS before entering C and remember that correction on the interrupt's own stack/register context; swap back before IRET resumes the interrupted window. No GS consumers, C calls, or scheduling precede this normalization. Align the C-call RSP while retaining the original `struct regs` pointer and restoring that RSP before pops. A test must cover both sides of every window boundary and nested frame independence; IF masking alone is not accepted as NMI protection.

The temporary interval starts immediately after the first SWAPGS, includes the last SWAPGS instruction and ends immediately after it. Classification also requires CPL0. Actual entry bytes contain LFENCE before anchor GS accesses, after the conditional normalization join and after ordinary NT GS restoration, following [Intel's SWAPGS guidance](https://www.intel.com/content/www/us/en/developer/articles/technical/software-security-guidance/technical-documentation/speculative-behavior-swapgs-and-segment-registers.html). NMI/DF default terminal handling skips shared driver/user recovery callbacks; a later true hardware NMI diagnostic needs a separately reviewed bounded non-scheduling handler.

## Task 1: Actual-C red controls and immutable input capture

**Files:** Create `shizukudos/tests/test_k64_dispatch_context.c`, `shizukudos/tests/test_k64_dispatch_entry.py` and `shizukudos/tests/run_k64_dispatch_host.py`. Existing `test_k64_cpu_api.c`/`test_k64_runqueue.c` stay regression inputs, not replacement models.

- [ ] Capture own test/helper/compiler bytes before execution, actual compiler-MM project closure, commands/logs/executable SHA before and after; cap each process and the output budget.
- [ ] Include actual `sched.c` and actual identity provider, substituting only privileged CPU/stack boundaries. Required new CPU-context API must fail RED when absent.
- [ ] Pin this process to one host CPU for the real CPUID-provider fixture; simulated topology/online state is explicitly logical-owner fixture data, not AP proof.
- [ ] Test mapped unonline/unknown identities, invalid indices and invalid stack bounds fail with byte-identical context/queue/anchor state.
- [ ] Test CPU-selected current/idle/accounting and dispatch operate on the selected CPU record in a controlled admitted fixture, with CPU0 state unchanged.
- [ ] At the real switch boundary assert ticket unlocked and old TCB on_cpu/unqueued; inject wake, terminal join/reap attempts and policy changes; completion publishes exactly once on the destination CPU and no live stack is reclaimed.
- [ ] Run six concurrent logical owners on production queue/context transition helpers, preserving all TCB identities and queue/current/outgoing exclusivity; label host concurrency only.
- [ ] ASM controls assemble actual entry with bounded generated incbin fixtures, inspect actual symbols/instructions/relocations, and reject legacy global scratch. This is compile/disassembly proof, not native NMI/GS proof.

## Task 2: Production-consumed CPU context, AP admission still closed

**Files:** Modify `shizukudos/kernel64/sched.c`, `sched_cpu.h`, `k64.h`. No global shared waiter/object APIs become AP-safe.

**Interfaces proposed:**

- `uint32_t sched_cpu_identity(void)` remains strong-provider-backed.
- Internal `k64_cpu_sched_t *sched_owner_context(void)` returns a record only for a valid scheduler-online identity; unknown/unonline owner returns null.
- `thread_current()` reads that record. Globals may remain ABI compatibility mirrors only for CPU0 and are not read by dispatcher/entry.
- `void sched_set_current_kstack(uint64_t top)` becomes the authoritative stack publication path, checking current ownership and real stack span before publishing the anchor/TSS.
- Internal bounded `k64_rq_dispatch_locked(...)` / `k64_rq_complete_locked(...)` centralize actual queue/current/outgoing transitions, consumed by `schedule()` and completion; they cannot allocate or switch stacks.
- `sched_cpu_register(uint32_t)` retains -2 for APs. A later admission API cannot turn architecture ONLINE into scheduler ONLINE implicitly.

- [ ] Replace CPU0 dispatch/accounting references with an owner-selected context; preserve CPU0 policy behavior byte-for-byte where practical.
- [ ] Generalize outgoing completion to actual owner identity and validate old/new lifetime, on_cpu and outgoing slot under the same ticket.
- [ ] Keep shared semaphore/mutex/object timeout scanning, creation/reap/proc and NT paths BSP-restricted. AP local ticks in future must not run those callbacks.
- [ ] Preserve scheduler clock as BSP wall time; future AP timer increments per-CPU service/accounting only. Aging/wait deadlines continue to use the same wall-time domain.
- [ ] Restrict initial affinity to the real online mask; all rejected updates preserve queue/current/outgoing ownership.
- [ ] Pass actual-C RED controls plus unchanged CPU API/queue regressions under GCC and Clang sanitizers.

## Task 3: Entry anchor, trusted NMI stack and exact user publication

**Files:** Modify `start.asm`, `arch.c`, `k64.h`; propose one exact `proc.c:user_thread_main` replacement of direct global write with `sched_set_current_kstack(top)` (parent/c957 coordination before edit). Read existing `smp_boot.h`; do not change its owned layout.

**Interfaces proposed:** `int arch_sched_entry_bind(uint32_t cpu, uint64_t top)` and `int arch_sched_entry_set_stack(uint32_t cpu, uint64_t top)` initially support actual BSP only and return unsupported for APs; no AP TSS fallback to singleton. Bind writes `MSR_KERNEL_GS_BASE` to `&shz_smp_cpus[cpu]`, after validated context publication and while IF is clear. `MSR_GS_BASE` is never repurposed.

- [ ] Add static offset assertions and MSR constant; normalize the syscall prologue and preserve its existing synthetic frame, register semantics, NTContinue IRET and SYSRET paths.
- [ ] Add BSP NMI IST and the window-normalization/ABI alignment logic, keeping DF separate and all schedulable BSP timer gates IST0.
- [ ] Ensure destination completion runs before POPFQ on resumed and first-started thread contexts; preserve FX/CR8/GS and callee-saved state.
- [ ] Route dispatch and exact proc stack publication through the same checked setter.
- [ ] Pass ASM controls and compile actual C/ASM with freestanding normal flags. Hold native claims until a source-bound native slot is authorized.

## Task 4: Later private AP scheduler handshake (not autoactivated by this foundation)

Agreement with the SMP owner is required before changing `cpu_arch_bringup.c/h` or an AP callback. Proposed seam is a CPU-local, IF-off installation of dedicated common frame timer/F0 gates with IST0 and private TSS RSP0; private F1 TLB handler/IST ownership stays intact. The owner must acknowledge identity, retained stack/tables, physical interrupt endpoint and current kernel CR3. A timer must EOI before switching and never schedule on IST1/IST2. Existing AP loops keep the old private gates until explicit handoff succeeds.

Initial admission is an explicit kernel-only cohort, not public `thread_create` AP exposure. Every admitted thread must be created/published on BSP, have no process/TEB/object/IPC/wait/APC/user address-space state, use immutable shared kernel mappings and only the reviewed kernel-thread entry/yield/exit/atomic test contract. General allocation, wait, driver and user calls must remain unavailable until their real owners establish concurrency. Admission must publish current+idle+anchor+TSS before online bit; failure rolls back before interrupts are unmasked. Runtime online CPU count must reflect actual admitted dispatchers.

Load balance moves only saved READY contexts with on_cpu NONE, under the same ticket; affinity migration of running threads requires a pending request and actual owner IPI, never direct remote removal. F0 reschedule admission records generation/target and queues are unlocked before physical IPI. CPU0 remains the sole wall-clock/timeouts owner. Useful preemption requires an actual native timer (calibrated by existing owner; no TSC guess).

Required native RED/GREEN later: real 2/4 CPUs with at least two useful kernel threads per AP, repeated timer preemption on distinct retained thread stacks, affinity/migration, load balance and actual IPI acknowledgements; guard/stack canaries, exactly-once ownership and terminal conservation. Windows remains one vCPU and no full user/MM/SMP completion is claimed.

## Acceptance and review

- [ ] Parent approves this written design/plan and exact file ownership before production edits.
- [ ] Host and ASM controls record genuine RED and GREEN with complete pinned closure; old failures remain untouched.
- [ ] Parent grants separate compile/VM epoch. Fresh source-bound UP KVM/TCG original focused 17 plus practical broad 38 verify unchanged policy and actual syscall/GS/ring3 return behavior.
- [ ] Independent reviewer checks GS/NMI window, stack alignment, lock/switch lifetime, fail-closed owner admission and evidence scope before own commit.
- [ ] Separate AP handshake, actual 2/4 CPU acceptance and wider shared subsystem safety remain open until their own evidence exists.
