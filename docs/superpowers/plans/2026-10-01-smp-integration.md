# Actual Shizuku backend SMP implementation plan

> **For agentic workers:** Use `superpowers:subagent-driven-development`; implement and independently review each task before importing it into the canonical integration branch.

**Goal:** Run Kernel32, Kernel64 and wrapper workers concurrently on multiple logical CPUs, with affinity, balancing and remote wakeups; retain actual Windows98 on one compatibility vCPU and produce the parent's final integrated ISO.

**Architecture:** Production kernels gain CPU-owned architectural and scheduler state. Standalone kernels start physical APs through a validated ACPI/APIC path; Supervisor modern domains receive a versioned paravirtual CPU-start/notification contract and multiple vCPUs. Windows98 keeps its current one-vCPU/no-LAPIC compatibility contract. Existing native schedulers are migrated rather than duplicated.

**Tech stack:** Freestanding i486/x86-64 C, NASM, existing PMA atomics and ABI, Intel VMX, ACPI/APIC, QEMU KVM/TCG and actual-C sanitizer controls.

**Spec:** User attachment SMPsection4, PMAsection3, observabilitysection35, feature flagssection36; `docs/agents/status/smp-integration.md` records the exact audited starting point.

## Global constraints

- Real Windows98 VMM/VxD/USER/GDI/Explorer remains the product OS; Windows98 itself retains a conservative single-vCPU profile.
- `smp=off` and platforms without usable SMP must boot through the existing UP path.
- Preserve BIOS/CSM/DOS, native Windows, old AP experiments and failed evidence.
- Never activate an AP scheduler against global syscall stacks, local-only memory/wait protection or an unowned VMCS.
- Common ABI changes are versioned appended contracts; old writers/consumers retain safe UP behavior.
- Root owns source import/build freeze/final ISO; Core owns current scheduler diagnostics. No concurrent shared-index commits.

## Review focus

1. Late or duplicate AP entry after a bounded startup failure cannot execute through freed bootstrap stacks or publish a false online count.
2. Timeout, remote signal and kill cannot enqueue one TCB twice or free a stack used by any CPU.
3. A CPU idle transition racing a remote enqueue cannot lose its wakeup; progress must result from delivered IPIs rather than timer luck.
4. Address-space unmap/protection changes must receive remote acknowledgements before a physical page is reused.
5. Guest/host SYSCALL, FS/GS and VMCS state must survive parallel domain execution while Windows98's one-vCPU configuration remains intact.

## Task1: Production topology and bounded AP bringup

**Files and owners (updated after peer review):** Fada owns the single `smp_acpi.[ch]`, `smp_boot.[ch]`, `smp_boot_guard.h` and `smp_ap_trampoline.asm` implementation. This integration lane owns normal `main.c`/`pci.c` hooks, `standalone/boot32.c`, retained `native_firmware.h` and `qemu_firmware.h`, and new `cpu_firmware.[ch]`/`cpu_bringup.[ch]`/private architecture consumer. Import only exact reviewed frozen peer sources; do not duplicate the parser, hardware startup or final-table walker. Core scheduler/arch/header/start remain frozen under their owner.

**Implemented native interfaces:** `shz_smp_acpi_probe()` validates bounded32-slot topology; `shz_smp_this_cpu()` maps the actual physical xAPIC ID to the dense BSP-index0 map and rejects an unknown CPU with32. `shz_smp_boot_start_with_reader()` performs bounded physical startup, and its installed `shz_smp_boot_set_resource_check()` callback verifies owned resources before INIT. `shz_smp_online_count()` counts acknowledged architecture entries; scheduler-ready CPU masks remain independently1. APs initially run an explicit private architecture/work/IPI consumer. The later per-CPU scheduler owns its online/affinity mask and activation contract; this native dependency does not fabricate a64-CPU-capable mask or support x2APIC.

- [x] Run the existing native four-CPU acceptance test and preserve expected `observed1/requested4` RED evidence.
- [x] Preserve own32-check parser RED/GREEN, then retire it in favor of Fada's reviewed parser. Peer452-check successor rejects physical xAPIC255; enabled x2APIC remains explicitly unsupported until the later backend extension.
- [x] Implement complete retained Multiboot map validation before copies and before the former unsafe variable-length memory_layout loop. Preserve all64 rows including denials; count overflow rejects the entire map, absence clears stale metadata, UEFI-direct cannot consume the native record.
- [x] Implement bounded QEMU fw_cfg original E820 acquisition and read-only reserved-RAM ACPI admission from actual original RAM plus retained BIOS cover. The managed254MiB limit does not reject legitimate tables below the original256MiB machine limit; MMIO/ROM/nonRAM conflicts remain denied.
- [x] Verify normal production `main.c`/Multiboot stub firmware consumption with real2CPU/4CPU/SMP-off boots. Preserve the first old-Core whole-gate failure; import the independently reviewed644c94f Core fix as a separate own commit and retain the next observed PASS distinctly.
- [x] Correct the producer's helper load-before-capture defect through private actual-helper behavioral RED/GREEN. Capture the complete closure before helper execution, execute exactly the captured bytes, reject changed compiled sources/artifacts during reuse, and record a separate actual2CPU/4CPU/off receipt with full219-file archived inputs. This proves firmware/runner scope only, not AP execution.
- [x] Adopt the single bounded physical reader/parser and dense BSP-index0 map. Actual unknown physical identities and unsupported x2APIC/topologies are rejected. Future scheduler-ready mask support remains under its CPU owner.
- [x] Use proven retired native0x1000 distinct from bootinfo0x7000. Enter APs through real/protected/long-mode bootstrap with unique stacks and temporary4096-byte identity mapping; switch to the final shared CR3 before consumer entry.
- [x] Adopt actual initialCR3 capture and exact old1000/2000/4000 shape guard, complete type1 RAM plus real PMM-allocation ownership for every full nonleaf/PT page, and one private bootstrap root. Archive/remove the independently tested5000 alternative and retain one common walker. UEFI's separate trampoline contract remains protected.
- [x] Install private AP GDT/IDT/TSS/boot/IRQ/DF resources and verify actual SGDT/SIDT/STR, shared finalCR3, physical-to-logical identity, disabled AP SYSCALL and boot-stack canaries. Perform real independent work with bidirectional BSP/AP progress and physical F0/F1 acknowledgements.
- [x] Exercise actual suppressed-IPI, delivered-but-withheld acknowledgement and returned-entry failure controls. Returned AP publishes FAILED, retains its actual PMM stack and rejects restart. Completion-vector delivery is not a TLB shootdown.
- [ ] Add remaining raw CR0/CR4/EFER entry records plus native duplicate/late-entry fault controls. Resource lifetime already retains all AP-visible pages after INIT; do not claim unexecuted fault controls passed.
- [x] Verify source-bound actual normal KVM2/4, bounded TCG2, native1 and `smp=off` with the same227-file compiled source closure. Preserve evaluator-helper replacement RED/GREEN and capture executed producer/helper bytes.
- [ ] Resolve the distinct absent-ACPI whole-kernel PMA failure before claiming every fallback gate passed. Its AP consumer rejects activation and leaves the UP path, but existing useful-work phase2 observes242 loops versus unchanged1000; no retry or threshold relaxation. Core owns diagnosis.
- [ ] Review and commit the bringup change with its limited scope. Do not change scheduler stats to count parked APs.

## Task2: CPU architectural state and shared-memory ownership

**Files:** production `kernel64/arch.c`, `start.asm`, `cpu.h`; `mem.c`, `objects.c`, `krandom.c`, `ipc_core.c`; corresponding lock types in existing `k64.h`. Coordinate Core before modifying these files.

**Interfaces:** `struct cpu_local` owns current/idle pointers, GDT/TSS/IST, syscall stack/scratch, IRQ nesting and local accounting. `cpu_send_ipi(unsigned target, unsigned reason)` is nonblocking; `vm_shootdown(uint64_t pml4, uint64_t start, uint64_t bytes)` acknowledges all active mappings before reclamation.

- [ ] Add native simultaneous SYSCALL/exception/SSE/FS-GS controls that fail when CPUs share RSP0 or syscall scratch.
- [ ] Add actual allocator and page-map races that fail on duplicate live pages, overlapping heap blocks or stale remote translations.
- [ ] Install CPU-owned descriptor tables, emergency stacks and syscall entry state with an explicit kernel/user GS discipline compatible with the NT driver's KPCR.
- [ ] Replace `ipc_core.c`'s UP static APC CONTEXT scratch with CPU-owned or stack-owned storage; verify simultaneous APC delivery does not exchange user frames.
- [ ] Replace local-only guards on shared allocator, object refs/waits, entropy and page-table mutation with documented atomic lock ownership. Use local IRQ masking only for local interrupt exclusion; never hold a spin lock across a blocking operation.
- [ ] Implement address-space active-CPU tracking and IPI shootdown with finite failure reporting; reclaim unmapped pages only after acknowledgements.
- [ ] Run race controls, sanitizers and native fault/stack/page conservation; preserve Core UP priority/quantum bounds and all existing native regressions.
- [ ] Independently review lock order and interrupt reentry before committing.

## Task3: Existing Kernel64 scheduler becomes multicore

**Files:** Core-owned `sched.c`, `k64.h`, native SMP test body in `pma_tests.c` or a separate production test unit/hook approved by Core.

**Interfaces:** retain `thread_create/resume/wake`, sleep/join and `thread_set_sched_policy()`. Extend valid affinity masks to the actual online mask. Append TCB CPU/queue/context-switch ownership, per-CPU ready queues and migration/IPI counters; retain existing32priorities, quantum1..16, aging and cancellation semantics.

- [ ] Add native pinned non-yielding workers on each CPU; each must execute multiple contexts and >1000useful body loops while both BSP/AP observe increasing peer work.
- [ ] Add wake/signal/timeout/kill/policy races that require one READY owner and one RUNNING CPU per TCB, exact token conservation and no early stack reaping.
- [ ] Migrate existing ready queues/current/idle/tick state to CPU contexts; protect publication and waits with atomic locks. Never hold a queue lock across `switch_stacks()`.
- [ ] Place ready work on an eligible CPU; enforce affinity after policy changes and before dispatch. Choose local runnable work by existing priority/aging rules.
- [ ] Add ordered work stealing, bounded migrations and coalesced remote wake IPIs. Pair idle publication with a final queue check before interruptible halt.
- [ ] Make one monotonic timebase authoritative for deadlines; charge local CPU execution without multiplying timeout rate by CPU count.
- [ ] Pass native2/4/8CPU acceptance including migrations and wakes, UP fallback, scheduler starvation controls and ordinary app regression. Independent review must reject a CPU-count-only implementation.
- [ ] Commit before enabling broad wrapper concurrency.

## Task4: NT wrapper workers and Kernel32 multicore port

**Files:** `ntdrv_ke.c`, `ntdrv_ex.c`, relevant provider shared state; independently owned Kernel32 `sched.c`, `arch.c`, `start.asm`, `mem.c`, `user.c`, `ipc.c` and `k32.h` after6970/Core ownership agreement.

**Interfaces:** processor queries return actual logical index/mask; KPCR and DPC dispatch belong to the CPU. Kernel32 retains its distinct32-bit ABI and receives the same topology/wake ownership contract, with i486-safe locked atomics.

- [ ] Test real concurrent provider calls, per-CPU DPC targeting, IRQL isolation, spin contention, timer/cancellation and request ownership; preserve ABI layouts.
- [ ] Implement `KeIpiGenericCall()` with actual remote callbacks and a completion barrier; test each active CPU executes exactly once and caller return waits for every callback.
- [ ] Replace provider singleton IRQL/ISR KPCR/DPC queues and local-only shared-state guards; make fair contention wait for another CPU without permitting same-CPU reentry deadlock.
- [ ] Add actual Kernel32 non-yielding per-CPU workers plus concurrent ring3 PID/fault/publication/page-reclamation tests.
- [ ] Port CPU-local architecture, memory protection and existing round-robin scheduler to Kernel32; preserve its finite deadline helper and48-slot behavior until a separately reviewed capacity change.
- [ ] Run fresh native32/64 and wrapper tests; record component scope and commit each independent port.

## Task5: Supervisor and actual Windows98 integration

**Files:** `supervisor/src/{platform,vmx,domain,kdom,hcall}.[ch]`, VMX assembly, pool/EPT/shared IPC guards and versioned ABI extension; native Win98 creation/test profile.

**Interfaces:** per-host-CPU VMXON/host GDT/TSS/stack/capability state; per-modern-domain vCPU array with exclusive CPU owner. Versioned modern CPU topology/start/IPI hypercalls boot secondary Kernel32/64 vCPUs into the exact production AP entry; Windows98 retains its one vCPU and no-LAPIC CPUID view.

- [ ] Add actual native VMX controls for CPU ownership/host register banking, secondary vCPU launch and simultaneous Kernel32/64 useful work; malformed startup rejects without modifying the Windows domain.
- [ ] Initialize VMX per physical CPU; keep one VMCS active on one host CPU, with explicit clear/reload migration and refreshed host fields.
- [ ] Save/restore host and guest SYSCALL/SYSENTER/FS/GS/KERNEL_GS state and FXSAVE context per vCPU; guard shared EPT/pool/channel lifetime state.
- [ ] Implement modern secondary-vCPU launch and remote event routing; maintain atomic domain generation/rundown and bounded worker pools.
- [ ] Boot actual Windows98 on ShizukuDOS's DOS-to-VMM path concurrently with modern workers; validate real VMM/PMA wrapper requests, reply delivery and Windows desktop responsiveness under stress.
- [ ] Verify Windows98 still reports its compatibility CPU view; test all UP/feature-disabled controls and hardware-backed simultaneous modern domains.
- [ ] Parent integrates release installer/ISO only after actual boot, SMP and lifecycle gates pass. No proprietary media/source publication.

## Requirement coverage

User section4 BSP/AP/perCPU structures maps to Tasks1–2; perCPU queues, balancing,
affinity and IPIs to Task3; multicore Kernel32/64/wrapper workers to Tasks3–4;
conservative single-vCPU Windows98 and UP fallback to Tasks1/5. Section35 CPU,
migration, contention and remote-wake observability travels with Tasks2–5.
Section36 `smp=on/off` is covered by Tasks1/5. Full VMM connection, complete
Windows boot and final ISO are Task5/parent acceptance and remain explicit.

Next review covers the exact normal production AP integration source and its
positive/expected-negative/native fallback receipts, including the preserved
absent-ACPI whole-gate failure. Core's isolated per-CPU queue/context foundation
is the next dependency; public AP scheduler activation remains rejected until
shared architecture, memory, interrupt and syscall ownership is proven. Native
AP work/IPI evidence is a dependency for Tasks2–5, not final SMP acceptance.
