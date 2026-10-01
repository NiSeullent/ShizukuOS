# SMP integration evidence and implementation requirements

Owner: `/root/smp_integration_lead`, delegated by the 163f orchestrator.
Worktree: `/root/Win98-Modern-smp-20261002`; branch: `codex/smp-integration-20261002`.
Audited source: `085f057bd2b9356619f26fd95ab070f622809575`.
Scope: actual multicore Shizuku backend execution while real Windows 98 remains
a single-vCPU VMM/USER/GDI/Explorer domain. Full Windows boot and the final ISO
remain parent integration requirements; neither is proved by the native test.

## Current authoritative implementation

| Requirement | Actual code and evidence | Remaining work |
| --- | --- | --- |
| BSP initialization | Kernel64 `arch_init()` installs one GDT/TSS/IDT and SYSCALL MSRs | Turn CPU-owned tables and stacks into distinct CPU contexts |
| AP startup | `shizukudos/smp/` is a separate BIOS hash-job experiment; APs park after work | Connect validated AP startup to the production kernels/Supervisor |
| CPU-local state | Global `current`, `idle_thread`, TSS, double-fault stack and syscall scratch | Current thread, idle, RSP0, interrupt nesting and syscall scratch per CPU |
| CPU-local queues | One global array of 32 priority FIFO heads/tails in Kernel64 | Per-CPU queues with atomic ownership and ordered migration |
| Affinity | `thread_set_sched_policy()` rejects every mask other than one | Validate active masks; enforce placement, wake and migration |
| Remote wakes / IPIs | No production scheduler IPI path; vector0x21 is PIC keyboard/doorbell | Reserved IPI vector, coalesced request state and atomic idle wake handshake |
| Load balancing | No production migration or CPU ownership | Steal only runnable eligible work under ascending CPU-lock order |
| Memory safety | PMM bitmap and heap lists use local IRQ masking | Cross-CPU allocator locks, address-space locks and acknowledged TLB shootdown |
| Wait/timeout safety | Semaphore/mutex/object queues and object refs use local IRQ masking | Cross-CPU ownership; one terminal wake across timeout/signal/kill |
| NT worker execution | Global software IRQL, ISR KPCR, DPC queues; CPU number0/count1 | CPU-owned IRQL/KPCR/DPC execution; atomic shared provider state |
| Kernel32 multicore | One global current/TSS and48-slot round-robin table | Separate i486-compatible port using the same topology/ownership contract |
| Supervisor multicore | One VMXON region, host stack/TSS and one vCPU per domain | Per-CPU VMX host contexts and multiple modern-kernel vCPUs |
| Windows compatibility | Supervisor CPUID reports one logical CPU and no LAPIC | Preserve this profile for Windows98 even when backend domains use SMP |
| UP fallback | Existing native UP and Supervisor single-CPU paths | Preserve `smp=off`, absent/invalid topology and bounded AP-failure fallback |

The compiler source closure also includes the real synchronization and PMA
service code. Its existing threaded host tests establish atomic helpers and
service behavior, not multicore execution of the kernels.

## Concrete hazards before enabling AP scheduling

1. `kernel64/start.asm` writes global `g_user_rsp_scratch` and reads global
   `g_kstack_top` on every SYSCALL. Two simultaneous entries can run on the same
   kernel stack. `arch.c` likewise writes one shared TSS.RSP0.
2. `sched.c` can mark a thread RUNNING only relative to one global `current`.
   Wake/policy/reaping use local IRQ masking, which excludes no other CPU.
   Kernel-stack reclamation must exclude every CPU's current/context-switch
   ownership, not only the old `current` pointer.
3. `mem.c` allocators can hand out the same page/heap block on two CPUs.
   `vm_unmap()`/`vm_protect()` invalidate only the local TLB; releasing a page
   while a remote CPU retains its mapping permits use-after-free.
4. `ntdrv_ke.c` has one ISR KPCR and global DPC queue/software IRQL. Existing
   atomic spin storage does not make these surrounding providers SMP-safe.
   Its current spin acquire panics on contention under the UP model.
5. Supervisor `domain_t` owns one VMCS/vCPU, one saved FXSAVE area, timer and
   pending interrupt state. Sharing it between physical CPUs is invalid.
   `kdom.c` passes STAR/LSTAR/CSTAR/SFMASK and KERNEL_GS_BASE through with an
   explicit one-Long-Mode-domain-per-CPU assumption. Host/guest MSR banking must
   be established before scheduling modern vCPUs on arbitrary host CPUs.
6. The prototype's SIPI trampoline at physical0x7000 collides with production
   `SHZ_BOOTINFO_GPA == 0x7000`. Production startup must reserve a separate
   conventional-memory page and validate it against bootinfo, EBDA, firmware
   memory map, initrd and loader-owned ranges. The final Kernel64 page tables
   do not retain an identity mapping for that trampoline.
7. Existing PCI MSI-X code already enables the BSP's LAPIC at `pci.c:192`;
   the new APIC owner must reconcile this path rather than create a second
   independent LAPIC initializer. PIC IRQ0/device routing remains a valid UP
   fallback; a scheduling IPI must not steal PIC0x20/keyboard0x21 or MSI vectors.
8. `ipc_core.c` builds user APC frames in one static CONTEXT buffer with the
   explicit UP assumption that IRQ masking makes one buffer enough. Concurrent
   APC delivery needs CPU-owned or stack-owned scratch. Existing GS is a user
   TEB or a per-thread driver KPCR, with no `swapgs` discipline; CPU-owned kernel
   GS state must be reconciled across syscall, interrupt, driver and user return
   paths. `KeIpiGenericCall()` currently runs only its local callback and must
   gain a real remote barrier before it can serve multicore wrappers.

## First native failing acceptance test

`shizukudos/tests/run_k64_smp_integration.py` boots the **actual existing**
Kernel64 image under hardware KVM with `-smp4` and no Win64 archive. Inputs
are unchanged copies of the parent's source-bound build, with independent
copy provenance in `build/smp-baseline-085f057/copy-provenance.json`.
Before launch the test requires the exact complete current211-file build
closure plus matching native kernel/stub hashes. After execution it verifies
the same source closure, artifact/receipt bytes, evaluator/helpers and QEMU.

The test requires four online CPUs in the real scheduler snapshot. It also
requires native per-CPU useful work, multiple context switches, distinct APIC
identities, bidirectional overlapping work observations, affinity correctness,
exclusive RUNNING ownership, queue/token conservation, actual migrations,
remote IPI wakes and reclaimed kernel-stack pages. Missing native records fail;
the Python evaluator never manufactures them. The first snapshot check is a
valid initial RED gate, but a CPU count alone can never satisfy SMP acceptance.

Observed RED: `build/smp-red-native4-085f057/result.json`, SHA256
`3d2e9f2056be14b6db299edbb9bee8ba6c3400842f6051b0d1c81c518cf9c0c7`.
The actual KVM guest completed in1.21seconds, QEMUexit1/`SHZ-EXIT:0`, with
zero existing PMA failures and all211source inputs unchanged. Its real
scheduler summary reported `cpus=1` despite QEMU's four configured CPUs.
All native AP-work/IPI/migration records were absent, so the SMP gate failed
on those requirements as intended. Ordinary UP success is retained as control.
No production C/header/assembly file was changed while this baseline executed.
The separate existing scheduler starvation failure is being diagnosed by the
Core lead; this lane does not reinterpret or hide that failure.

## Hardware references and design inference

Firmware CPU identity and enablement must come from bounded validated MADT
entries, with RSDP/RSDT/XSDT checksums and address validation. The ACPI table
defines separate local APIC/x2APIC records and enablement flags.
[ACPI6.6 software programming model](https://uefi.org/specs/ACPI/6.6/05_ACPI_Software_Programming_Model.html).

INIT/SIPI startup, local interrupt handling and VMX state ownership are defined
by Intel's system programming manuals. A VMCS requires explicit ownership
when moved between logical processors.
[Intel software developer manuals](https://www.intel.com/content/www/us/en/developer/articles/technical/intel-sdm.html).

The dependency order below is a design inference from these hardware rules
and the audited singleton kernel state; it is not an assertion of working SMP.
