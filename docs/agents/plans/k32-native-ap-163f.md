# Real Kernel32 AP dispatch: bounded implementation plan

This approved design baseline is retained for review. The implementation and
actual source/host evidence are recorded in the status document; native hardware
acceptance remains open. Preserve Windows 98 as the operating system and keep its
Supervisor domain on one vCPU. The first deliverable is an explicit bare-metal
Kernel32 kernel-thread cohort running on real 32-bit APs. General user/process
MM, IPC/device callbacks and Supervisor virtual APs remain subsequent work.

Inspection began at canonical `507cd74db5510c8ea9f60984a68d8d6101a8420b`.
ROOT serialized its NT8/K64 dispatcher adoption during the read-only inspection;
the final 59 source/document pins match clean
`98416391ccc53c3f7438c51fa23b901ce8b132be`. All selected Kernel32 bytes are
unchanged from 507. The changed K64 dispatcher/bringup diff and its new owner
documents were reread. No repository helper, compiler, test or VM ran here.
`inspection.json` records the hashes and this epoch change.

## What is already usable, and what is actually absent

| Actual source | Reuse / concrete missing boundary |
| --- | --- |
| `kernel32/sched_cpu.h` | Existing bounded 48-TCB/32-record FIFO ticket admission, distinct ready/wait links, affinity validation, current/outgoing ownership and reapability. Do not introduce another scheduler. |
| `kernel32/sched.c:142-179`, `start.asm:switch_stacks` | Existing ticket release before ESP transfer and completion callback on the destination stack, before POPFD. Preserve this ordering. |
| `kernel32/sched.c:69-75` | Actual public AP registration is `-2`; metadata, CPU count or a parked processor cannot make it online. Keep this general API closed and add a private native-cohort admission. |
| `kernel32/arch.c:22-44` | One global GDT/IDT/TSS, GS anchor accepted only for id 0, and TSS update asserted CPU0. Needs private 32-bit architecture resources and an owning update. |
| `kernel32/sched.c:181-208` | AP tick currently does nothing. Retain BSP wall-clock/timeout ownership; add a separate admitted AP service/preemption path. |
| `kernel32/mem.c` | Existing PMM and heap IRQ-save tickets are integrated. Do not repeat that work. Two-level non-PAE kernel page tables and general VM mutations are not SMP-safe. |
| `kernel32/user.c:proc_create` | Local IRQ publication and process-slot/address-space lifetime are UP contracts. New native cohort admission must not authorize these paths on APs. |
| `kernel32/lib.c` | Console line buffer is global and guarded only by local IRQ masking. AP cohort code must report through private records, with BSP printing. |
| `kernel64/smp_acpi.[ch]` | Portable copied-byte checksum/RSDP/RSDT/XSDT/MADT parser, bounded physical reader, duplicate/BSP/limit checks and x2APIC/id255 rejection. Compile the unchanged parser for ELF32. |
| `kernel64/standalone/native_firmware.h`, `qemu_firmware.h`, `memholes.h` | Checked captured-map, exact usable/readable span and QEMU original-RAM attestation. Read permission never grants allocator ownership. |
| `kernel64/standalone/boot32.c:174-193` | Shared actual stub captures firmware, but STUB_K32 does not publish the record at 0x6800. Its memory planner already rejects holes for K32 and protects low boot RAM. |
| `kernel64/standalone/boot_pm.asm` | Real ELF32 Multiboot-to-K32 entry, paging off and flat protected-mode segments. Suitable as the unchanged native K32 loader entry. |
| `kernel64/smp_ap_trampoline.asm`, `smp_boot_guard.h` | Not reusable as a K32 entry: they install PAE/EFER long mode and validate retired four-level K64 boot roots. K32 needs a distinct 16-to-32-bit trampoline and a writer-specific low-page contract. |
| `supervisor/src/domain.h:domain_t`, `domain.c:handle_cpuid`, `kdom.c` | Exactly one `vcpu_t` per domain; CPUID reports one logical CPU and no LAPIC. No guest INIT/SIPI/IPI service. Physical Supervisor AP startup is not virtual K32 AP execution. |
| `supervisor/src/vmx_cpu_state.h:109`, `ap_start.c:117` | Win98 binding remains CPU0 and native-Win98 AP opt-in is refused. Do not alter these policies. |

The newly imported K64 cohort provides useful reviewed patterns for suspended
workers, destination-stack online/withdrawal and pending-timer drain. It does
not supply a 32-bit trampoline, TSS/GS implementation, or Supervisor vAP ABI.

## Exact isolated owner scope

Start a ROOT-created worktree at the final canonical adoption commit. One owner
should implement architecture, scheduler handoff and the native backend together
because their stack publication is sequential. Do not split overlapping writers.

Modify only these existing paths:

- `shizukudos/kernel32/arch.c`: perCPU private GDT/IDT/TSS/GS anchor, AP vector
  classification, local TSS stack update and private fatal/drain records.
- `shizukudos/kernel32/sched.c`: private staged cohort, real-stack admission and
  withdrawal, AP service tick/reschedule and existing outgoing completion.
- `shizukudos/kernel32/k32.h`: exact 32-bit private entry/stack declarations.
- `shizukudos/kernel32/main.c`: native policy consumption before the existing
  service validator; staged startup after BSP scheduler initialization.
- `shizukudos/kernel32/mem.c`: only read-only PMM/heap allocation observers and,
  if needed, a bounded BSP pre-INIT MMIO/firmware mapping seam. Preserve existing
  allocation/free/accounting algorithms and locks.
- `shizukudos/kernel32/user.c`: refuse process create/admission while the private
  cohort is active, rather than extending local-IRQ publication to APs.

Add unique paths (proposed names; freeze them before implementation):

- `shizukudos/kernel32/smp_native.h`
- `shizukudos/kernel32/smp_native.c`
- `shizukudos/kernel32/smp_firmware.c`
- `shizukudos/kernel32/smp_ap_trampoline.asm`
- `shizukudos/kernel32/standalone/native_boot32.c`
- `shizukudos/kernel32/standalone/native_handoff.h`
- `shizukudos/tests/test_k32_native_ap.c`
- `shizukudos/tests/test_k32_native_ap.py`
- `shizukudos/tests/run_k32_native_ap.py`
- unique `docs/agents/plans/k32-native-ap-163f.md` and status counterpart.

`kernel32/start.asm` already has the correct ordinary switch callback and does
not require mutation. Put the new bootstrap-to-idle/idle-to-bootstrap assembly
helpers beside the new 32-bit trampoline. No changes to K64 lead's 15 paths,
common parser/firmware headers, `kbuild.py`, shared `boot32.c`/`boot_pm.asm`,
Supervisor/loader/ABI, NT paths or Fada boot paths. ROOT alone later serializes
shared build integration. The memory observer addition needs its own source
review; it is not a duplicate allocator concurrency milestone.

## 1. Native provider and pre-INIT ownership

Use a K32-only loader wrapper around the captured, unchanged actual
`boot32.c` with STUB_K32 and an aliased `stub_prepare` symbol. Call that real
provider, then copy its captured static `native_firmware` to 0x6800 after all
Multiboot reads and copies are finished. The unchanged `boot_pm.asm` calls the
wrapper's exported `stub_prepare`. No whole-build import or new loader parser.

Publish a small versioned/checksummed K32 native handoff at 0x6000, a currently
unused K32 low-page location, with explicit writer/profile and trampoline span.
Require the actual loader to enter with paging off, own usable [0x1000,0x8000),
finish every source read before reuse, and retain bootinfo at 0x7000. K32 uses
0x1000 as an owned native trampoline page, not a supposedly retired K64 PML4.
The existing 4MiB loader stack/image is retired after the jump; no pointer to its
static firmware/Multiboot storage can be retained in the kernel. Snapshot the
low records into kernel-owned bytes before allocator startup. Reject absent,
malformed, foreign writer, UEFI-direct or Supervisor records.

Use exact private opt-in `shz.k32-ap=2` or `shz.k32-ap=4`. Default empty command
line and explicit `smp=off` do not probe firmware, allocate AP resources or send
INIT/IPIs. Parse the original ABI tail before normalization. Reject duplicate,
unknown, truncated and service/foundation-conflicting requests. `smp=off` may
override a valid explicit cohort request, but may not hide malformed input.
Consume a recognized native policy before the current strict K32 service parser
rejects its nonempty line. Supervisor builds refuse native cohort requests and
keep the current Win98/service policy. Do not change ABI flags or topology.

For this first native cohort require: no channels, no initrd, actual complete
firmware capture, contiguous managed RAM, kernel/BSS below the 2MiB heap start,
and requested CPU count exactly available from the complete validated topology.
Limit admitted scheduler CPUs to 2/4, within 48 TCBs. Parse the full topology;
do not silently discard an invalid extra CPU record. BSP occupies logical0 by
its actual physical APIC id, independent of MADT enumeration.

The 32-bit firmware reader reuses the portable coverage validators and original
QEMU-map exception, not K64 direct-map code. All physical addresses/spans must
fit the 32-bit map. RAM/ACPI storage may be mapped read-only during discovery
before INIT; narrow BIOS BDA/EBDA/RSDP windows close after retaining the exact
RSDP span. Reject unavailable/high/unowned ranges before dereferencing. Firmware
readability cannot authorize PMM/heap use. No generic type2/MMIO read fallback.

Add BSP-only read-only observers under the existing respective ticket:
allocated PMM page membership and an exact live heap block covering its claimed
stack bytes. Never use the observer as a pin/reclamation API. Validate every
non-PAE PD/PT page, all private architecture/boot/idle/worker spans, pairwise
nonoverlap and complete usable-RAM coverage before INIT. The no-initrd and
contiguous-RAM contract matters because current K32 PMM has a single allocation
bitmap, unlike K64's reserved-versus-allocated distinction.

Preallocate every AP boot stack, private architecture resource, suspended idle
and two worker TCBs/stacks on BSP. Ordinary `thread_create` publishes READY, so
add a private staged constructor using the same actual frame/allocator logic;
do not allocate an ordinary live thread and edit its state without admission.
Use existing TS_ALLOCATING or an explicit private staged state, never a queue
entry. No AP allocator callback or constructor. The kernel root is complete
and static throughout this cohort; no remap, page retirement or process-root
reclamation is admitted. Do not port the K64 four-level guard to this root.

## 2. Real protected-mode AP entry and private architecture

Implement a relocation-free blob below 1MiB with explicit 32-bit parameters:
non-PAE CR3, logical id, physical APIC id, single-use claim, private ESP and entry.
SIPI begins in 16-bit mode. It must use no shared stack before loading its private
32-bit stack: CLI/CLD, low GDT, PE far jump, actual CPUID physical-id match and
atomic claim, non-PAE paging/shared kernel CR3, then a 32-bit C call. Do not set
PAE, EFER.LME/NXE or enter 64-bit code. Do not call `kmain`, `arch_init`,
`sched_init` or `mem_init` on an AP; those reset BSP/shared state.

Opt-in startup first checks CPUID availability and real APIC/MSR support,
enabled xAPIC, no x2APIC, bounded APIC base matching MADT and actual LAPIC id.
Keep the default i486 path free of new unconditional CPUID/MSR instructions.
Map only the LAPIC page with proven strong UC attributes before touching it.
Current `vm_map` masks flags to 7, so it cannot establish PCD/PWT cache control.
Check the selected actual PAT entry and effective memory type; do not infer UC
from those bits while ignoring a nondefault PAT. Capture/compare supported
PAT/MTRR/cache controls on BSP and AP before work, with no firmware MSR writes;
use the reviewed WBINVD/cache-enable sequence only after equality.

Intel's startup example identifies AP code by a low SIPI vector and describes
protected-mode APIC mapping with strong UC. Its timer and interrupt chapters
specify count-down/periodic operation and fixed-interrupt EOI; spurious delivery
does not enter ISR and returns without EOI. These are the architectural facts
used here; the ownership/queue policy is this plan's design.
[Intel SDM volume 3A, sections 10.4.4, 12.5.4, 12.8-12.9 and 13.12](https://cdrdv2-public.intel.com/835754/253668-sdm-vol-3a.pdf).

Reuse the reviewed bounded directed INIT/SIPI sequencing and PIT2 actual delays
as an algorithm, rewritten with 32-bit parameters/IO. Never broadcast or use
APIC id255. Publish one target's parameters before sending INIT, then acquire
its real entry/consumption acknowledgement before reuse for a different target.
Late/duplicate/wrong-id entries park before using another target's stack.
Once any INIT has been sent, timeout/return/failure retains every AP-visible
page/stack/root/low blob, rejects retries and fails the explicit component.
Pre-INIT failure may roll back all newly allocated resources and counts.

Each AP installs its own GDT, 32-bit TSS, IDT and immutable GS anchor. Reuse the
shared immutable ISR code/table; its 0x30 load then selects the owning private
GDT's anchor. Validate magic, sealed id and actual physical mapping rather than
accepting a caller id or CPUID count. `tss_set_kernel_stack` updates the owning
private TSS with local IRQs off. Check actual SGDT/SIDT/STR/CS, ESP span and CR3,
and report distinct architecture resources. AP vectors only admit native F0
reschedule, F2 timer and FF spurious; ring3/syscalls, PIC/doorbell/device and
demand-page recovery do not run on APs. Unexpected AP faults record a private
fatal value and park; no global console, allocation or queue-held callback.
Dedicated hardware NMI/DF recovery remains separate unless explicitly built
and tested; private tables alone are not NMI/DF stack isolation.

## 3. Actual stack publication, preemption and withdrawal

AP reaches PRIVATE_READY on its retained boot stack, not scheduler ONLINE.
A new real 32-bit assembly helper saves that boot context and transfers to the
preallocated idle stack. Only its C destination callback, with IF clear and
actual ESP inside that stack, may admit the idle/current TCB and online bit under
the existing queue ticket. No BSP metadata write substitutes for this transfer.
No lock crosses ESP/TSS/CR3/IO, wait, allocation or an external observer.

Keep public `sched_cpu_register` unsupported for APs. Private cohort-tagged
kernel TCBs alone receive AP affinity. Reject process, ordinary kernel/IPC/device
TCBs, unknown/offline CPUs, live-owner removal and repeated/unprepared entry
without mutation. The initial cohort may pin each worker to its real owner;
add one saved-READY migration in CPU4 only if it remains bounded. Never migrate
an executing/outgoing context. Preserve `sched_switch_complete` as the sole
ordinary outgoing-stack release and wake publication; join/discard requires its
existing inactive/reapable proof.

Use BSP PIT for wall jiffies and timed-wait scans. AP LAPIC F2 charges only the
owning private service/current-thread counters and preempts the admitted cohort;
it never increments global jiffies or invokes shared UP object/process/device
paths. Use bounded real PIT2 calibration, not bootinfo's nominal TSC. The small
first implementation can reuse the newly reviewed K64 BSP-calibrated algorithm
and qualify that machine's shared timer frequency; a broader perCPU calibration
must serialize PIT2 ownership and must not overlap startup delays. Either way,
acceptance requires each AP's actual repeated F2 delivery and useful preemption.

F0/F2 perform owning LAPIC EOI before a possible context transfer. The existing
PIC timer continues to EOI the 8259 only on BSP. Publish perCPU pending/request
generation under ticket, send physical F0 after unlock and validate the exact
owning handler ACK. Fixed-IPI coalescing is allowed; a logical wake must not
depend on counting one IRQ per enqueue. Use bounded pending state and a correct
idle check with CLI/queue observation and STI;HLT. Every send locally masks IRQs
around its CPU-local ICR writer and never spins with the queue ticket held.

Preserve or explicitly validate the BSP PIT/8259 delivery route when enabling
its LAPIC/SVR; do not infer that legacy IRQ0 still arrives after APIC setup.
AP LINT0/LINT1 stay masked. A real BSP wall-clock progress gate must pass after
startup, independently of AP timer counters. Retain and restore the original
BSP calibration registers/port61 state before INIT.

Workers execute arithmetic and real 32-bit atomics without voluntary yields in
the preemption phase. Two CPU-bound workers per AP must both run and observe
peer progress, different actual thread ESP spans and correct payloads. BSP owns
reporting. A timer counter alone or manually switched logical identity is not
dispatch evidence. Add separate actual yield/exit/wake-handoff controls if used;
do not enlarge this into generic AP wait/object admission.

For normal controlled stop, all workers first reach inactive terminal ownership.
AP idle masks its timer, installs/activates a non-scheduling F0/F2 EOI drain state
and transfers back to its retained bootstrap stack. Only the destination
bootstrap callback may clear idle ownership and withdraw the scheduler-online
bit. Masking the timer does not retract a pending IRR interrupt. BSP waits for
exact withdrawal acknowledgements before reclaiming worker/idle stacks. Retain
bootstrap/architecture/LAPIC root resources for parked or late APs. Restore
scheduler mask1 and then run the unchanged BSP UP suite, if the owner proves
that no retained AP path can enter shared VM/process recovery. Otherwise end the
narrow cohort guest without claiming the later UP suite. Never free a live
AP boot/idle stack on a collection mismatch or startup timeout.

## 4. Test-first implementation and concrete evidence

1. Capture the exact initial actual K32 files, helper bytes, schemas, tool/subtool
   identities and real compiler dependency maps before their consumers. Preserve
   the original foundation suites and original bounds.
2. The first baseline host capability RED must compile and run the existing
   declared provider: actual `sched_cpu_register(1)` returns -2 and leaves mask1;
   actual CPU1 timer cannot charge/dispatch. Record a failing native-start-required
   capability gate with these factual results, not a missing-function compiler
   error. The existing UP refusal remains correct after a private cohort is
   added: do not relabel it as a paired public-API GREEN. New private stack/gate
   tests establish their own contract RED before implementing admission.
3. GCC and Clang ASan/UBSan actual-C controls: bad native writer/checksum/full map,
   malformed policy, firmware reservation, forged/unallocated page or heap block,
   non-UC LAPIC attributes, wrong CPU/root/ESP/IF/identity, duplicate admission,
   offline affinity, queue/live-stack duplication, wake between selection and
   destination completion, and early join/withdrawal. Host privilege adapters
   are explicit and provide no AP execution evidence. Never seed a native online
   array or fake hardware identity to satisfy the real-AP gate.
4. Assemble the actual 32-bit trampoline/context code, inspect relocations/mode
   and execute suitable unprivileged stack-boundary controls. Build real changed
   units in both Supervisor and standalone i486 flag profiles. Verify ELF32,
   no unresolved symbols, kernel image/BSS bounds and all selected inputs/tools
   and output bytes before and after consumption. Freeze for independent source
   review before any native epoch.
5. ROOT later assigns a sole native slot. Same captured producer and same compiled
   K32 source: actual KVM2/KVM4, default-UP and forced-UP. Positives require distinct
   raw hardware APIC identities, private tables/TSS/GS/boot and thread stacks,
   non-PAE shared CR3, real repeated LAPIC timer and exact physical F0 generation
   ACKs, both CPU-bound workers useful/preempted, unchanged BSP wall ownership,
   destination-only outgoing release and exact terminal queue/heap/PMM accounting.
6. Actual no-INIT/wrong-entry/withheld-ACK/withheld-timer controls must refuse or
   fail their intended gate. Missing EOI must fail repeated delivery/preemption,
   not a copied expected counter. No-IPI must fail exact F0 ACK even if timers let
   workers progress. Preserve all raw FAILs and pre/post maps. F6 persistent
   producer/source replacement must reject before loading/executing the changed
   helper; new native producer reuses ROOT's approved r5/adcf process lifecycle
   and conservative prep/launch guards, without editing other producers.
7. ROOT independently reviews exact source/tests/docs and the actual bounded
   native receipt, then serializes source adoption and fresh combined builds.
   No host or standalone component result closes Windows/Supervisor/full-SMP.

Do not expand this task into firmware parser rewrites, another memory-lock
project, NT affinity/object support, AP user entry, generic page-table shootdown,
installer work or concurrent guest runs. Use one bounded component output leaf;
capture full source/helper/dependency proof, but do not duplicate SDKs or old
archives. A concrete source blocker or insufficient remaining budget should
produce a frozen honest handoff, not a broader unverified acceptance claim.

## Later Supervisor work, explicitly separate

To give the K32 service domain multiple virtual CPUs requires an agreed versioned
guest interface: per-domain vCPU array/VMCS owner and lifetime, guest AP entry
state, shared EPT/RAM identity, virtual LAPIC INIT/SIPI/IPI/timer/EOI or explicit
equivalent hypercalls, CPU-specific interrupts/doorbells, topology and failure
protocol, plus shared object/process/MM locking. That belongs to a separate
Supervisor/Fada ownership epoch and must retain native Win98's one-vCPU view.
Merely moving a single existing VMCS among host APs or exposing CPUID count
does not supply this protocol. This plan intentionally leaves it unimplemented.

Implementation epoch: 98416391. Exact 17-path ownership approved by ROOT.
No guest, full kernel build, index or commit is authorized in this epoch.

## Implemented amendments and handoff limits

The initial one-target reused parameter design was replaced by immutable
per-AP records at 0x1800, with a bounded prepublished count at 0x17fc. Real CPUID
selects a unique record; its single-use CAS precedes private ESP. All records
are written before FIRST INIT, so a late entry cannot borrow another target's
repurposed record. The only permitted mutable record word is its claim.

Strong GS descriptor comparison permits its hardware A bit; base/type/limit
and actual physical id remain exact. Private TSS esp0 stores use independently
proven aligned volatile 32-bit storage with owning CPU/IF checks. Current
online requires first-INIT state; current withdrawal independently reads ESP
and rejects forged destination arguments before queue mutation. Actual C RED
witnesses precede both corrections.

Pending failures retain all resources. Normal inactive scheduler stacks can
be discarded only after every actual destination bootstrap ACK; whole-set
validation precedes the first mutation/free. Errors after that completed
lifetime transition report reclaimed scheduler stacks truthfully, while
retaining root/boot/private architecture/mappings and refusing retry. The
explicit component exits before generic user/MM work.

Final evidence is source/host/component-only. Real ELF32 ESP transfer was
executed unprivileged; privilege/GS/APIC/INIT/SIPI/actual AP dispatch is still
pending ROOT's independent review and later guest epoch. Shared build and
Supervisor/Win98 virtual CPU policy were not changed. See the status document
and frozen owner manifest for exact evidence/qualification.
