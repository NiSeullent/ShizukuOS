# Kernel32 native AP source candidate — frozen first component

Exact 17-path owner candidate at base 98416391. No index, commit, canonical
source, shared build, QEMU, native guest, NAS or network changes occurred here.
Source is ready for independent review and ROOT's later guarded native epoch.
Physical Kernel32 AP dispatch, privileged IF/GS/table installation and the
2/4-CPU hardware controls remain **unaccepted**. Windows98 remains one vCPU.
General process/MM/object/device/AP and full SMP/Windows/runtime/ISO acceptance
remain false. The original PMA 361/runtime claims are not promoted.

Implemented: explicit native32 wrapper over unchanged boot_pm/boot32; checked
writer/complete usable low-span handoff; exact native 2/4 opt-in/default/forced
UP policy; unchanged copied-byte firmware parser and qualified original QEMU
map reader; pre-INIT read-only PMM/heap observers and bounded mapping seam;
strong UC PAT3/MTRR/cache equality admission, bounded PIT2 timing/calibration,
directed xAPIC INIT/SIPI/F0; distinct non-PAE 16-to-32 trampoline; private
GDT/IDT/TSS/GS and strong actual physical identity; staged idle/two pinned
workers per AP; destination-stack online/withdrawal and saved-context release;
BSP clock/AP F2 accounting, F0-only request ACK, useful non-yielding worker
checks, controlled withdrawal/drain, whole-set discard validation, conservation.

All AP parameter slots are published before FIRST INIT and never reused. The
blob selects a fixed slot by real CPUID physical id and single-use CAS before
private ESP. GS descriptor comparison masks only the hardware accessed bit.
No allocator/table/root retirement or console callback runs in the AP IRQ
handler. Dedicated NMI/DF recovery and Supervisor virtual AP protocols are
outside this component.

Pending/post-INIT failure before completed withdrawal retains every resource
and refuses retries. Only after all actual bootstrap-stack withdrawal ACKs may
normal inactive worker/idle stacks be reclaimed. A subsequent accounting/QA
failure reports scheduler_reclaimed separately; it does not claim those freed
stacks are still retained. Boot stacks/private architecture/root/mapping pages
remain retained and the explicit component ends before old UP user/MM tests.
Public AP registration remains -2. Private online requires the first-INIT epoch;
withdrawal checks its argument AND independently observed current ESP. AP
process creation, ordinary thread creation and UP object/join mutations refuse.

Actual evidence: final-green-12/result.json PASS; GCC host and Clang ASan/UBSan
76 checks each, eight offline blob-gate rejections, seven real changed top-level
translation units in BOTH i486 standalone/Supervisor profiles under BOTH
compilers, plus actual wrapper units; real native ELF32 provider link with no
unresolved symbols; relocation-free 174-byte blob with CPUID/CAS/ESP/CR3 order;
actual new stack-enter/leave assembly executed as unprivileged ELF32 under
both compilers. That ELF32 execution proves ESP transfer/return, not privileged
IF, GS, AP identity, INIT/SIPI, APIC delivery or physical dispatch.

The producer captures project C/ASM/schema/helper/tool bytes before consumers;
actual -M maps and exact header pins precede real unit compilation. Each owned
command uses the captured adcf9a lifecycle helper, 30s work plus <=2s cleanup,
with group-empty/drain/reap and source/tool/input hashes. SDK/runtime environment
is explicitly qualified, not fully sealed or copied. Host PMM's physical base
is relocated to 0x10000000; IRQ/identity/ESP are declared adapters. These models
cannot constitute physical AP acceptance.

Original baseline public-2/ignored-AP-tick/mask1 RED is preserved. Private
missing-destination admission RED, pre-INIT admission RED and forged-withdrawal
ESP RED retain actual compiler/run logs and snapshots. Failed development
tries remain under the owner leaf: first clang -MM link-flag issue; initial GCC
indentation warning; policy/low-BDA warnings; final-green-6 packed atomic warning
and caught objcopy in-place object mutation. That interrupted try has explicit
ERROR classification and no fabricated complete result receipt. Later success
never relabels earlier results.

The normal shared kbuild loader still uses unchanged boot32.c. The new
run_k32_native_ap.py lists the separate explicit native provider; it does not
launch a guest. ROOT must integrate/select this wrapper, build a fresh full
Kernel32 image and independently validate actual AP2/AP4/default/forced-UP and
negative hardware controls. Legacy UP host fixtures need a separate owner to
add new backend-symbol adapters, preserving their real UP assertions.
