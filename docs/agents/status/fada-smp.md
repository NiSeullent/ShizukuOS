# Native AP bootstrap component: tested handoff

This lane implements ACPI enumeration, physical xAPIC startup and CPU-private
bootstrap resources. Actual Windows 98 remains the product and its VMM keeps
scheduler ownership. These native component results do not establish whole-kernel
SMP, preemptive threads, Windows SMP or product acceptance.

Isolated tree `/root/Win98-Modern-smp-fada-20261002`, branch
`codex/smp-backend-fada-20261002`, base `085f057`. Parser commit
`55b684c4dd35b7e406b5580ae573fb4c95cd6820` rejects enabled physical xAPIC ID 255,
which denotes the broadcast destination, as unsupported. Existing scheduler,
arch, memory, startup, main, PCI and shared ABI sources were not changed here.

## Implemented component contract

`smp_acpi.[ch]` reads firmware through a bounded caller-supplied physical reader.
It validates RSDP/RSDT/XSDT/SDT checksums, MADT bounds, duplicates, BSP presence,
CPU limits and LAPIC overrides. Enabled x2APIC is explicitly unsupported.

`smp_boot.[ch]`, `smp_boot_guard.h` and the relocation-free
`smp_ap_trampoline.asm` start actual APs with bounded INIT/SIPI and PIT-based
delays. The native caller captures initial CR3 before `mem_init`, disables IRQs
and supplies its AP entry and validated firmware reader. APIs are:

```c
shz_smp_boot_start(rsdp_pa, entry, initial_cr3);
shz_smp_boot_start_with_reader(rsdp_pa, entry, read, context, initial_cr3);
```

Only the retired native Multiboot PML4 page at `0x1000` is reused. Its checked
old table shape, a different active final CR3 and absence of surviving non-leaf
low-table dependencies are required before hardware writes. GDT `0x5000` and
bootinfo `0x7000` remain intact. A private bootstrap root copies the kernel half
and identity-maps exactly the one 4 KiB trampoline page.

The guard proves page-table location in the PMM address range and absence of
retired low-table dependencies. **The consumer separately proves actual
allocator ownership and excludes retained firmware holes.** Readability through
an ACPI reader does not prove allocator ownership. Independent review reproduced
a readable reserved-page chain admitted by the guard and rejection when the
consumer reader excludes that page; this is a documented admission precondition.

Boot, IRQ and DF stacks are allocated before the first INIT. Partial or late AP
failure retains all AP-visible resources and refuses retries. An AP consumer
installs CPU-private architecture state before marking ONLINE and stays in its
CPU loop. Unexpected return marks the CPU FAILED and prevents subsequent IPI
admission. Supervisor builds explicitly refuse physical startup/IPIs; their
virtual AP service remains an integration seam.

## Actual and host evidence

`build/shizukudos/smp-native-final-reviewed-kvm/result.json` records terminal
exit 0 and six actual, source-built KVM cases, with explicit no-NIC QEMU launch:

| Case | Expected actual outcome |
| --- | --- |
| 1 CPU | BSP work and self IPIs; no AP target |
| 2 CPU | Distinct BSP/AP IDs, stacks, work and physical IPIs |
| 4 CPU | Physical APIC IDs 0/1/2/3 and independent AP work/IPIs |
| ACPI disabled | Startup fails with missing firmware; guest exit 2 |
| IPIs suppressed | AP work executes but delivery gates fail; guest exit 4 |
| AP entry returns | FAILED, online count 1, IPI refused, retry refused; guest exit 6 |

Positive cases independently verify raw CPUID APIC IDs, final CR3 `0x00f00000`,
distinct AP boot stacks and CPU-private IRQ stacks, rotating hashes and two-sided
computational progress. The private test consumer initializes separate
GDT/IDT/TSS and handles reschedule/TLB vectors. This verifies vector delivery,
not a completed scheduler wakeup or TLB shootdown protocol. DF stacks are
allocated and installed in TSS; DF delivery/recovery was not exercised.

IPI requests in the fixture wait for acknowledgement before the next AP sends
the same vector to the BSP. Concurrent fixed IPIs can legitimately coalesce in
APIC IRR; a production wakeup/shootdown consumer needs pending state or a queue,
not an assumed one-interrupt-per-request count.

Final receipt SHA256:
`ca6d8c359241c59dbce9e5a402cd061063df68b2e8a24642a52fa87ece056473`.
Kernel binary SHA256:
`61f4841be5b9c221ed5663a334acbdc99bc02585d56204b62a891d60efebe96a`.
Native boot ELF SHA256:
`1bf309575860c09d6b24999bf17e19a01ee46f2a0032a6e316b0fc4c1a2dead4`.
All 221 captured public repository inputs match before/after build and guest
execution. Tool executable identities and each VM's binary inputs are unchanged.
This closure does not claim every external compiler header or firmware binary
is pinned. No Microsoft media is included in the captured inputs.

Additional scoped receipts:

- `smp-acpi-broadcast-green/result.json`: 452 checks each with GCC and Clang
  ASan/UBSan, plus 32/64-bit freestanding compilation.
- `smp-boot-guard-final-reviewed/result.json`: 1,565 checks each with GCC and
  Clang ASan/UBSan, plus 32/64-bit freestanding compilation without runtime
  dependencies; source/tool closure unchanged.
- `smp-runner-final-modeled-frozen/result.json`: 27 modeled verifier controls,
  source closure unchanged; these controls execute no VM or AP.
- `smp-supervisor-final-compile/result.json`: strict freestanding Supervisor
  compilation only, unchanged source; no virtual AP service executed.

Original failures remain preserved: missing AP startup; firmware tables outside
allocator RAM; early two-sided progress sampling failure; a 32-bit guard compile
warning fixed by explicit recursion bounds; callback return leaving an AP ONLINE;
and concurrent fixed-IPI coalescing. `smp-native-returned-ap-red-kvm` includes the
actual returned-AP failure and its exact public source snapshot. The earlier
`smp-runner-final-modeled` receipt is invalid because source changed during its
run; only the later frozen receipt is accepted. No live job was restarted merely
because an observation wait expired.

## Remaining production integration and ownership

The reciprocal split is recorded in
`/srv/shizukudos-session-coordination/MESSAGE-163f-FADA-SMP-SEAM-ACK.md`.
163f consumes this shared parser/backend rather than duplicating the hardware
implementation. Their lane owns production main opt-in, PCI/LAPIC coordination,
CPU-private production architecture consumer and retained loader resources.
Core retains scheduler/arch/start/memory ownership and the canonical UP evidence.

The fixture's ACPI reader uses the actual validated E820 handoff and narrowly
admits QEMU's 256 MiB reserved RAM tail containing firmware tables. It does not
authorize arbitrary reserved/MMIO reads. Production BIOS/UEFI validated retained
span and page retirement contracts, allocator locks, per-CPU scheduler/idle,
timers, syscall stack entry, migration/affinity, queued wakeups, actual TLB
shootdowns and Supervisor virtual AP/IPI interfaces remain to be integrated and
tested by their owners. Windows 98 full boot/service execution and final ISO
publication are outside this component's acceptance evidence.
