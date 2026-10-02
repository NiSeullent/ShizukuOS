# Supervisor physical AP startup plan

Base: `bcb603ba1d7823c1131ab55329a185f1d0b2c858`; isolated branch
`codex/supervisor-ap-163f-20261002`. No canonical checkout edits or commits.

This component initializes real physical APs in VMX root mode and performs bounded
parallel integrity work. Windows 98 and all guest domain scheduling stay on CPU0.
There is no guest AP emulation or distributed domain scheduler in this change.

Owned source: `supervisor/src/platform.[ch]`, new `src/ap_start.[ch]`,
`src/ap_contract.c`, `src/ap_trampoline.asm`, `include/ap_boot.h`,
`loader/ap_prepare.[ch]`, and minimal `src/main.c`, `build.py`, `loader/loader.c`
hooks. Own focused host/guest tests and this plan/status. Do not edit accepted
VMX implementation, kernel MM/TLB, or NT consumers.

The version-3 shz_info layout is unchanged: reserved_in[0..1] carry physical
address/size of a separately versioned retained resource/evidence block. An
optional exact 16-byte APCFG.BIN selects 1..32 component CPUs; absent means UP.
Native Windows 98 rejects this component config before ExitBootServices.

1. Establish RED host tests for checked retained map coverage, handoff/topology
   bounds and disjointness, immutable per-CPU startup states, and independent
   expected integrity hashes. Reuse kernel64/smp_acpi.c without edits.
2. In firmware, validate MADT through a bounded UEFI-memory-map reader. Allocate
   LoaderData resource block and one separate low startup page per requested AP,
   below 1 MiB; copy locally assembled trampoline before ExitBootServices. Refuse
   invalid topology/config/unsupported x2APIC, insufficient CPUs or allocation.
3. Recheck complete LoaderData ownership and disjointness against final retained
   map before INIT. Seal VMX CPU identity map before BSP VMXON. Build private AP
   stacks, 64-byte GDT, 4096-byte IDT, 104-byte TSS and CR3 roots; immutable paging
   children are shared. PCIDE/PGE remain off on every CPU.
4. Send bounded directed INIT/SIPI sequence. Each distinct retained page checks
   AP identity and claims once. Publish failure monotonically; never retry,
   recycle or free possibly live resources. APs use private info/caps snapshots.
   Serial VMX initialization avoids concurrent use of the existing UP console;
   useful work starts together and BSP publishes results after completion. The
   bounded integrity task reads actual loader-owned DOS boot-prefix bytes; the
   guest harness computes its expected hash independently from the qualified input.
5. Run GCC host tests, Clang ASan/UBSan and accepted Supervisor VMX host tests.
   Build freestanding payload/EFI with source/helper closure. Coordinate one
   bounded KVM guest at a time with root: UP, 2 CPU, 4 CPU, missing VMX and explicit
   topology/refusal controls. Use only qualified DOS component disk.
6. Freeze uncommitted source/artifact hashes and status for independent review;
   no commit/import until review. Record remaining actual Windows desktop gates.

Primary specifications consulted: Intel SDM revision 093, Volume 3A chapter 11
(11.4.4 startup, 11.5 INIT-preserved state; local APIC ICR), Volume 3C chapters 26/27
(VMX operation and per-logical-processor VMXON), from Intel's official index
https://www.intel.com/content/www/us/en/developer/articles/technical/intel-sdm.html
and official PDFs https://cdrdv2-public.intel.com/929359/253668-093-sdm-vol-3a.pdf
and https://cdrdv2-public.intel.com/929361/326019-093-sdm-vol-3c.pdf.
ACPI 6.6 sections 5.2.5/5.2.12, MADT enabled Local APIC semantics:
https://uefi.org/specs/ACPI/6.6/05_ACPI_Software_Programming_Model.html.
UEFI 2.11 sections 7.2/7.4 (AllocatePages, memory map, ExitBootServices):
https://uefi.org/specs/UEFI/2.11/07_Services_Boot_Services.html.
Independently authored startup/validation; existing repository parser reused.

Review correction epoch r5: retain r4 source/generated/header/artifact bytes and
all raw results; reproduce high IA32_APIC_BASE alias and retained-page-tail
overlap in actual C, then correct both predicates. Capture exact driver/helper
byte arrays and identities before compilation/execution. Pin selected actual
compiler subtools before query/compile, discover each translation unit's include
closure before its object consumer (including generated headers), retain a
pre-command receipt, and verify inputs/tools afterwards against an execve audit.
Runtime layout/configuration tools use the same guard before preparation. Host
controls exercise exact retained r4 functions and controlled helper/include
mutations. Fresh r5 payload/EFI and source/helper closure cover this successor;
r4 observations remain qualified rather than retroactively upgraded. Coordinate
guest slot before affected AP2/AP4 and minimal UP/refusal controls, then freeze
for independent re-review without commit/import. Existing 384 MiB aggregate cap
and all memory/media floors remain unchanged.
