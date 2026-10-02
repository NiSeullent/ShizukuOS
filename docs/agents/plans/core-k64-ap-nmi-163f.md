# Retained private Kernel64 AP NMI stack

Isolated codex/k64-ap-nmi-163f-20261002, base16fb8ba687ee38bdb3698526607657c695becb83.
Own only cpu_arch_bringup.c/.h and cpu_bringup.c's architecture resource extent,
plus unique host controls/helper and own status/plan. Aggregate outputs <=64MiB.
No VM, full kernel builds, canonical/peer/index/global/NAS/media writes or commit
before independent review. Windows98 remains the product OS; full SMP stays open.

The existing AP table routes vector2 to fatal IST1, shared with F1. The successor
embeds an aligned8192-byte private NMI stack after descriptor storage, defines
SHZ_CPU_ARCH_BYTES=16384 and SHZ_CPU_ARCH_PAGES=4, and asserts the complete struct
fits the retained allocation. Actual TSS IST3 derives from that member's end;
vector2 uses IST3 with the existing emergency fatal handler. DF stays IST2;
F1 gate, handler, invalidate/generation and IST1 are unchanged. No allocation
occurs after INIT; the entire16KiB resource remains retained after faults.

The pure actual table builder permits real host struct addresses for controls,
and rejects misaligned/overflowed resource extents or overlap with boot/IRQ/DF
spans before mutation. Actual native pre-INIT resource admission validates the
entire16KiB PMM-owned extent and uses that extent in all pairwise overlap checks.
Allocation and pre-INIT rollback consume/free four pages, not the former two.

Test first: capture the existing production C table/allocator and prove real
vector2 IST1, absent private stack and two-page requests fail the new contract.
Then cover derived stack alignment/bounds, unchanged F1/DF, invalid-resource
rejection without writes, allocation rollback/full extent and retained private
gates across cohort install/restore. Run GCC/Clang sanitized actual-C controls,
unmodified AP cohort17/10/7 and original architecture controls, then actual
changed-unit compiler-M profiles for native and nonstandalone. Helpers and local
source bytes are captured before consumers, tools/subtools/header/artifacts are
pinned before/after, and approved adcf owned-group cleanup records full reaping.
Host results prove table/resource/ABI behavior only; actual hardware NMI entry,
isolation under QMP injection and AP preemption require a separate native epoch.
