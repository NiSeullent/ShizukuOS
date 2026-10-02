# Supervisor physical AP component — r5 review correction

Independent r4 review requested four P2 corrections; exact review JSON SHA256
`6dd881ef00a658b3b8f51e4a6920cbb8f5405f945064590458ee4e2944c3f502`, captured
at `build/shizukudos/supervisor-ap/r4-independent-review.json`. No P0/P1 was
reported. Known low-LAPIC KVM physical observations were accepted, while the
complete candidate was not approved. The r4 source, generated/system include
bytes and compiled artifacts are retained under `r4-retained`; every raw guest,
failure, old base, receipt and `review-r4` source/patch/manifest remains intact.

## r5 corrections and current evidence

F1: the actual-C high-address alias `IA32_APIC_BASE=0x1fee00900` versus
MADT `0xfee00000` failed RED with the original predicate. The production helper
now compares every high MSR bit and rejects any base beyond this component's
low-address limit, with enabled xAPIC required, before LAPIC MMIO. Valid low
base, disabled/x2APIC and mismatched low-base controls remain covered.

F2: a region wholly in the retained resource page's final 672 bytes passed the
old 3424-byte overlap check, producing actual-C RED. The predicate now uses the
complete allocated 4096-byte page. That negative and the aligned positive pass.
Logs: `supervisor-ap/f1-red.log`, `f2-red.log`.

F3: exact retained r4 `fresh` was exercised with a helper that writes a successor
to its own source during execution: r4 recorded successor bytes while executing
the predecessor. The corrected drivers capture/re-execute their producer body,
capture all local module byte arrays before any project module executes, and
compile/execute only those arrays; their loaded digests must equal source pins
before build/runtime preparation. No project Python bytecode cache is consumed.
`f3-red.log` retains the controlled r4 counterexample.

F4: exact retained r4 post-build dependency function was exercised after a
generated header changed between compilation and final discovery; the binary
reported the old value while the receipt pinned the new header. `f4-red.log`
retains RED. The shared `ap_provenance.py` pins the actual driver and selected
compiler subprograms before queries/execution, discovers every translation
unit's includes before its object consumer, retains pre-command receipts, and
checks the same inputs/tools afterwards. Actual successful execve paths must
belong to those pre-pinned tools. Generated headers are captured before their
first object consumer. Runtime layout/config tools use the same guard, with
declared output mutations and pinned config source sectors; selfcheck's own
temporary C/probe bytes are retained before consumption. Final r4 includes
were discovered after compilation; r4 helper hashes lacked pre-entry loaded-byte
binding, and r4 top-level tool pins did not establish compiler subprograms.
These r5 results do not upgrade any r4 attestation.

Fresh r5 build receipt SHA256
`b7e667bb4a97b20daa4d0e834ed82c48a8c63ed9e579e6f2c35cb0dff5e018e0`:
28 pre-object include groups / 89 pins, 40 pre/post command events, 4 exact
loaded driver/helper identities and 27 tool/subtool identities, all PASS.
EFI SHA256 `8c3d72bc83ad3ea0f642227b7eaaa44b1e05094146ff492102411b816e378540`
(198656 bytes); payload.bin
`931ad019afb3755dc43cab49102ce2eaa67506a710c18e70b0f635e77bcc40d1`;
34 MiB immutable ESP
`b11e9dcfe3b47569e0791e75d260987cf977b54b1640bd7ba6e88eabbbcc4dab`.
Fresh complete embedded DOS/EFI byte reads and FAT32 free-cluster checks passed.

Changed AP contract GCC and Clang ASan/UBSan, helper/include positive/mutation
controls, actual QA layout plus temporary-source guard, and original AUTO180
assertions each GCC/Clang passed. Host successor receipt SHA256
`492aa4b9eced897b4b67989e925cecea3ebde36165d732b6c89ac33f8f6c1542`
at `build/shizukudos/supervisor-ap/host-r5/result.json`; captured host driver,
fixture/provenance byte arrays, pre-compiler include/tool events and binaries
are bound there. ASan test binaries execute directly with before/after binary
pins because its leak checker refuses ptrace; compiler subprograms are audited.
Unchanged VMX foundation/ACPI raw r4 host observations remain inherited below.

The first actual r5 AP2 (PID1811465, reaped) exposed a noncompiled final QA
predicate trying to hash selfcheck's deleted temporary probe rather than its
verified retained original. Its raw serial/info/AP/command inputs and exact
failed driver are preserved in `ap-run-ap-2-2-review`; `failure.json` records
terminal successor FAIL. No PASS is reconstructed. Only the noncompiled QA
driver changed; all r5 C/ASM/generated inputs, build/helper tools and artifacts
were verified current-equal and explicitly reused for the covering runtime.

An outer admission wrapper also misclassified existing libvirt VMs and allowed
its following launch after an assertion. Admission now runs in actual QA main
before preparation and again immediately before qemu.launch. Exact historical
argv hashes, process start ticks, executable and boot identity bind exclusions
2153/2681/1930826, with baseline SHA256
`94da486c4fef2589d5ccbed25518f6958c9bceb7fd1a715c316bc60869c2a1a1`.
No process-name-wide exception exists; unknown guests or changed historical
identity fail admission. Production VMs/Android were read only and untouched.
Controlled peer, deficient host memory, deficient cgroup margin and combined
peer/host negatives invoked actual QA main and rejected before any preparation
or Popen/QEMU call (all counters zero). The first host control used the wrong
assertion substring; its no-guest failure and helper are retained separately.
`supervisor-ap/admission-control-r5-result.json` and its captured helper record
the passing controls plus actual read-only historical/resource admission.

Covering r5 runtime driver SHA256
`9d38eabed51be4355cdb473dc565ce4dc8d5bfc7167cbcd1dacb1fa1f7507645`
executes captured exact bytes and preserves strict existing source/helper/tool
pins. Deleted selfcheck probes are accepted only through their pre-consumption
retained original bytes; a live changed file still fails. Every covering r5
guest below passed complete source/helper/artifact/tool checks, exact live
historical-process admission and original host/cgroup floors, before preparation
and again immediately before launch. All children are reaped and the guest slot
has been released to root. No native C rebuild was needed for the noncompiled
receipt/admission correction; only the separately bound QA driver succeeded it.

| Covering r5 directory under `build/shizukudos/supervisor/` | Checks | PID | Result |
|---|---:|---:|---|
| ap-run-ap-2-2-guarded | 14 | 1854717 | PASS/reaped |
| ap-run-ap-4-4-guarded | 26 | 1857438 | PASS/reaped |
| ap-run-up-4-4-guarded | 6 | 1860893 | PASS/reaped |
| ap-run-novmx-2-2-guarded | 6 | 1869639 | PASS/reaped |
| ap-run-refuse-2-4-guarded | 6 | 1874490 | PASS/reaped |
| ap-run-malformed-2-2-guarded | 6 | 1880745 | PASS/reaped |

AP positives again confirm actual VMXON/DONE/private host tables and independent
QMP CR3/stack plus real DOS-prefix integrity hash `0x7f9d1517e04a0725`; BSP DOS
exit code 0. UP remains CPU0. Capability/config/topology negatives refuse before
Supervisor/INIT. This covers known-low Intel KVM/OVMF physical AP component work,
not high-base hardware, general domain scheduling, virtual AP or Windows gates.
AP fault attribution/concurrent exception diagnostics remain unverified.

Commands reuse the pinned r5 compiled artifact and change only runtime mode:
`python3 shizukudos/supervisor/test_ap_qemu.py --cpus {2,4} --requested {2,4}
--mode {ap,up,novmx,refuse,malformed} --timeout 30 --build-label r5 --label guarded`;
exact argv resides in each result. Host controls:
`python3 shizukudos/supervisor/tests/test_ap_provenance.py`,
`python3 build/shizukudos/supervisor-ap/host-r5.py`, and
`python3 build/shizukudos/supervisor-ap/admission-control-r5.py`.
The final `review-r5` manifest captures exact 20 owned source hashes, original
producer/covering noncompiled driver lineage, complete command/raw receipts,
helper/generated/include/artifact bytes and all predecessor evidence identities.
No commit/index/import was performed; independent re-review is pending.

r5 build forecast was 390763912 bytes under the unchanged 402653184-byte cap;
before review capture the complete aggregate was 395891724 bytes. The separate
review-capture intent/seal records exact new-byte forecast and final peak/free
space. All predecessors remain retained, with no resource/media floor waiver.

## r4 historical record, qualified by the review above

Isolated worktree `/root/Win98-Modern-supervisor-ap-163f-20261002`, branch
`codex/supervisor-ap-163f-20261002`, base
`bcb603ba1d7823c1131ab55329a185f1d0b2c858`. Source is uncommitted, frozen for
independent review; no canonical/other-worktree/index edits or import performed.
Actual physical AP startup, private host resources and per-CPU VMXON now pass
fresh 2/4-CPU KVM component checks. Ordinary boot and Windows 98 remain CPU0.

## Scope and contracts

Owned production files: `shizukudos/supervisor/src/platform.[ch]`,
`src/ap_start.[ch]`, `src/ap_contract.c`, `src/ap_trampoline.asm`,
`include/ap_boot.h`, `loader/ap_prepare.[ch]`, and minimal `src/main.c`,
`loader/loader.c`, `build.py` hooks. Owned tests: `tests/test_ap_contract.c`,
`build_ap_component.py`, `test_ap_qemu.py`. Root separately authorized the narrow
`native_win98/tests/test_gop_auto_host.py` fixture seam; its C fixture and all
original 180 assertions are unchanged. Plan: `../plans/supervisor-ap-163f.md`.
No changes to accepted `vmx.c/h/vmx_cpu_state.h`, kernel MM/TLB or NT consumers.

`shz_info_t` version 3 and its existing layout remain unchanged. Reserved input
words 0/1 carry address/size of a separately versioned 3424-byte retained block
inside one LoaderData page. Exact 16-byte `APCFG.BIN` selects 1..32 component CPUs
only under explicit `mode=supervisor`; absence selects UP. Native Windows 98
rejects APCFG before ExitBootServices, and the payload rejects an AP handoff with
the native Win98 flag. No desktop multicore policy is enabled.

The loader allocates retained LoaderData pages before ExitBootServices: a
resource page below 4 GiB and one distinct low trampoline page per AP below
1 MiB. ACPI is read through checked whole memory-map ranges, with descriptor
stride/type/cache-capability/overflow/overlap validation. The existing audited
`kernel64/smp_acpi.[ch]` parser is reused without edits. Only enabled xAPIC IDs
are accepted; duplicate IDs/UIDs, enabled x2APIC, missing BSP, insufficient
topology and invalid config refuse startup. Final retained-map coverage and
ACPI topology are rechecked after ExitBootServices and before INIT.

Each AP receives its own 64 KiB stack, 64-byte GDT, 4096-byte IDT, 104-byte TSS,
CR3 root and private `shz_info_t`/caps snapshot. Shared paging children remain
immutable; PGE/PCID are off on APs. The complete CPU map is sealed before BSP
VMXON. Existing V2 code owns separate per-CPU VMXON/MSR banks and validates live
descriptor tables. AP VMX initialization is sequential while BSP is quiet,
avoiding concurrent use of the existing UP console. Work is released together.

Startup sends directed INIT, waits 10 ms, sends SIPI, waits 200 us and sends the
second SIPI only if the AP has not claimed its own page. No startup retry or
resource reuse occurs. Startup/VMX/work state advances atomically; failure claims
a terminal publication state and retains the first error. Partial failure keeps
low pages, stacks, roots and VMXON resources allocated. This initial component
parks initialized APs in VMX root after work; it provides no AP guest VMCS,
guest AP emulation, VMCS migration or distributed domain scheduling.

Before enabling AP caches, complete supported BSP/AP PAT/MTRR banks must agree.
The LAPIC UC proof walks the owned active CR3/PML4/PDPT hierarchy and checks the
actual 2 MiB PDE. PCD/PWT select PAT index 3, PAT[3] must be UC, and large-page
PAT bit 12 must be zero. A meaningful regression rejected the previous weakened
predicate, then passed with the corrected mask. UEFI descriptor cache bits are
capabilities, not exclusive current settings: valid OVMF attributes 0xf are
accepted, while actual owned page-table/PAT state is checked independently.

Useful work hashes the actual LoaderData DOS disk boot-prefix (4096 bytes, 512
rounds, 2097152 bytes read per AP). The runtime driver computes the expected
FNV-1a value independently from the qualified input: `0x7f9d1517e04a0725`.
The seed-buffer predecessor was intentionally rejected by this independent
input oracle before the real-input implementation passed.

## Verification and receipts

All paths below are relative to this worktree. Final build receipt:
`build/shizukudos/supervisor/ap-build-result-r4.json`, SHA256
`33f769b84f7e7253a92fbf609fca32f299047da99e81051d00be9a0aeb7b99b2`.
Fresh build/source/tool pre/post equality passed, with 28 compiler dependency
groups and 89 dependency pins, including generated/system headers.

| Final artifact | Bytes | SHA256 |
|---|---:|---|
| BOOTX64.EFI | 198144 | 689e9da5ae9d6071fefe78ec56a372c10690b2af8ccabe2bb81ac47a2019b5aa |
| payload.bin | 151606 | e2bcff6f774d752e0b4b2746969896585ad726742e96e22a9d80290b36a3b56c |
| payload.elf | 175016 | 4ef85c6c569ec550dc54a103054ce5c74c1aa4fe068b5f5fbb711dc1dc84adcd |
| ap-trampoline.bin | 4096 | dc5f1dea6f39089c2720ded337fe05bbfd881871f37f44b1abf2b4e476adf80c |
| ap-component-base-r4.img | 35651584 | 1668d846dd8dacaecf17f1d1cea00e1130e56072ee4012b50bc64ee4abae4e10 |

The dedicated 34 MiB FAT32 base has 68528 clusters, 2614 free 512-byte clusters.
Actual `mtype` reads verified every embedded EFI and qualified DOS byte before
sealing. No optional kernel image or private Windows media was acquired.
The captured Sep29 DOS-only conformance input is 33546240 bytes, SHA256
`aa40e4f0dd81fb6d611aa4425c69782214f59cf78de75e716a9f41407446e0e2`;
`qualified-dos-origin.json` matches the original `hd32.img` artifact receipt.
This does not establish a new ordinary DOS producer or Windows acceptance.

Final captured host run: `build/shizukudos/supervisor-ap/final-host/result.json`
SHA256 `96657268b7b794844b14f0f0cd4cbc3752594ec0ac4cb3ee20134da7a31f75f0`.
Production AP contract GCC and Clang ASan/UBSan passed; unchanged accepted VMX
state fixture passed 63 assertions, actual CPU/load admission passed 34, and
table-publication/construction race passed 20000 rounds with zero aliased
admissions, duplicate or missing claims. Compiler-discovered dependencies,
exact commands, binaries, helper and tools are pinned before/after. The load
fixture substitutes only VMCLEAR/VMPTRLD and uses real pinned host CPUID.
An initial dependency-receipt parser preparation error occurred before binary
execution and is retained separately in `final-host/preparation-failure.json`.

Reused production ACPI parser fixture: `supervisor-ap/acpi-host/result.json`,
GCC 452 and Clang ASan/UBSan 452 assertions, freestanding 32/64 compile PASS.
AUTO fixture: `supervisor-ap/gop-auto-final-gcc/result.json` and
`gop-auto-final-sanitize/result.json`, original 180 assertions PASS each. It
includes the actual AP header/config contract and a fail-fast substitute for
unused AP preparation; it does not simulate AP startup.

Every final guest used the pinned `/usr/libexec/qemu-kvm`, KVM q35/OVMF, 512 MiB,
30-second deadline, immutable base plus bounded QCOW2 overlay. QMP samples each
physical CPU with explicit `cpu-index`, confirming unique live CR3, GDT64,
IDT4096, busy TSS104 and stack, independently of payload evidence.

| Final run directory under `build/shizukudos/supervisor/` | Checks | Child PID | Result |
|---|---:|---:|---|
| ap-run-ap-2-2-final | 14 | 1325880 | PASS/reaped |
| ap-run-ap-4-4-final | 26 | 1335069 | PASS/reaped |
| ap-run-up-4-4-final | 6 | 1356447 | PASS/reaped |
| ap-run-novmx-2-2-final | 6 | 1360552 | PASS/reaped |
| ap-run-refuse-2-4-final | 6 | 1364401 | PASS/reaped |
| ap-run-malformed-2-2-final | 6 | 1369926 | PASS/reaped |

AP positives reached real VMXON/work DONE with zero error and independent
input hash; BSP reached DOS GUEST_EXIT stage 6/code 0. UP reached the same DOS
exit with absent AP handoff. Missing VMX, insufficient topology and malformed
config refused before Supervisor entry/INIT. All six source/artifact/tool
post-checks passed. All owned QEMU children are reaped and the guest slot has
been released to root.

Commands (exact compile/launch argv also reside in receipts):

```sh
python3 build/shizukudos/supervisor-ap/final-host/run.py
python3 shizukudos/tests/test_k64_smp_acpi.py --out build/shizukudos/supervisor-ap/acpi-host
python3 shizukudos/supervisor/native_win98/tests/test_gop_auto_host.py --cc gcc --out build/shizukudos/supervisor-ap/gop-auto-final-gcc
python3 shizukudos/supervisor/native_win98/tests/test_gop_auto_host.py --cc clang --sanitize --out build/shizukudos/supervisor-ap/gop-auto-final-sanitize
python3 shizukudos/supervisor/build_ap_component.py --disk build/shizukudos/supervisor-ap/qualified-dos-hd32.img --origin build/shizukudos/supervisor-ap/qualified-dos-origin.json --label r4
python3 shizukudos/supervisor/test_ap_qemu.py --cpus 2 --requested 2 --mode ap --timeout 30 --build-label r4 --label final
python3 shizukudos/supervisor/test_ap_qemu.py --cpus 4 --requested 4 --mode ap --timeout 30 --build-label r4 --label final
python3 shizukudos/supervisor/test_ap_qemu.py --cpus 4 --requested 4 --mode up --timeout 30 --build-label r4 --label final
python3 shizukudos/supervisor/test_ap_qemu.py --cpus 2 --requested 2 --mode novmx --timeout 30 --build-label r4 --label final
python3 shizukudos/supervisor/test_ap_qemu.py --cpus 2 --requested 4 --mode refuse --timeout 30 --build-label r4 --label final
python3 shizukudos/supervisor/test_ap_qemu.py --cpus 2 --requested 2 --mode malformed --timeout 30 --build-label r4 --label final
```

Initial contract/whole-map overlap/cache-capability RED was observed before each
fix. Retained evidence includes `lapic-guard-red.log`, `lapic-pat-red.log`, prelaunch tool pinning
failure, bad-policy and memory-guard failures before INIT, QMP path/CPU-selection
harness failures, and `ap-run-ap-2-2-realinputred` independent-input mismatch.
Unchanged r2 predecessor AP2/AP4/UP/missing-VMX PASS remains distinct: its work
read a deterministic seed, not the final DOS prefix. Every old 96/40 MiB base,
producer receipt, retained compiled artifact/source closure and failure remains.

Build forecast was 358147291 bytes under the specifically authorized 384 MiB
aggregate cap (402653184), with rootfs free 3123392512 bytes at build preflight.
Final measured aggregate before review capture was 343350890 bytes. The freeze
receipt records the final post-capture total/free space. Every guest independently
required host MemAvailable >=4 GiB +512 MiB and bounded cgroup headroom >=768 MiB;
no host/cgroup/global/private-media floor was relaxed. Only owned short QMP
socket leaves were removed, after child reap; no full disk or RAM captures.

## Primary provenance and remaining gates

Independently authored startup and guards; no third-party implementation copied.
Intel SDM revision 093, Volume 3A chapter 11 (11.4.4.1 Table 11-1 startup timing,
11.5 INIT-preserved MTRRs/cache state), Volume 3C chapters 26/27 (VMX operation
and per-logical-processor VMXON):
[official index](https://www.intel.com/content/www/us/en/developer/articles/technical/intel-sdm.html),
[Volume 3A](https://cdrdv2-public.intel.com/929359/253668-093-sdm-vol-3a.pdf),
[Volume 3C](https://cdrdv2-public.intel.com/929361/326019-093-sdm-vol-3c.pdf).
[ACPI 6.6](https://uefi.org/specs/ACPI/6.6/05_ACPI_Software_Programming_Model.html)
sections 5.2.5/5.2.12 define RSDP/MADT/Local APIC relationships.
[UEFI 2.11 Boot Services](https://uefi.org/specs/UEFI/2.11/07_Services_Boot_Services.html)
sections 7.2/7.4 define page ownership, retained map and ExitBootServices;
7.2.3 explicitly describes cache attributes as capabilities.
QMP per-command CPU selection is documented in the
[primary command definition](https://gitlab.com/qemu-project/qemu/-/blob/v1.5.3/qmp-commands.hx).

Pending independent review and root's scoped commit/import. KVM on this Intel
host establishes component behavior; real bare-metal firmware variants, x2APIC,
more than four CPUs, AP partial-start hardware timeout and general domain SMP
are not established. Native Windows 98 VMM/USER/GDI/Explorer, approved private
media boot, final ordinary producer/all-kernel builds and final ISO acceptance
remain root-level gates. This DOS-only component does not substitute for them.
