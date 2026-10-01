# Agent ownership

Worktree: `/root/Win98-Modern-pma-20261002`; branch: `codex/pma-integration-20261002`; initial upstream: `a648e9b`.

| Role | Owned files | Dependencies | Review |
| --- | --- | --- | --- |
| Master Orchestrator | `docs/agents/`, build provisioning, integration receipts | All leads | Independent validation/review wave |
| Core Kernel Lead | `kernel64/sched.c`, `k64.h`, `pma_tests.c`, one `tests.c` hook | Existing allocator, context switch, object waits | Kernel/concurrency reviewer |
| Core subordinate k32_publication | `kernel32/user.c`, distinct publication host/guest runners | Existing Kernel32 thread publication; disjoint from peer deadlines | Final integration reviewer |
| Firmware/Display Lead | `uefi/efi.h`, `boot.[ch]`, `test.c`, `main.c`; loader GOP call sites | Existing handoff; firmware QueryMode/SetMode | Firmware/ABI reviewer |
| Windows/NT Compatibility Lead | `ntwrapper/vxd/bridge.[ch]`, bridge tests/README | Existing SHZ ABI 1.1, VxD DIOC | Bridge lifetime/concurrency reviewer |
| Kernel regression runner | `tests/run_k64_standalone.py`, scoped status | Preserved baseline binaries and explicit display input | Final integration reviewer |

Leads may delegate disjoint validation/review tasks in later waves within the four-agent host limit. Keep writes inside assigned files, report interface changes before consumers use them, and do not edit another active worktree. Build directories are independently named. Root serializes final source snapshots and commits; workers do not commit a shared index concurrently.

## Other chat lanes

- `Integrate ShizukuDOS 10 PMA` (c957): common fair atomic/ticket synchronization, framebuffer validation and common capability manifest, on separate worktrees.
- `Win98 현대화 구조 병렬 구현` (65e2/fada): versioned VMM/PMA payload and event/completion service, including `kernel64/subsys64.c`; this chat relinquishes that file and supplies its audited corruption/source defects.
- `Coordinate ShizukuDOS integration` (fd5c): integration acceptance and unowned Supervisor safeguards.
- `Win98에 테마 및 현대 앱 지원 추가` (6970): Kernel32 deadline helper/arithmetic and separately tested storage repair; preserve current upstream storage enhancements in any later three-way import.

DOS_GATE audit/executor ownership is assigned to the Windows/NT Compatibility Lead; root coordinates bootstrap integration with the existing native boot lane. Implementation remains gated by real VM/thread/PSP context and reverse request/lifecycle contracts. Native lock and PMA event service results do not establish serialized DOS service execution.

Cross-chat coordination is exchanged through `/srv/shizukudos-session-coordination/` and `/root/Win98-Modern/.codex-collaboration/`, and confirmed with app chat snapshots. No send-message-to-chat tool is exposed in this session; shared records are the available communication channel.

## Full-goal continuation ownership

- Root: actual replacement boot integration, private input/resource accounting, final ISO source/artifact gates.
- Windows lead: VMM endpoint/callback and DOS executor context contracts, real implementation after pinned DDK inspection.
- SMP integration lead: separate native SMP bringup/per-CPU roadmap and executed requirement tests; active Core scheduler files remain Core-owned.
- Core: current actual KVM useful-work failure, followed by reviewed scheduler/per-CPU interface evolution.

Primary boot chat01a0f109 and cb43 are observed interrupted/idle in the app; their source-only handoff57eebbe and preserved actualDOS/XMS/ScanReg evidence will be reused rather than discarded. Neither original main nor historical receipts are edited by this continuation.


Continuation splits: Fada new kernel64/smp_acpi/smp_boot/trampoline sources;163f SMP lead existing standalone/boot32.c + native_firmware.h writer and main/pci actual integration; Core scheduler/arch/header source epoch held. Fada new Win32 PMA native client/probe + demux namespace;163f Windows lead existing native/control/bridge + new pma_endpoint/vmm_callbacks. Fada private NAS transport/mount and new release-preparation tool; root163f only bounded private /mnt/shizukuos-native-workspace-fada-20261001/163f output. Root retains canonical index/commit/integration ownership.


Checkpoint — reviewed source successors (2026-10-01):
- Canonical b5c49d8 includes 3cbc1f8, which binds Kernel32 IPC validation to compiler-discovered project headers and tools; persistent drift controls and seven actual endpoint cases per compiler passed. Native PMA VxD/client source is committed as 9853325 after independent F4/F5 review: strict i486 VxD,21 host groups and245 client assertions per GCC/Clang sanitizers passed. Failed alias unlocks remain retained, and notification holds fence event lifetime. Actual Windows VMM/caller delivery and DOS execution remain unverified.
- Fresh four-profile212-input build after the PE loader correction passed172.313s, Kernel64S9d8fed5. Its actual combined KVM guest finished200.94s with151 ordinary apps exit0/PMA16/W64loop48; the original refresh check passed first33/useful1015770, but the new arrival assertion failed ready_wait5/remaining4. That whole FAIL and exact source/helper snapshot remain preserved.
- Actual production-scheduler host and native ISR/context RED reproduced a READY coordinator taking its own aged grant. The candidate fixture blocks that coordinator on a finite completion semaphore throughout measurement. The same fresh212-input Kernel64S6518d678 passed natural KVM17/17 and TCG17/17; first_wait4/remaining4/low_charges4/coordinatorBLOCKED1. Scheduler policy and all original bounds remain unchanged. Independent fixture review approved source b5c49d8; root fresh four-profile build is running, followed by a full combined successor guest.
- Isolated boot55a6714 corrects the actual combined DOS startup patch pipeline: five explicit strict patches, rebased standard-mode DX bit0 predicate, no duplicated CBC assembly record. Applying the old complete pipeline failed; the actual old startup body produced98304 failures. Final actual patched body passed294919 assertions each GCC/Clang sanitizers and the22-byte NASM record check. Independent review approved these three files. Actual DOS/FreeCOM component compilation is underway; Watcom archive differs from the manifest pin, so exploratory compilation cannot establish pin-conformant release inputs.
- Isolated SMP b9e9ae5 preserves checked firmware maps and original-RAM-attested SeaBIOS ACPI reads; normal2/4/forced-UP receipts pass with scheduler_cpus1. F6 captured-producer/helper correction and six adversarial helper/reuse controls were independently approved. Frozen Fada backend55b684c4+981debb9 is available for integration. Actual private RED exposes an unreadable level1 page-table ownership gap; proposed common-walker extension passes1567 controls per compiler but is not yet production acceptance. AP execution, per-CPU queues/allocator/syscalls/TLB and Supervisor virtual APs remain open.
- NAS transport failed at21:18:36UTC; the private2GiB copy terminated with EIO before QEMU creation. No Windows VM, Enter or restart ran. Fada owns verified transport/filesystem recovery; root163f has no live NAS handles and holds new NAS writes. USB stage/combine receipt race remains pending: attempted RED hit the unchanged17GiB resource guard and is invalid race evidence. Boot source remains isolated until that correction is reviewed.
- Other-chat collaboration uses shared source handoffs and independent reviews. Fada is implementing a real installed-Windows source/launch producer with explicit WIN.COM invocation and private backups; c957 owns public bilingual site/download verification. Component, source-presence and site checks do not discharge actual Windows98 VMM/desktop, Windows→wrapper→PMA result, full SMP, installer cold boot/install/restart or the final ISO. The full goal remains active.
