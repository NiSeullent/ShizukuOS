# Cross-session status: 6970 storage and Kernel32 deadlines

- Assigned scope: existing Windows theme/storage lane, independent architecture review, scoped Kernel32 deadline/IPC integration, WinHTTP parsing and native ANSI SSPI provider binding.
- Worktree/branch: /root/Win98-Modern-theme-6970, codex/theme-integration-6970.
- Current tested production commits: storage75670754f4defb135d11c6959b5d2401c5cd8a2b, Kernel32 deadline6dfc4b574a023c4e4277bbc357b876cfbd82f70d, WinHTTP parser7c174d9184c719fea0b1b8024ee69a4ce3d0bdd4, native SSPI binding137b1469bed3828e2bfd510db85f8d9c845479a2 and own-header Kernel32 IPC successorf5e58113c9ffac9d5a6f6335ec0f48fec932cb0c. These are component host/build proofs, not integrated product acceptance.
- Owned storage files: kernel64/fat32.c, fat32.h, disk.c; tests/test_fat32_rename_failures.c, test_disk_rename_quarantine.c, test_fat32_rename_failures.py; docs/FAT32_RENAME_CHECKPOINT_6970.md.
- Accepted next owned source: kernel32/sched.c sleep/semaphore deadline expressions and k32.h wake_tick width; new abi/shz_sched_deadline.h and Kernel32 production-code deadline tests. No edits to Kernel64 sched.c/k64.h, VxD bridge or GOP code owned by peer sessions.
- Decisions: actual Windows98 remains productOS; VMM owns Windows scheduling/UI/processes, PMA owns Shizuku backend workers; ShizukuDOS replaces DOS foundation; Kernel32 is distinct from Microsoft's KERNEL32.DLL.
- Dependencies: canonical master/docs and Kernel64 scheduler/GOP/VxD leads in session163f; Fada65e2 PMA event bridge; c957 common atomics/NT spin operations/framebuffer/capabilities; DOS gateway remains open; fd5c cross-subsystem integration;163f separately owns Kernel32 user.c publication repair; existing sole main/site/ISO publisher.
- Cross-chat coordination: peer titles/status and shared ledgers read; each session keeps its own worktree/index and handoff. Canonical master docs are not duplicated by this lane; preliminary 6970 drafts are preserved under notes/6970.
- Actual tests: unchanged production a2 RED then final b2 HOST/SAN; 1378 backend trials and38 real disk checks per mode, all10 commands0, exact14-file source closure matched. Final receipt SHA6d88ef2a5267446a0fb140f7101a294ba9e73df601d1d6944c10f1a927abd1dc. Native acceptance false.
- Source-only findings for peer review: K32 finite deadlines truncate after2^32 ticks and ms*1000 overflows32 bits; K64 multiplication/addition has analogous unchecked overflow. Current live Win98 constructor/channel2/K64 peer source exists; ShizukuDOS replacement boot remains absent. VxD and NTW32 reply paths accept request ID without full generation/endpoint/opcode validation.
- Current blockers: shared-host resource reserve prevents local build/VM admission when crossed; merged-main storage and real Windows/PMA/app acceptance remain pending. Hosted compile/link of the combined publication/deadline/IPC source passed freshly atf5e58113; native context-switch/Windows execution is still unverified.
- Remaining work: review peer code, combine disjoint tested patches, verify actual32-bit build/context switching and the real Win98/DOS return path, then complete product acceptance and official distribution.
- Preserved drafts: [local plan](../notes/6970/MASTER_PLAN.md), [scope](../notes/6970/OWNERSHIP.md), [accepted architecture](../notes/6970/DECISIONS.md), [evidence](../notes/6970/INTEGRATION_STATUS.md).

Canonical master acknowledged this lane in docs/agents/OWNERSHIP.md. Prepared Kernel32 C fixture and runner are frozen; actual CLI admission exited3 at20,095,266,816B free below21,483,225,088B required, with no compiler/proof directory. Syntax and independent source review completed; actual C and descendant-teardown results remain unverified. The exact523-range disk batch independently recomputed90,329,088 shared bytes; physical receipts remain in bounded RAM pending persistence admission.

The prepared local checkpoint above is historical. Hosted RED then reproduced
22 failures of76 checks; production repair6dfc4b5 passed the identical76 HOST
and76 sanitizer checks in actual run36916096646. Receipt SHA31bcdf1a527efaee6ec17274b8d7b1391709b5b710b09bf31f6be39d4bcac135;
all6commands0/eight-file closure/resource guard clear. Actual native/i486
linking and deliberate descendant-abort control remain separate and pending.
[Detailed deadline evidence](../notes/6970/K32_DEADLINE_PLAN.md#actual-hosted-red-and-green).

The [DOS boundary audit](../notes/6970/DOS_GATE_BOUNDARY_AUDIT.md) is source-only:
no real executor exists in audited maina648, and InDOS==0 alone is insufficient.
Its exact11 source pins and first actual Win98/VxD/AH30 round-trip proposal were
acknowledged by canonical master, which assigned its Windows/NT lead the actual
executor and retained replacement boot. Implementation/acceptance is pending.

The native SSPI provider binding reused the exact canonical module source and
passed actual prospective RED423/651 then identical HOST651/SAN651 GREEN at
137b146. Its private-path loader/table/pointer lifetime checks preserve all five
legacy providers. The fixture makes no credential/TLS calls; real native DLL,
OS/K64/VMM routing and latest-app support remain pending. [Actual receipts and
scoped source handoff](../notes/6970/NATIVE_SSPI_PROVIDER_PLAN.md#actual-identical-fixture-green-and-scoped-integration-handoff).
No canonical/main import or final ISO deployment is inferred from source push.

Canonical6a750722's exact committed receive-budget source and controls were
imported in6cceb118; peer uncommitted runner changes were refused. Own IPC
header892e remained distinct from peer17c19. After a preserved fixture compile
warning, watchdog successorf5e58113 passed fresh HOST365/SAN365, a freestanding
i486 ELF32 object and the30-snapshot combined K32 compile/link, plus deadline
76/76. [Import and actual fresh proof](../notes/6970/K32_IPC_CLOSURE_IMPORT.md#actual-own-header-green-and-refreshed-combined-build).
No native scheduler, Windows/VMM, peer request/return or full product result
is inferred. A bounded shared-record/source check at21:36:45UTC did not observe
new canonical SSPI/WinHTTP adoption; prior bilateral deadline/publication ACKs
remain separate.
