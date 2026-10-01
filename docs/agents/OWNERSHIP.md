# Agent ownership

Worktree: `/root/Win98-Modern-pma-20261002`; branch: `codex/pma-integration-20261002`; initial upstream: `a648e9b`.

| Role | Owned files | Dependencies | Review |
| --- | --- | --- | --- |
| Master Orchestrator | `docs/agents/`, build provisioning, integration receipts | All leads | Independent validation/review wave |
| Core Kernel Lead | `kernel64/sched.c`, `k64.h`, `pma_tests.c`, one `tests.c` hook | Existing allocator, context switch, object waits | Kernel/concurrency reviewer |
| Firmware/Display Lead | `uefi/efi.h`, `boot.[ch]`, `test.c`, `main.c`; loader GOP call sites | Existing handoff; firmware QueryMode/SetMode | Firmware/ABI reviewer |
| Windows/NT Compatibility Lead | `ntwrapper/vxd/bridge.[ch]`, bridge tests/README, `kernel64/subsys64.c` bounded receive/source checks | Existing SHZ ABI 1.1, VxD DIOC | Bridge lifetime/concurrency reviewer |

Leads may delegate disjoint validation/review tasks in later waves within the four-agent host limit. Keep writes inside assigned files, report interface changes before consumers use them, and do not edit another active worktree. Build directories are independently named. Root serializes final source snapshots and commits; workers do not commit a shared index concurrently.

## Other chat lanes

- `Integrate ShizukuDOS 10 PMA` (c957): common fair atomic/ticket synchronization, framebuffer validation and common capability manifest, on separate worktrees.
- `Win98 현대화 구조 병렬 구현` (65e2): DOS call serialization/compatibility validation.
- `Coordinate ShizukuDOS integration` (fd5c): integration acceptance and unowned Supervisor safeguards.

Cross-chat coordination is exchanged through `/srv/shizukudos-session-coordination/` and `/root/Win98-Modern/.codex-collaboration/`, and confirmed with app chat snapshots. No send-message-to-chat tool is exposed in this session; shared records are the available communication channel.
