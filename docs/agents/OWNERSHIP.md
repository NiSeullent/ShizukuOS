# Explicit agent and cross-chat ownership

Baseline `a648e9baa1c57289d50e58d3380827bd9239bc52`. Date 2026-10-02 (Asia/Seoul).

| Owner | Workspace | Files/contracts |
| --- | --- | --- |
| c957 Master Orchestrator | `/root/Win98-Modern-pma-c957-20261002` | Global c957 plan/spec/decisions/status; local cherry-picks and final source-bound validation |
| c957 Core Kernel Lead | `/root/Win98-Modern-pma-c957-core-20261002` | Shared `kcommon/pma_sync.h`; NT driver spin functions only; new lock/IRQL tests; `status/core-c957.md` |
| c957 Firmware/Display Lead | `/root/Win98-Modern-pma-c957-display-20261002` | Kernel64 framebuffer getter and `gfx_fb_present` only; new actual-code tests; `status/display-c957.md` |
| c957 Windows/NT Compatibility Lead | `/root/Win98-Modern-pma-c957-compat-20261002` | New `ntwrapper/capabilities/` only; `status/windows-compat-c957.md` |
| Peer chat 163f | `/root/Win98-Modern-pma-20261002` | Kernel64 scheduler/header/guest tests; UEFI GOP/EDID helpers and loader call sites; VxD admission/epoch safety |
| Peer chat fd5c | `/root/Win98-Modern-pma-integration-fd5c-20261002` proposed | Independent acceptance/integration review and unowned Supervisor safeguards |

Do not edit peer indices/worktrees, duplicate schedulers/object fabrics or modify frozen historical evidence. Cross-chat ledgers are `/root/Win98-Modern/.codex-collaboration/01a0f8c9-3b2c-pma.json` and `/srv/shizukudos-session-coordination/PMA-c957-20261002.md`. Integration takes scoped tested commit SHAs; live/uncommitted assumptions remain provisional.

Each lead status records scope, owned files, decisions, dependencies, blockers, commands/tests, remaining work and source commit. Four local execution slots are time-shared; leads may delegate disjoint validation when a slot becomes available. Final integration requires independent review.
