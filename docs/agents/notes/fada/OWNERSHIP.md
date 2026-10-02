# Ownership — PMA bridge lane

| Worker/chat | Exclusive files | Deliverable |
| --- | --- | --- |
| fada / win98_survey | `shizukudos/abi/shz_vmm_pma.h`, `shizukudos/pma_bridge/service.h`, `shizukudos/pma_bridge/tests/test_service.c`, `shizukudos/pma_bridge/test.py`, `shizukudos/pma_bridge/README.md` | Versioned event service and host tests |
| fada / shizukudos_survey | `shizukudos/kernel64/subsys64.c` entire service, `shizukudos/tests/run_k64_pma_bridge.py` | Actual worker connection and threaded acceptance |
| fada / bridge_validation | `shizukudos/pma_bridge/test_transport.c`, `test_transport.py` | Independent production ring stress and review |
| fada / root | This worktree's master docs, local input provenance, final commits | Review, verification, handoff |
| 163f / 文서화 Win98 통합 아키텍처 | Existing schedulers/priority/quantum tests, UEFI/GOP, VxD transport | Native scheduling, firmware selection, transport safety |
| c957 / Integrate ShizukuDOS 10 PMA | `kcommon/pma_sync.h`, NT driver spin operations, framebuffer validation, wrapper capabilities | Common infrastructure |
| fd5c / Coordinate ShizukuDOS integration | `abi/shz_ipc.h`, `abi/test_abi.c`, native doorbell/video/handle lanes in its own tree | Shared channel/pool validation and integration review |

163f explicitly relinquished `subsys64.c` in its ownership document and supplied
its audited receive identity/corrupt-ring defects to this lane. We added those
guards and real guest regressions along with PMA dispatch. Native DOS executor
integration remains unassigned; fair atomics do not establish DOS serialization.
Root also owns the `kbuild.py` source receipt inclusion of the new service.
Do not edit peer worktrees or another worktree's Git index.

Cross-chat mailbox: `/srv/shizukudos-session-coordination/`.
Live records: `/root/Win98-Modern/.codex-collaboration/`.
Publish tests and commits there before integration; uncommitted claims are not evidence.

Source and validation code are committed separately from these local docs,
so peers can cherry-pick d461529 without conflicting with their canonical
MASTER_PLAN/OWNERSHIP/DECISIONS/INTEGRATION_STATUS documents.
