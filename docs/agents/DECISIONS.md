# Integration decisions — c957

| ID | Decision | Reason/evidence |
| --- | --- | --- |
| C957-001 | Use latest `a648e9b`, preserve stale-tree findings as superseded | Original main `e455f01` predates substantial NT/native-Windows/GOP work |
| C957-002 | VMM remains Windows authority; PMA owns native workers | Explicit user architecture, current `AGENTS.md` |
| C957-003 | Reuse existing schedulers/objects/IPC/VxD/GOP | Actual code already implements these foundations; avoid competing fabrics |
| C957-004 | Split source ownership across chats and independent worktrees | Peer163f owns scheduler/EDID/VxD; c957 owns spin/display-safety/manifest |
| C957-005 | Keep NT lock ABI while adding native fair ticket locks | KSPIN_LOCK is pointer-sized; ticket layout cannot replace it silently |
| C957-006 | Keep UP fail-fast and IRQL semantics during atomic migration | Current IRQL/KPCR/DPC implementation is not SMP; spinning on same-CPU owner can deadlock |
| C957-007 | Repair actual framebuffer/present code; defer arbitrary masks | Current ABI carries format without per-channel masks; complete mask support requires coordinated renderer migration |
| C957-008 | Manifest capabilities fail closed and bind actual source/evidence | Export existence and host tests do not establish WDDM/D3D/native-positive support |
| C957-009 | Preserve historical/private media and receipts | User provenance and no-false-completion requirements |
| C957-010 | All requested phases remain tracked until real acceptance | Verified component slices are progress, not actual Windows98 integration completion |

Lock order for this slice: native ticket lock protects its bounded caller-owned metadata; it must never enclose sleep, blocking waits, DOS/VMM entry or callbacks. NT driver spin paths retain existing IRQL ownership and release the atomic flag before lowering IRQL/flushing DPCs. A normal thread cannot take a lock shared with its own interrupt handler unless the caller masks that interrupt or uses the documented IRQL boundary.
