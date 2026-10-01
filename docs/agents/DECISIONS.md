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
| C957-011 | Validate copied VxD headers using geometry only, with real ring checks at the actual mapped window | The new IPC validator reads rings; applying it to 128-byte snapshots reproduced three OPEN transport failures |
| C957-012 | Admit GOP ranges only below the shared 64-GiB graphics arena boundary | A broad nonwrapping aperture still aliases existing pixel buffers, SYSBLK, KWIN, driver images and KUSER; independent 63-case regression passes |
| C957-013 | Bind external glyph/header dependencies and exact evaluator bytes into build/test receipts | Actual compiler and mutation controls revealed missing provenance inputs; historical receipts remain untouched |
| C957-014 | Keep DOS serialization pending until actual entry and transfer paths are connected | Pinned FreeDOS EXEC/exit/critical-error and fast/internal services bypass a simple INT21 wrapper; native locks alone cannot provide admission |
| C957-015 | Require the exact complete current compiled source map and imported evaluator/helper identities for K64 PMA admission and compare both after execution | Root2ec1183 omission repair is historical; canonical2bde convergence in3efbc6f rejects omitted or unexpected inventory entries and persistent helper drift;16 controls and a real11-check KVM guest pass |
| C957-016 | Require fresh component output and exact guest debug-exit success | Bridge4e60535 and focused3efbc6f reject reused outputs before launch and use exclusive directory creation; controls preserve original receipt/serial bytes and reject abnormal guest termination |
| C957-017 | Retain a historical Win64 component archive with its original receipt and explicit fixture provenance | Cached archive a098a49 is immutable; source epoch 6d860bf is not relabeled as a newly rebuilt current-source runtime or Windows 98 media |
| C957-018 | Bound K32 receive passes and yield before waiting | Repeated corrupt head/invalid metadata and sustained refill must not monopolize a native worker; actual production 365-check GCC/Clang fixtures and strict i486 compile pass |
| C957-019 | Make the injected two-yield observation atomic without changing scheduler or timing gates | Actual KVM raw97/service32,65 with individual ready residence32 reproduced preemption between capture/yield; context-owned IF lets competing threads keep receiving timer interrupts |
| C957-020 | Parse and hash the same captured capability manifest bytes and publish only after source rechecks | 4e6beea closes the reproduced parse/hash and persistent publication-drift races;78 guards plus independent11 actual CLI controls pass, while native-positive flags remain false |
| C957-021 | Permit a non-stripped DLL with relocation directory0/0 to move only when its preferred range is occupied | d08e1cb preserves real-record ASLR/fixup checks and fixedEXE/stripped/half-directory collision rejection; actual production eager/lazy mapping RED fails twice/compiler, GREEN and independent251 checks/compiler pass |
| C957-022 | Preserve all92 existing public assets before a full website refactor | The prior publisher omitted9 live continuation/USB files; consume frozen57eebbe bytes and narrow reviewed gates, keep pending final ISO and private-source exclusions |
| C957-023 | Preserve resource floors and existing release ownership during NAS capacity work | Fada owns verified snowra-f-nas storage handoff and full-product readiness tooling; no competing mount/config/publisher or unowned cache deletion |

Lock order for this slice: native ticket lock protects its bounded caller-owned metadata; it must never enclose sleep, blocking waits, DOS/VMM entry or callbacks. NT driver spin paths retain existing IRQL ownership and release the atomic flag before lowering IRQL/flushing DPCs. A normal thread cannot take a lock shared with its own interrupt handler unless the caller masks that interrupt or uses the documented IRQL boundary.
