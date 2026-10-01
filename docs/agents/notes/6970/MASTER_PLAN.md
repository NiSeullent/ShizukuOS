> Local 6970 audit/planning draft preserved after cross-chat ownership discovery. Canonical docs/agents master files are owned by session163f in /root/Win98-Modern-pma-20261002. This draft does not reserve another session's files. See ../../status/6970-master.md for current scope.

# Win98-Modern PMA integration master plan

> For agentic workers: use the subagent-driven-development or executing-plans workflow for each independently reviewed task. Source ownership and actual acceptance evidence govern integration.

**Goal:** Extend the real Windows 98 product with ShizukuDOS native preemptive workers, modern hardware services and explicitly synchronized compatibility bridges.

**Architecture:** Windows 98 retains VMM, VxD, USER/GDI, Win16/Win32, Explorer and its process/thread authority. ShizukuDOS replaces the DOS foundation; its Supervisor and Kernel32/Kernel64 provide backend execution and translation services. Reuse existing domain and thread schedulers before adding PMA functionality, keeping VMM scheduling and native worker scheduling distinct.

**Tech stack:** Existing independently authored C and x86 assembly, UEFI GOP, VMX/EPT isolation where already used, project-owned versioned channels and pinned upstream compatibility patches.

**Spec:** [Decisions and accepted requirements](DECISIONS.md), [ownership](OWNERSHIP.md), [current evidence](INTEGRATION_STATUS.md), and [Windows 98 architecture contract](../../../SHIZUKUOS_ARCHITECTURE_CONTRACT.md). The user reaffirmed the product architecture on 2026-10-01.

## Global constraints

- Windows 98 is the product OS; normal final boot reaches its actual desktop.
- Kernel32 denotes the Shizuku protected-mode service component, distinct from Microsoft KERNEL32.DLL. Kernel64 is a backend, not another product desktop.
- VMM owns Windows scheduling. PMA owns Shizuku native workers. The bridge must preserve Win16 serialization, V86, critical sections and callback ordering.
- Preserve BIOS, CSMWrap, original-DOS controls, current GOP paths, standalone component tests and immutable historical evidence.
- Use public specifications and attributed compatible upstream sources. Never invent VMM service numbers, publish proprietary Windows code/media, or claim stub exports are working features.
- The final ISO remains exclusive to m98.nyase.kr; GitHub carries public development source and patches.
- Keep the existing 20 GiB VM/build reserve, 256 MiB private COW limit, and bounded proof outputs. Space pressure never permits weakening acceptance gates.
- Integrate passing changes in small commits; the main/site/ISO publisher is a separate sole writer.

## Review focus

1. A Windows thread or UI must retain Windows ownership across backend requests and cancellation.
2. Signal/enqueue/sleep races, stale generations and peer restart must not lose or double-complete work.
3. Non-reentrant DOS calls require an explicit serialization boundary with PSP/MCB/InDOS ownership.
4. Framebuffer pitch, formats, mode failure and legacy video lifetime must preserve GOP ownership and the Windows display bridge.
5. Failed storage/async completion must preserve data or report recovery uncertainty without successful stubs.

## Current assigned execution

Phase 0 read-only audits completed in this lane: the Core Kernel Lead maps existing scheduling, synchronization, SMP and timer paths; the Windows 98/Validation Lead maps DOS/VMM/VxD/channel ownership; root mapped firmware/display and wrapper infrastructure. Canonical master session163f and the c957/fada/fd5c peer lanes now implement their separately owned components. This lane prepares the Kernel32 finite-deadline regression; its production change awaits explicit peer ownership coordination. The separate disk agent preserves logical media contents while recovering duplicate allocations.

The first implemented prerequisite is the actual FAT32 rename/disk failure repair. It passed production-code HOST and ASan/UBSan tests after demonstrated failures in unchanged production. See [its checkpoint](../../../FAT32_RENAME_CHECKPOINT_6970.md). Final merged main sources still need their own validation.

Do not add another scheduler, wrapper object table or hardware stack before the current-source audit identifies its reuse boundary. Phase-specific implementation plans will pin exact existing interfaces, files, failing cases and native acceptance gates before edits.

## Dependency order and acceptance

| Phase | Deliverable | Acceptance boundary |
| --- | --- | --- |
| 0 | Source map, ownership and regression baselines | Actual source anchors and immutable evidence; assumptions explicitly pending |
| 1 | Extend existing native preemptive scheduler | Actual context switch, timer preemption, states, priority/quantum and lifecycle; 1/100/1000 threads where memory allows |
| 2 | Common native synchronization and lock ordering | Mutex/event/semaphore/RW/condition/barrier/completion/timer/work queue tests, lost/double wake and cancellation controls |
| 3 | SMP and CPU-local scheduling | BSP/AP, per-CPU queues, affinity/migration/IPI/wakeup; AP failure preserves UP; Windows stays conservative single-vCPU |
| 4 | GOP/EDID mode selection and safe handoff | Validated pitch/format/bounds after ExitBootServices; safe firmware fallback |
| 5 | Resolution-aware boot/recovery console | Dynamic geometry, Unicode/codepages, scroll/cursor/input/backbuffer/dirty rectangles; >=1024x768 actual boot |
| 6 | On-demand legacy video contexts | Actual DOS INT10/mode13/palette/VRAM requests rendered through GOP; process exit restores prior display |
| 7 | Serialized DOS gateway | InDOS/critical error/PSP/MCB/SFT/CDS/driver/callback ownership and concurrent negative controls |
| 8 | VMM/PMA bridge using existing VxD/channel | Real VMM wait/signal/timeout/death/restart/overflow sequencing; bridge disabled still boots Windows |
| 9 | Shared wrapper capability/ownership ABI | Machine-readable per-API backend/status/thread/sync/error/ABI tests; deterministic unsupported errors |
| 10 | Core NT/user/runtime translation | Real symbol/parameter/concurrency/cleanup/death paths through shared services |
| 11 | Graphics/storage/network/input/audio modules | Evidence-selected working translation, explicit partial/unsupported status and async stress |
| 12 | Actual Windows 98 + Kernel64 integration | Windows app -> wrapper -> Shizuku service -> PMA worker -> result -> same Windows app |
| 13 | Regression and stress | Win16/Win32/DOS, lock/lifecycle/timer/queue stress, GUI/input/storage/shutdown and two cold boots |
| 14 | Reproducible release gates | Source clone/build, original media separately supplied, outside HTTPS homepage/download checks and actual final ISO |

Independent leads may prepare later phases; integration respects dependency order. A component host test, standalone kernel demo or OEM DOS control never substitutes for the final Windows path.
