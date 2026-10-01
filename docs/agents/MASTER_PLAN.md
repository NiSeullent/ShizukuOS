# Win98-Modern parallel integration implementation plan

> For agentic workers: use `superpowers:subagent-driven-development` for owned implementation and independent review. Track verified steps here and in status files.

**Goal:** Integrate tested native backend improvements beneath actual Windows 98, cooperating with peer chats implementing PMA, GOP and VMM transport.

**Architecture:** Reuse existing UP preemptive schedulers, VMX/EPT Supervisor, shared ABI 1.1, VxD/Win64 transport, NT driver contracts and GOP backend. Windows VMM owns Windows scheduling; PMA owns native workers. Every change remains reversible and has a truthful component acceptance scope.

**Tech stack:** Freestanding C/NASM, Python test runners, GCC/Clang sanitizers, existing SHZ ABI 1.1, local Git worktrees.

**Spec:** [INTEGRATION_SPEC.md](INTEGRATION_SPEC.md).

## Global constraints

- Actual Windows 98 remains the product OS and final normal desktop.
- Preserve VMM/USER/GDI/VxD/Win16/Win32 scheduling semantics.
- Preserve ABI 1.1 layouts, `KSPIN_LOCK` pointer size, historical evidence and existing boot paths.
- No proprietary source copies, successful unimplemented APIs or invented VMM ordinals.
- Native Windows remains single-vCPU while integrated SMP is unverified.
- Work only in owned worktrees/files; consume peer committed SHAs.
- Component tests do not promote pending native Windows integration gates.

## Review focus

1. A lock must publish protected writes before another owner acquires it, including ticket-counter wraparound.
2. IRQL/interrupt restoration must remain valid for driver calls from interrupt or dispatch context.
3. Truncated/malformed framebuffer metadata must leave the caller's output untouched and avoid dereferencing invalid storage.
4. Extreme rectangle coordinates must not overflow or reach a backend with a negative/out-of-bounds rectangle.
5. Metadata must not advertise a stub, absent backend or native-positive result as a supported feature.

## Task 1: Shared fair synchronization and NT spinlock migration

**Owner:** Core Kernel Lead. **Files:** `shizukudos/kcommon/pma_sync.h`, narrow spin operations in `kernel64/ntdrv_ke.c`, `tests/test_pma_sync.c`, `tests/test_pma_sync.py`, `kernel64/tests/test_ntdrv_spin_host.c`, `docs/agents/status/core-c957.md`.

**Interfaces:** Shared FIFO ticket lock and pointer-sized binary atomic helpers, fixed declarations recorded by the lead before consumers use them. Existing NT exported signatures and lock storage remain unchanged.

- [ ] Add failing tests for FIFO contention, release/acquire publication, non-barging trylock, wraparound and actual NT spin/IRQL behavior.
- [ ] Run `python3 -B shizukudos/tests/test_pma_sync.py` and preserve expected failures.
- [ ] Implement shared atomics/ticket lock and consume atomic binary lock operations in existing NT exports.
- [ ] Run normal and `--sanitize` tests, including freestanding i486 compile/link dependency checks.
- [ ] Commit only owned files; independently review ABI, IRQ and concurrency behavior.

## Task 2: Existing framebuffer handoff and rectangle safety

**Owner:** Firmware/Display Lead. **Files:** only `k64_boot_framebuffer` in `kernel64/main.c`, only `gfx_fb_present` in `kernel64/gfx_fb.c`, focused consumed helpers if necessary, `tests/test_k64_boot_framebuffer.c`, `tests/test_gfx_present_rect.c`, `tests/test_display_contract.py`, `docs/agents/status/display-c957.md`.

**Interfaces:** `k64_boot_framebuffer(k64_boot_fb_t *)` and `gfx_fb_present(int,int,int,int)` retain signatures. Tests call actual production functions; no independent desktop, graphics stack or firmware ownership is added.

- [ ] Add failing malformed/truncated/padded-pitch framebuffer and extreme rectangle tests with an independent range oracle.
- [ ] Run `python3 -B shizukudos/tests/test_display_contract.py` and preserve expected failures.
- [ ] Repair bounded validation and clipping in existing paths.
- [ ] Run normal and `--sanitize` display tests; verify output preservation and unchanged normal clipping/statistics.
- [ ] Commit owned files and review against peer GOP mode-selection metadata.

## Task 3: Source-backed common wrapper capability inventory

**Owner:** Windows/NT Compatibility Lead. **Files:** `ntwrapper/capabilities/{manifest.json,validate.py,test_validate.py,README.md}`, `docs/agents/status/windows-compat-c957.md`.

**Interfaces:** Strict versioned JSON schema, read-only validation by default, optional explicit `--out` report with fresh source hashes. Existing exports, wire layouts and capability bits remain authoritative.

- [ ] Add failing schema/duplicate/source/export/capability-promotion mutation tests.
- [ ] Implement manifest, all requested architectural families, and deterministic validation with useful failure messages.
- [ ] Run `python3 -B -m unittest discover -s ntwrapper/capabilities -p test_validate.py -v`.
- [ ] Run `python3 -B ntwrapper/capabilities/validate.py --out build/pma-c957-compat/capabilities.json`.
- [ ] Commit and independently verify statuses against current source/native-negative evidence.

## Task 4: Integrate passing local and peer changes

**Owner:** Master Orchestrator and independent Validation Lead. **Files:** `docs/agents/`, coordination ledger, scoped aggregate validation if unowned.

- [x] Read both complete user requirements and preserve canonical Windows98 architecture.
- [x] Audit original and current trees; supersede stale `e455f01` conclusions.
- [x] Create isolated integration/core/display/compat worktrees at `a648e9b`.
- [x] Discover/read other active chats and publish cross-chat ownership messages.
- [ ] Obtain scoped commits and review each actual diff against its tests.
- [ ] Integrate passing commits with dependency order, retain peer ownership/status.
- [ ] Run fresh `python3 -B shizukudos/kbuild.py` and source-bound Supervisor compilation.
- [ ] Run appropriate host ABI/VxD/display/kernel/firmware regression gates; retain source hashes and actual scope.
- [ ] Publish tested commit SHAs and blockers for peer integration.

## Complete requested sequence

| Phase | Goal | Ownership/status |
| --- | --- | --- |
| 0 | Repository audit and evidence inventory | Current baseline inspected; detailed owned audits underway |
| 1 | PMA native scheduler core | Peer 163f priority/quantum/ready-queue implementation |
| 2 | Synchronization primitives | Existing object waits reused; c957 fair atomics and NT spin migration |
| 3 | SMP/AP startup/per-CPU queues/IPIs/UP fallback | Pending integrated native acceptance; preserve current UP |
| 4 | UEFI GOP/EDID/retained framebuffer | Peer 163f mode selector; c957 handoff safety |
| 5 | High-resolution console | Existing backend backbuffer; complete shell acceptance pending |
| 6 | On-demand per-process VGA/SVGA | Existing emulation preserved; full virtualization pending |
| 7 | Serialized DOS gate/InDOS/PSP/MCB/SFT/CDS | Pending actual DOS execution-boundary integration |
| 8 | VMM↔PMA bridge | Existing VxD reused; peer 163f admission/epoch safety |
| 9 | Common NT ABI/handles/capabilities | Existing fabric reused; c957 source-bound manifest |
| 10 | Evidence-driven NT/user32/gdi/runtime contracts | Existing concrete APIs catalogued; remaining contracts pending |
| 11 | Graphics/storage/network/USB/audio translation | Existing implementations retained; per-driver/API acceptance required |
| 12 | Actual Windows98+Kernel64 integrated execution | Pending real Windows peer/work/result/GUI positive acceptance |
| 13 | Stress and regression | Local synchronization/display/metadata tests in progress; full matrix pending |
| 14 | Documentation/release gates | This ledger maintained; release not complete until real-path gates pass |

Full requirements remain active; a completed slice is not the final architecture completion.
