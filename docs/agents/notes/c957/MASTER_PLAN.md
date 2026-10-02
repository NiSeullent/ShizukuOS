# Win98-Modern parallel integration implementation plan

> For agentic workers: use `superpowers:subagent-driven-development` for owned implementation and independent review. Track verified steps here and in status files.

**Goal:** Complete the requested Windows98/PMA/GOP/VMM/NT architecture, then produce the final ISO and fully refactor and deploy m98.nyase.kr. Native backend changes are intermediate work toward that end state; cooperate with the existing peer owners.

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

- [x] Add failing tests for FIFO contention, release/acquire publication, non-barging trylock, wraparound and actual NT spin/IRQL behavior.
- [x] Run `python3 -B shizukudos/tests/test_pma_sync.py --out build/pma-core-red` and preserve expected failures.
- [x] Implement shared atomics/ticket lock and consume atomic binary lock operations in existing NT exports.
- [x] Run `python3 -B shizukudos/tests/test_pma_sync.py --tsan --out build/pma-c957-integrated-core`, including freestanding i486 compile/link dependency checks; all 11 commands pass.
- [x] Commit owned files and independently review ABI, IRQ and concurrency behavior; final source is 8a74d9a.
- [x] Repair independent ABA and source-binding findings, including three copied-source mutation cases.

## Task 2: Existing framebuffer handoff and rectangle safety

**Owner:** Firmware/Display Lead. **Files:** only `k64_boot_framebuffer` in `kernel64/main.c`, only `gfx_fb_present` in `kernel64/gfx_fb.c`, focused consumed helpers if necessary, `tests/test_k64_boot_framebuffer.c`, `tests/test_gfx_present_rect.c`, `tests/test_display_contract.py`, `docs/agents/status/display-c957.md`.

**Interfaces:** `k64_boot_framebuffer(k64_boot_fb_t *)` and `gfx_fb_present(int,int,int,int)` retain signatures. Tests call actual production functions; no independent desktop, graphics stack or firmware ownership is added.

- [x] Add failing malformed/truncated/padded-pitch framebuffer and extreme rectangle tests with an independent range oracle.
- [x] Run `python3 -B shizukudos/tests/test_display_contract.py` and preserve expected failures.
- [x] Repair bounded validation and clipping in existing paths.
- [x] Run normal and `--sanitize` display tests; verify output preservation and unchanged normal clipping/statistics.
- [x] Commit owned files and review against peer GOP mode-selection metadata.
- [x] Reproduce the reserved-alias finding and conservatively bound GOP below the unchanged 64-GiB arena with a shared constant; GCC/Clang ASan each pass 63 + 156579 assertions.
- [x] Independently approve the reserved-alias followup; current-source kernel build running.

## Task 3: Source-backed common wrapper capability inventory

**Owner:** Windows/NT Compatibility Lead. **Files:** `ntwrapper/capabilities/{manifest.json,validate.py,test_validate.py,README.md}`, `docs/agents/status/windows-compat-c957.md`.

**Interfaces:** Strict versioned JSON schema, read-only validation by default, optional explicit `--out` report with fresh source hashes. Existing exports, wire layouts and capability bits remain authoritative.

- [x] Add failing schema/duplicate/source/export/capability-promotion mutation tests.
- [x] Implement manifest, all requested architectural families, and deterministic validation with useful failure messages.
- [x] Run `python3 -B -m unittest discover -s ntwrapper/capabilities -p test_validate.py -v`.
- [x] Run `python3 -B ntwrapper/capabilities/validate.py --out build/pma-c957-compat/capabilities.json`.
- [x] Commit and independently verify statuses against current source/native-negative evidence.
- [x] Correct the reviewed KeSetTimer and ExQueueWorkItem contracts; all 67 contract guards pass independently and the combined-source report validates 120 families/56 frontend/17 backend APIs.
- [x] Repair capability manifest capture/publication provenance (4e6beea);78 total tests and11 independent CLI race controls pass without native promotion.

## Task 4: Integrate passing local and peer changes

**Owner:** Master Orchestrator and independent Validation Lead. **Files:** `docs/agents/`, coordination ledger, scoped aggregate validation if unowned.

- [x] Read both complete user requirements and preserve canonical Windows98 architecture.
- [x] Audit original and current trees; supersede stale `e455f01` conclusions.
- [x] Create isolated integration/core/display/compat worktrees at `a648e9b`.
- [x] Discover/read other active chats and publish cross-chat ownership messages.
- [x] Obtain scoped commits and review each actual diff against its tests.
- [x] Integrate passing core/display/inventory, IPC/doorbell/GOP, VxD/text/handle and K32 publication commits in dependency order.
- [x] Repair the combined VxD copied-header conflict; independent 13-test approval.
- [x] Bind actual shared font dependencies to Supervisor compile receipts; independent mutation-control approval.
- [x] Converge canonical2bde source/helper closure in3efbc6f, preserve focused evidence;16 controls and real KVM11checks pass.
- [x] Repair eager/lazy empty-relocation DLL collision in d08e1cb; independently approved production-path host251checks/compiler and actual archived WinMM execution.
- [x] Import reviewed b9f170c scheduler, d461529 PMA service, 402f2cb GOP AUTO, 6dfc4b5 K32 deadlines, 97bafff bounded K32 IPC and merged compiler-derived VxD receipt closure.
- [x] Run fresh `python3 -B shizukudos/kbuild.py` atd08e1cb (212stableinputs) and preserve the still-current105input source-bound Supervisor compile. These are compile/component evidence.
- [x] Import the independently reviewed four-file canonical644c94f finite aging grant; fresh212-input build, focused11-check/35-assertion guest and full standalone38/38 guest pass at the frozen fcb36a0 epoch.
- [x] Independently verify canonical b5c49d8 coordinator-isolated successor:38/38 full UP component checks and151 archived apps pass; retain original5/4 failure and natural-attribution limit.
- [x] Commit reviewed partial NT runtime consumer ad6fdfa;3348 host checks per compiler, seven real units, targeted320-input ntdll/kernel32 link and actual321/0 API guest execution verified. Preserve whole API guest FAIL from earlier PMA useful work361<1000.
- [x] Correct omitted pe_parse.h in899bf2e;217 real C dependency units plus independent header and omitted-C controls pass. Preserve old213 strict-build failure and qualification of historical212 maps.
- [x] Verify distinct ROOT214-source frozen four-profile build, focused11/35 PMA, K32 nine-check and full38/38 historical-archive guest with151 app exits and48 total service checks.
- [x] Collect one independently reviewed bounded spinner diagnostic:602/605 records,320 paired IRQ/tick entries,1241 stable inputs. Preserve original361 FAIL and two later diagnostic failures; no production acceptance or inferred original cause.
- [ ] Diagnose and close the distinct current-DLL API guest's earlier PMA useful-work failure without relaxing thresholds or exit gates; passing historical-archive regression does not close it.
- [x] Run host ABI/VxD/display/kernel/firmware and production PMA service/ring gates; retain source hashes and actual scope.
- [x] Publish tested commit SHAs, exact receipts and blockers in shared peer coordination mailboxes; continue exchange for subsequent units.
- [x] Import peer private replacement constructor and close two independent readback validation gaps in a4fcab9;30 actual synthetic host controls pass. Return a correction-only patch to the original owner; actual DOS producer/profile/Windows boot remain separate gates.

## Complete requested sequence

| Phase | Goal | Ownership/status |
| --- | --- | --- |
| 0 | Repository audit and evidence inventory | Baseline and actual owned production paths audited; detailed component receipts retained |
| 1 | PMA native scheduler core | Reviewed b9f170c native-UP priorities, quantum, aging, queues and bounded stress imported; current execution recorded in status |
| 2 | Synchronization primitives | NT atomic spin and shared FIFO locks implemented and independently approved; full primitives remain per-contract work |
| 3 | SMP/AP startup/per-CPU queues/IPIs/UP fallback | Pending integrated native acceptance; preserve current UP |
| 4 | UEFI GOP/EDID/retained framebuffer | Host checks and actual OVMF retained-framebuffer execution pass; reserved-address correction independently approved; 402f2cb AUTO stops after fatal mode-selection/restore failure; actual extracted entry passes 15 scenarios/180 checks per compiler |
| 5 | High-resolution console | Existing backend backbuffer; complete shell acceptance pending |
| 6 | On-demand per-process VGA/SVGA | Existing emulation preserved; full virtualization pending |
| 7 | Serialized DOS gate/InDOS/PSP/MCB/SFT/CDS | Actual pinned FreeDOS entry/EXEC/exit/reentry audited; executor/VMM callback prerequisite work assigned to 163f Windows/NT lead; real transport/boot acceptance pending |
| 8 | VMM↔PMA bridge | Existing VxD reused and copied-header conflict repaired/retested; fada d461 production events/deferred waits/epoch fences imported and independently reviewed; root host tests pass; real Windows VMM delivery pending |
| 9 | Common NT ABI/handles/capabilities | Source-bound 120-family/56-frontend/17-backend API inventory, timer/work correction and78 contract/receipt guards pass; native-positive flags remain false |
| 10 | Evidence-driven NT/user32/gdi/runtime contracts | Existing concrete APIs catalogued; remaining contracts pending |
| 11 | Graphics/storage/network/USB/audio translation | Existing implementations retained; per-driver/API acceptance required |
| 12 | Actual Windows98+Kernel64 integrated execution | Pending real Windows peer/work/result/GUI positive acceptance |
| 13 | Stress and regression | Local sanitizer/concurrency/mutation tests and isolated K32/OVMF guests pass at recorded epochs; fresh merged component executions recorded in status; full product/SMP/real-VMM matrix pending |
| 14 | Documentation/release gates | This ledger maintained; release not complete until real-path gates pass |

Full requirements remain active; a completed slice is not the final architecture completion.

## Final goal deliverables — active, not achieved

- [ ] Actual Windows 98 on ShizukuDOS meets the required native VMM, DOS, driver, GUI and modern-application gates; component/old-DOS controls cannot substitute.
- [ ] Assemble the final1.0.0 ISO using the project installer and frozen admitted production sources; validate artifact contents, exact checksums and actual intended boot/install paths. Private Microsoft media remains private.
- [x] Refactor the official distribution website source into coherent bilingual download, installation, compatibility, development and real-execution pages, preserving all92 existing public paths and75 immutable artifacts. Source7050f3e; publication remains the separate gate below.
- [x] Stage and inspect the frozen100-asset website in real Chrome; validate exact HTTP/download hashes, desktop/mobile layout, keyboard navigation, both48-frame viewers, browser game controls and no-JavaScript original PNG/JSON access.54 regression tests and independent source review pass; see status/site-ux-c957.md.
- [x] Deploy the reviewed100-file static website through existing m98 nginx with both publication locks, exact source/current guards and preserved rollback/console. Actual normal headed Chrome verifies public HTTPS,100 body hashes and all five existing ZIP downloads; see status/site-ux-c957.md.
- [ ] Publish and verify the complete final ISO download after production build, actual boot/install and native acceptance. Official ISO distribution remains m98.nyase.kr; GitHub remains source/patch only.

The goal is still active. Final artifacts and native acceptance remain required;
passing component tests and static website delivery do not complete it. Current
implementation/evidence and open native failures are in INTEGRATION_STATUS.md.
