# Windows 98 modern backend integration implementation plan

> Agentic execution uses `superpowers:subagent-driven-development`. Implement and test existing subsystems in dependency order, with explicit ownership and independent review.

**Goal:** Extend the existing native scheduler, firmware display path and Windows bridge with real tested behavior while preserving actual Windows 98 as the product OS.

**Architecture:** Windows 98 keeps VMM, VxD, USER/GDI, Win16/Win32 and Explorer. ShizukuDOS supplies the boot/hardware foundation; Kernel32 and Kernel64 are service domains. The existing native scheduler and NTWRAP9X/channel2 transport are extended, not replaced with competing implementations.

**Tech stack:** Freestanding C and NASM, public UEFI protocols, existing Shizuku ABI 1.1, host C/Python tests, GCC/Clang sanitizers, QEMU/OVMF.

**Spec:** [integration requirements](INTEGRATION_SPEC.md).

## Global constraints

- Windows 98 is the product OS; its VMM remains the Windows scheduling authority.
- Preserve existing BIOS, CSMWrap, DOS16, native Windows, Kernel32/64 and historical evidence paths.
- Keep native Windows single-vCPU compatibility while integrated native SMP is unproven.
- Do not invent VMM service numbers or replace USER/GDI with a development desktop.
- Keep ABI 1.1 wire layouts and opcodes compatible during this slice.
- No proprietary source copying, private Windows media publication or fake-success stubs.
- Component/host tests never establish Windows 98 integration or hardware acceleration.
- No changes to client-global configuration; all new artifacts stay in this isolated worktree.

## Review focus

1. A woken thread must occur once in the runnable queue, including signal/timeout races.
2. Priority selection must retain bounded progress for lower-priority native threads.
3. Corrupt EDID, unsupported masks or unsafe pitch must retain a valid firmware display fallback.
4. Stale bridge responses must never release another epoch's pool allocation or reach a client as valid data.
5. Failed/reentrant bridge operations must release admission ownership and return deterministic errors.

## Task 1: Native PMA scheduler policy and runnable queues

**Owner:** Core Kernel Lead. **Files:** `shizukudos/kernel64/sched.c`, `k64.h`, `pma_tests.c`, and the single PMA test hook in `tests.c`.

**Interface:** Existing `thread_create`, `thread_resume`, `thread_wake`, sleep/join and context-switch paths remain usable. Add documented priority/quantum/CPU0-affinity controls and bounded scheduler statistics; exact declarations belong to the existing `k64.h`, not a new scheduler ABI.

- [ ] Establish fresh baseline kernel build and real non-yielding-thread test.
- [ ] Add failing tests for duplicate wake, priority changes, timed semaphore waits, invalid policy and runnable accounting.
- [ ] Extend the existing ready/block/wake transitions with explicit ready queues and starvation protection; keep CR3, SSE, GS and IRQL restoration.
- [ ] Run the new guest tests and existing standalone Kernel32/64 regressions with freshly built kernels.
- [ ] Record source-bound evidence and create a scoped commit after review.

## Task 2: Safe high-resolution firmware GOP selection

**Owner:** Firmware/Display Lead. **Files:** `shizukudos/uefi/efi.h`, `boot.c`, `boot.h`, `test.c`, `main.c`; GOP selection call sites only in `supervisor/loader/loader.c`; optional focused firmware test.

**Interface:** Reuse the existing framebuffer handoff structure and RGBX/BGRX backend. Add typed QueryMode/SetMode and EDID lookup/selection in the shared boot helper; expose the exact helper in `boot.h`.

- [ ] Run existing host display tests before editing.
- [ ] Add failing mode enumeration, EDID, pitch/mask/budget and firmware-error tests.
- [ ] Implement validated EDID geometry preference, requested resolution ladder, allocation cleanup and original-mode fallback before ExitBootServices.
- [ ] Run GCC host tests, Clang sanitizer tests, EFI build and bounded fresh OVMF boot.
- [ ] Record selected-mode evidence with component scope and create a scoped reviewed commit.

## Task 3: Existing Windows bridge concurrency and epoch safety

**Owner:** Windows/NT Compatibility Lead. **Files:** `ntwrapper/vxd/bridge.c`, `bridge.h`, `tests/test_w64vxd.c`, necessary test driver, `README.md`; bounded receive/source checks in `kernel64/subsys64.c` after baseline. The separate c957 chat owns the common capability manifest.

**Interface:** Retain NTWRAP9X DIOC and SHZ ABI 1.1. Add atomic nonblocking admission to existing shared state; return ERROR_BUSY for overlap. Validate live generation/endpoints and incoming response ownership before delivery or pool release.

- [ ] Run current VxD build/host tests.
- [ ] Add failing concurrent/reentrant, stale-generation, wrong-domain and corrupt-ring tests.
- [ ] Implement bounded admission/receive/reset behavior without fabricating blocking VMM synchronization.
- [ ] Keep outstanding pool memory allocated across reset until a terminal peer response; document missing cancellation/rundown acknowledgement rather than freeing peer-visible memory early.
- [ ] Run VxD host sanitizer/control/ABI tests and rebuild native VxD artifact.
- [ ] Record unchanged actual-Windows runtime gate and create a scoped reviewed commit.

## Task 4: Integration, independent review and reproducible gates

**Owner:** Master/Validation Lead. **Files:** `docs/agents/*`, status reports and focused aggregate validation tooling if needed.

- [ ] Review all cross-subsystem declarations and complete task reports.
- [ ] Build fresh Kernel32/64 and EFI sources after the final source change.
- [ ] Execute appropriate native kernel, bridge and firmware tests; retain logs and source/artifact hashes.
- [ ] Resolve blocking findings through the responsible lead and run covering tests.
- [ ] Commit passing source changes incrementally; preserve all failures and remaining acceptance gates.

## Full integration sequence and remaining gates

The user-requested program continues through audit; PMA; synchronization; integrated SMP; retained GOP; high-resolution console; per-process on-demand legacy VGA/SVGA; serialized DOS gateway; VMM/PMA synchronization; common NT ABI; evidence-driven wrapper families; actual Windows 98/Kernel64 requests; stress/regression; release gates. Independent work may run ahead, but integration follows dependencies.

The present three implementation tasks do not discharge integrated SMP, per-process VGA, the DOS-to-VMM replacement contract, actual PMA/VMM wait/signal, all wrapper families or the final actual-Windows GUI/media acceptance matrix. Those remain explicit in INTEGRATION_STATUS.md until exercised in real execution.
