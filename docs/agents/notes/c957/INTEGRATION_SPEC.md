# Win98-Modern PMA integration specification — c957

Date: 2026-10-02 (Asia/Seoul). Baseline: `a648e9baa1c57289d50e58d3380827bd9239bc52`.

## Approved intent

The user supplied the PMA/GOP/VMM/NT integration requirements and Windows 98 architecture principles, explicitly approved implementation and all local actions, and required parallel agents plus cooperation with other chats. Working source and reproducible execution take precedence over a proposal-only result.

Windows 98 is the product OS. Its real VMM, VxD, USER/GDI, Win16/Win32, Explorer and desktop remain authoritative. ShizukuDOS modernizes and replaces the DOS/boot/hardware foundation. PMA schedules native Shizuku backend workers; VMM schedules Windows threads. They communicate through explicit versioned synchronization. Kernel32 is not Microsoft's KERNEL32.DLL, and Kernel64 is a backend domain rather than a replacement desktop.

## Existing substrate

The latest source already contains preemptive UP kernel schedulers, VMX/EPT domain scheduling, opt-in `native_win98` source, ABI 1.1 SPSC rings and request tracking, Windows VxD and Win64 transport, native NT driver contracts, software graphics and a GOP framebuffer backend with a backbuffer. Extend these; do not generate competing schedulers, object fabrics or empty wrapper DLLs.

The original checkout `e455f01` is stale. Initial read-only findings from that checkout are superseded by current source inspection. The architecture audit file itself describes a historical source epoch and is preserved rather than rewritten.

## Current independent implementation contracts

### Native synchronization

Provide architecture-safe acquire/release atomics and a bounded-storage FIFO ticket lock in shared `kcommon`. Keep `KSPIN_LOCK` pointer-sized and ABI compatible. Migrate actual NT driver spin operations to atomic acquisition/release while preserving the existing UP IRQL/interrupt and contention failure semantics. This does not make the remaining per-CPU/IRQL/DPC model SMP capable. Test mutual exclusion, publication ordering, FIFO admission, non-barging trylock, counter wraparound and freestanding i486 linkage.

### Display safety

Test and repair the existing Kernel64 framebuffer handoff and present paths. Reject a null destination, truncated handoff, unsupported format, misaligned pixel base/pitch, insufficient storage and address overflow before exposing a framebuffer. Reject invalid rectangles and clip valid ones without signed integer overflow. Preserve accepted padded pitches, output on rejected handoffs, and the existing backend/dirty-update behavior. Use actual production functions in host tests, including sanitizer runs. GOP mode selection belongs to the peer firmware lane. Arbitrary PixelBitMask support remains a separate ABI migration until every renderer can consume masks.

### Honest wrapper capabilities

Provide machine-readable module/API/backend/ABI/convention/ordinal/status/threading/synchronization/ownership/evidence metadata for existing concrete paths, and architectural families for unimplemented contracts. Validate against current source and exports, fail on malformed/duplicate/missing bindings, and refuse unsupported WDDM/D3D/GPU or positive native Windows/x64 claims. Capability information may establish a boundary, but never substitutes for runtime acceptance.

## Cross-chat interfaces

Peer `01a0f8c9-163f` owns native priority/quantum/ready queues, UEFI EDID/mode selection and Windows VxD admission/epoch safety. Peer `01a0f8ca-fd5c` proposes independent acceptance validation and cross-subsystem review. Exchange exact file lists and tested commit SHAs through `/root/Win98-Modern/.codex-collaboration/` and `/srv/shizukudos-session-coordination/`. Each chat retains its own index/worktree; integration consumes committed evidence rather than uncommitted assumptions.

## Failure and acceptance rules

No false-success stubs or invented VMM service numbers. Preserve historical receipts, proprietary media privacy, BIOS/CSMWrap/DOS/Kernel32/Kernel64/native-Windows baselines. Native Windows remains conservatively single-vCPU. A component test, host model, original-DOS Windows boot or standalone backend desktop cannot establish actual Windows 98 running on replacement DOS, integrated SMP, modern app GUI, hardware graphics acceleration or complete driver compatibility.

The final requested acceptance still requires real PMA preemption/synchronization/SMP, retained high-resolution GOP, per-process legacy VGA/SVGA, serialized DOS execution, Windows VMM↔PMA synchronization, and a genuine Windows application→wrapper→PMA worker→result→Windows path. Missing gates stay explicitly pending.
