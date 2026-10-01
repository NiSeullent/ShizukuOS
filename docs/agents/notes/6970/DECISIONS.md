> Local 6970 audit/planning draft preserved after cross-chat ownership discovery. Canonical docs/agents master files are owned by session163f in /root/Win98-Modern-pma-20261002. This draft does not reserve another session's files. See ../../status/6970-master.md for current scope.

# Accepted PMA and Windows 98 architecture decisions

These are user requirements accepted on 2026-10-01, not implementation or completion claims.

## Product and execution authority

Windows 98 is the actual product operating system. Its real VMM/VxD, USER/GDI, Win16/Win32, KERNEL, Explorer, Windows process model and desktop remain first-class components. A replacement desktop or an API-emulated imitation of Windows 98 does not meet the goal.

ShizukuDOS replaces and modernizes the MS-DOS boot/runtime/hardware foundation. Its native shell and GUI are boot, recovery, diagnostics and development environments. Normal final boot is ShizukuDOS -> Windows boot contract -> WIN.COM -> actual VMM -> Windows 98 desktop.

Shizuku Kernel32 is a protected-mode backend service component and is distinct from Microsoft KERNEL32.DLL. Kernel64 supplies Long Mode/x64, modern libraries, driver translation, rendering, storage/network/crypto/media and asynchronous workers. Windows-visible processes, windows and message loops remain owned by Windows 98.

Windows VMM schedules Windows threads; PMA schedules Shizuku native work. Explicit synchronization connects them. Do not force every VMM thread into a PMA thread, double-schedule it, remove VMM or boot an NT kernel to satisfy compatibility.

## Native scheduling requirements

Extend reusable implementation into real preemption with processes/threads/IDs/TCBs, quantum/priority, CPU-local runnable and wait/sleep/blocked queues, context/kernel/user stacks, TLS, terminate/join/yield/sleep/wake/timeout/cancellation and explicit CREATED/READY/RUNNING/BLOCKED/WAITING/SLEEPING/SUSPENDED/TERMINATING/TERMINATED states.

Use architecture-appropriate atomics and shared lock primitives: fair spinlock, mutex/required recursive mutex, semaphore, manual/auto events, condition/RW/barrier/wait queues, completion, timer/waitable timer, work/deferred queues. Document lock ordering and validate it where practical. Normal synchronization must not rely on globally disabling interrupts.

PMA supports BSP/AP initialization, CPU-local state/queues, affinity, load balancing and cross-CPU/IPI wakeups. Keep safe UP and failed-AP fallback. Normal Windows 98 execution stays conservative single-vCPU; experimental multi-vCPU Windows requires a disabled-by-default flag and independent proof.

Non-reentrant DOS services use one serialized gateway tracking InDOS, critical errors, PSP/MCB, SFT/CDS, INT21, driver chains and callbacks. Native concurrency cannot turn arbitrary DOS calls into concurrent kernel entry.

## Display and device ownership

GOP is the primary physical UEFI display. Enumerate supported modes, consult valid EDID, prefer native/preferred resolution then safe 3840x2160/2560x1440/1920x1080/1600x900/1366x768/1280x720/1024x768 choices within firmware/framebuffer constraints. Validate RGB/BGR/bitmask formats, pitch, size, mapping and post-ExitBootServices lifetime; a mode failure preserves a safe firmware path.

The boot/recovery console uses resolution-derived geometry, rasterization, scrolling/cursor, backbuffer/dirty updates, Unicode-safe storage and codepage/input translation. It is not the product desktop. The physical display feeds the Windows 98 display/GDI bridge.

Legacy INT10/VBE, VGA ports/palette and A0000/B0000/B8000 accesses create only the requesting process's legacy video context. Shadow VRAM, text/mode13/planar/VBE rendering and aspect-preserving composition keep physical GOP ownership. Process exit returns the prior display without firmware reconstruction.

Prefer one Shizuku hardware backend with DOS/Windows/NT frontends for storage, xHCI/HID, NIC and graphics. Do not create competing hardware owners or separate wrapper driver stacks.

## Bridge and wrapper fabric

Inspect both sides of the existing VxD/VMCALL/shared-channel implementation before defining layouts. Use public DDK/API contracts with provenance, never invented service numbers.

Versioned messages represent domain/process/thread identity, capability/size/operation/status/flags, monotonic sequence, timeout, payload bounds and explicit owner/permissions/lifetime/generation. Wait/signal/cancel/completion must handle duplicates, lost wakeups, stale response, timeout, process/thread death, peer crash/restart and overflow. Check/enqueue/sleep and signal ordering require explicit atomics.

All NT kernel, driver, PE/runtime, Win32, graphics, storage, USB/input/audio, network, crypto and media wrappers share ABI negotiation, handles/objects/references, errors, tracing, thread/sync model, memory and async ownership. Reuse current implementations. Module names do not authorize empty DLL generation or an entire second Windows/NT kernel.

The per-API manifest records name/ordinal/calling convention/minimum ABI/backend, NATIVE/TRANSLATED/FORWARDED/SOFTWARE/PARTIAL/STUB/UNSUPPORTED status, concurrency/blocking/reentry/DOS/VMM/Kernel64 entry, lock level and actual test status. Unsupported calls return deterministic ABI errors, never fake success.

Graphics supports explicit process/context/frame/surface ownership, bounded workers, fences and async completion. Software rendering is valid when labelled accurately; D3D/WDDM exports alone establish no graphics support.

## Time, memory, sessions and failure

Use calibrated monotonic scheduling time independent of UEFI services after exit; wall time is separate. Audit existing TSC/APIC/HPET/PIT layers before additions. Address spaces, heap/pages/stacks/guard pages, framebuffer/EPT/DMA/shared mappings carry explicit ownership and bounds; do not trust guest pointers.

Sessions separate system workers, Windows desktop and optional compatibility contexts without one global foreground process. DOS contexts isolate PSP/environment/console/video/timer/input/V86 state.

Bootability and compatibility govern feature flags and defaults. PMA initialization attempts safe UP; AP failure leaves BSP usable; GOP failure falls back safely; legacy video failure affects its application; VxD handshake failure permits Windows operation with the bridge disabled.

## Proof and provenance

Acceptance executes real paths: native preemption/synchronization/SMP, GOP >=1024x768 after ExitBootServices, legacy video through GOP, ShizukuDOS -> WIN.COM -> VMM -> Windows desktop, original Win16/Win32 behavior, persistent files and keyboard/mouse/timer/shutdown/reboot. At least one Windows app request must reach a real PMA backend worker and return to that same Windows app before integrated-architecture acceptance.

Preserve all historical pass/fail results and original media. Record upstream repository/revision/file/license/concept/code-copy status. Public-source tests and host component results remain scoped; no false native, x64, WDDM, driver or full DOS completion claims.
