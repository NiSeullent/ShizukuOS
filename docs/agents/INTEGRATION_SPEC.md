# Integration requirements

The user's two supplied architecture documents are the design authority. Windows 98 is the real product OS, including its VMM, VxD, USER, GDI, Win16, Win32 and Explorer. ShizukuDOS modernizes the DOS, firmware and hardware foundation. Shizuku Kernel32 is not Microsoft KERNEL32.DLL; Kernel32 and Kernel64 are auxiliary backend/service domains. Normal product boot must eventually reach the real Windows 98 desktop.

## Scheduling and ownership

Extend the existing preemptive native scheduler, using real saved contexts and interrupt-driven execution. Preserve VMM's separate scheduling decisions and legacy Win16 serialization. Native priority, quantum, wait/signal/timeout/cancellation and lifetime policies must be exercised by executing threads. Integrated SMP requires per-CPU contexts, stacks, IRQ/IPI handling and synchronization of shared memory/object/device state; a standalone AP probe does not establish it.

Non-reentrant DOS services need an explicit serialized ownership boundary. A host-side lock model or a DOS version string does not establish the actual DOS/VMM contract. Actual bridge wait/signal requires inspected public VMM contracts and live peers, not invented service numbers.

## Firmware and display

Select a supported, safe high-resolution GOP mode before ExitBootServices. Use validated EDID preference where available, then the requested resolution ladder, then validated firmware fallback. Respect pitch, framebuffer extent, pixel format and bounded memory use. After handoff, GOP remains the physical backend; Windows USER/GDI stays the window/desktop authority. Legacy VGA/SVGA becomes per-process virtualization through shadow VRAM/composition when implemented, not physical VGA ownership changes.

## Compatibility transport

Reuse the existing SHZ ABI 1.1/channel2 and NTWRAP9X VxD. Preserve binary compatibility. Concurrent/reentrant requests must not corrupt shared scratch/ring/pool state. A response is acceptable only for the live epoch and expected source/destination, and only a matching response may release request resources. Queue failures and unsupported operations return deterministic errors. Capability reporting distinguishes implementation state from actual execution evidence.

## Validation and provenance

Tests must execute the actual changed path: host models validate bounded algorithms; fresh freestanding builds validate linkage; QEMU kernel/OVMF boots validate component execution; only actual Windows cold boot and native application requests validate Windows integration. Record commands, failure outputs, source/artifact/input hashes and unresolved gates. Do not overwrite historical receipts or distribute proprietary media. No source-count, export-count or successful stub result establishes compatibility.
