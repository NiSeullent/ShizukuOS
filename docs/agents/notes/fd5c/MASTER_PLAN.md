# PMA integration master plan — fd5c, 2026-10-02

## Product contract

Actual Windows 98 remains the product OS and owns VMM scheduling, USER/GDI,
Win16/Win32, Explorer and the final desktop. Shizuku PMA owns modern backend
workers; Kernel32/Kernel64 are auxiliary execution domains. Preserve existing
BIOS/UEFI/CSMWrap, standalone kernels, source provenance and historical receipts.
Do not infer native Windows compatibility from host models or exports.

## Current design and implementation plan

Baseline: `a648e9baa1c57289d50e58d3380827bd9239bc52`. This chat coordinates a
bounded integration tranche of the larger user-supplied architecture, alongside
other active chats. It does not claim to complete every subsystem listed there.
The user explicitly grants implementation authority and requires no questions.

1. Audit existing scheduler, firmware/display, DOS/VMM, wrappers and runtime in
   parallel. Completed read-only against the current baseline.
2. Run unchanged ABI baseline. Establish current channel/domain behavior.
3. Three independent agents repair existing paths, with regression failures
   captured before fixes:
   - ABI: reject invalid/overlapping channel regions and unsafe size arithmetic
     before reads/writes, preserving wire structures and valid version 1.1.
   - Supervisor: pending doorbells keep a domain runnable until ACK, including
     already-injected notifications; injection is not acknowledgement.
   - Legacy text: bounds-safe BIOS string writes, reused CP437 glyphs, cursor
     shape/visibility and complete framebuffer cache invalidation.
   - Follow-up client repair: retain per-record handle generations and retire
     exhausted records, preserving the existing public 13-bit encoding.
4. Review each patch independently; compile actual production C in host models
   and freestanding builds. Test GCC strict plus Clang ASan/UBSan where available.
5. Exchange tested commits and findings with chats c957, fada and 163f through
   `/srv/shizukudos-session-coordination` and the base collaboration ledger.
   Integrate compatible peer commits only after reviewing their evidence.
6. Run combined regressions; publish local coherent commits and exact receipts.
7. Import independently reviewed PMA event/wait backend and existing Kernel64
   priority/quantum/aging extension, plus Kernel32 finite-deadline repair.
   Build all four kernel profiles and the actual Supervisor/EFI loader from the
   combined source. Run source-bound focused guests and the integrated runtime
   component; retain any failing integration logs while canonical owners fix
   the cause. Source-bound runner controls remain separate from CPU execution.

## Whole-program roadmap and release gates

Existing UP kernels already execute preemptive threads; extend them rather than
create a second scheduler. Peer 163f adds priority/quantum, EDID/GOP selection and
VxD bridge serialization and Kernel32 process publication. Peer c957 owns native
synchronization helpers and common wrapper capability reporting. An actual DOS
execution gateway remains unassigned; lock helpers do not establish it.
Peer fada owns a versioned PMA payload
service and Kernel64 integration. See OWNERSHIP.md for exact file boundaries.

Remaining architecture work requires integrated AP startup/per-CPU run queues,
affinity/IPI and load balancing; syscall MSR domain isolation; native DOS
serialization entry points; legacy VGA trapping/contexts and mode13h/VBE;
actual VMM wait/completion frontend and Windows process/window lifetimes;
modern hardware/driver contracts and real x64 GUI/runtime acceptance.

Native acceptance requires ShizukuDOS → WIN.COM → VMM → actual Windows98
desktop, bridge enabled/disabled, input, timers, persistent disk I/O, Win16 and
Win32 threading, a real Kernel64 peer and completion path. GOP acceptance needs
post-ExitBootServices high-resolution console and Windows display ownership.
Host tests, original Microsoft DOS controls and standalone loopbacks retain
their actual scope. They cannot satisfy those product gates.
