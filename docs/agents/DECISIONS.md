# Architecture decisions — PMA bridge lane

1. Extend existing channel ABI 1.1 with a separately versioned PMA payload.
   Do not change the 64-byte header or invent VMM service numbers.
2. Retain scheduling ownership: Windows VMM schedules Windows threads;
   the existing Kernel64 scheduler runs the service worker. No duplicate scheduler.
3. The service thread serializes its event/owner/wait state. SPSC ring producer
   ownership remains unchanged. Windows client calls require VxD admission;
   multiple native callers must use their existing serialization boundary.
4. Use explicit process/thread/object identities and channel generations.
   Never dereference guest-provided pointers or treat stale identities as live.
5. A signal becomes a retained completion before publication. Full rings
   apply backpressure without losing the wake or completing a wait twice.
6. New unsupported synchronization operations fail explicitly. No fake success
   or broad claim of NT/VMM compatibility based on exported names.
7. Test the same portable service in host and native Kernel64 execution.
   Isolated loopback evidence is distinct from actual Windows 98 execution.
8. Preserve historical receipts. Record new tests with current hashes and time.
9. QUERY exposes the backend monotonic nanosecond clock; finite waits use a
   checked absolute deadline derived from that clock, never an unrelated
   Windows local tick count.
10. Shutdown stops admission immediately, converts accepted waits to retained
    cancellations, and bounds final draining to 5000 ms before the existing
    native domain-exit boundary. Do not modify the Supervisor-owned epoch.
11. Retain PID/TID tombstones with an explicit per-epoch identity budget.
    Exhaustion fails with E_NOMEM; documented higher lifetime generations or
    a coordinated newer channel epoch are required for reuse.
