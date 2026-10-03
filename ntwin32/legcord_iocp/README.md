# Legcord/Node completion port provider (LCIOCP.DLL)

SPDX-License-Identifier: GPL-2.0-only

Windows 98 KERNEL32 has no I/O completion ports. Node 24's libuv event loop
(`src/win/core.c`) is built on `CreateIoCompletionPort`,
`PostQueuedCompletionStatus` and `GetQueuedCompletionStatus(Ex)`; `uv_async_send`
and every threadpool completion (all `uv_fs_*`, DNS, `uv_queue_work`) arrive as
posted packets. Without a port the loop cannot even initialize, so this is a
hard startup blocker for the Electron main process that Legcord runs in.

This leaf provider implements the posted-packet subset with Win95/98 primitives
only (critical section, counting semaphore, `WaitForSingleObject`):

* `lc_iocp.c/.h` - portable core: 64 generation-bound ports, 4096 shared packet
  slots, FIFO delivery, multi-entry dequeue with exact token accounting, bounded
  `ERROR_NO_SYSTEM_RESOURCES`, `WAIT_TIMEOUT`, and close that discards packets
  and wakes blocked waiters with `ERROR_ABANDONED_WAIT_0`.
* `lc_iocp_native.c` + `.def` - PE32 `LCIOCP.DLL`, exports `ShizukuLc_*` with
  the NT argument/failure contracts; `OVERLAPPED_ENTRY` layout statically checked.
* `lc_iocp_host_test.c` - real-thread host regression; `check.py` runs it and
  cross-links the DLL, enforcing a KERNEL32-only Win95/98 import allowlist.

Truthful gaps (no placeholder success):

* Associating files/sockets/pipes returns `ERROR_NOT_SUPPORTED`. Win98 has no
  overlapped disk I/O; TCP/pipe handles need a Winsock2 event / worker bridge.
  libuv TCP, pipes and TTY therefore still fail at their association call.
* Alertable `GetQueuedCompletionStatusEx` returns `ERROR_NOT_SUPPORTED`.
* `NumberOfConcurrentThreads` is accepted only as a hint and not enforced.
* Handles are provider-private; the libuv port must close them with
  `ShizukuLc_CloseIoCompletionPort`, not `CloseHandle`.

Evidence so far is host-only (ASan/UBSan and TSan runs of the core) plus a static
PE32 link/import/export check. The DLL has not been loaded on Win98, libuv has
not been rebuilt against it, and no Electron/Legcord/Discord operation has run.

## ntdll providers (lc_ntdll.[ch], lc_ntdll_native.c)

libuv 1.52.1 `uv__winapi_init` aborts unless ntdll exports RtlNtStatusToDosError,
NtDeviceIoControlFile, NtQueryInformationFile, NtSetInformationFile,
NtQueryVolumeInformationFile, NtQueryDirectoryFile, NtQuerySystemInformation and
NtQueryInformationProcess exist (RtlGetVersion is optional). LCIOCP.DLL exports
them as `ShizukuLc_*` and the `UV_SHIZUKU_LCIOCP` winapi.c hunk resolves them
from the DLL with ANSI lookups (Win98 has no ntdll and `GetModuleHandleW` is a stub).

* RtlNtStatusToDosError: documented NTSTATUS table, FACILITY_NTWIN32 forms
  (0xC007xxxx / 0x8007xxxx, as written by lc_sock.c), unmapped -> ERROR_MR_MID_NOT_FOUND.
* Mapped to real Win98 calls: FileBasic/Standard/Position/All query, FileBasic times
  / EndOfFile / Position set, FileFsVolumeInformation serial (from
  GetFileInformationByHandle), ProcessBasicInformation for the current process
  (parent via Toolhelp32), RtlGetVersion (GetVersionExA).
* Exact failures otherwise: NtQueryDirectoryFile and NtQuerySystemInformation
  STATUS_NOT_IMPLEMENTED, NtDeviceIoControlFile STATUS_INVALID_DEVICE_REQUEST,
  unsupported info classes STATUS_NOT_IMPLEMENTED, attribute changes / rename /
  disposition STATUS_NOT_IMPLEMENTED before any side effect.
* Documented deviations (no Win98 source): FileAllInformation reports an empty name and
  zero Ea/Access/Mode/Alignment; AllocationSize is the size rounded to 512 bytes;
  ChangeTime equals LastWriteTime; DeletePending is always 0; volume creation time and
  label are 0/empty.

## Shutdown contract (close is quiescent)

`ShizukuLc_CloseIoCompletionPort` wakes blocked getters (they fail with
`ERROR_ABANDONED_WAIT_0`) and returns only after the last getter has left the port
and the context lock (per-port drain semaphore, re-entry orders after the getter's
final `LeaveCriticalSection`). It blocks without bound, so do not call it from a
thread a getter depends on. `lc_iocp_open_ports` falls at the START of a close;
DLL detach uses `lc_iocp_busy` (open + closing + occupied) and leaks the lock rather
than delete it under a live getter. If the backend refuses the wake or the drain
wait fails, the slot is retained forever and the error is returned.

Required unload order for the libuv integration:
1. stop producers (no more `PostQueuedCompletionStatus`, socket I/O or `closesocket` callers);
2. cancel or drain outstanding socket requests (lc_sock worker idles out);
3. join every thread that may be inside `ShizukuLc_GetQueuedCompletionStatus(Ex)`;
4. `ShizukuLc_CloseIoCompletionPort` on each port (returns when quiescent);
5. only then `FreeLibrary(LCIOCP.DLL)`. A returned getter may still be executing the
   last instructions of provider code until it is joined, so step 3 precedes step 5.

Regression: `lc_iocp_quiesce_test.c` frees the lock and context right after close and
joins getters afterwards (ASan use-after-free / TSan race if violated), run by `check.py`.
