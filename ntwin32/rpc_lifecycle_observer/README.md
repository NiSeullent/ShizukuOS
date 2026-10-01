# RPCRT4 lifecycle observer (native proof pending)

This separately built diagnostic observes the unchanged Korean Windows 98 SE
RPCRT4 image whose SHA-256 is
`3ec2a0156d76fabec725b55a40f438c7260a8af14c3c35e2e6501c3d4d14f5bf`.
It does not implement a replacement RPC service or correct the observed VLC
exit fault. Licensed Microsoft binaries are neither distributed nor modified.

Two local execution debug registers observe the DLL entry at RVA `0x15a4`
and the six-byte `mov [0x7fbdc02c],edi` at RVA `0x804c`. The latter reports
the **pre-store EDI and previous field**, not a completed zero write. At each
owned first-chance hardware event it preserves EIP and all integer/segment
registers, sets RF, clears only the owned DR6 event bit, and reads the context
back before continuing the original instruction. RF transparency still needs
the separately owned RPFIX/RPCFIX native fixture; host checks cannot establish it.

Admission requires the genuine LOAD_DLL opened file's whole hash plus the
actual process base, PE geometry/timestamp and relocation-adjusted instruction
windows. A missing file handle cannot be replaced by a guessed name or backing
path. Existing and newly created debug-event threads receive the same two
breakpoints; conflicts, limits, missing context access, identity gaps or counter
overflow make coverage incomplete. Windows owns debug-event process/thread
handles until continued exit; this observer closes only image file handles.
It restores its original DR0/1 slots on an observed unload only after confirming
their addresses/type/enable fields still belong to this observer. DR2/3 and
unrelated DR6/DR7 changes remain untouched; pre-existing meaningful DR6 status
prevents initial admission. It rearms after a new admitted load. First- and
second-chance exceptions otherwise stay with the
original OS. The sole exception is the pinned native initial KERNEL32.DebugBreak
event, allowed once on the initial thread at its exact `CC C3` export.

No target termination is requested. A 600-second guest budget marks the trace
incomplete while continuing events. Uncertain context writes or event
continuation hold the paused event for the separately controlled outer VM cap;
Win98 has no assumed modern safe-detach API. Report I/O failure also prevents
trace completion. A complete trace with an actual process exit is **not** a
normal application exit verdict; the child's original exit/fault/UI must be
reviewed separately. Debugger scheduling itself can influence a teardown race.

Build only in a fresh private output using `build.py --out <repo>/build/<new>`;
run portable controls with `test.py --build <output> --out <new-host-output>`.
Neither command starts a VM or executes any Windows image. The eventual owned
fixture command is `C:\VXDLAB\RPCOBS.EXE --fixture --log C:\VXDLAB\RPCDBG.LOG`.
The fixed VLC mode directly starts the exact preserved VLC executable and video
with the previously used switches; it does not precede it with QTLOAD.

The event/handle and exception contracts are from Microsoft's
[WaitForDebugEvent](https://learn.microsoft.com/en-us/windows/win32/api/debugapi/nf-debugapi-waitfordebugevent),
[ContinueDebugEvent](https://learn.microsoft.com/en-us/windows/win32/api/debugapi/nf-debugapi-continuedebugevent),
and [LOAD_DLL_DEBUG_INFO](https://learn.microsoft.com/en-us/windows/win32/api/minwinbase/ns-minwinbase-load_dll_debug_info).
These current documents do not themselves prove Win98 behavior. RF instruction
breakpoint resume is documented by Intel's
[architecture manual](https://www.intel.com/content/dam/www/public/us/en/documents/manuals/64-ia-32-architectures-software-developer-vol-3b-part-2-manual.pdf).
