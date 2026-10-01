# Native process-termination notification candidate

`M98EXIT.DLL` is a real OS-loaded, freestanding i486 DLL for native Windows 98.
It does not replace, intercept, or emulate `ExitProcess`. The existing native
mapped-image loader still refuses `ExitProcess`; this candidate is independent
until actual Windows 98 evidence proves its narrower contract.

Explicit initialization validates the real native process EXE and acquires one
extra native module reference outside DllMain. That reference stays owned until
the OS ends the process. Each registered callback must be in a nonwritable
executable section of that EXE, with a borrowed context wholly inside writable,
nonexecutable static EXE data and verified committed native-image pages. Main
stack, heap, manually mapped code, and arbitrary DLL callbacks are refused.
Those address checks prove storage ownership; callers must separately ensure
context consistency and that every callback follows DllMain restrictions.

The registry publishes complete immutable snapshots with one atomic operation.
Eight callbacks and 128 snapshots (including the empty initial snapshot) are
explicit process-lifetime bounds. Snapshots are never reused. Registration and
unregistration serialize with a nonwaiting atomic claim; contention returns
170. Exhaustion returns 8, including unregister, and therefore does not release
the borrowed context. A successful unregister is required before that context
may stop being valid. Tokens are not reused. Process detach atomically seals the
published snapshot, ignores any stopped publisher's mutation claim, and invokes
callbacks in reverse registration order once. It rejects NULL reserved (dynamic
unload/load failure) and every reason except `DLL_PROCESS_DETACH`.

The termination path performs no private-lock acquisition, worker wait, thread
termination, heap/TLS/mapping reclamation, or native DLL load/unload. It forwards
the actual DLL reason and reserved pointer to its native EXE callback. A mapped
graph implementation would need a separately committed static detach plan and
lock-free notifications; it cannot reuse current loader cleanup. PE TLS callback
Reserved is zero, so graph TLS callbacks must not receive the nonNULL DLL value.
Native refs retain mappings; they do not prove that other native dependencies
remain initialized at notification time. An exit during graph attach or a
future graph mutation also requires an independent transaction/lifetime design.

Build and freeze host/native controls into a fresh private output:

```text
python3 ntwin32/process_exit/build.py --out build/process-exit-candidate-v1
```

The build receipt identifies every source, compiler and artifact by SHA-256,
runs real ASan/UBSan host concurrency/fault/publication controls, and rejects
native imports absent from the observed OEM export table. These are host and
compile evidence only. Native execution and application execution remain false.
The preserved official Chromium root's `ExitProcess` import is checked but the
application is never launched or modified by these controls.

`PXSUIT.EXE` runs seven owned `PXPROBE.EXE` children in `C:\VXDLAB`: main/worker
initiated process exit through the imported function and the resolved native
Kernel32 export, explicit unregister rollback, and a parent-owned
`TerminateProcess` negative control, and a real NULL-reserved dynamic unload.
The last uses the separately named `PXUNLD.DLL` fixture variant: it compiles the
same registry/native dispatcher but intentionally omits the permanent pin and
adds a static EXE observation export. Production `M98EXIT.DLL` has neither
test-only behavior. The loaded variant is actually freed with two callbacks
registered; the EXE checks the observed native detach reason/reserved and that
neither callback ran. Every probe uses native EXE static context
and a preopened private log. A victim thread deliberately holds a private lock;
its thread exit state is queried without waiting from the callback. The callback
records actual detach reason/reserved, thread ID and live TLS marker. The
observer DLLs loaded before and after the manager record actual native detach
order. The parent independently watches real child exits, checks the final
reports, and rejects every watchdog-triggered exit. Its own zero exit still
requires independent guest observation.

Windows 98 ordering cannot be inferred from current NT documentation. The
pinned KernelEx source `apilibs/kexbases/Kernel32/process.c` includes an
`ExitProcess_fix` which lowers the caller priority to improve caller-last
behavior. A successful generic notification fixture does not prove that an
arbitrary exiting caller's TLS survives or that Chromium graph notifications
are safe. All four mode logs must be examined before adding any caller-TLS
contract. Both existing installed compatibility routing and direct native
addresses must be identified by the guest trial, not by a host assumption.
The original-export modes use the pinned KernelEx SDK original resolver when
resident, retain its module outside DllMain, validate original Win98 4.10.2222
version, and require the returned executable address to belong to Kernel32.

Primary contracts: [Microsoft ExitProcess](https://learn.microsoft.com/en-us/windows/win32/api/processthreadsapi/nf-processthreadsapi-exitprocess),
[Microsoft DllMain](https://learn.microsoft.com/en-us/windows/win32/dlls/dllmain),
[DLL best practices](https://learn.microsoft.com/en-us/windows/win32/dlls/dynamic-link-library-best-practices),
[PE TLS format](https://learn.microsoft.com/en-us/windows/win32/debug/pe-format).
These references motivate the constraints and do not establish Windows 98
runtime success. No completion claim for Chromium, Legcord, Office, or Steam
follows from this component.
