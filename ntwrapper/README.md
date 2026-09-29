# NTWrapper9x

Original kernel-side foundations for **Windows 98 Shizuku's Second Edition**.
This code does not use KernelEx, Wine, ReactOS, an NT kernel binary, or a C runtime.

`core.c` implements a bounded object table, access masks, generation-protected
handles, reference leases, close/rundown, manual/automatic-reset events and
atomic nonblocking wait consumption. Closed objects remain allocated until
their final lease ends. A generation-exhausted slot retires instead of reusing
a stale handle. Resource exhaustion and unsupported operations are not success.

The embedding kernel supplies an IRQ-safe, non-reentrant `enter/leave` lock
pair. Initialization and shutdown require exclusive ownership: no concurrent
entry may race context initialization or shutdown. Lease storage starts zeroed,
must not be copied, and is private to its owning caller. The public C structures
are trusted kernel storage, not a userspace marshalling or security boundary.

Build and test from the repository root:

```sh
python3 platform/build.py
python3 platform/test.py
```

The build produces freestanding i486 COFF object/library files in
`build/platform/`. Host tests exercise invalid handles, access denial, close
with a live lease, exhaustion, retired generations and simultaneous consumers.
The separate `shizukudos/uefi` integration can execute this core at CPL0 after
ExitBootServices; its evidence is a different target from Windows 98.
The `shizukudos/uefi32` integration additionally executes it after an actual
x64-to-32-bit protected-mode transition, verified under OVMF/KVM.

The original [native VxD binding](vxd/) now builds `NTWRAP9X.VXD`, with an LE
packager, DDB/control dispatch, VMM page-validation query bridge and a guest
load/query probe. Its host and native i386 assembly tests have passed. In the
[actual Windows 98 V86 loader trial](../docs/VXD_V86_LOADER_TRIAL.md), the frozen
data-SHARABLE candidate passed byte preflight but was rejected with native
error 6 (bad device file). Kernel initialization and VMM service behavior have
no native pass. ReactOS kernel/user exception dependencies for the next binding
are traced in the [exception port](../ntwin32/exception/NATIVE_BINDING.md).

Still required for a Windows 98 kernel extension: a verified VxD/LE loader and
VMM service binding, locked/nonpaged allocations, process-local handle tables,
safe user/kernel request copying, blocking wait queues and thread cancellation,
IRQL/interrupt dispatch, page tables and a driver I/O manager. The current
COFF archive itself is not a VxD, an NTOSKRNL replacement, or a driver ABI;
the separately built VxD is an experimental binding with a bounded query ABI.
`ntw_event_try_wait` returning `NTW_PENDING` never parks a thread.

All code here is independently written, GPL-2.0-only. Public interface references:
[Microsoft event objects](https://learn.microsoft.com/en-us/windows/win32/sync/event-objects),
[object handles](https://learn.microsoft.com/en-us/windows-hardware/drivers/kernel/object-handles).
The C API is deliberately project-owned and does not assert NT binary layout.
