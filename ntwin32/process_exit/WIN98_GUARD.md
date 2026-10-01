# Native Win98 code ownership candidate

The original v3 source and frozen artifacts remain unchanged. Its actual seven
children exited with code 22 before manager initialization. This is a guard
failure, and proves no callback or thread termination ordering.

The separate native diagnostic v2 ran on the original Windows 98 4.10.2222
kernel. Its independent parent observed a real child exit of zero. Kernel32's
original `ExitProcess` and `GetVersionExA` exports were committed pages owned by
the real Kernel32 allocation, with `PAGE_READONLY` and `MEM_PRIVATE`. Their PE
section had readable and executable flags and no write/discardable flags. A
native EXE callback had the same page protection; EXE static data was writable
and its stack belonged to a different allocation. The unchanged v3 guard refused
these code pages because it expected NT `PAGE_EXECUTE*` values.

The final additive files `original_kernel_win98_v3.c`, `native_win98.c` and
`win98_guard.c/h` handle only this observed distinction. The exact original
`GetVersionExA` lookup is the sole version bootstrap: its pointer must belong to
the actual Kernel32 module, a bounded loaded DLL PE executable/readable section
with no writable or discardable flags, and a committed nonwritable page. The
resolved pointer must also equal the bounded loaded export-directory entry named
`GetVersionExA`; forwarded, duplicated, oversized or unreadable export records
are refused. The
original native version call must report Win98 4.10.2222 before ordinary export
or callback admission can accept Win98's readonly code metadata. This bootstrap
uses the same pinned two-argument KernelEx original resolver when resident.

Callbacks still require the native main EXE and immutable executable PE section.
Borrowed contexts require nondiscardable, writable, nonexecutable EXE static
storage and the matching committed allocation and complete page range. Writable
code pages, guard/noaccess/unknown protections, foreign DLL code, stack contexts,
nonexecutable data, and readonly code used as writable context are refused.
The manager's process-lifetime pin and immutable snapshot dispatch are unchanged.

The host controls recheck the original registry/concurrency corpus and exercise
the new guards against exact OEM headers, observed native page values and fault
controls. Host PASS is not native acceptance. The new native suite preserves all
seven original controls and adds data-as-code and code-as-context negatives.
The frozen v5 fixture subsequently ran on the actual native Win98 GOP desktop.
All seven controls completed their actual child waits: six normal exits were 73,
and the explicit TerminateProcess control exited 74. Both main modes dispatched
the two callbacks on the victim thread itself; both worker modes dispatched them
on the main thread. None dispatched on the initiating caller, and the caller's
TLS marker did not survive in any of the four notification modes. Native
dependency B had already detached, while A had not. Dynamic unload had an actual
NULL reserved pointer and invoked no registered callback; unregister and forced
termination controls also invoked no callback.

The victim's GetExitCodeThread value was FFFFFFFF during every notification.
That is an OS-reported exit state, not proof of physical worker cessation: the
main-mode callback was executing on that same victim. The original compiled
label "other worker terminated before notification" remains in the frozen raw
logs, but must not be read as a physical thread-stop or NT ordering guarantee.
The additive interpretation correlates all actual main, victim and caller IDs
and explicitly records physical worker cessation as unproved.

The bounded evidence is in
`build/process-exit-native-interpreter-20261001T0129-v2/result.json` (SHA256
`fab0e8c00fba8b41b2284f149a0f66ee5fe6820d0caa0acbde893f8a96a6b9f2`).
It binds the original v5 fixture, eight unchanged raw logs, six input readbacks,
23 protected file readbacks, four preserved frames and 31 producer source pins.
Its nine mutated-log refusal controls are host checks, not extra native runs.

This proves only the native EXE/static-context notification fixture. It does not
admit the current manually mapped graph's lock, wait, thread-TLS reclamation or
native dependency cleanup path. Modern WINXP application mode, mapped graph
termination, and the suite's own OS exit still need independent evidence. No
production loader, Chromium, Legcord, LibreOffice or Steam integration is implied.
