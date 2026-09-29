# Native GDI software presentation probe

This original component belongs to **Windows 98 Shizuku's Second Edition**.
`NTWGPROB.EXE` links the unchanged NTWDDMWrapper9x software core to an
application-owned GDI bitmap. It has been built and checked on the host;
**native Windows 98 execution remains unverified**.

The executable requests a 320 × 200 top-down, 32-bit `BI_RGB` DIB. Its byte
layout matches `NTWG_PIXEL_XRGB8888`: blue, green, red, unused high byte. Core
allocations use `HeapAlloc`/`HeapFree`. The adapter clears the DIB after binding,
waits for preceding GDI use before CPU writes, and presents through
`BitBlt(SRCCOPY)` plus `GdiFlush` in `WM_PAINT`. All calls execute on one thread.

This establishes an application-level integration path. It does not replace
the Windows display driver, map physical video memory, implement WDDM, load
vendor miniports, accelerate a GPU, provide Direct3D, or change display modes.
The executable uses native `KERNEL32`, `USER32`, and `GDI32`; it imports neither
KernelEx nor a replacement system DLL. It is also independent of `NTW32.DLL`.

## Build and host tests

From the repository root, with existing Python 3, Clang and i686 MinGW tools:

```sh
PYTHONDONTWRITEBYTECODE=1 python3 ntwddm/win98/test.py
PYTHONDONTWRITEBYTECODE=1 python3 ntwddm/win98/build.py
```

These commands write only `ntwddm/win98/build/`. They install nothing and run
no Windows binary or VM. `test.py` runs the real portable core and adapter with
an independently allocated bitmap and injected platform failures. The normal
and ASan/UBSan variants each pass **398,287 checks**. Coverage includes full
initial clearing, odd dimensions and padded rows, snapshot-correct overlapping
blits, partial presents and untouched pixels, CPU fences and invalidation,
double open/close, mapped-surface destruction refusal, allocation failures,
partial DIB creation, sync/paint/release failures, retained cleanup ownership,
and retry after failed teardown. The native GDI callbacks are not executed by
these tests.

`build.py` produces `build/NTWGPROB.EXE` with an original entry point and memory
support routines, no CRT, and `-march=i486` without SSE/MMX. It parses the PE32
image, checks GUI/OS version 4.10, rejects TLS/delay imports/CLR/load configuration,
and checks every imported name against an explicit classic API allowlist.
The source-bound build receipt includes the executable and build-log hashes.
Host receipts distinguish their results from unexecuted native GDI behavior.
Compiler CPU flags and PE inspection do not independently prove instruction
execution on a physical i486.

## Native run contract

On an authorized, disposable, clean installed Windows 98 guest, copy the EXE
to a writable directory and run it there. It creates `NTWGPROB.LOG`, displays
four colored regions after an overlapping copy, repeatedly repaints, and exits
after approximately five seconds or an earlier close request. The window has a
fixed client size; resizing, scaling and display mode changes are not implemented.
The polling message loop has a five-second deadline with bounded message batches.
An individual hung native API cannot be interrupted by that same thread, so a
guest supervisor must still enforce its external execution deadline.

The log format uses fixed field names and decimal values, without wall-clock
timestamps or pointer addresses. Paint count and OS/display values depend on
the actual run. The self-test verifies DIB bytes against a coordinate-based
oracle, checks an expired fence after rebinding, and verifies that WDDM/D3D
capability requests remain unsupported. The probe records OS identity, display
depth, pixel checks, successful native paints and cleanup. A failed operation
records its stage; `LAST_ERROR` is diagnostic and may be stale for failures
originating in the portable core.

Exit codes are **0** for completed pixel/GDI/cleanup checks, **1** for a failed
check or native operation, and **2** for log I/O failure. A partial log is not a
pass. Accept native Win98 evidence only when the process exits 0, the complete
log has `WIN98_IDENTIFIED=1`, `PIXEL_CONTRACTS=PASS`, at least one successful
paint, `CLEANUP=PASS` and `RESULT=PASS`, and the tested executable hash matches
its build receipt. Capture the visible window separately: a byte-correct DIB
does not itself establish visible scanout. On low-color displays, GDI may
quantize/dither screen colors; the exact pixel oracle applies to the 32-bit DIB.

CPU-copy fences cover completed writes to application memory. GDI success is
reported separately, and neither establishes vblank, atomic presentation or
physical GPU completion. On cleanup failure the adapter retains ownership for
an explicit retry; the probe logs failure and then exits, allowing Windows to
reclaim its process resources. It does not report that fallback as successful
explicit cleanup.

Private guest media, checkpoint archives and CI integration are managed outside
this directory. Consult their current manifests and lab receipts for whether
this exact executable is included or executed; this build does not update them.

## Public contracts and provenance

All source in this directory was independently authored for this project and
is GPL-2.0-only. No Microsoft, KernelEx, Wine, ReactOS or vendor implementation
was copied. `adapter.c/h` implement the platform ownership contract;
`selftest.c` supplies an original coordinate oracle; `probe.c` supplies the
native callbacks, window and logger; the test/build scripts verify the declared
scope. The linked software core and freestanding memory routines retain their
own adjacent provenance. MinGW supplies declarations and import libraries for
native operating-system services, not a bundled operating-system implementation.

The design follows Microsoft's public contracts for
[CreateDIBSection](https://learn.microsoft.com/en-us/windows/win32/api/wingdi/nf-wingdi-createdibsection),
[top-down BGRX bitmap layout](https://learn.microsoft.com/en-us/previous-versions/dd183376(v=vs.85)),
[BitBlt](https://learn.microsoft.com/en-us/windows/win32/api/wingdi/nf-wingdi-bitblt)
and [GdiFlush](https://learn.microsoft.com/en-us/windows/win32/api/wingdi/nf-wingdi-gdiflush).
Current Learn support tables begin at Windows 2000; those tables do not validate
this executable on Windows 98. Native export availability and behavior require
the actual guest run. Microsoft documents WDDM as beginning with
[Windows Vista](https://learn.microsoft.com/en-us/windows-hardware/drivers/display/windows-vista-display-driver-model-design-guide).
