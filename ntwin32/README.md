# NTWin32Wrapper9x

The independent application compatibility path for **Windows 98 Shizuku's
Second Edition**. The app-local filename is `NTW32.DLL` to fit an 8.3 filename.
The provider exports ordinary named Win32 functions, not KernelEx tables.
All new implementation code here is original GPL-2.0-only; no legacy `src/`
provider, Unicode tables, KernelEx, Wine, ReactOS or third-party runtime is linked.

Implemented families: seven pointer-sized SRW operations, four InitOnce
operations, observed-wrap `GetTickCount64`, and scoped `GetProcAddress`
redirection: thirteen exports in total. Shared readers and an
exclusive writer use 32-bit atomic acquire/release ordering; contention yields
through native `Sleep(0)`. There is no fairness guarantee, recursive acquisition,
cross-process use, condition-variable integration or owner tracking.
`GetTickCount64` serializes 32-bit samples and counts observed wraps. It cannot
recover wraps before DLL load or multiple wraps between calls; this limitation
bars a full native-equivalence claim. The five native imports are `Sleep`,
`GetTickCount`, `GetModuleHandleA`, `GetProcAddress` and `SetLastError`.
There is no CRT dependency.

The original InitOnce implementation provides synchronous and asynchronous
initialization, publication of an aligned context, and retry after callback
failure. See [INITONCE.md](INITONCE.md) for concurrency, error-policy and
native-equivalence limits. A real calling-convention adapter connects the
portable callback to a Win32 `WINAPI` callback.

The redirected `GetProcAddress` intercepts only implemented, case-sensitive
names requested through the real `KERNEL32.DLL` module handle. Other modules,
unknown names and ordinal lookups go to the native resolver unchanged. This
does not manufacture handles or replace the system DLL. An application must
have its resolver import prepared to use this route; calls originating in
unprepared dependencies still use the native resolver.

## Build and prepare

```sh
python3 platform/build.py
python3 platform/test.py
python3 ntwin32/prepare.py input.exe prepared.exe
```

Put the prepared application beside `build/platform/NTW32.DLL` in a **disposable
Windows 98 SE guest with no KernelEx installed**. The generated
`build/platform/NTWPROBE.EXE` tests static imports, dynamic lookup, SRW and
InitOnce callbacks; success writes
`NTWPROBE.LOG` in its working directory and returns zero. This repository does
not contain a new Win98 guest pass for these artifacts yet.

The preparer writes a new `.ntwimp` section with native/provider descriptor
runs, retaining original IAT addresses so application instructions remain
unchanged. It unbinds imports using the original lookup table. The original
file is never overwritten. `routes.json` is the exact implemented routing
allowlist; exported names and the routing list are tested for equality.
Unsupported imports remain unresolved by this provider. There is no claim
that preparation makes an arbitrary modern application run.

The initial subset rejects PE32+, signed images, TLS, load configuration,
delay imports, CLR, unsupported loader flags, newer subsystem requirements,
malformed ranges and insufficient section-header slack. No signature removal
or silent version downgrade occurs. API sets, dependent-DLL recursion and
apps that assume NT internals need subsequent work. Preparing `NTW32.DLL`
itself is rejected: its native loader imports must remain native to avoid
resolver recursion.
Native Windows 98 loading of adjacent IAT descriptor runs is **unverified**.
The host loader model and binutils parsing do not replace that guest test.

## Evidence and provenance

Tests exercise 80,000 concurrent exclusive updates with interleaved readers,
invalid object/lifetime states, wrap detection, all 65,536 ordinal lookup
values, 72 eight-thread InitOnce contention rounds, malformed PE inputs,
non-destructive writes, retained IAT addresses and the actual linked exports.
Address/undefined sanitizers cover the C core. Exact artifacts and hashes are
in ignored `build/platform/manifest.json`.

Original implementations derive behavior from these public specifications:

- [PE/COFF import format](https://learn.microsoft.com/en-us/windows/win32/debug/pe-format)
- [SRW semantics](https://learn.microsoft.com/en-us/windows/win32/sync/slim-reader-writer--srw--locks)
- [GetTickCount64](https://learn.microsoft.com/en-us/windows/win32/api/sysinfoapi/nf-sysinfoapi-gettickcount64)
- [GetProcAddress](https://learn.microsoft.com/en-us/windows/win32/api/libloaderapi/nf-libloaderapi-getprocaddress)

Legacy provider code remains in the repository as attributed historical work;
the independent build does not compile it. Replacing those implementations is
tracked by foundation and API families, not by relabeling their binaries.
