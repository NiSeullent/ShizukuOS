# NTWin32Wrapper9x

The independent application compatibility path for **Windows 98 Shizuku's
Second Edition**. The app-local filename is `NTW32.DLL` to fit an 8.3 filename.
The provider exports ordinary named Win32 functions, not KernelEx tables.
The earlier SRW, InitOnce, tick, resolver and UTF exports are original
GPL-2.0-only code. The vectored-handler exports link the
[ReactOS-reference registry](exception/README.md) through `k32veh.c`.
That registry is not a CPU exception hook and does not claim native Win98 VEH.

Implemented families: seven pointer-sized SRW operations, four InitOnce
operations, observed-wrap `GetTickCount64`, and scoped `GetProcAddress`
redirection, plus UTF-8 `MultiByteToWideChar`/`WideCharToMultiByte`, and
`AddVectoredExceptionHandler` / `RemoveVectoredExceptionHandler`: seventeen
exports in total. The vectored-handler exports implement first/last order and
reject a null callback; they are not installed into the CPU exception path.
Shared readers and an
exclusive writer use 32-bit atomic acquire/release ordering; contention blocks
through native `Sleep(1)`. A zero-delay Sleep leaves a waiter runnable, so it
cannot be the only backoff when a lower-priority owner needs to run. The
[documented Sleep contract](https://learn.microsoft.com/en-us/windows/win32/api/synchapi/nf-synchapi-sleep)
does not promise an exact one-millisecond delay; the native timer resolution
can increase contention latency. There is no fairness guarantee, recursive acquisition,
cross-process use, condition-variable integration or owner tracking.
`GetTickCount64` serializes 32-bit samples and counts observed wraps. It cannot
recover wraps before DLL load or multiple wraps between calls; this limitation
bars a full native-equivalence claim. The seven native imports are `Sleep`,
`GetTickCount`, `GetModuleHandleA`, `GetProcAddress`, `SetLastError`,
`MultiByteToWideChar` and `WideCharToMultiByte`.
There is no CRT dependency.

The original InitOnce implementation provides synchronous and asynchronous
initialization, publication of an aligned context, and retry after callback
failure. See [INITONCE.md](INITONCE.md) for concurrency, error-policy and
native-equivalence limits. A real calling-convention adapter connects the
portable callback to a Win32 `WINAPI` callback.

The two conversion exports use the [original UTF core](unicode/README.md)
for `CP_UTF8` (65001). Other code pages, including ACP/OEM/UTF-7, pass every
argument unchanged to the original KERNEL32 imports; their behavior remains
that of the installed Windows version. UTF-8 accepts zero flags for U+FFFD
replacement, or `MB_ERR_INVALID_CHARS` / `WC_ERR_INVALID_CHARS` for strict
rejection. UTF-16 surrogate pairs and every Unicode scalar are supported.
The `WideCharToMultiByte` default-character arguments must both be NULL for
UTF-8. This does not implement locale tables, normalization, or case mapping.

Positive source counts process exactly that many units, including embedded
NULs; `-1` scans through the first NUL and includes it in the result. Zero and
other negative source lengths fail. Capacity zero queries the full length;
other negative capacities fail. Identical source/destination pointers fail
even for queries, while unrelated destination values are ignored at capacity
zero. Scanning has no fixed string-length limit, but rejects address/count
overflow. UTF-16 storage must be naturally aligned; active source/output
ranges must be disjoint. The caller supplies accessible, stable memory.

UTF errors return zero and set LastError to 1004 (flags), 1113 (malformed
strict input), 122 (insufficient or incorrectly NULL output), or 87 (invalid
parameters, overlap, or unrepresentable result). Successful UTF-8 conversion
preserves LastError. Validation and counting precede output, so failures leave
the destination unchanged. Output counts above `INT_MAX` are rejected before
writing. Maximal-subpart replacement, full-range overlap rejection, alignment,
failure precedence, and extreme-count error mapping are explicit project
policies whose exact native Windows equivalence remains unverified.

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
InitOnce callbacks, UTF-8 strict/replacement/query/NUL behavior, and native
ACP delegation; success writes
`NTWPROBE.LOG` in its working directory and returns zero. This repository does
not contain a new Win98 guest pass for these artifacts yet.

The preparer writes a new `.ntwimp` section with native/provider descriptor
runs, retaining original IAT addresses so application instructions remain
unchanged. It unbinds imports using the original lookup table. The original
file is never overwritten. `routes.json` is the exact implemented routing
allowlist; exported names and the routing list are tested for equality.
Unsupported imports remain unresolved by this provider. There is no claim
that preparation makes an arbitrary modern application run.

The initial subset rejects PE32+, signed images, CLR, malformed TLS, malformed
load configuration, non-RVA delay imports, unsupported loader flags, and
Control Flow Guard without a validated function table. A complete 24-byte TLS
directory, a consistent load-configuration directory, and RVA-based delay
imports are preserved rather than stripped. Subsystem versions above 4.10 are
retained and are not rewritten to 4.10; `stock_win98_loader_accepts_subsystem`
records that the stock Windows 98 loader still rejects them. DYNAMIC_BASE and
NX_COMPAT are retained. NX is not enforced and ASLR is not implemented.
No signature removal or silent version downgrade occurs. API sets, dependent-DLL recursion and
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

The UTF suite exhaustively roundtrips all 1,112,064 Unicode scalars, with
15,578,938 assertions per normal/sanitized run and an independent host-codec
comparison. `python3 platform/abi32/build.py` additionally executes the actual
linked DLL's x86 stdcall exports at preferred and relocated bases. Its UTF
checks include output preservation, errors, dynamic lookup and native import
forwarding. Host service mocks establish CPU/ABI behavior, not native Windows
error parity or Windows 98 loading.

Original implementations derive behavior from these public specifications:

- [PE/COFF import format](https://learn.microsoft.com/en-us/windows/win32/debug/pe-format)
- [SRW semantics](https://learn.microsoft.com/en-us/windows/win32/sync/slim-reader-writer--srw--locks)
- [GetTickCount64](https://learn.microsoft.com/en-us/windows/win32/api/sysinfoapi/nf-sysinfoapi-gettickcount64)
- [GetProcAddress](https://learn.microsoft.com/en-us/windows/win32/api/libloaderapi/nf-libloaderapi-getprocaddress)
- [MultiByteToWideChar](https://learn.microsoft.com/en-us/windows/win32/api/stringapiset/nf-stringapiset-multibytetowidechar)
- [WideCharToMultiByte](https://learn.microsoft.com/en-us/windows/win32/api/stringapiset/nf-stringapiset-widechartomultibyte)
- [Unicode encoding forms and maximal subparts](https://www.unicode.org/versions/Unicode17.0.0/core-spec/chapter-3/)

Legacy provider code remains in the repository as attributed historical work;
the independent build does not compile it. Replacing those implementations is
tracked by foundation and API families, not by relabeling their binaries.
