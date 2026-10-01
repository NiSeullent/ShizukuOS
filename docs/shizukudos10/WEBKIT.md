# ShizukuDOS 10 — WebKit on Kernel64 (WEBKIT)

Goal: Internet Explorer's engine becomes "Trident+WebKit". WebKit (<https://github.com/WebKit/WebKit>) is the layout and
JavaScript engine in place of Wine's Gecko; the Trident COM/DOM API layer on top is agent W2's. This page covers the
WTF/JavaScriptCore part (agent W1): the toolchain decision and JavaScriptCore on the Kernel64 Win64 runtime. WebCore
and WebKit proper (agent W3) add their own sections. Status and evidence per milestone: `reports/W1.md`.

Evidence kinds follow `BASELINE.md`. Everything marked GUEST_RUN ran under QEMU **TCG** in a cloud container without
`/dev/kvm`.

## 1. Upstreams (pinned in `shizukudos/upstream/manifest.json`)

| name | commit | fetch | licence |
|---|---|---|---|
| `webkit` | `5c289247285a71147ba4e7fd213394d68dc44da9` (main, 2026-09-30) | shallow, `--filter=blob:none`, sparse: top-level files, `Source/CMakeLists.txt`, `Source/cmake/`, `Source/WTF/`, `Source/JavaScriptCore/`, `Source/bmalloc/`, the files (not subdirectories) of `Tools/Scripts/` (`hmaptool`, `webkit-build-directory`, used by the CMake build), `JSTests/stress/` | see below |
| `icu` | `457157a92aa053e632cc7fcfd0e12f8a943b2d11` (tag `release-77-1`; the pin W3 made for WebCore's ICU, so JavaScriptCore and WebCore use one ICU) | shallow | Unicode-3.0 AND ICU |
| `mingw-w64`, `llvm-project-runtimes` | `de62c283…` (v13.0.0), `c13b7485…` (llvmorg-18.1.3) | shallow (entries and `deps/toolchain.py` by W3) | ZPL-2.1 and others / Apache-2.0 WITH LLVM-exception |

Nothing of either tree is committed here. Local changes to WebKit are `.patch` files under
`shizukudos/win64/webkit/patches/`, listed in the manifest's `webkit.patches` and applied by `build.py` after the files
they touch are restored to the pinned commit.

### Licence of the WebKit tree, per file

`shizukudos/win64/webkit/licscan.py` classifies the grant text in the first 8 KB of every source file of the three
directories JavaScriptCore is built from (pinned commit above; `build-result.json` carries the same table):

| directory | BSD-2-Clause | BSD-3-Clause | LGPL-2.0-or-later | LGPL-2.1-or-later (+BSD-3) | other | no grant found |
|---|---|---|---|---|---|---|
| `Source/WTF` | 698 | 80 | 97 (+1 with BSD-3) | 1 (`DateMath.cpp`) | 197 ICU headers (Unicode-3.0); 4 MPL-1.1/GPL-2.0/LGPL-2.1 tri-licence (`DateMath.h` and relatives); Apache-2.0 3; MIT 3; ISC 1; mixed MIT/BSL-1.0 (Brigand, Variant, fast_float) 5; BSD-2+MIT 5 | 12 (scripts) |
| `Source/JavaScriptCore` | 3266 | 103 (+1 with MIT) | 188 | 1 (`JSDateMath.cpp`) | MPL tri-licence 1; MIT 3; BSD-2+ISC 1; BSD-2+MIT 1 | 14 (scripts, generated tables) |
| `Source/bmalloc` | 622 | 5 | — | — | ISC 1; MIT 6 (mimalloc) | 124 (libpas headers without a grant, docs) |

So the manifest records `BSD-2-Clause AND BSD-3-Clause AND LGPL-2.0-or-later AND LGPL-2.1-or-later AND (MPL-1.1 OR
GPL-2.0-or-later OR LGPL-2.1-or-later) AND ISC AND MIT AND Apache-2.0 AND BSL-1.0 AND Unicode-3.0`. The LGPL files (the
KDE-derived lexer, parser, runtime objects and `HashTable`) make a linked `jsc.exe`/JavaScriptCore **LGPL-2.0-or-later
as a whole**; shipping it requires offering the corresponding source (the pinned tree plus our patches), which
`shz.py package` already does for every fetched upstream.

## 2. Toolchain (decided by experiment)

**Decision (revised 2026-09-30 ~09:50 UTC): the shared WebKit toolchain of `shizukudos/win64/webkit/deps/toolchain.py`
— clang 18 for `x86_64-w64-mingw32`, a mingw-w64 v13 sysroot whose headers and CRT are built for the UCRT
(`--with-default-msvcrt=ucrt`), compiler-rt builtins, and libc++/libc++abi/libunwind 18 built with that sysroot and
shipped as `libc++.dll` and `libunwind.dll`.** It was written by agent W3 while this branch did not exist yet; W1 adopts
it (verbatim, including its two llvm-project patches and the `shzucrt_fix` shim) so that JavaScriptCore and WebCore are
built by one toolchain with one C++ runtime. This is candidate A of the task ("llvm-mingw style") as stated. The first
decision (clang + Ubuntu's GCC 13 libstdc++, below) was withdrawn because the full JavaScriptCore link proved it wrong;
the experiments that led to each decision are kept here.

Requirements checked first: WebKit at the pinned commit requires GCC ≥ 13.1 or clang (it still supports clang 18 for
the GTK/WPE ports: `Source/cmake/WebKitCompilerFlags.cmake`). Container: clang 18.1.3, lld 18, CMake 3.28, Ninja 1.11,
mingw-w64 11.0.1 with GCC 13.2 (Ubuntu packages; used only in the withdrawn variant).

### 2.1 Experiments

The C++ probe `webkit/tests/probe_cxx.cpp` (`std::vector`/`std::map`/`std::string`, four `std::thread`s under a
`std::mutex` with an atomic counter, a `thread_local`, a thrown and caught `std::runtime_error`, `snprintf("%.3f")`; exit
0 only if every value is right) was built each way and run in the guest with
`python3 shizukudos/tests/run_k64_webkit.py probe --exe <exe> --expect "PROBE v=100"`. `build.py --probes` rebuilds the
probes with the adopted toolchain (`build/shizukudos/win64/webkit/out-probes/`); every import is checked against the
exports of the Shizuku DLLs by `webkit/importcheck.py` (API sets resolved with `kernel64/apiset_contracts.txt`).

| # | stack | guest result |
|---|---|---|
| A1 (withdrawn) | clang 18 gnu target + Ubuntu's libstdc++ 13 (static) + mingw-w64 11 UCRT import library, CRT objects from Ubuntu's msvcrt build | probe **PASS** 6 of 7 runs; one run hung (a worker thread at its first `thread_local` store; reports/W1.md "Observed"). **But the full JavaScriptCore link failed** on three ABI mismatches of that libstdc++ with clang in UCRT mode: (1) `std::type_info::operator==` defined twice (GCC's mingw target predefines `__GXX_TYPEINFO_EQUALITY_INLINE=0`, clang does not); (2) `std::__once_call`/`__once_callable` undefined — libstdc++ was built with GCC's *emulated* TLS (`__emutls_v.*`), clang references native TLS symbols; (3) `std::codecvt<wchar_t,char,_Mbstatet>` undefined — under the UCRT headers `mbstate_t` is the `_Mbstatet` struct, libstdc++ was built with msvcrt's `int`, so the mangled names differ. (1) can be patched over; (2) and (3) are properties of that prebuilt library |
| A2 (withdrawn) | GCC 13 mingw-w64 + libstdc++, default libraries spelled out with `-lucrtbase` | probe **PASS**; not pursued (same library, and WebKit's Windows code paths are written for clang) |
| A3 | clang gnu target, C, `__thread` in the main and a `CreateThread` thread (`probe_tls.c`) | **PASS** (native TLS through the PE TLS directory works in the Kernel64 loader) |
| A4 | clang gnu target, `__try/__except` around a null store (`probe_seh.c`, `-fms-extensions`) | **FAIL as a toolchain property**: clang 18 accepts `__try` on this target but emits no handler (no handler flag in `main`'s unwind info), so the fault is unhandled (`c0000005`). WebKit's two uses are MSVC-only after patch 0001 |
| A5 (adopted) | `deps/toolchain.py`: clang 18 + mingw-w64 13 UCRT sysroot + libc++ 18 DLLs | W3's guest run `t_tc_cxx` PASS 16 (exceptions through three frames, a throw inside libc++.dll, `exception_ptr` across threads, 4 threads × 50 throws, condition variables, iostreams, chrono, `std::filesystem`), `t_tc_c` PASS 13 (W3 report §1). The probes of this page rebuilt with it: see reports/W1.md |
| B | clang `--target=x86_64-pc-windows-msvc` + microsoft/STL `main` (`f023531`, Apache-2.0 WITH LLVM-exception) against the Shizuku `ucrtbase`/`vcruntime140`/`msvcp140` | **does not compile**: `yvals_core.h:526: fatal error: 'vcruntime.h' file not found`. The STL headers include 60 headers they do not ship (`vcruntime*.h` from the MSVC toolset; `corecrt*.h`, `crtdbg.h`, `sal.h` and the C headers from the Windows SDK UCRT), all under Microsoft licences and not available here; the STL's out-of-line part is `msvcp140.dll` (+ `_1/_2/_atomic_wait`), of which the Shizuku `msvcp140` has 39 exports. Not run |

Nothing from Microsoft is used in A5 (the task's "no Microsoft SDK binaries may be redistributed" holds).

### 2.2 The link, in detail

- Every image imports the C runtime through the `api-ms-win-crt-*` contracts, which the Kernel64 loader maps to the
  Shizuku `ucrtbase.dll`; C++ comes from `libc++.dll`/`libunwind.dll`, shipped next to `jsc.exe`.
- Functions Windows' ucrtbase has and the Shizuku one lacks (`rand_s`, `__C_specific_handler`, `_assert`, `_wassert`,
  `_*_l` collation/conversion, setjmp/longjmp) come from W3's `deps/shim/shzucrt_fix.c`, merged into the sysroot's
  `libmingwex.a` (asked from K5 in reports/W1.md and W3.md).
- WebKit links `-lDbgHelp` and `-lWinmm` in mixed case; `build/shizukudos/win64/webkit/libalias/` maps them to the
  sysroot's libraries (lld on Linux is case-sensitive). WTF calls DbgHelp only in debug builds.
- After the link, `build.py` checks every import of every output (`jsc.exe`, `wkbatch.exe`, the two runtime DLLs)
  against the Shizuku DLLs and fails the build on a miss.

## 3. JavaScriptCore builds

`python3 shizukudos/win64/webkit/build.py [--config cloop]` (after `python3 shizukudos/win64/build.py`):
the toolchain (`deps/toolchain.py`, if not built yet), the ICU host build, then the static Win64 ICU (common, i18n,
the full data archive), then CMake/Ninja with `PORT=JSCOnly`. Output: `build/shizukudos/win64/webkit/out/` with `jsc.exe`, `libc++.dll`, `libunwind.dll` (+ `wkbatch.exe`, the stress batch driver) and
`build-result.json` (commands, tool versions, patch list, per-image import check, licence table).

| config | CMake options | used for |
|---|---|---|
| `cloop` | `ENABLE_JIT=OFF ENABLE_C_LOOP=ON ENABLE_WEBASSEMBLY=OFF ENABLE_SAMPLING_PROFILER=OFF ENABLE_STATIC_JSC=ON` (bmalloc on Windows uses mimalloc; `USE_SYSTEM_MALLOC` is rejected there by `BPlatform.h`) | M1 |

Compile flags for every WebKit unit (`build.py` `WEBKIT_FLAGS`), each forced by a failure:

- `-mcx16`: libpas uses 16-byte atomics; without it clang calls `__atomic_load/store/compare_exchange`, which no library
  of the sysroot provides (link error). With it they are inline `cmpxchg16b` (every CPU 64-bit Windows 8.1+ runs on).
- `-fms-extensions`: JavaScriptCore's Windows x86-64 `DECLARE_CALL_FRAME` (`interpreter/CallFrame.h`) uses the MSVC
  intrinsic `_AddressOfReturnAddress`, a clang builtin only in MS mode (without it: undefined symbol at link). WebKit's
  own Windows builds are clang-cl, i.e. always MS mode.
- `-DU_STATIC_IMPLEMENTATION`: ICU is linked statically.

Local patches (`patches/0001-mingw-clang-portability.patch`): the MSVC `I64` literal suffix in `CurrentTime.cpp`; the
`<Windows.h>` include spelling in `PathWalker.h` (case-sensitive host); `ThreadingWin.cpp`'s thread-naming `__try` kept
for MSVC (clang's gnu target compiles `__try` without a handler: probe A4); `ProfilerSupport.cpp`'s `open`/`fdopen`
shims kept for MSVC (mingw-w64 declares the POSIX names).

Link: `webkit/compat/shzwk_missing.c` (stand-ins for the Windows functions the Shizuku runtime does not export yet,
each forwarding to the real export when it appears; reports/W1.md lists them with their owners) and the Shizuku
`libntdll.a` ahead of the sysroot's kernel32 import library (for `crt2.o`'s `__C_specific_handler`).

## 4. Running it in the guest

`python3 shizukudos/tests/run_k64_webkit.py [m1|stress|probe]` puts `jsc.exe` (+ any DLLs next to it) on a FAT32 D: disk
and starts it through `shz.autorun` (as `run_k64_chromium.py`). `m1` runs `webkit/tests/m1.js`: closures, JSON with a
reviver, RegExp (named groups, lookbehind, `\p{Script=Greek}`), UTC `Date`, typed arrays and `DataView`, number
formatting, `Math`, classes with private fields, generators, `Proxy`, `BigInt`, Unicode string operations, `Intl` (if
built with ICU) and Promise/async ordering; each part is compared with its expected value, and the last line
`W1-JSC-M1 OK parts=N intl=I fnv=H` is printed from an async continuation. The expected values were checked on the host
with V8 (node 22.22.2: `W1-JSC-M1 OK parts=11 intl=1 fnv=c71a9032`); the runner recomputes the hash from its own copy.
PASS = every part equal, the marker with the recomputed hash, exit code 0, no process fault. `stress` runs the
`JSTests/stress` subset listed in `webkit/tests/stress-subset.txt`, one `jsc.exe` process per test, and reports pass/fail
counts as they are.

**M1 result (GUEST_RUN, QEMU TCG, 2026-09-30):** `jsc.exe` (C loop, 56 MB) printed all 11 parts equal to the expected
values, `Intl` included (ICU 77 with the full data), and `W1-JSC-M1 OK parts=11 intl=1 fnv=c71a9032`, the hash V8
computes; exit 0, no fault, 3.7 s of guest time. Evidence: reports/W1.md, milestone 3.

## 5. JIT (M2) — what Kernel64 must provide

See `reports/W1.md` "Needed from K4" for the exact asks (executable memory with W^X toggling, dynamic function tables,
exception dispatch through JIT frames).

## 6. WebCore and the Shizuku port (agent W3)

Status and evidence per milestone: `reports/W3.md`. Code: `shizukudos/win64/webkit/port/` (port) and
`shizukudos/win64/webkit/deps/` (toolchain, dependencies).

### 6.1 Dependencies

Built statically with the shared toolchain by `deps/build_deps.py` (zlib, libpng, libjpeg-turbo, libwebp, brotli, woff2,
SQLite, libxml2, libxslt, FreeType, HarfBuzz, OpenSSL, curl, libpsl; ICU is W1's static build). Each has a guest check
(`deps/run_deps_guest.py`, one small program per library). Pins and licences are in the manifest.

### 6.2 Why a new single-process port ("Shizuku")

| Candidate | What it needs from Kernel64 | Decision |
|---|---|---|
| Upstream `PORT=Win` (WebKit2) | UI, Web and Network processes with IPC over pipes and shared memory, ANGLE on D3D11, Media Foundation | no: three processes each start JSC/WebCore under TCG, and ANGLE/D3D11 are not available |
| WebKitLegacy on Windows | was removed upstream | not possible at the pin |
| GTK / WPE | GLib, GObject, Cairo or libwpe/EGL, Unix-style loops | no: large non-Windows dependency stack |
| **Shizuku** (`PORT=Shizuku`) | Win32 user32/gdi32 only | **yes** |

Shizuku is `PLATFORM(WIN)` plus `USE(SHIZUKU)` (`port/overlay/Source/cmake/OptionsShizuku.cmake`). WTF uses the Win
port's files (RunLoopWin, a message-only window; verified in the guest by `port/tests/t_wk_msgloop.c`). JavaScriptCore and
bmalloc use the JSCOnly C-loop configuration from W1. WebCore uses the Win port's file list without the ANGLE,
Media Foundation, full-screen and resource-usage files. Everything is linked statically into the program, and
WebKit/WebKitLegacy are off. The port layer (`port/shizuku/`) builds a WebCore `Page` in the same process, as WebCore's own
`SVGImage` does. It paints through `GraphicsContextSkia` into a 32-bit top-down DIB (Skia CPU raster). Window messages
drive the input. Fonts are FreeType through Skia's directory font manager, reading `%WEBKIT_TESTFONTS%` or
`<windir>\fonts` (`port/webcore/FontManagerShizuku.cpp`). Skia's Ganesh/GL code compiles against ANGLE's headers and a
stub EGL (`port/egl/shzegl.c`) whose `eglInitialize` fails, and accelerated buffers are disabled at start. Networking
(R3) uses a `ResourceHandle` on curl.

Upstream changes are kept as patches (`port/patches/`, listed in the manifest as `shizuku_port_patches`) and new files
as an overlay (`port/overlay/`, `shizuku_port_overlay`). `port/build_port.py` restores the patched files, applies
the patches after W1's patches, and refuses an overlay file that exists upstream.
