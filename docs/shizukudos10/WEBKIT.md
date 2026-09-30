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
| `icu` | `21d1eb0f306e1141c10931e914dfc038c06121da` (tag `release-78.3`) | shallow, sparse: `icu4c/` | Unicode-3.0 |

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

**Decision: clang 18 `--target=x86_64-w64-windows-gnu` + mingw-w64 11 headers in UCRT mode + GCC 13's libstdc++ (the
`win32` thread-model runtime of Ubuntu's `g++-mingw-w64-x86-64-win32`, linked statically) + lld, importing only from the
Shizuku DLLs (`ucrtbase.dll`, `kernel32.dll`, `ntdll.dll`, ...).** The CMake toolchain file is
`shizukudos/win64/webkit/toolchain-mingw-clang.cmake`.

Requirements checked first: WebKit at the pinned commit requires GCC ≥ 13.1 or clang (it still supports clang 18 for
the GTK/WPE ports, with a `__cpp_concepts` shim for libstdc++'s `<expected>`: `Source/cmake/WebKitCompilerFlags.cmake`).
The container has clang 18.1.3, lld 18, mingw-w64 11.0.1 with GCC 13.2, CMake 3.28, Ninja 1.11.

### 2.1 Experiments

The same C++ probe (`webkit/tests/probe_cxx.cpp`: `std::vector`/`std::map`/`std::string`, four `std::thread`s under a
`std::mutex` with an atomic counter, a `thread_local`, a thrown and caught `std::runtime_error`, `snprintf("%.3f")`; exit
0 only if every value is right) was built each way and run in the guest with
`python3 shizukudos/tests/run_k64_webkit.py probe --exe <exe> --expect "PROBE v=100"`. All probes are rebuilt by
`python3 shizukudos/win64/webkit/build.py --probes` (`build/shizukudos/win64/webkit/out-probes/`), and every import of
each is checked against the exports of the Shizuku DLLs by `webkit/importcheck.py` (API sets resolved with
`kernel64/apiset_contracts.txt`).

| # | stack | link | guest result |
|---|---|---|---|
| A1 | clang 18 gnu target + libstdc++ 13 (static) + mingw-w64 UCRT import library | imports only `ucrtbase`, `kernel32`, `ntdll`, `bcryptprimitives`; 0 missing after the glue below | **PASS** 6 of 7 runs (`PROBE v=100 m=100 sum=26 caught=1 sqrt=1.414 tl=5`, exit 0, 50 ms). One run (the first, while ICU and the gates were building in parallel) hung: a worker thread stayed runnable at its first store to its `thread_local` block for 300 s. Not reproduced in 6 reruns, 5 of them under the same host load; see `reports/W1.md` "Observed" |
| A2 | GCC 13 mingw-w64 + libstdc++ (static), default libraries spelled out with `-lucrtbase` instead of GCC's `-lmsvcrt` | 0 missing after the glue | **PASS** |
| A3 | clang gnu target, C, `__thread` in the main and a `CreateThread` thread (`probe_tls.c`) | 0 missing | **PASS** (native TLS through the PE TLS directory: the Kernel64 loader's per-thread array works) |
| A4 | clang gnu target, `__try/__except` around a null store (`probe_seh.c`, `-fms-extensions`) | 0 missing | **FAIL, as a toolchain property:** clang 18 accepts `__try` on this target but emits no handler (the `main` unwind info has no handler flag; the disassembly is the plain store), so the access violation is unhandled (`c0000005`, process terminated). JavaScriptCore uses `__try` only in `jsc.cpp`'s crash-report wrapper, which the build disables |
| B | clang `--target=x86_64-pc-windows-msvc` + microsoft/STL `main` (`f023531`, Apache-2.0 WITH LLVM-exception) against the Shizuku `ucrtbase`/`vcruntime140`/`msvcp140` | **does not compile**: `yvals_core.h:526: fatal error: 'vcruntime.h' file not found`. The STL headers include 60 headers they do not ship: `vcruntime.h`, `vcruntime_new.h`, `vcruntime_exception.h`, `vcruntime_typeinfo.h` (MSVC toolset) and `corecrt*.h`, `crtdbg.h`, `sal.h` and the C headers (Windows SDK UCRT) — all under Microsoft's licences, not open source and not in this container. The mingw-w64 headers are not a substitute (different `crtdefs`/`_CRT` machinery). Separately, the STL's out-of-line part is `msvcp140.dll` (and `msvcp140_1/_2/_atomic_wait`), of which the Shizuku `msvcp140` has 39 exports | not run |

Why A1 over A2: both run. WebKit's Windows port is a clang port (`COMPILER(CLANG)` code paths, `-fms-extensions`
constructs), clang's gnu target uses native PE TLS (A3) where GCC uses emulated TLS through libgcc, and one compiler
builds ICU, WTF, JavaScriptCore and the probes. Why not libc++ (llvm-mingw style): libstdc++ 13 is a supported WebKit
standard library at this commit and already runs in the guest (A1/A2); building libc++/libc++abi/libunwind from a
pinned llvm-project would add a third upstream for no demonstrated gain. This stays open if libstdc++ blocks something
(it would be the answer to a libstdc++-only failure, e.g. in `<format>` or `<chrono>` time zones).

Why not B: it needs Microsoft-licensed headers at build time that are not available here, and a much larger
`msvcp140`. "No Microsoft SDK binaries may be redistributed" holds for A: nothing from Microsoft is used at all.

### 2.2 The link, in detail

- Headers: mingw-w64 in UCRT mode (`-D_UCRT -D__MSVCRT_VERSION__=0xE00 -D_WIN32_WINNT=0x0A00`). WebKit adds
  `__USE_MINGW_ANSI_STDIO=1`, so `printf`-family formatting comes from mingw-w64's `libmingwex`, not from ucrtbase.
- Startup objects and static libraries from mingw-w64 (`crt2.o`, `libmingw32`, `libmingwex`) and GCC 13 (`libstdc++`,
  `libgcc`, `libgcc_eh`, `libwinpthread` through CMake's `Threads`) are linked statically. They were compiled for msvcrt;
  mingw-w64's `libucrtbase.a` supplies the msvcrt-style entry points they call (`__getmainargs`, `_onexit`, ...) on top
  of ucrtbase. This mix is what A1/A2 exercised; it is a known risk area (a libstdc++ built for UCRT would remove it).
- Import libraries: the Shizuku `libntdll.a` and `libbcryptprimitives.a` are linked by path ahead of mingw-w64's, then
  `-lucrtbase` (mingw-w64's, UCRT). `build.py` then checks every import of every output against the Shizuku DLLs.
- Glue (`webkit/compat/shzwk_compat.c`), because the Shizuku ucrtbase lacks two functions mingw-w64 expects there
  (asked from K5 in `reports/W1.md`): `rand_s` (libstdc++'s `std::random_device`) over `ProcessPrng`, and
  `__C_specific_handler` for `crt2.o`'s unwind data, bound to the Shizuku ntdll's export by link order.

## 3. JavaScriptCore builds

`python3 shizukudos/win64/webkit/build.py [--config cloop]` (after `python3 shizukudos/win64/build.py`):
ICU 78.3 host build, then the static Win64 ICU (common, i18n, the full 33 MB data archive), then CMake/Ninja with
`PORT=JSCOnly`. Output: `build/shizukudos/win64/webkit/out/jsc.exe` (+ `wkbatch.exe`, the stress batch driver) and
`build-result.json` (commands, tool versions, patch list, per-image import check, licence table).

| config | CMake options | used for |
|---|---|---|
| `cloop` | `ENABLE_JIT=OFF ENABLE_C_LOOP=ON ENABLE_WEBASSEMBLY=OFF ENABLE_SAMPLING_PROFILER=OFF ENABLE_STATIC_JSC=ON` (bmalloc on Windows requires mimalloc: `USE_SYSTEM_MALLOC` is rejected by `BPlatform.h`) | M1 |

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

## 5. JIT (M2) — what Kernel64 must provide

See `reports/W1.md` "Needed from K4" for the exact asks (executable memory with W^X toggling, dynamic function tables,
exception dispatch through JIT frames).
