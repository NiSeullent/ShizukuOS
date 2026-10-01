# Genuine Zetscape engine capability prerequisites — 83bd

This disjoint lane targets ordinary **Win98SE 4.10.2222 x86** and actual
Shizuku Win98 GPU integration. It adds a concrete genuine-JSC Wasm probe patch
and an effective-feature check. It does not implement a Wasm execution backend,
compile/link the engine, launch a browser, or supply a GPU driver/provider.
All native Wasm, GPU and full-browser verdicts remain **unverified**.

The local independent IEWebKit source profile pins WebKitGTK2.54.0 and commit
`5220e80b97a253c60ed899361654142ab5021998`, archive SHA256
`846fd19ccedbae1dbfe904f26dbf2d68a800a33a50caf2ad5222c8dcb3f25682`.
Actual observed source/configuration hashes are bound in `profile.json`.
The canonical IE variants tool has no exact IE5.5/Win98SE/x86/legacy-inproc
selection; that check rejected the target instead of substituting WinME.
This standalone Zetscape lane uses the root's explicit Win98SE host profile;
separate IE/OS/security variants still require their own selection/evidence.

## Actual constraints

The configured generated header selects C_LOOP=1, JIT/DFG/FTL=0,
WEBASSEMBLY=0, WEBGL=0 and WEBGPU=0. The cache contains WEBGL=ON, but
OptionsJSCOnly overrides it to OFF and excludes WebCore. The focused compiler
check confirms the effective headers; cached toggles are insufficient.

The [pinned CMake feature rules](https://raw.githubusercontent.com/WebKit/WebKit/5220e80b97a253c60ed899361654142ab5021998/Source/cmake/WebKitFeatures.cmake)
conflict Wasm with C_LOOP. PlatformUse selects JSVALUE32_64 for this x86 target;
PlatformEnable forcibly disables its JIT, DFG and FTL tiers. The [pinned Wasm
IPInt interpreter](https://raw.githubusercontent.com/WebKit/WebKit/5220e80b97a253c60ed899361654142ab5021998/Source/JavaScriptCore/llint/InPlaceInterpreter.asm)
has no x86 register backend and emits an error in its JS-to-Wasm entry when
C_LOOP is enabled. Removing conflicts or changing ENABLE flags cannot supply
missing calling conventions, execution, traps, memory or JS bridges.

A real next implementation must either port a genuine x86 non-C_LOOP
interpreter/calling bridge or add a genuine portable Wasm execution path to
JSC. It must preserve module validation and JS API identity, i64/BigInt,
memory/table ownership, bounds/traps, exception/GC integration and teardown.
This patch does neither; it supplies actual failing/passing probes for that
work after the unfinished genuine JSC runtime is repaired and linked.

## Concrete source patch and measured checks

`prepare_probe.py` requires the unchanged canonical caller preimage:
`tools/iewebkit_port/core_jsc_native.cpp`, SHA256
`1d38eab54d9bd6f166d6811188087170a27c4c62118a6913fe0cac7657d630e0`.
It checks each patch anchor exactly once and stages only into a new directory
under this lane, preserving existing outputs and rejecting path/symlink escape.
It never applies a patch to the canonical source.

The active candidate is `private/probe-r2/native-jsc-modern-wasm.patch`, SHA256
`880d4deda45c69cb42b6ec94db0f1d69ec96dcf41649c3a338c6dd970b0e00e7`.
The staged caller SHA256 is
`759845e1f6902090093f77921015ae3df278055bff97a5664cc654a7230db6cd`.
Its pinned fixture header SHA256 is
`7cbd4b4e37c3eb2a170b6f3a672bffc61e951744a3881bfbf51f7b7bf80e4146`.
The original MIT notice remains intact.

After the engine owner repairs native initialization and regenerates the
matched graph, compile this staged caller with the pinned API/header arguments
and link it to that genuine JSC/WTF/ICU and paired Win9x runtime. Keep the extra
`wasm_cases.h` include path and bind every linked archive/member/runtime hash.
The current C_LOOP build is a legitimate negative control for unsupported Wasm;
it cannot produce a positive Wasm result. A positive trial needs the separately
implemented genuine x86 Wasm backend and its reviewed effective feature profile.

The actual JSC C API creates a new context and evaluates eight real Wasm cases:
API presence, valid module/instance, i32 execution, i64 BigInt return, memory
load/growth/detachment/maximum, out-of-bounds trap, malformed-module rejection,
and exported-function table/growth limits. There are no replacement WebAssembly
objects or success stubs. Disabled Wasm fails the aggregate; it is never skipped.
The binary module is 92 bytes, declares at most two 64KiB memory pages and has
no imports or loops. Its source tests have no browser/network/GPU side effects.

The candidate creates only a fresh native `C:\GOPLAB\WASM83BD.LOG` with a fresh
ASCII nonce, records effective build features and each stage before entering
actual JSC, and preserves collection/context/group release checks. No native
log has been produced. A future exit=0 in this file is still before CRT/TLS
process teardown and needs a separate native process-exit observer, exact input
digests, actual OS evidence and normal stopped-guest readback.

The two units passed actual i686 MinGW `-fsyntax-only -Werror` using the existing
JSC compile database and pinned generated header/API paths. No object, link,
archive build or Windows executable was produced. Receipt:
`private/check-r2/syntax-reference-receipt.json`, SHA256
`53005a3a3231addd1a9d154c21c6e12fe19d3fabac2eba0dfaace0a191052230`.
The same eight scripts passed an explicitly separate host Node26.3.0/V8
reference control and all eight failed with WebAssembly unavailable. Host V8
validates fixture inputs, not JSC or Win98. Private r1 outputs are superseded:
that early check used preprocessor-only macros as C++ expressions and its
driver aborted before a complete receipt. The corrected r2 receipt is active.

Reproducible bounded commands, from the Win98-Modern-boot repository:

```text
python3 -B tools/iewebkit_port/zetscape_capabilities_83bd/prepare_probe.py
python3 -B tools/iewebkit_port/zetscape_capabilities_83bd/source_controls.py
python3 -B tools/iewebkit_port/zetscape_capabilities_83bd/prepare_probe.py --output private/probe-NEW
python3 -B tools/iewebkit_port/zetscape_capabilities_83bd/syntax_check.py --staged private/probe-NEW --output private/check-NEW
```

The checker requires the actual generated config SHA256
`65becf92311c7c05a574ab7ad2093d233eb2119579ae549140006a3d1aed3670` and
copies its real x86 compiler/header arguments while replacing object output
with syntax-only checks. Changed configuration requires a newly reviewed pin.
Child compiler address space is capped at1GiB and CPU at30seconds per unit;
Node heap at64MiB, each evaluation at1second, Wasm memory at128KiB. Private
check outputs are capped at256KiB. Full builds remain subject to the20GiB floor.
The128KiB bound is the module's declared logical memory, not a measurement of
JSC's internal address-space reservation or guard regions. Native execution
still needs the owner's external deadline, memory accounting and exit observer.

## Ordinary Win98 and Shizuku GPU connection

Ordinary Win98 permits genuine software rendering, but it still needs actual
WebCore layout/fonts/paint, DOM/JS, WebGL shader execution/readback and all
required modern-web behavior. The pinned Windows options default to Skia;
`USE_SKIA=OFF` selects Cairo. Neither flag provides a completed Win98 renderer.
WebGL's ANGLE/EGL platform backend and a complete WebGPU implementation need
separate real API/driver work even if ordinary rendering is performed in software.

The existing Win98 GOP driver `drivers/shizuku_gop/backend.c` explicitly sets
`FB_FORCE_SOFTWARE`, draws with CPU `wram_blit` and copies to the firmware
framebuffer. Its PCI ownership and presentation do not establish GPU rendering.
`shizukudos/win64/include/shzgpu.h` provides actual context/resource/submit/
readback contracts, but its DLL build selects x86_64 and its NtShzGpu system
calls belong to Kernel64. This separate operating-system path cannot be loaded
or relabeled as a native x86 Win98 driver connection.

The concrete missing Shizuku Win98 path is:

1. An x86 Win98 user/kernel transport to an actual owned GPU device, with real
   resource allocation, submission, fence/completion, readback and release.
   The existing 64-bit ShzGpu contracts are reference inputs, not that transport.
2. A genuine WebCore/ANGLE/EGL or WGL renderer backend consuming it, with proper
   context/thread ownership, device-loss handling and window presentation.
   WebGPU additionally needs a real supported implementation and driver API.
3. Provider-side extension observations bound to driver/device hashes and actual
   submitted/presented frames. Root's Zetscape extension metadata has no WebGPU
   hardware bit and cannot prove shader execution. Shared IEWK capability bits63
   cover HTML/CSS/DOM/JSC/TLS/origin; they do not certify Wasm/WebGL/WebGPU.
4. Separate ordinary/software and Shizuku/hardware native trials, deterministic
   shader/compute pixels, driver traces, completion and visible frames. Hardware
   initialization failure remains hardware FAIL; CPU/llvmpipe fallback cannot
   earn hardware acceptance.

## Dependencies and remaining scope

The engine owner's genuine WTF initializer/CRT/TLS repair is first; the old
19/88 JSC graph needs regeneration and real JSC linking/native tests. Real
WebCore/provider creation, navigation, painting, input, history, origin/TLS and
full lifecycle are still pending. These staged sources do not modify that work,
root Zetscape, canonical IE, drivers, NTWin32 or VM controls.

Eight representative core Wasm cases do not cover SIMD, threads/shared memory,
Atomics, reference/GC types, exceptions, tail calls, multiple memories, memory64,
streaming compilation, asynchronous browser integration or full conformance.
Complete JavaScript, CSS, WebAssembly, WebGL and WebGPU support needs versioned
finite inventories, pinned WPT/test262/Wasm tests and native application evidence.
Full modern-web coverage and both platform verdicts remain false.
