# Trident WebAssembly implementation seam audit — 2026-10-01

Modern browser WebAssembly is mandatory alongside current JavaScript, CSS,
WebGL and WebGPU. A complete WebKit port is optional. The inspected Trident
QuickJS/Automation component does **not** implement WebAssembly. This document
records a read-only source audit and proposed implementation gates; it is not a
port, native execution result or application/conformance certification.

The actual target remains Windows 98 SE 4.10.2222, x86, with installed Microsoft
IE 5.00.2614.3500/MSHTML. Only this new audit document was written. No dependency
was downloaded, no repository script was run, and no peer engine source,
provider ABI, guest, registration or system configuration was changed.

## Current implementation and reusable seams

The owned `m98_trident_script` code embeds pinned QuickJS 2026-06-04 and exposes
bounded scalar/UTF-16/object/function/method values to genuine Automation. Its
public value ABI has no BufferSource, ArrayBuffer, typed-array or BigInt value
conversion. No Wasm loader, validator, interpreter, JS bindings or browser Wasm
execution evidence was found in the inspected owned sources. Filename searches
of boot `shizukudos`, `src`, `platform`, `tools`, `tests`, `docs` and independent
IEWebkit `include`, `host`, `renderer`, `porting`, `docs` found no corresponding
Wasm implementation file. This is a bounded source audit, not an assertion that
all external upstream trees lack Wasm.

The already-present original QuickJS header provides `JS_NewArrayBuffer`,
`JS_GetArrayBuffer`, `JS_GetTypedArrayBuffer`, BigInt conversion, Promise and
interrupt APIs. **Proposed seam:** add real WebAssembly builtins inside the
interpreter, with its own per-context Wasm store and JS object lifetimes. A
namespace stub or passing Wasm bytes through the current scalar COM ABI would
not implement the browser API. Actual DOM imports can later use the reviewed
Automation bridge under its thread, ownership and reentry rules.

Current context limits are 256 KiB–32 MiB runtime memory, 16–256 KiB script stack,
finite interrupt checks and pending jobs, four contexts and one owning UI
thread. External modules are rejected; SharedArrayBuffer is explicitly removed
from this profile. These limits and omissions are measured local source facts,
not browser feature support. New Wasm allocations and execution need their own
enforced accounting within the same context budget. A QuickJS interrupt hook
does not automatically interrupt a separately embedded interpreter.

The independent IEWebkit bootstrap pins WebKit commit
`5220e80b97a253c60ed899361654142ab5021998` and selects JIT off, C_LOOP on and
WebAssembly off. That upstream commit explicitly declares C_LOOP and
WebAssembly conflicting options. Enabling a flag is therefore not a working
Wasm port. [Pinned upstream feature configuration](https://github.com/WebKit/WebKit/blob/5220e80b97a253c60ed899361654142ab5021998/Source/cmake/WebKitFeatures.cmake).

IEWebkit's existing ABI requires the specifically named JavaScriptCore bit in
`IEWK_REQUIRED_CAPS=63`. It has no explicit Wasm/version feature gate. QuickJS
must not impersonate JavaScriptCore; any general-runtime/versioned capability
change belongs to that provider's owner. This audit changes neither path.

## Verified primary references and candidate limits

The inspected core change history is labelled WebAssembly 3.0, dated
2026-09-30. It records modern changes including tail calls, typed references,
GC, multiple memories, 64-bit memories/tables and the newer exception model.
The checked JavaScript API is an Editor's Draft dated 2026-09-30; pin the chosen
normative baseline and draft requirements explicitly. A year label is not a
conformance profile. [Core changes](https://webassembly.github.io/spec/core/appendix/changes.html),
[JavaScript API](https://webassembly.github.io/spec/js-api/index.html).

WAMR is an actual embeddable C VM candidate with interpreter modes and a
documented platform-port layer. Its C API supplies loading, instantiation,
calls and exceptions. Its platform documentation provides the custom OS seam.
These make it a plausible implementation starting point; no inspected evidence
proves its MinGW/Windows profile works on Windows 98. Preserve upstream notices
and any port patches. [Embedding API](https://github.com/wasm-micro-runtime/wasm-micro-runtime/blob/main/doc/embed_wamr.md),
[Platform port](https://github.com/wasm-micro-runtime/wasm-micro-runtime/blob/main/doc/port_wamr.md).

Its current build configuration explicitly lists the current exception proposal,
JS string builtins and relaxed SIMD as unsupported, while its exception switch
selects the legacy model. It rejects Memory64 on 32-bit targets. The combination
checks reject SIMD in the classic interpreter and reject legacy exceptions and
multiple memories in the fast interpreter; Memory64 is also rejected in that
mode. A README's aggregate feature list does not establish one usable target
profile. These are substantial gaps for a blanket latest-Wasm claim, before
browser bindings are added. [Configuration](https://github.com/wasm-micro-runtime/wasm-micro-runtime/blob/main/build-scripts/config_common.cmake),
[Combination checks](https://github.com/wasm-micro-runtime/wasm-micro-runtime/blob/main/build-scripts/unsupported_combination.cmake).

Those WAMR URLs reference moving `main`, inspected on 2026-10-01. Before any
implementation/fetch, select an immutable revision and hash its source, complete
feature configuration and patches. No WAMR archive/revision is frozen by this
audit, and no runtime was selected or built.

## Real implementation and acceptance gates

1. Implement actual binary validation, decoding, instantiation and execution.
   Pin a feature matrix and matching core/spec tests; test valid instructions,
   malformed modules, type/limit errors, traps and unsupported proposals. Host
   C API or WASI execution alone is not browser WebAssembly.
2. Implement the real JS object/API model: Module, Instance, Memory, Table,
   Global, callable exports/imports and required exception/tag/GC behavior.
   Validate copied BufferSource bytes, i64/BigInt conversion and JS exception
   propagation. Preserve per-agent object identity and cache/store ownership.
3. Test memory growth and old/new ArrayBuffer relationships, typed-array views,
   bounds checks, 64-bit index overflow and native allocation limits. Charge
   linear memories, VM stacks, GC/store objects and compiled-module data to the
   context budget; do not turn JS's 32 MiB cap into an unbounded external heap.
4. Enforce Wasm instruction/call-depth deadlines and safe UI-thread import
   callbacks. Verify reentry, thrown JS values, Promise compile/instantiate
   settlement and job ordering against actual engine behavior.
5. Add shared-memory/atomic semantics only through a separately verified
   origin/thread profile. The current single-thread profile explicitly lacks
   them; leaving their namespace visible is not support.
6. Bind streaming compile/instantiate to real Fetch response bodies, MIME,
   cancellation, redirects, URL/origin and certificate validation. The
   [browser Web API](https://webassembly.github.io/spec/web-api/index.html)
   adds requirements beyond the core and JS bindings. Offline memory-BIO TLS
   evidence does not prove this transport or OS/browser TLS integration.
7. Prove navigation/context teardown releases imports, memories and stores,
   cancels pending work and cannot call a previous document. Keep browser
   storage/origin partitions and native privileges separate.
8. Audit the linked x86 PE, exact installed imports, instruction baseline,
   dependencies, stack and ABI; then run genuine native Win98 module/JS/DOM
   interactions with fresh logs, independently observed child exit and reviewed
   input/paint. Publish conformance failures and unsupported features. Legcord,
   Signal and current Office workflows require their own actual tests.

The existing frozen Automation v4 and owned-child observer v2 are useful
foundations for genuine DOM callbacks and child-completion evidence. Their host
tests/static gates provide no native Wasm, current CSS, WebGL/WebGPU, ordinary
browser-navigation or modern-app pass.

## Source pins

Current files were read with unchanged inode/size/mtime/ctime during each read
at 2026-10-01T07:37:51Z; the original QuickJS header was read immediately after.
The concurrently owned runtime builder was refreshed at 2026-10-01T07:39:42Z.
These are audit snapshots, not a frozen combined runtime build or authority to
overwrite a peer's later work. Paths below are absolute and the peer checkout
remains owned by its existing engine/host integrators.

| Source | SHA-256 |
| --- | --- |
| `/root/Win98-Modern-theme-tls-5abe/src/m98_trident_script.h` | `e63b2421d87cbb637fa24768a6d0dcaba21dd97c1cc121258ae95b0d2cd97c11` |
| `/root/Win98-Modern-theme-tls-5abe/src/m98_trident_script.c` | `40a3594813db6b232984525d5646b72f73fcaad3dbe82d8224f6f64fe81add98` |
| `/root/Win98-Modern-theme-tls-5abe/src/m98_trident_script_port.h` | `ad71e7b97cf61fe2e4921811a66c10853458281a01534f62743016073a987127` |
| `/root/Win98-Modern-theme-tls-5abe/src/m98_trident_script_port.c` | `056a8ab07f1680b2cc252fded07424b0d1249d2ff440b881e0edb32698064ee6` |
| `/root/Win98-Modern-theme-tls-5abe/src/m98_trident_script_win32.c` | `af04669d0899a3f18f7dd2bb2591276602345078e94dbd2ebdea7543228c86f3` |
| `/root/Win98-Modern-theme-tls-5abe/src/m98_trident_automation.h` | `9941b31b323712ecfaaf6200aed5aed96294267398793efaeef1d9f3a94aa616` |
| `/root/Win98-Modern-theme-tls-5abe/src/m98_trident_automation.cpp` | `7ecff16195548bf681170b97f0a4626c51639b3d287962e3eb6a9aaa425bf358` |
| `/root/Win98-Modern-theme-tls-5abe/tools/build_trident_script.py` | `f80ad33d1ec86bca368b0beaa35f1d4fa5e08eb07752d0a53ff61489c230b1eb` |
| `/root/Win98-Modern-theme-tls-5abe/build/trident-script-sources/quickjs-2026-06-04/quickjs.h` | `2165f47772af9faee1798999a599fa9de850d1bf0259502dade1c25d4a588316` |
| `/home/almalinux/workspace/iewebkit/include/engine.h` | `d80a8b1d2bced21b9c30fbfe6577b66e3e71719ded719e85e946c38fbee853e2` |
| `/home/almalinux/workspace/iewebkit/porting/configure-jsc-me.sh` | `7c1c730d8333a62f0d107f3c8f548d094bb6b048bbe9125de7555e7e82ec300b` |
| `/home/almalinux/workspace/iewebkit/porting/README.md` | `1470603500df5be5801af39aa32415017ada680b3e7e6ced195206aecb245d4f` |
