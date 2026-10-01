# Bounded current WebAssembly execution component

The component executes actual WebAssembly modules through official WAMR revision
`f5f57c09aee623436f5fb87a90798fdd2cdf39fd` (2026-09-30). It implements an
independent numeric C ABI. Browser WebAssembly, current proposals, Trident
integration and native Win98 execution remain mandatory unfinished work.
The earlier audit is `TRIDENT_WASM_HANDOFF.md`.

The immutable official archive is 6,136,546 bytes with SHA-256
`620d40c4c67269f371a46ef4923d398ef96cdf569a7f66e6aab70788e235f907`.
The archive and all 2,001 original regular source files remain in the ignored
source directory, including the full original LICENSE and per-file notices.
Only an unrelated Python binding LICENSE symlink to the retained root LICENSE
is skipped during extraction. WAMR's license is Apache-2.0 WITH LLVM-exception:
the original exception explicitly covers linking compiled software with GPLv2
and discusses waiver of entire conflicting sections for that combined software
if a competent court determines a conflict. Plain Apache-2.0 compatibility is
not assumed. Original port/tool/adapter files are GPL-2.0-only. No combined
binary is published by this work.

## Actual execution and bounds

One live store belongs to an actual OS thread and uses an actual 32-bit CAS gate.
Foreign threads and host callback reentry are rejected. Typed generation handles
separate modules and instances, reject stale handles after unload/close, and
refuse generation exhaustion. Modules copy their binary bytes because WAMR
retains references into them. Instances and execution environments are destroyed
before modules; callbacks are unregistered and their pointers cleared on close
and failed registration.

The actual WAMR allocator charges allocation headers, copied modules, VM objects,
GC heaps, interpreter stacks and linear memory to one total budget. Its limits
are 256 KiB–32 MiB total memory, 16–256 KiB interpreter stack, 1–10,000,000
interpreter dispatches per call/start, 1–256 pages per linear memory, eight live
modules and eight instances, and one MiB copied module bytes. Memory reads/writes
copy checked ranges; they expose no persistent native linear-memory pointer.
Actual VM `memory.grow` and the C growth API both enforce allocator limits and
re-query memory after relocation. Meter traps interrupt infinite normal and
tail-call loops, including the module's actual start function. There is no
asynchronous cancellation/thread ABI in this profile.

The C caller keeps callback code and `user` data alive until store close, and
keeps input/output buffers valid for each synchronous call. Import names and
signatures are copied; callback code/data are borrowed. Callback argument/result
storage is valid only during the callback. Arbitrary C callback CPU/memory work
is outside the VM allocator/dispatch budget and must be bounded by the embedding;
the VM meter cannot interrupt an infinite host callback. This contract still
requires real JS import conversion, JS execution budgets and reference retention
when the component is integrated with Trident.

Imports must match explicitly registered numeric callbacks and actual linked
upstream import descriptors before instantiation. Missing, memory/table/global
and reference-valued imports fail. Signatures accept at most eight numeric
arguments and one result; exported calls allow eight numeric results. These
limits do not provide JavaScript BufferSource, i64 BigInt or reference-object
bindings. Actual VM traps are copied into bounded diagnostics, and subsequent
calls clear traps and remain usable. Browser-style instantiation runs only the
actual Wasm start section; Emscripten ctor export lookup is disabled.

## Pinned source and target profile

`tools/build_wasm_runtime.py` pins the complete configuration, original archive
members, prepared source hashes, every patch, compiler version/flags, actual
commands/logs and content-addressed object provenance. Each build uses a fresh
ignored directory and snapshots its source closure even on failure. Compilation
uses at most two workers. Optional `--fetch-source` restores original pinned
sources into a fresh `--source-dir`, bounds the download/extraction, and executes
no upstream script. Earlier failed extraction/build/sanitizer/control/native
trials and their original archives remain preserved.

The classic interpreter enables GC, reference types, tail calls, bulk memory
including the optimized bulk opcodes, extended constants and multiple memories.
It disables JIT/AOT, libc/WASI, shared memory, worker threads, hardware fault
bounds and Windows GS/TLS assumptions. The final receipt contains the full
macro map; enabling a switch is not a proposal conformance claim.

Prepared source patches retain original notices and bytes separately:

- The actual classic switch dispatch checks the meter before every opcode,
  closing upstream tail-call paths that skipped end-of-dispatch metering.
- Start execution receives a meter before any guest start instruction executes.
- VM frames and branch blocks use the actual four-byte bytecode-cell alignment,
  including on the 64-bit diagnostic host.
- Usage-aware memory relocation saves a valid heap offset before reallocation
  and keeps absent heap pointers null. This fixes an actual UBSan overflow in
  upstream relocation; sanitizer checks remain enabled.
- Each prepared C unit selects the original Win98 platform/math adapter, and
  the platform include selects the same pinned adapter.

The Win98 platform uses actual owner IDs, critical sections, system stack
boundary and original system MSVCRT. It verifies the already loaded MSVCRT's
system path before resolving original `_vsnprintf`, and always terminates
bounded diagnostics. The native profile explicitly disables MinGW ANSI-stdio,
checks compiler-derived PRI64 uses original CRT I64 formats, and verifies the
dynamic `_vsnprintf` against the actual original OEM export catalog. An original
reentrant tokenizer replaces modern
`strtok_s`; an original integer ctz helper avoids post-i486 prebuilt libgcc code.
Optional process memory statistics explicitly fail, and CPU profiling is
disabled. No fabricated condition/thread/platform API reports success.

The component saves/restores all 108 bytes of caller x87 state before platform
readiness/provider resolution, including readiness failure. Deliberately
clobbering test-only provider modes verify both paths with pending flags/live
registers and unchanged failure output; they are not native provider evidence. Internal x87
control uses nearest rounding with PC53; host callbacks temporarily regain the
original caller state, including pending flags and live registers. The host
compiler uses `-mfpmath=387 -mpc64 -ffloat-store`; its 64-bit calling convention
still uses register moves. Native compilation uses i486, no SSE/SSE2/MMX, the
same x87 profile and no modern runtime startup. Bit-based rounding helpers and
explicit PC53/PC24 square roots avoid modern CRT math imports. Official numeric
oracles still require actual native execution before claiming native arithmetic.

The native DLL checks PE32/x86, GUI/OS 4.10, original installed OEM imports,
exactly twelve C exports, relocation/entry/stack metadata, absent modern PE
flags/TLS/load-config/delay/CLR directories and bounded image size. The frozen
common decoder additionally checks every declared executable-section byte and
address with an explicit i486/x87 allowlist, recursive prefixes and operand
checks, including linked libgcc. Its real assembled modern-instruction controls
are run; no control binary is executed. A successful static gate does not mean
Win98 loaded or ran the DLL.

## Measured scope and remaining requirements

The preserved v19 build passed 1,228 actual-engine assertions in both normal
and full ASan/UBSan x87-profile processes. Separate deliberately invalid
ASan/UBSan programs failed with the required diagnostics. Its DLL exported twelve APIs and imported only original OEM symbols.
It passed all declared executable-byte/address coverage and real modern-opcode
rejection controls. Two fault profiles cover 96 allocation positions each,
without and with actual registered imports. The final fresh receipt includes
compiler-derived original-CRT macros and image metadata. Fault tests deny real VM allocations through
initialization/load/instantiation and demand zero tracked bytes after every
failed/successful teardown and a working subsequent store.

The separate selected official diagnostic passed all 5,896 binary/numeric
commands from original current i32/i64/f32/f64 suites in normal and full
ASan/UBSan x87 processes. Eight original text-parser commands are individually
excluded because they produce no Wasm binary. The initially incorrect trap
adapter result arity caused twenty recorded failures and was corrected against
the original WABT JSON. Expected bits and NaN classes were not relaxed. See
`TRIDENT_WASM_SPEC_SELECTED.md`; this is a selected core diagnostic.

| Requirement | Current evidence | Required continuation |
| --- | --- | --- |
| Numeric core, validation, traps | Actual engine, original fixtures and selected official binary oracles | Full core/proposal oracles and native execution |
| Imports, growth, budgets, ownership | Real callback/allocator/meter/lifetime tests | Browser imports, JS conversion/ref lifetime and asynchronous cancellation |
| GC/reference types | Enabled in actual engine | Official GC/ref oracles and JS object bindings |
| Tail/bulk/multiple memories | Original positive/negative binary tests | Full selected official proposal suites |
| Fixed SIMD | Classic interpreter excludes it | Software implementation or suitable interpreter port |
| Relaxed SIMD, new exception handling, JS string builtins | Unavailable in the selected profile/upstream | Current proposal implementations and oracles |
| Memory64 | Selected WAMR excludes 32-bit targets | Actual bounded 32-bit implementation |
| Shared memory/threads | Disabled in this owner-thread profile | Real browser/thread/atomic integration |
| Browser WebAssembly/Trident | No browser JavaScript/DOM integration | BufferSource, BigInt, async/streaming/origin, errors and real MSHTML host |
| WebGPU/WebGL, current JS/CSS, apps/themes/TLS | Separate mandatory work | Actual integrated native/app acceptance |

All browser-Wasm/JS-API/full-modern-Wasm/MSHTML/full-browser/WebGPU/WebGL/app
and native-execution receipt flags remain false.

To reproduce with retained original source, run
`python3 tools/build_wasm_runtime.py --build-dir build/wasm-runtime-replay-v1`.
A cold original-source restore uses the additional
`--fetch-source --source-dir build/wasm-runtime-source-replay-v1` options.
The selected official diagnostic requires the separate preserved pinned
spec/WABT originals and the exact SHA of the resulting runtime receipt.
