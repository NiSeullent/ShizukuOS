# Additive classic scalar SIMD profile

This six-path slice adds actual integer/data vector execution to the pinned
WAMR classic interpreter, on the accepted fixed-65536-byte memory profile.
The upstream revision is f5f57c09aee623436f5fb87a90798fdd2cdf39fd. Original
Apache-2.0 WITH LLVM-exception licenses and per-file notices stay intact.
The original numeric, corrected-memory, and genuine QuickJS profiles stay frozen.

Only fifteen secondary instructions are supported: v128 load/store/const,
byte shuffle/swizzle, i32x4 splat/extract/replace/add, and v128 not/and/andnot/or/
xor/bitselect. Validation decodes real u32 LEB secondary opcodes and rejects
every unimplemented instruction before publishing a module. The classic switch
interpreter carries vectors in four 32-bit cells, clears all vector reference
bitmap slots, excludes vectors from upstream scalar local rewrites, and handles
vector globals, drop/select, typed select, and existing generic call/control
cell counts. Linear bytes use explicit little-endian access without aligned
vector casts. Memory operations check the full sixteen-byte span before writing.

The frozen public numeric ABI remains scalar. Vector export boundaries fail
before execution; vector imports require unavailable bindings. Vector GC heap
fields are rejected during loading because the upstream classic heap handlers
still assume at most eight-byte scalar storage. Scalar/reference GC remains
enabled and its regressions must run against this new engine.

The new tests use original project WAT and independently computed scalar byte
oracles. Existing pinned WABT assembles these fixtures. No locally pinned
current official SIMD WAST is available; this is not an official SIMD suite.
The unchanged 1237 numeric, 386 memory, 4641 selected original memory, and 622
genuine QuickJS memory predicates must execute on the new backend normally and
with every new engine object instrumented by ASan/UBSan. Numeric foreign-thread
observations move after join solely to avoid the historical test counter race;
both original predicates and their expected results are retained.

The bounded recipe requires 22,595,387,392 free bytes and 6 GiB MemAvailable
before creating its owned build child. During commands it checks the global
22,058,516,480-byte free floor, 6 GiB available memory, a 512 MiB whole owned
logical-file budget and 2 GiB aggregate owned-process-group RSS. Child files
are limited to 64 MiB. Sampling is every 250 ms, so transient overshoot remains
possible. A failed/deadline command retains stdout/stderr and kills/reaps only
the exact process group created by its own Popen. At most two compiler jobs run.
Root coordinates the large-build reservation with the graphics agent.

Original archives, source/config/patches, accepted cache metadata and compile
logs, actual new objects, per-TU configuration, MMD non-system dependencies,
fixture bytes and raw result logs are pinned and reread at the end. Compiler
driver executables/version are recorded; complete external compiler subtool,
system header and system library closure is not claimed. Native compilation,
when requested separately after the host seam passes, must check the complete
linked PE executable byte stream against the frozen i486/x87 decoder, original
Win98 OEM imports and exactly twelve scalar exports. No PE is launched here.

No passed receipt exists yet. Full fixed SIMD, relaxed SIMD, modern exception
handling, full current Wasm, reflected standard browser WebAssembly APIs,
actual Trident integration, native execution, WebGL/WebGPU and modern app
compatibility remain mandatory unfinished work. This private numeric groundwork
installs no global WebAssembly namespace.
