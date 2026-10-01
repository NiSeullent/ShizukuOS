# Selected actual official WebAssembly numeric tests

This diagnostic compiles original `i32.wast`, `i64.wast`, `f32.wast` and
`f64.wast` from official WebAssembly/spec revision
`bc030375d734de845aa2246b783ca6a7ee865eb4` (2026-09-30) using the immutable
official WABT 1.0.42 host `wast2json` tool. Archive, binary, original source,
licenses, JSON script operands, compiled modules and generated adapter headers
are preserved and hashed. Test arguments and expected bit patterns are used
unchanged. Canonical/arithmetic NaN expectations test their specified IEEE
classes rather than substitute a specific payload.

The original project's full official script runner is not run. The original
numeric invoke, trap and binary invalid-module commands execute through the
actual bounded WAMR component. Text malformed-module parser tests have no Wasm
binary; each excluded command is listed with its reason. These results are a
selected core diagnostic, not full current Wasm conformance, JavaScript API,
Trident integration or native Win98 execution. Failed commands set a nonzero
process/tool exit status and remain recorded; unsupported proposals are not
removed from the user's requirements.

Official tests and WABT are Apache-2.0; their original licenses are retained.
Only original port/tool/adapter source is committed under GPL-2.0-only. Generated
foreign test tables/binaries remain in the ignored private diagnostic build;
no combined binary is distributed by this work.

Normal and instrumented selected runs are separate, required evidence. Native
PE/static i486 gates for the execution component do not establish native spec
execution. Browser APIs, DOM, streaming/origin rules, full proposal support,
WebGPU/WebGL and modern apps remain unfinished mandatory work.

The measured v2 diagnostic passed 5,896/5,896 commands in both normal and full
ASan/UBSan processes. Its preserved receipt SHA-256 is
`04fae836946806bc6a0488ea047a31a291640c239d67e133c5a0ad39f9e73834`.
The runs used actual GCC x87 arithmetic (`-mfpmath=387 -mpc64 -ffloat-store`)
and the component's internal PC53 profile, including explicit PC24 f32 square
roots. All original 5,000 f32/f64 return oracles passed their unchanged bit/NaN
checks. This measures the Linux diagnostic profile; native arithmetic requires
actual Win98 execution.

Eight original text `assert_malformed` commands are excluded individually with
suite/line/reason. All binary invalid-module commands are executed and must
return a validation error. Traps use the original typed result arity from WABT
JSON before execution and match an actual engine trap diagnostic. The preserved
v1 trial supplied incorrect zero trap-result arity and failed twenty commands;
its failure exit code and receipt remain retained.

Run `python3 tools/test_wasm_spec_selected.py --runtime-build <fresh-runtime-dir>
--runtime-receipt-sha <exact-runtime-receipt-sha> --build-dir <fresh-selected-dir>`.
The tool verifies current/frozen runtime sources, prepared sources, object and
log provenance plus original spec/tool/license hashes before and after testing.
The runtime's entire original engine/port object set is reused, replacing only
the original test main. Full original official script execution and excluded
proposal/browser/native coverage remain separate mandatory gates.
