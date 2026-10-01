# Selected official JavaScript semantic fixtures — 2026-10-01

`tools/build_trident_test262_selected.py` uses real host objects from the frozen
QuickJS runtime, not a second installed JavaScript interpreter. It selects
Map/WeakMap `getOrInsert`/`getOrInsertComputed`, `Iterator.concat` and Uint8Array
base64/hex tests from official Test262 revision
`7ab7fafa0003f73fc85c1b95d88094d33f7eb8bd` (2026-09-23). The pinned archive is
`https://codeload.github.com/tc39/test262/tar.gz/7ab7fafa0003f73fc85c1b95d88094d33f7eb8bd`,
9,582,263 bytes, SHA256
`1d497a1e7430094a41d06f38db775df4a63db5d587b2a8b08aba6fad5de19585`.

All 220 selected source/harness/license pins are derived from the verified tar
archive and compared with the retained source files. The adapter can fetch and
prepare that exact bounded source selection into a fresh owned build directory;
no upstream Python/shell runner is executed. Each synchronous positive fixture
uses a fresh real realm/process, global-script evaluation, official harness
include order and required strict/sloppy variants. The only final source
normalization is `void 0`, needed for the scalar result ABI. Original fixtures
remain unchanged; every generated variant, adapter source snapshot, binary and
build log is retained. Thread identity uses the actual Linux thread ID; this is
a host profile, not native Windows execution.

This adapter implements a **limited fixture protocol**. It excludes any case
requiring Test262 `$262` host bindings, modules, asynchronous completion, raw
execution or negative-phase handling, with a recorded reason. It does not claim
the complete Test262 host API or full ECMAScript conformance. The selected
runtime uses 32 MiB memory, 256 KiB script stack, 1,000 interrupt checks and 128
pending jobs. Positive, thrown-error and infinite-loop controls verify that
execution and failure are real. Failed cases produce a nonzero command status.

Measured v4 fixtures: 174 originals selected, 170 executed in 338 variants;
334 passed and 4 failed. Four original detach-buffer fixtures were excluded
because the host binding is absent. The failures are strict/sloppy variants of
`setFromBase64`/`setFromHex` on immutable ArrayBuffers. That separately tagged
feature is still a Stage 2.7 proposal in the inspected primary repository;
it is not a completed ECMAScript 2026 language feature. It remains unsupported
and recorded, without replacing its fixtures or making the methods pretend to
provide immutable storage. See [the proposal's status](https://github.com/tc39/proposal-immutable-arraybuffer)
and the [ECMAScript 2026 structured-data specification](https://tc39.es/ecma262/2026/multipage/structured-data.html).

The later v5 checkpoint additionally binds the feature tags and propagates
test failures to the command status. Preserve v1–v3 adapter bring-up failures
and v4 observations separately. Reproduction with the existing original source:

```text
python3 tools/build_trident_test262_selected.py --runtime-receipt /root/Win98-Modern-theme-tls-5abe/build/trident-script-v10/result.json --runtime-sha256 7e036db6906484a046c1253e4668930c4d85645f492ce2bf9a626fd6a1cbf716 --source /root/Win98-Modern-theme-tls-5abe/build/test262-2026-source-v1 --out /root/Win98-Modern-theme-tls-5abe/build/test262-selected-next
```

Current JavaScript, CSS, browser WASM, WebGPU and WebGL all remain mandatory
targets. These selected host results certify none of their complete native or
browser profiles and do not establish Legcord, Signal or Office functionality.
Test262's BSD license, per-file copyright notices and complete downloaded
archive remain in ignored build storage. The adapter and this handoff are
original GPL-2.0-only project code.
