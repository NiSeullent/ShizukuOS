# Private numeric JavaScript and Wasm seam

This work joins the frozen actual QuickJS and WAMR interpreters in a genuine
QuickJS context. The explicitly attached private object provides load,
instantiate, numeric call, memory snapshot/write/grow/size, teardown and info.
It does not install a global WebAssembly object.

Foundations are QuickJS 2026-06-04 at `build/trident-script-v10` (receipt
7e036db6906484a046c1253e4668930c4d85645f492ce2bf9a626fd6a1cbf716)
and WAMR f5f57c09aee623436f5fb87a90798fdd2cdf39fd at
`build/wasm-runtime-v24` (receipt
26b28af54df7566a9653633078c1948ff5211714f95a836f4a3b2bb0ea773d91).
Original archives, licenses/per-file notices, prepared headers, actual cache
recipes/objects, original compile-source/header/log bytes and current source
snapshots are pinned and re-read by the new builder. Historical QuickJS cache
metadata did not record a compile-log hash: those retained older logs are
explicitly pinned by this closure, rather than described as a historical SRI.

The host must attach in a fresh trusted context before executing untrusted
JavaScript, retain its import callbacks and userdata, use the context/store on
their owner OS thread, and detach before destroying the JS context/runtime.
The host remains responsible for JavaScript memory, stack and interruption
budgets. The native Wasm store separately enforces its frozen real allocator,
stack, linear-memory and dispatch/start instruction budgets.

Calls use an explicit private descriptor `{params:["i32",...],results:1}` and
an argument array. The frozen native ABI validates actual parameter kinds and
result count before executing. Returned values use their actual native kind:
i64 becomes BigInt, and i32/f32/f64 become Number. No binary signature reader
or declared output kind is added. i64 input follows actual ToBigInt64 modulo
64 conversion; Number does not silently replace BigInt.
f32 inputs use a direct x87 binary64-to-binary32 store under nearest-even and
restore the full caller x87 state; halfway controls cover all four ambient
rounding modes. NaN tests assert the permitted NaN class, not invented payload
bit equality.

Actual ArrayBuffer, TypedArray and DataView bytes are copied with their view
offsets. Captured original DataView getters perform the internal brand check.
Proxies, spoofs, shared/detached/out-of-range buffers and copies over 1 MiB
are rejected. All user conversions complete before obtaining byte pointers.
Memory reads return snapshots, not a live browser WebAssembly.Memory buffer.

The frozen backend rewrites memories in modules with no memory.grow/size
instruction. A declared 1..3-page memory reports 1 page and grow(1) returns -1;
a declared 2..4-page memory coalesces to one 131072-byte backend page, reports
1 page and also cannot grow. These measured behaviors remain a mandatory
backend/browser memory integration gap. The separate grow/size-containing
fixture retains 65536-byte pages and demonstrates actual growth 1 -> 2 -> 3,
followed by the actual maximum failure. No universal growth claim is accepted.

Opaque module objects retain the owner; instance objects retain their module.
JS references are freed during their class finalizer, while QuickJS still owns
the cyclic graph. Only native C records are queued: subsequent private entry,
exit, host inspect or detach closes all queued instances before module unloads.
Native cleanup during a synchronous import's JS GC waits until WAMR leaves
its native gate. After store close, C-only records can be reclaimed immediately.
Explicit close/detach invalidates all retained handles.
No asynchronous JavaScript callback imports are installed by this component.

The builder consumes pinned original/prepared source and actual normal/full
ASan+UBSan cache objects without mutating foundations or downloading sources.
Its WAT fixtures are original project tests compiled by pinned official WABT,
not an official full conformance suite. Failed fresh build directories remain.

The current actual host suite has 140 assertions in each normal and fully
ASan+UBSan-instrumented engine profile, plus deliberate address/undefined
behavior fault controls. It covers differing results, i64 beyond 2^53/modulo,
floating signed zero/subnormals/rounding, pre-execution arity/type/result-count
failures with unchanged memory, brands/detachment/view offsets, real validation,
link/start/call traps and fuel, callback reentry, original JS throw identity from
both call and start imports, cyclic GC during a native import, retained objects,
foreign-thread rejection and cyclic cleanup after host detach. The host bounds
JS to 32 MiB/262144-byte stack and separately verifies JS interruption; Wasm
uses 8 MiB/65536-byte stack/2000 instructions/three linear pages.

Failed v3 host oracles (11 failures) and v6/v7 cyclic-GC crash traces remain in
their original build children. v7's real ASan heap-use-after-free identified
deferred JS-reference destruction after QuickJS cycle removal; the corrected
seam releases JS references in the finalizer and defers only native records.
Earlier draft/preflight and deliberately rejected instrumentation trials are
also preserved. No foundation source or historical receipt was changed.

Actual Win98 execution, Trident/DOM integration, standard reflected browser
WebAssembly APIs, shared memory, JS reference bindings, streaming/origins,
current proposals, complete modern Wasm/JS/CSS/GPU and application acceptance
remain mandatory unfinished gates. This private groundwork accepts none of
those broader claims.
