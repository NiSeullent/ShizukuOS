# Private QuickJS seam with corrected Wasm memory

This additive integration recompiles the unchanged private numeric bridge and
links actual QuickJS 2026-06-04 objects with the separately accepted WAMR
fixed-64-KiB memory profile. It installs no global WebAssembly object. The
historical v11 bridge sources, original tests, fixtures, receipts and measured
backend gaps remain unchanged.

The exact foundation receipts are:
- Private bridge v11: b3e0e6ef6b966b9c9cb0beaaaf41d8227e048fbe6245232b73d825d0584705ac.
- Corrected memory v8: 657308666b48175c0369cdac0d3c35f9888d053f7c3038c5625c1ee5209dc5dc.
- Actual QuickJS profile: 7e036db6906484a046c1253e4668930c4d85645f492ce2bf9a626fd6a1cbf716.

Every normal/instrumented binary contains the exact 28 original QuickJS
engine/math/platform objects and 30 real corrected WAMR/numeric-ABI objects.
The frozen bridge C source is compiled afresh without production changes.
The 1727-byte original fixture header is copied exactly, with SHA256
bdbaa12932eddc4a940077e982ea6284c4ae965c42a2e4a0fc33b76ce906bdd2.
No download, VM or native launch is part of this recipe.

The new test is a copy of the original test with an additive helper block and
main entry. The builder reverses those insertions and exactly two literal
predicate changes, then requires equality with every original test byte:
- A no-grow module declaring 1..3 pages now reports one page, grows by one
  with old count one, and reports two pages.
- A no-grow module declaring 2..4 pages now reports two pages, grows by one
  with old count two, and reports three pages. Byte 131071 remains accessible.

All 140 original predicate positions remain represented, including genuine
BigInt precision/modulo, Number conversions, traps/fuel, callback exception
identity, BufferSource branding/offset/detachment, getter/reentry transactionality,
cyclic GC, retained ownership, close/detach and ambient f32 rounding.
The original options cap three pages; separate new four-page-cap tests verify
the declared 2..4 maximum. A retained original/prepared source pair and exact
unified delta make the changes reviewable.

New JavaScript methods must verify complete initial/new page zeroing, every
retained prefix byte, exact 65536-byte boundaries, zero-size growth, module
limits, overflow failure, copy independence and dirty-block reinstantiate
zeroing. Getter throws and reentry must remain transactional. Fresh bounded
pre-attach allocator fault points 1..192 search for an actual one-shot realloc
failure through JavaScript memoryGrow. The required failure result is -1,
not an exception or fabricated success. The unchanged native inspector observes
denied allocations +1 and unchanged actual usage; JavaScript observes unchanged
pages, prefix and bounds, then successful growth on the same instance and an
entire zero new page. Earlier real load/instantiate errors are recorded according
to their actual phase/code and each trial must leave zero tracked VM memory.
A separate byte-budget denial must retain the same invariants and allow a
smaller legitimate growth. Its fresh real initial footprint is measured first;
the limit is that exact usage plus 98304 bytes, strictly between one and two
extra logical pages. The same footprint/interval is asserted after reopening.
The first trial used 262144 bytes and correctly rejected even the smaller
growth; that failed recovery expectation is retained, not rewritten as success.

A captured integer-only memoryGrow dispatch is measured under all four x87
rounding modes and a seeded masked invalid status with a nonempty x87 stack.
Each mode uses a fresh actual instance and successful growth. All inputs and
method values are retained before the 108-byte snapshots, and caller state is
restored before diagnostics. This checks that specific integer JS_Call boundary;
it does not assert preservation across arbitrary JavaScript, getters, Number
conversion or an entire JS_Eval operation. The original f32 nearest-even and
ambient-rounding controls are also retained.

The recipe requires both ordinary and fully instrumented real engines, equal
assertion summaries, original-140 summaries and two observed realloc recoveries.
Deliberate actual ASan/UBSan faults prove the instruments are active. Exact
original cache recipes, object bytes, sources, prepared headers, actual flags,
compile/config logs, original archives through retained evidence closures,
fresh objects, fixtures, test deltas and linked binaries are pinned and rechecked
late before the receipt is sealed. Historical QuickJS logs lacking an original
cache log hash retain the explicit v11 limitation: their present bytes were
pinned by that later closure, not by a fabricated historical receipt. Fresh
bridge/test compilation also emits actual non-system header dependencies with
GCC -MMD; every dependency must already match the pinned foundation/context.

Compiler driver executables/versions and actual source/header/object/log recipes
are pinned. Complete external compiler-subtool, linker-library and system-header
dependency closure is not claimed. Builds use fresh bounded owned children,
at most two jobs, compiler deadlines of 300 seconds and other deadlines of
180 seconds. Timeout cleanup is confined to the process group created by the
exact current Popen, with partial output retained.

Native execution, standard browser WebAssembly reflection/API, shared-memory
and reference JS bindings, streaming/origins, complete current Wasm proposals,
Trident/DOM, WebGL, WebGPU and application compatibility remain mandatory
unfinished gates. An accepted historical native v24 probe does not certify
this corrected memory or private JavaScript integration profile.
