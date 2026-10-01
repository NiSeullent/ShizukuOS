# Fixed 64 KiB Wasm memory backend profile

This is an additive, separately versioned correction over frozen WAMR v24.
Original runtime/bridge sources, caches, numeric probe and canonical native
stages remain unchanged. It does not install a browser WebAssembly namespace.

The official loader rewrites memories when a module contains neither memory.size
nor memory.grow. The auxiliary-heap branch can shrink bytes/page; a separate
MULTI_MODULE=0 branch coalesces initial pages and forces initial/max counts to
one (or zero). SHRUNK_MEMORY=0 alone leaves that second rewrite active.

The new pinned profile sets M98_WASM_BROWSER_MEMORY=1 and SHRUNK_MEMORY=0.
Its additive loader patch excludes both rewrites. Declared 64 KiB pages and
limits are retained independently of the instructions present in the module.
Allocation, bounds, memory growth/reallocation and the numeric C ABI remain
the real frozen implementations. The usage-aware malloc/realloc path previously
left initial/new linear bytes uninitialized: the guarded prepared-memory patch
zeros initial bytes and precisely the successful growth tail, retaining the
prefix and the unchanged state on failure. A uint64-to-unsigned callback size
guard rejects 4 GiB instead of narrowing it to zero. The original selected
suite also exposed a misaligned table following four global bytes; guarded
arena/start/stride padding uses the compiler's actual table alignment and keeps
the structure layout unchanged. Actual host/sanitizer/native alignments and
element sizes are emitted by the respective compilers and decoded as absolute
object symbols without native execution.

The loader patch is applied to its exact official body. The common-memory and
runtime-arena patch sections are applied to their exact frozen-v24 prepared
bases, preserving the prior bounded-profile patches. The profile pins both
official originals, prior prepared bytes, and corrected prepared bytes. Every
linked translation unit's actual
preprocessor configuration is recorded for normal, full sanitizer and native
profiles. No previous failure is reclassified as standard success.

Regression requirements include no-grow declared 1..3 and 2..4 memories,
auxiliary-heap metadata, zero/multiple memories, precise 65536-byte boundaries,
maximum/overflow, zero-fill/data preservation/copy/traps, actual denied realloc
and recovery, byte-budget denial, import reentry, dispatch budget and complete
x87 state preservation. Original selected memory_grow/copy/fill WAST is
compiled unchanged by pinned official WABT. The >800-page initial grow group
exceeds the unchanged 256-page/32 MiB host budget and is excluded as a whole;
cross-module imported-memory registry groups and a standalone register command
also remain explicit exclusions, with original inputs and commands preserved.
This selection has 4656 original commands, 4641 selected and 15 excluded; no
text-only malformed command occurs in these three retained suites.
The pre-open-only frozen allocation fault hook is exercised by bounded real
allocation-point trials until the actual growth realloc fails, then growth
retries on the same instance after that one-shot fault is consumed. Complete
zero pages, dirty-block reuse, 4 GiB initial/growth rejection, multiple/zero
tables after four global bytes, and the unchanged official table group are
required checks. Failed v1-v3 trials and the real UBSan alignment trace remain
available in their original build children; no failure oracle is rewritten.
v4's compiler failure and the first positive v5 proof are also preserved.
v5 passed 386 project checks and 4641 original official commands under both
normal execution and full ASan/UBSan instrumentation, with deliberate failures
confirming both instruments were active. The final recipe also rechecks every
new compile object, log, generated header/module/input, linked test binary and
DLL pin before sealing its receipt.

Compiler driver executables, versions, actual compiled source/object bytes,
flags and logs are pinned. This does not claim complete external compiler
subtool, linker-library or system-header dependency closure. The native record
captures the checked PE32/x86 DLL identity, OS/subsystem 4.10, zero timestamp,
stack/entry/relocations/modern-directory constraints, exact twelve named exports
without ordinal-only entries/forwarders, and unique named original OEM imports
from exactly KERNEL32/MSVCRT. It also records the actual relevant PE field values.

Fresh Win98 PE32/4.10/OEM-import/full-byte i486 gates are required on the new
profile DLL. Native execution, Trident/browser APIs, DOM, complete modern Wasm,
shared memory/reference JS bindings, GPU and application acceptance remain
mandatory unfinished gates. The historical v24 numeric stage intentionally
continues to describe v24 until a separately reviewed future stage is created.
