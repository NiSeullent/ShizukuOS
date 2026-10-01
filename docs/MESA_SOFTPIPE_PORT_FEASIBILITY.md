# Current Mesa software shader foundation for native Win98

The selected candidate is Mesa **26.2.3**, released 2026-09-16, using its real
Gallium softpipe interpreter with LLVM disabled. The first bounded component
should execute shader programs and read their computed outputs. It supplies a
foundation for further graphics work; neither a shader interpreter nor software
surface presentation establishes WebGL, WebGPU, GLES, GLSL ES, hardware GPU
execution or Trident integration. All those completion flags remain false.

## Exact source and license receipt

The [official release notes](https://docs.mesa3d.org/relnotes/26.2.3.html) publish
archive SHA256 `1628058a8d2c0615975de5a15ab7bbb9638c50000b5bed9456ff423ea034a81f`.
The archive downloaded from
`https://archive.mesa3d.org/mesa-26.2.3.tar.xz` is exactly 68,561,540 bytes and
matches that pin. `build/mesa-softpipe-audit-v1/archive.json` records the download.
The source selection records 13,626 archive members, 376,146,620 regular-file
bytes overall, and extracts only 2,552 regular files totaling 41,231,477 bytes.
No archive script was executed, and no system package or configuration changed.
Two selected symlinks were recorded and skipped rather than followed.

Original selected source bytes remain unchanged under the ignored audit source
folder. `source-pins.json` SHA256
`71b5e6199051ac9baa9b1bfb21816324cf57325039cf4dcbd9f9c110ebcf4efa` binds every
selected original file. The selection contains include/licenses, c11/util,
compiler, Gallium headers/auxiliary/softpipe and Mesa state-tracker sources.
Generated headers and any later prepared portability patches need separate pins.
The complete upstream engine has not been built or run in this checkpoint.

Mesa's [license guidance](https://docs.mesa3d.org/license.html) requires checking
individual files. The selected TGSI executor/parser and softpipe fragment code
retain VMware's permission/license notices; half-float code retains Brian Paul,
Philip Taylor, AMD and Intel notices. `util/softfloat.c` contains the Berkeley
SoftFloat3e BSD license and University of California/John Hauser attribution.
The Win32 c11 thread implementation is BSL-1.0. Do not relabel all Mesa sources
as MIT or erase their notices when preparing a subset. Existing project glue can
remain original GPL-2.0-only; copied upstream source retains its own license.

## Real execution seams

The [official driver list](https://docs.mesa3d.org/systems.html) distinguishes
softpipe's shader interpreter from LLVMpipe's JIT. The exact selected source
confirms that distinction:

| Source seam in Mesa26.2.3 | Actual behavior and bounded consequence |
| --- | --- |
| `gallium/drivers/softpipe/sp_context.c` | Creates a real fragment `tgsi_exec_machine`; a complete pipe context also initializes draw, surfaces, state and resource modules. |
| `softpipe/sp_state_shader.c` | Accepts TGSI or converts genuine NIR to TGSI. Its NIR route is a further compiler dependency, not implemented by a wrapper accepting shader-shaped strings. |
| `softpipe/sp_fs_exec.c` | Binds the shader, invokes `tgsi_exec_machine_run`, applies the returned lane mask and reads the interpreter outputs. |
| `auxiliary/tgsi/tgsi_exec.c/.h` | Real four-lane scalar shader machine, arithmetic, registers, constants, masks, derivatives and resource callbacks. Sixteen-byte alignment is a layout requirement; it does not by itself require SIMD. |
| `auxiliary/tgsi/tgsi_build.c` | Constructs actual TGSI tokens. A typed, bounded adapter can use it without exposing the unchecked raw TGSI parser to arbitrary caller bytes. |
| `compiler/glsl`, `compiler/nir`, `auxiliary/nir/nir_to_tgsi.c` | Actual compiler route needed to consume GLSL ES and feed the driver. [Mesa's compiler documentation](https://docs.mesa3d.org/glsl.html) describes this pipeline; accepting IR alone does not exercise it. |
| `mesa/state_tracker` plus frontend/winsys | GL/GLES state, resource and render-target integration needed for draw/readPixels. Browser bindings, WebGL validation and canvas lifetime are additional work. |

The small direct executor is therefore a justified first native foundation.
Full softpipe screen/context and GLSL/GLES remain a larger next slice. WebGPU
additionally needs real WGSL validation, device/queue/buffer/resource semantics
and an appropriate execution backend; a Gallium fragment test cannot satisfy it.

## Verified native gaps

[Current Mesa build documentation](https://docs.mesa3d.org/install.html) lists
modern compilers and Windows SDK20348+/VS2022. It does not certify Windows98.
The local toolchain has GCC/Clang, MinGW x86, Ninja, Flex and Bison, but no Meson
or Mako installation. A bounded manually selected C executor build can avoid
those broad build tools; complete compiler/driver builds need a pinned tool plan.

* `c11/impl/threads_win32.c` directly calls Initialize/Wake/Sleep condition-variable
  APIs and GetThreadId. These are absent from the actual Korean Win98SE OEM
  export baseline. Microsoft documents [condition-variable initialization](https://learn.microsoft.com/en-us/windows/win32/api/synchapi/nf-synchapi-initializeconditionvariable)
  and [GetThreadId](https://learn.microsoft.com/en-us/windows/win32/api/processthreadsapi/nf-processthreadsapi-getthreadid)
  as later Windows APIs. **TryEnterCriticalSection is present** in that actual
  baseline, so the modern documentation minimum table alone must not classify
  it as missing. A single-owner direct interpreter need not include the thread
  implementation; a full driver must port actual synchronization semantics.
* `util/os_memory_stdc.h` selects `_aligned_malloc/free/realloc` on Windows;
  those exports are absent from the original MSVCRT baseline. Port real checked
  aligned allocation and retain a recoverable original pointer and size.
* `util/rounding.h` assumes nearest rounding for rint/rintf-based operations.
  Preserve/restore the caller's x87 state and establish correct shader rounding.
  Float math and helpers must use actual verified implementations, not stubs or
  optimistic linkage to a modern host libm. Original MSVCRT exports double
  cos/sin/log/exp, but lacks rint/rintf, roundf, exp2f/log2f and aligned allocation.
* `tgsi_exec_machine_bind_shader` has unchecked declaration/instruction realloc
  results and a void return contract. Its immediate allocation failure can leave
  a partially bound program. Prepared failure-path changes must preserve the
  original source pin, return an explicit error and unwind owned allocations.
* Raw TGSI parsing trusts header/body lengths and uses assertions for bounds.
  General loop execution has no public instruction budget. The first adapter
  should build tokens from validated typed instructions, reject loops, enforce
  initialized register reads and admit only bounded structured control flow.
* Full native artifacts need exact i486/noSIMD flags and a scan of **all linked
  instructions**, including math and compiler helpers. Disable Mesa's default
  x86 SSE2 option and all LLVM paths. Exact OEM imports, PE32/OS4.10 headers,
  relocations and adequate stack commit are separate required gates.

## Smallest meaningful implementation and acceptance

Proposed disjoint glue is `src/m98_softpipe_shader.[ch]`, a host test, a native
build/probe gate, a bounded builder and its handoff. It should construct genuine
TGSI fragment programs through the upstream builder and execute the actual
interpreter with dynamic inputs and constants. Register/swizzle/type/operand
bounds, IF/ELSE/ENDIF nesting and missing END are checked before binding.
Unsupported loops, textures/images, compute and general raw TGSI input fail
explicitly until their execution budgets and real resources exist.

Tests must independently calculate expected outputs for varying uniforms and
input lanes, divergent branch masks, discard, DDX/DDY and multiple contexts.
Changing a constant must change the actual computed output. Reject malformed
programs and unsupported opcodes transactionally; test each allocation failure,
close/reopen and caller floating-point state restoration with normal and
ASan/UBSan runs. Never turn a failed operation into a constant color or success.

Then compile the same selected source plus actual native math/allocator port to
original i486 PE32 and inspect its complete import and instruction closure. A
future genuine Win98 test must load the exact adjacent component, run changing
shader inputs, independently read results and record actual owned-child exit and
flush/close. This audit contains no such native run. Later draw/texture/depth/
blend/render-target execution, real GLSL ES compilation and genuine MSHTML
canvas/input/paint evidence remain explicit completion prerequisites.
