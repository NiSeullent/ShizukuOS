# Genuine Mesa TGSI fragment foundation

This component builds genuine Mesa26.2.3 TGSI tokens from a bounded private typed
IR and executes the actual upstream scalar fragment interpreter. It does not
provide GLSL ES compilation, general text/raw TGSI ingestion, Gallium
rasterization, GLES, WebGL, WebGPU, textures, loops, compute or browser bindings.
Those mandatory modern targets remain unfinished. Native guest execution is
pending; host results and native artifact gates are distinct evidence.

The official original source archive and selected per-file pins are explained in
`docs/MESA_SOFTPIPE_PORT_FEASIBILITY.md`. Original upstream copyright/license
notices remain present. Prepared source patches add checked binding allocation
failures, adapt real allocation, and select scalar half-float paths. They do not
replace shader arithmetic, control masks, interpolation or derivatives with test
results. The current checked generator executes only its pinned enum-generation
recipe and writes captured stdout into the fresh build directory.

Opaque monotonic cookies identify at most16 live contexts; close clears a caller
cookie. Callbacks and their user storage remain alive through close. All calls
are serialized using i48632-bit compare-exchange; concurrent calls or callback
reentry return BUSY before shared state is read. The allocator tracks real
aligned allocations against a4MiB/context cap and unwinds failed construction.
Program instructions and run IO are snapshotted before external callbacks.
Failed operations leave output cookies/results unchanged. Cookies are never
reused; stale and zero run cookies fail. Do not modify or release callback
storage while any context is alive. An allocator must return distinct usable
storage and correctly release it; arbitrary caller pointer validity is outside
this C ABI's contract.
Returned allocation storage belongs exclusively to the component until its
deallocate callback. An embedding allocator must not modify retained blocks or
the private TGSI tokens. These trusted native callbacks are not a browser shader
ingestion interface.

At most128 instructions,4 linear-interpolated inputs,8 dynamic constants,
16 temporaries,2 outputs and16 nested conditionals are accepted. All registers
are four-channel floats; destinations write all four channels. Every source
register must be initialized on every control path. IF/ELSE/ENDIF merge
initialized sets; derivatives in conditional bodies fail unsupported. No loop,
image, texture, indirect register, integer division or compute opcode is admitted.
An END must appear exactly once at the end. Real output values are copied after
successful execution and cleanup; the reported alive mask is the actual returned
mask restricted to the four lanes and caller's live mask. Input planes use the
upstream genuine linear interpolation declaration, not injected undeclared inputs.
SIN/COS/SQRT/POW lower each vec4 component to genuine scalar-X TGSI operations
and a private scratch-to-destination move. This preserves self-swizzled
temporaries. Expansion is bounded to at most640 TGSI instructions and4096 tokens;
the finite forward-only conditional program admits no backward control flow.

Selected scalar math uses a checked actual provider for double
cos/sin/log/pow/sqrt/floor/ceil/ldexp, converting float requests at the boundary.
Portable bit-level helpers implement truncation, nearest-even and signed-zero/
NaN-aware min/max. This bounded profile does not claim correctly rounded GLSL ES
math across all inputs. MAD is ordinary multiply-add with possible intermediate
rounding; FMA is unsupported. The native fixture resolves exact original-system
MSVCRT exports and uses actual Win98 heap APIs. No modern float libm object or
cached peer object is implicitly imported. The full native DLL/probe instruction
and OEM import closures are gated. Scalar half helpers retain genuine x87 FISTP
integer rounding; the original SoftFloat implementation remains present for
unexposed interpreter switch operations. It does not create a public FMA claim.
The pinned common scanner checks raw bytes/address coverage of every executable
PE VirtualSize section and uses an explicit i486/x87 instruction allowlist. Its
original objdump bytes, command, per-section coverage and hashes are retained for
both artifacts. Native FNSAVE/FRSTOR preserves the full caller
x87 state while the component runs with nearest rounding and masked exceptions;
host fenv checks separately test state restoration.

The meaningful core oracle uses analytical varying planes/constants and literal
expected quad outputs, divergence, discard, fine DDX/DDY, channel swizzles,
allocation failures, callback errors/reentry, parent-independent context
lifetime, stale cookies and output transactionality. Modern-host execution
cannot establish native Win98 or browser behavior. The next full GLES slice
needs genuine GLSL ES compile/link plus actual draw/texture/depth/blend/render
target readback before browser canvas, context-loss and security validation.
