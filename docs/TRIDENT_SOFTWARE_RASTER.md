# Genuine TGSI triangle raster foundation

This opt-in component draws a real triangle into caller-owned color/depth memory
using the frozen Mesa 26.2.3 scalar TGSI fragment interpreter, implementation
commit `e40cd6b`. Every successful host test dispatches `m98_sp_run`; there is no
canned frame, DOM mock, GLSL parser or browser capability flag. The interpreter
build receipt is SHA-256
`b2c21ccdbf876d310affac58202d4b3139c30f1d71db7b696d12980dfb81cac2`.
The new raster code is original GPL-2.0-only code under the repository license.
Upstream Mesa MIT/per-file SoftFloat and other notices stay in that immutable
build's original-source closure; no upstream generator or download is rerun.

The five new source paths are `src/m98_softpipe_raster.[ch]`,
`tests/m98_softpipe_raster_host.c`, `tools/build_softpipe_raster.py` and this file.
The builder pins and rechecks the original 16 source, 49 upstream, seven prepared,
180 compiler-header, generated-file, toolchain, artifact and successful-log sets
before and after execution. It creates a fresh ignored build directory and
copies all fourteen consumed/new repository sources plus its actual native
header closure. Existing shader sources and old evidence stay untouched.

## Exact raster contract

`m98_raster_draw` accepts one triangle, a genuine shader cookie/run function,
an allocator, up to four float4 varying planes, eight uniform float4 values,
RGBA8 color and float32 depth. All vertices, constants and function-table entries
are copied and checked before callbacks. Callers keep the cookie, callback code,
user data and exclusive attachment memory alive and unmodified until return.
Full declared attachment capacity spans and the stats object must be disjoint,
including trailing row padding and unused suffix capacity. Callback allocators
return exclusively owned blocks of at least the requested size and aligned
float storage; callbacks cannot free the shader or mutate attachments.

The target is at most 64 by 64 pixels, origin at top-left with y increasing down.
Signed vertex coordinates have exact 1/16-pixel units and magnitude at most 4096
units (256 pixels). Signed 64-bit edge equations determine center-sample coverage
at `(x+0.5,y+0.5)`. Winding is normalized with complete associated vertex values.
For positive edge orientation, upward edges and rightward horizontal edges are
inclusive; other edge ties are exclusive. Adjacent triangles therefore cover a
shared-edge pixel once. Writes are bounded by the target; vertices can all lie
outside and still cover it. Degenerate/outside triangles succeed without shader
dispatch or allocation, so a stale shader cookie cannot be diagnosed there.
This center/top-left and helper-quad model follows the documented raster rules,
with a narrower private API. [Microsoft rasterization rules](https://learn.microsoft.com/en-us/windows/win32/direct3d11/d3d10-graphics-programming-guide-rasterizer-stage-rules).

Varying and z planes are affine in screen coordinates, computed in double and
checked before conversion to float. True top-left centers of 2 by 2 groups are
passed into Mesa. Its helper lanes retain the input planes needed for DDX/DDY;
the live mask contains only target-covered/depth-passing samples. The returned
discard mask can only remove those lanes. Only surviving lanes with a finite
single RGBA output commit pixels. This slice has no perspective interpolation,
homogeneous clipping, vertex shader, stencil, MSAA, scissor state or shader depth.

Depth modes are off, less, less-or-equal and always. Depth values must initially
be finite in [0,1]; finite interpolated z is clamped to that interval. An explicit
boolean selects depth writes. Depth rejection happens before shading, which is
valid for this no-shader-depth/no-side-effects lane; discarded samples write
neither color nor depth. Geometry-covered 2 by 2 groups reserve a conservative
budget before allocation, bounded by 1024. Depth rejection can reduce real runs
but does not lower the reservation.

## Defined byte-domain blending

Finite shader channels are clamped to [0,1] and converted to UNORM8 by
`floor(channel*255 + 0.5)`. Replace stores these four bytes directly. Source-over
uses straight-alpha byte-domain composition without sRGB transfer. For source
bytes `s`, destination bytes `d`, and their alpha bytes `Sa`, `Da`, define:

```
D = Sa*255 + Da*(255-Sa)
outA = floor((D + 127) / 255)
outC = floor((sC*Sa*255 + dC*Da*(255-Sa) + floor(D/2)) / D)
```

For `D==0`, all output RGBA bytes are zero. The RGB equation unpremultiplies by
the composed alpha; integer nearest rounding resolves exact halves upward.
Intermediate integer numerators fit uint32. A transparent source preserves a
nontransparent destination; a transparent destination retains source RGB.
For red alpha 128 over green alpha 128, the literal result is `(170,85,0,192)`.
This precisely defined operation does not claim general WebGL blend-state or
color-space compliance.

## Transaction and evidence boundaries

At most 32 KiB of active color/depth scratch is allocated per draw. Allocation,
budget, invalid/nonfinite data, genuine shader failures and unsupported multiple
outputs leave both full strided attachment spans and caller stats unchanged.
Successful draws commit only active rows, leaving padding and guard memory
unchanged. Nested and concurrent calls return BUSY before reading shared state.
Each `m98_r_ops` allocate, deallocate and run_shader callback has a scoped masked
nearest-even floating-point environment. The outer call restores the original
complete x87 state on native x86 and the host floating environment on success
and failure. The unchanged shader foundation calls its own trusted heap/math
providers directly. Those nested providers must preserve the shader's internal
FP environment: a success-path mode change can affect later TGSI arithmetic
before the outer run_shader scope returns. Individual isolation of those
providers requires a separately rebuilt shader profile and dedicated controls;
this raster profile does not establish that stronger guarantee.

Host normal and ASan/UBSan probes independently tabulate coverage, center colors,
derivatives at partially covered quads, true discard masks, depth equality and
gradient values, reversed winding, shared/subpixel edge ties, offscreen/no-op
cases, alpha composition, guard memory, OOM and rollback after a later genuine
shader failure. Changing a real shader or uniform changes actual frame bytes.
An additional native `M98RAST.DLL` has exactly two C exports and no system/CRT
imports. The builder verifies PE32/Win98 4.10, relocations, 2 MiB/512 KiB stack,
and complete executable-byte i486/x87 decoding using the independently reviewed
frozen common scanner, including its real modern-instruction rejection controls.

The native DLL has not been executed in Windows 98. Native frame readback,
MSHTML integration, GLSL ES compiler/linker, full Gallium draw, GLES/WebGL2,
textures, loops, WebGPU/GPU compute, full browser and modern apps remain
unfinished. These are mandatory follow-on goals. An actual compiled vertex and
fragment shader, linked varying interfaces, textured/depth/blended triangle
readback, standard GL state/bindings and genuine Win98/MSHTML execution are
required before claiming a browser graphics backend.
