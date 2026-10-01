# Trident CSS and graphics source seams — 2026-10-01

Latest JavaScript, CSS, modern WebAssembly, WebGPU and WebGL are all mandatory
user targets. Full WebKit porting remains optional. This is a **read-only source
and saved-evidence audit**, with one new handoff document: no build scripts,
dependencies, registration, services or VM operations. It complements the
original Trident handoff and the independently reviewed Automation v4/observer
v2 source at `09e6285`; their real MSHTML native execution is still pending.

The root-owned `benchmarks/modern-web-targets-v1.json` pins the current standards
and acceptance policy (SHA256
`b8194c9fa5de0d7d09419334daf70eed6195928839a3dbfbe2c3ecf1a6f16657`).
No inspected component satisfies the combined modern browser target. A graphics
API can use a genuine software backend, but its shaders, resources, results and
web bindings must work; framebuffer presentation alone supplies none of them.

## Available implementation

| Source seam | Actual present behavior | Missing behavior / integration |
| --- | --- | --- |
| `ntwddm/include/ntwddm.h`, `src/ntwddm.c`, `src/ntwd_present.c` in Modern/boot | Original bounded software surfaces, exclusive mapping, fill/blit, format conversion and framebuffer copy with CPU completion fences | No shader execution, texture sampling, GPU command scheduler, residency, driver ABI, D3D, EGL/GLES or Vulkan. WDDM/D3D/GPU requests explicitly fail unsupported. |
| `ntwddm/win98/probe.c` | Real Win98 GDI/DIB integration source; saved native GDI trial reports software pixel/presentation checks | Neither browser canvas bindings nor WebGL/WebGPU. Historical native proof applies to that software component only. |
| Independent `renderer/subset.cpp`, `win32_view.cpp` | Bounded transient HTML tree, tag/class/id/universal selectors, simple specificity/source-order rules, selected color/font/display/margin/padding properties, block/inline flow and GDI text/background paint | No authoritative persistent script-visible DOM or modern CSS grammar/cascade/layout. No variables, media/container queries, Flex/Grid, transforms, animation or canvas/graphics contexts in these modules. |
| Boot `shizukudos/win64/trident/engine.h` | Proposed C API covers nodes, style/CSSOM, geometry, events and views | The Wine-MSHTML/xul adapter and engine builders referenced by the design are absent. Microsoft Trident implementation source is not present. This Win64/Kernel64 design is not an x86 Win98 DLL. |
| Boot `shizukudos/win64/include/shzgpu.h`, `dlls/shzgpu`, `kernel64/gpu_sys.c`, `gfx_virtio.c`, `shzvirgl.h` | Custom Kernel64 GPU ABI, virtio 2D/virgl submission/resource/readback source. Saved GPU document reports a real host virglrenderer/llvmpipe triangle | No Win98 VxD transport, no Windows D3D/DXGI/OpenGL/Vulkan ICD. Saved guest-to-QEMU virgl execution was blocked, and host execution is a different profile. Handwritten virgl subset lacks a general GLSL ES/WGSL compiler and compute support. |
| Boot `apps/zetscape/upstream/engine.h`, `zetscape_extensions.h`, `tests/layout.js`, `tests/canvas.js` | Real native browser-host source, optional graphics admission metadata and executable page assertions | Genuine provider DLL remains absent; tests have not run in that provider. Hardware flags, PCI identity and frame counts are admission data rather than proof. ABI requires specifically JavaScriptCore: a QuickJS port cannot set that bit. |

Boot shared-engine docs still describe the existing full-WebCore/JSC lane; that
is the peer's optional route, not a new mandatory condition. Its current
interpreter bring-up profile disables WASM and still has a measured WTF startup
failure. The independently implemented QuickJS/Automation bridge is a separate
genuine-MSHTML extension lane; it does not implement CSS/layout or GPU APIs.

## Genuine Trident extension boundaries

The installed target previously audited is Win98 SE 4.10.2222, x86, IE
5.00.2614.3500. Public element-paint interfaces are **version-specific**. Microsoft
documents `IElementBehaviorRender` for IE5 and the change to `IHTMLPainter` in
IE5.5. The latter receives element bounds/update rectangles and GDI or DirectDraw
drawing context; behavior factory discovery can use the host client site's
`IServiceProvider`. These are concrete element painting seams, not a documented
replacement for the entire Microsoft CSS/layout engine. Newer documentation's
minimum OS table must not substitute for testing the actual IE5 target. See
[Microsoft's IE5.5 binary-behavior article](https://learn.microsoft.com/en-us/archive/msdn-magazine/2001/january/cutting-edge-binary-behaviors-in-internet-explorer-5-5),
[IE5 behavior Draw](https://learn.microsoft.com/en-us/previous-versions/windows/internet-explorer/ie-developer/platform-apis/aa753726(v=vs.85))
and [behavior factory discovery](https://learn.microsoft.com/en-us/previous-versions/windows/internet-explorer/ie-developer/platform-apis/aa753739(v=vs.85)).

For this extension lane, MSHTML remains the real document/element identity
owner. New modern CSS logic must attach to those actual elements and synchronize
style mutations, inherited values, computed results and invalidation. Rebuilding
a second transient HTML tree and painting it while unrelated MSHTML objects
answer script queries would break document authority. A deeper complete layout
implementation needs a deliberate DOM/layout ownership seam; a separate
opensource compatibility backend is possible without the whole WebKit port,
but its COM/document contract and native behavior still require implementation.

## Smallest meaningful disjoint CSS implementation

Propose **new** `src/m98_css_tokens.[ch]`, `src/m98_css_variables.[ch]`,
`src/m98_trident_style.cpp` and separate host/native tests. Do not edit the frozen
Automation/runtime files or peer renderer/provider sources.

Start with CSS Syntax tokenization and custom-property computation rather than
ad-hoc semicolon/comma replacement. CSS Syntax defines tokenization, nested
component values and error recovery; selectors/cascade/property grammar remain
separate modules. Custom properties require case-sensitive names, inheritance,
real `var()` token substitution, fallback and dependency-cycle/invalid-value
semantics. The core can use a bounded callback interface supplying real parent
identity/declarations; the native adapter must use actual MSHTML style objects
to apply resolved supported properties. See [CSS Syntax 3](https://www.w3.org/TR/css-syntax-3/)
and [CSS Custom Properties 1](https://www.w3.org/TR/css-variables-1/).

Initial real native acceptance: modern JS changes a custom property on an
actual ancestor, resolving a descendant's foreground/background color and a
supported width; independently query native style and geometry, then review the
same MSHTML Korean view before/after. Include ancestor removal, changed
declarations, nested fallbacks, cycles, escaped/Unicode names, invalid values,
teardown and two-document isolation. The result is a named CSS slice. Do not
return true for `CSS.supports`, computed Grid/Flex values or native modern CSS
coverage until the corresponding semantics and layout exist. Partial token or
variable results do not complete CSS Snapshot 2026.

Flex/Grid/container layout additionally needs authoritative box trees, sizing,
reflow, scrolling, clipping, font metrics/shaping, hit testing and accessibility
mapping. Extending only the current subset painter cannot satisfy that list.
Selective reuse/porting of open layout components is permitted; copying private
Microsoft internals or requiring the entire WebKit engine is not this proposal.

## WebGL/WebGPU architecture and next measurable work

WebGL needs a browser context/binding and real GLES-compatible state/shader
execution. ANGLE provides EGL/GLES and shader validation/translation over native
graphics backends; it is not automatically a Win98 port or a complete browser
binding. Its backend support differs by GLES version, so legacy Direct3D drawing
cannot establish WebGL2. See [ANGLE's upstream backend table](https://chromium.googlesource.com/angle/angle/+/main/README.md).

WebGPU needs object/lifetime/validation rules, WGSL translation, render **and**
compute, asynchronous error/device-loss semantics and canvas composition. Dawn
separates validation/state frontend from actual native graphics backends, with
Tint for WGSL translation. A wire client still needs an executing backend and
browser origin/DOM bindings. Neither the inspected NTWDDM nor handwritten virgl
subset supplies those. See [Dawn's upstream architecture](https://dawn.googlesource.com/dawn/+/refs/heads/main/docs/dawn/overview.md).

The first graphics integration should be a **new version-specific real-MSHTML
element composition probe**, e.g. `src/m98_trident_paint.cpp` plus a native test.
Use an explicit local behavior factory and the actually supported IE5 or IE5.5
interface, avoiding global registration. Bind rendering to the same genuine DOM
element, native clipping/resize/invalidation and teardown. Its bounded surface
callback can consume real renderer-produced BGRA pixels and use the NTWDDM
software surface API where appropriate. This verifies composition only; a
constant rectangle or test pattern must never create a `webgl`/`webgpu` context
or set a standards capability bit.

In parallel, select and pin an actual x86 backend/compiler component before
porting. Require a real native offscreen shader render/readPixels test for GL,
and a WGSL compute storage-buffer/readback plus render test for WebGPU. Port
CRT, TLS/threading, allocation, executable code policy, CPU instruction profile,
driver loading and error handling explicitly. Modern Mesa LLVMpipe is a software
rasterizer using LLVM-generated machine code; its x86 documentation recommends
64-bit/SSE2 and later instruction support. It cannot be assumed to satisfy our
current i486/no-SSE native profile without a separately tested port. See
[Mesa's LLVMpipe requirements](https://docs.mesa3d.org/drivers/llvmpipe.html).

Hardware acceleration on Win98 needs its own real display/device transport,
memory ownership/mapping, command completion, reset/timeouts and driver backend.
Kernel64 syscall wrappers cannot be dropped into that process. NTWDDM software
fences count CPU writes; GPU queue fences must instead track actual submissions.
WDDM itself is a larger driver architecture introduced with Vista, including
user/kernel components, scheduling and memory management. A project name or
function-shaped wrapper is insufficient. A complete WDDM binary layer is not a
prerequisite for a deliberately implemented native/software graphics backend.
See [Microsoft WDDM overview](https://learn.microsoft.com/en-us/windows-hardware/drivers/display/windows-vista-display-driver-model-design-guide).

Final native graphics acceptance binds backend/device/driver/compiler hashes,
measured features/limits, real invalid-shader/errors, textures/depth/blending,
render and compute readback, resource destruction/device loss, and reviewed
canvas pixels in the same Trident document. Pin relevant WebGL/WebGPU CTS/WPT
revisions. Software output must be identified as software; hardware acceptance
also requires actual driver submission/completion/presentation evidence.

## Ownership and snapshot pins

Session 733e owns the independent host/porting lane; its coordination note is an
ownership record rather than a current VM/process assertion. Boot 83bd owns
original IE/Zetscape integration, 7707 owns coordinated compatibility/runtime
work, and root 5abe owns this new Automation/TLS lane. No peer file was edited.
The inspected independent AGENTS requires separate exact IE/OS variants and
actual rendering/navigation/input/unload evidence. Source/build/host-only results
do not certify Win98 rendering. Root owns any subsequent trial/staging.

Read-only source hashes at this audit:

| File | SHA256 |
| --- | --- |
| boot `ntwddm/include/ntwddm.h` | `d561123913b531e7e82bef0a2107c44954ecdef237f43a6280eaf9bd39c11950` |
| boot `ntwddm/src/ntwddm.c` | `0000ceaca7a1c7f437db2c60a1a8da5edef61020d80c0ecffad53644b3f6170c` |
| boot `ntwddm/src/ntwd_present.c` | `23a42f86a468ef33f93f02d67ea9250234d3236b4f35665cb7cc3b232bbb89cd` |
| independent `renderer/subset.cpp` | `c0234ba6870f41f7d1496b30195b56425d8b76aed95f215d8098bbac61844d45` |
| independent `renderer/win32_view.cpp` | `4acacb091b05f4114ce407162b6fc38cf34553519c8d76f0fe5e561881f9f034` |
| boot `shizukudos/win64/trident/engine.h` | `a24a698ac8c92b7c8b725a86e84498a7d74d72a312ee45eb9c14e9509888696a` |
| boot `shizukudos/win64/include/shzgpu.h` | `9e83de7e7b9c004f5b7aeb8bcac40dca33c9b1f95adab47cd0bed46a368d0eb7` |
| boot `apps/zetscape/zetscape_extensions.h` | `41994aecb558ea1b4914bfcde5a73bd9934c187bdfa01efcde1207c1398f882c` |

GPL-2.0-only original audit/handoff. No external engine or shader source was
copied; any selected implementation must retain its own per-file licenses and
exact upstream revision. All modern browser/GPU/application completion claims
remain unverified.
