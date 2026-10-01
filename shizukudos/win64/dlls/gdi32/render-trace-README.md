Opt-in software rendering observations
=====================================

`shz.k32trace` provides `SHZ_K32TRACE=1` to real processes. GDI then emits
`GDI raster:` lines for created DIB sections, ordinary raster blits, and the
actual `NtGdiPresent` return status at the existing flush point. GDI numeric
fields are hexadecimal. User-mode GDI reports metadata only and never reads
additional bitmap pixels: pages outside an operation's actual destination clip
can be inaccessible even when the clipped operation itself succeeds. Each operation/process emits its first 16 calls, then
every 64th call up to call 4096: at most 80 lines. It preserves thread LastError,
does not change pixels, and adds no public exports or dependencies.

Existing `shz.systrace` enables `K64 raster:` lines from the actual present
routine while its ordinary graphics lock is held. These report the live HWND,
owner/caller process, visible/style state, submitted rectangle, actual status,
and the number of actual framebuffer updates during that call. They sample
the successfully staged caller pixels and, when composition occurred, the
resulting damaged rectangle of the real framebuffer back buffer. Faulted or
empty submissions do not sample partially staged data. The first 32 calls,
then every 64th up to 4096, produce at most 96 lines for the whole kernel.

All pixel observations occur on kernel-owned buffers and use at most 64 evenly spaced in-bounds samples,
including the first and last pixel. `sample_hash`/`source_hash`/`screen_hash`
are bounded sample hashes, not whole-frame checksums. `nonface` counts sampled
RGB pixels that differ from the window manager's initial gray `0xc0c0c0`;
`differing` compares samples against their first pixel. Neither counter proves
that a particular HTML page rendered. Screenshot and application interaction
remain necessary acceptance evidence. No pixel is synthesized by tracing.

Primary path reference: Electron v43.2.0 pins Chromium 150.0.7871.129 in its
DEPS. That Chromium's `SoftwareOutputDeviceWinDirect::BeginPaintDelegated`
creates a section-backed platform canvas; `EndPaintDelegated` obtains the
target HWND's DC, invokes `skia::CopyHDC` (ordinary `BitBlt` for opaque output),
and releases the DC. Existing `--disable-direct-composition` avoids the
redirection-removal swap chain branch. These observations diagnose that real
software route without claiming missing D3D or composition backends work.

- https://github.com/electron/electron/blob/v43.2.0/DEPS
- https://github.com/chromium/chromium/blob/150.0.7871.129/components/viz/service/display_embedder/software_output_device_win.cc
- https://github.com/chromium/chromium/blob/150.0.7871.129/skia/ext/skia_utils_win.cc
- https://github.com/chromium/chromium/blob/150.0.7871.129/components/viz/common/features.cc

Validation: `tests/test_render_trace_host.c` exercises the exact production
GDI trace bodies with controlled environment/logging boundaries, including
protected unused source/backing pages, trace-off behavior, LastError
preservation, unchanged pixels, and the finite line cap. The shared kernel
sampler is tested on actual guarded/padded/top-down/bottom-up pixel memory.
It is a host test, not guest/UI proof.
