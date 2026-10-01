Retained pixels for non-layered transparent windows
=================================================

The actual publisher Legcord / Electron 43.2.0 software output worker submitted
real shared-section DIB pixels to its browser HWND. Kernel samples contained
the bundled setup.css background `ff1e1f22` and later differing content, while
the composed screen stayed `00c0c0c0`. The actual live tree identified its
full-client `WS_EX_TRANSPARENT` child, which never submitted client pixels.
The previous compositor drew that child's allocated gray surface over the
browser's real pixels.

The window manager now records exactly which opaque client pixels have been
submitted successfully. A non-layered transparent client composes those
pixels over previously composed parent/lower-window pixels. Unsubmitted
pixels leave that underlying content intact. Explicit gray pixels remain
opaque; alpha/RGB values never act as a coverage/color key. Window class
names and process/application identities never select behavior. Existing
layered-window composition remains separate.

Coverage is a lazy one-bit mask for every window's client surface so later
style changes retain genuine written content. At the current 16 MiB surface
limit this costs at most 512 KiB, plus the existing allocator's page rounding.
There is no mask allocation for untouched windows. Only fully staged caller
rectangles mark coverage; source faults and mask OOM leave old content intact.
Resize allocates replacement surface/mask before releasing anything, copies
only overlap, clears new areas, and discards clipped coverage. Window teardown
frees both owned allocations. Transparent top-level windows are excluded from
the optimization that skips supposedly opaque lower windows.

This supplies retained opaque presentation for the demonstrated software
rendering route. It does not provide alpha blending for non-layered windows,
new GDI destination-read semantics for drawing operations on transparent
windows, or all Windows same-thread transparent paint-message ordering.
Those existing GDI/message-manager limits require separate real contracts.

Validation uses exact production compositor, resize, and NtGdiPresent bodies,
an independent per-pixel coverage oracle, owned allocation accounting,
injected OOM/late source-row faults, and actual clipped/region composition.
The unchanged before source builds but fails the untouched-transparent-child
pixel assertion. The native guest fixture uses actual HWNDs, real caller
pixel submissions, and kernel composition readback, with an ordinary opaque
child as a negative control. Host/native builds are not actual guest or
application rendering proof; the parent owns isolated guest execution.

Primary contracts:

* [Microsoft WS_EX_TRANSPARENT](https://learn.microsoft.com/en-us/windows/win32/winmsg/extended-window-styles):
  underlying same-thread siblings paint before the transparent window.
* [Exact Chromium 150 legacy child](https://raw.githubusercontent.com/chromium/chromium/150.0.7871.129/content/browser/renderer_host/legacy_render_widget_host_win.cc):
  transparent child setup and background-erasure handler with no drawing.
* [Exact Chromium software output](https://raw.githubusercontent.com/chromium/chromium/150.0.7871.129/components/viz/service/display_embedder/software_output_device_win.cc):
  actual shared-section canvas, GetDC/CopyHDC/ReleaseDC presentation.
