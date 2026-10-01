# Same-desktop software presentation

`gfx_syscall_present` now accepts a live HWND owned by another process on
the runtime's existing single shared desktop. This implements the drawing
path used by Chromium/Electron's software GPU worker. It does not grant
permission to change another window's metadata, destroy it, or read its
surface through the private owner-restricted readback operation.

Microsoft's [GetDC contract](https://learn.microsoft.com/en-us/windows/win32/api/winuser/nf-winuser-getdc)
defines the target by HWND and permits GDI drawing into its client area.
Chromium's
[software window device](https://chromium.googlesource.com/chromium/src/+/150.0.7871.129/components/viz/service/display_embedder/software_output_device_win.cc)
uses `GetDC(hwnd_)` to present renderer output. The current kernel has one
desktop and no separate desktop/session security model. Multiple desktops
will require a desktop-access check before this path is reused there.

The private top-down 32-bit presentation ABI requires the source dimensions
to equal the actual destination surface, a stride of at least width times
four, and an actual surface no larger than the existing 16 MiB kernel limit.
Coordinates are widened before addition and clipped to client bounds. All
source reads use the actual caller's address space and range checks. Empty
rectangles are successful no-ops which read no pixels. Nonempty pixels are
staged in bounded kernel-owned memory before committing, so a later source
row fault leaves the destination unchanged. The staging allocation is freed
on every exit and the compositor retains no user pointer. This incurs one
temporary allocation and an extra pixel copy per presentation.

`test_gfx_present_layout.c` checks clipping, independent known row offsets,
stride/extent limits, signed coordinate extremes and user-address endpoints
under host sanitizers. `t_gui_present_child.c` is an actual display-dependent
guest contract: a real child process calls both NtGdiPresent and foreign
GetDC, then the owning parent uses PrintWindow to read the kernel compositor
surface. It checks real RGB pixels, stale generation-stamped HWNDs, invalid
pixel pointers and a genuine protected second source row; metadata and
destruction ownership checks must remain enforced. It returns nonzero when
there is no display, so an unexecuted contract cannot be reported as a pass.

Host arithmetic tests and actual AMD64 kernel/guest compilation are distinct
from executing that guest contract, observing a product's rendered UI, and
integrating a 64-bit window with the native Windows 98 desktop. Each needs
separate evidence.
