# szwin: native Win64 GUI frontend leaf (original code, GPL-2.0-only)

- `szwin.h/.c` (freestanding; builds for i486 PE32, x86_64 Win64 and Kernel64 `-mno-red-zone`): generation-bound
  window table, BGRX32 framebuffer descriptor + clipped blit, chunked CRC32-verified immutable frame assembly
  (partial/corrupt frames never reach the presented buffer), bounded input queue, close/exit/destroy lifecycle.
- `szwin_session.c`: one serialized step over a caller-supplied `szwin_transport` (input -> exit poll -> frame pull).
- `szwin_w98.c/.h`: actual Windows 98 HWND + top-down 32bpp `CreateDIBSection` presenter; WndProc only queues input;
  WM_CLOSE becomes a window-scoped CLOSE event; window torn down only after reported exit, failure or deadline.

The shared GUI ABI is defined in `shizukudos/abi/shz_w64_gui.h`. The production
transport is wired through `ntwin32/win64/ntw64_gui.c`, VxD owner admission,
Kernel64 `subsys64.c` and `w64_gui_service.c`. Absent/revoked authority and
unsupported contracts must still return errors; the host test transport does
not grant live owner or channel authority. Current-artifact native frame,
input, window/owner generation and exit evidence is required before claiming
this optional Windows 98 frontend works. Source integration is not runtime acceptance.

Framebuffer descriptors: Win98 DIB body; Kernel64 `g_fb.back` (`pitch = width*4`,
0x00RRGGBB == BGRX32); a mapped `shzgop_mode` (`width/height/pitch`, mapped `visible` bytes).

Host check: `gcc -std=c11 -Wall -Wextra -Werror szwin.c szwin_session.c tests/test_szwin_host.c` (host-only
evidence; the test transport is a model, not the Core GUI service).
