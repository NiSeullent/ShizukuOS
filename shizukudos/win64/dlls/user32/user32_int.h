/* SPDX-License-Identifier: GPL-2.0-only
 * user32.dll internals. user32 is a thin user-mode layer over the kernel window manager (kernel64/gfx_wm.c, gfx_msg.c):
 * the kernel owns windows, classes, queues, timers and update regions; this DLL turns them into the Win32 API and, above
 * all, is the only place window procedures are ever called (see the callback notes in gfx_wm.c).
 *
 * Without a display device (any profile but the standalone QEMU one with `-vga std`) every kernel call fails with
 * STATUS_NO_SUCH_DEVICE; the API then fails with ERROR_NOT_SUPPORTED and GetSystemMetrics(SM_CXSCREEN) is 0, which is how
 * programs (and the tests) detect that there is nothing to draw on.
 */
#ifndef SHZ_USER32_INT_H
#define SHZ_USER32_INT_H
#define _USER32_
#include "nt.h"
#include <wingdi.h>                                /* before winuser.h: several winuser.h structures need _WINGDI_ */
#include <winuser.h>
#include "shzgfx.h"

/* private gdi32 exports (win64/dlls/gdi32/gdi_win.c, gdi_rgn.c) */
HDC WINAPI ShzGdiWindowDC(HWND hwnd, int cx, int cy, const RECT *sysclip, int nclip);
BOOL WINAPI ShzGdiWindowDCRelease(HDC hdc);
VOID WINAPI ShzGdiFlushAll(void);
VOID WINAPI ShzGdiWindowGone(HWND hwnd);
HBRUSH WINAPI ShzGdiCreateStockSolidBrush(COLORREF color);
int WINAPI ShzGdiRegionRects(HRGN h, RECT *out, int max);
BOOL WINAPI ShzGdiRegionSetRects(HRGN h, const RECT *in, int n);

#define GFX_ENUM_MAX 256                            /* the kernel's window table size bounds every enumeration */
int u32_display(shz_display_info_t *out);           /* 1 if a display exists (and fills *out), else 0 */
DWORD u32_err(int32_t status);                      /* NTSTATUS -> Win32 error, also stores it with SetLastError */
#define U32_NEED_GFX(ret) do { if (!u32_display(0)) { SetLastError(ERROR_NOT_SUPPORTED); return (ret); } } while (0)

static inline uint64_t H2U(HWND h) { return (uint64_t)(uintptr_t)h; }
static inline HWND U2H(uint64_t v) { return (HWND)(uintptr_t)v; }

LRESULT u32_send(HWND hwnd, UINT msg, WPARAM wp, LPARAM lp, DWORD timeout_ms, int *failed);   /* SendMessage core */
LRESULT u32_call(uint64_t proc, HWND hwnd, UINT msg, WPARAM wp, LPARAM lp);
int u32_wq(HWND hwnd, uint32_t what, int32_t index, shz_wnd_t *q);                             /* NtUserWindowQuery */
void u32_notify_activation(uint64_t now_active, uint64_t prev_active);
HWND u32_desktop(void);
void u32_send_size_move(HWND hwnd, int moved, int sized);
int u32_metric(int index);
COLORREF u32_syscolor(int index);
HBRUSH u32_sysbrush(int index);

/* per-thread user32 state (TLS, allocated on first use; 0 only if the heap is exhausted) */
typedef struct {
    DWORD time; POINT pt; LPARAM extra;             /* the last retrieved message: GetMessageTime/Pos/ExtraInfo */
    HCURSOR cursor;                                 /* SetCursor/GetCursor */
    int cursor_count;                               /* ShowCursor display counter */
} u32_thread_t;
u32_thread_t *u32_ts(void);
#endif
