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
#include <winnls.h>
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
int u32_text_px(LPCWSTR s, int n);                   /* pixel width of s[0..n) in the default (built-in) font */
COLORREF u32_syscolor(int index);
HBRUSH u32_sysbrush(int index);

/* per-thread user32 state (TLS, allocated on first use; 0 only if the heap is exhausted) */
typedef struct {
    DWORD time; POINT pt; LPARAM extra;             /* the last retrieved message: GetMessageTime/Pos/ExtraInfo */
    HCURSOR cursor;                                 /* SetCursor/GetCursor */
    int cursor_count;                               /* ShowCursor display counter */
    int cursor_init;                                /* cursor_count initialised (0 with a mouse, -1 without) */
    UINT dbl_msg;                                   /* the last button-down, for double-click detection */
    HWND dbl_hwnd;
    DWORD dbl_time;
    POINT dbl_pt;
    WPARAM dbl_x;
    int dbl_client;
} u32_thread_t;
u32_thread_t *u32_ts(void);

/* user32_input.c */
int u32_mouse_translate(shz_msg_t *m, int remove);  /* a mouse input message (SHZ_MSGF_MOUSE): 0 = swallowed */
uint32_t u32_input_info(void);                      /* SHZ_INFO_* flags (0 without a display) */
void u32_cursor_push(void);                         /* tell the kernel the thread's cursor and ShowCursor state */
int u32_cursor_count(int delta);                    /* ShowCursor counter (+1/-1/0), pushes the visibility change */
/* user32_icon.c: the image of an icon/cursor as straight ARGB, at most 32x32 (larger ones are scaled down, hot spot too) */
int u32_icon_argb32(HICON h, uint32_t *out, int *w, int *hh, int *hx, int *hy);
LRESULT u32_def_mouse(HWND hwnd, UINT msg, WPARAM wp, LPARAM lp, int *handled);   /* DefWindowProc: mouse/keyboard parts */
void u32_sys_move_size(HWND hwnd, WPARAM cmd);      /* DefWindowProc WM_SYSCOMMAND SC_MOVE / SC_SIZE: the modal loop */

/* user32_sys.c */
void u32_private_message(const shz_msg_t *m);       /* SHZ_WM_SENDCB / SHZ_WM_ASYNCSHOW / SHZ_WM_WINEVENT, consumed by retrieval */
int u32_muldiv(int a, int b, int c);                /* MulDiv (kernel32 does not export it) */
int u32_user_object_count(void);                    /* icons/cursors, menus, accelerator tables, hooks of this process */
/* user32_hook.c */
void u32_winevent_deliver(void *rec);
int u32_hook_count(void);
int u32_call_msg_hooks(MSG *msg, int remove);       /* WH_GETMESSAGE, WH_KEYBOARD, WH_MOUSE: 1 = the hook discarded the message */
LRESULT u32_call_wndproc_hooked(uint64_t proc, HWND hwnd, UINT msg, WPARAM wp, LPARAM lp);   /* WH_CALLWNDPROC(RET) around a send */
void u32_winevent(DWORD event, HWND hwnd, LONG obj, LONG child);   /* raise a system WinEvent (NotifyWinEvent) */
LRESULT u32_cbt(int code, WPARAM wp, LPARAM lp);  /* WH_CBT hooks: nonzero = prevent */
/* user32_dlg.c */
void u32_register_controls(void);
int u32_dlg_remember_focus(HWND ctl);            /* SetFocus in a hidden dialog */
/* user32_icon.c, user32_menu.c */
int u32_icon_count(void);
int u32_menu_count(void);
int u32_accel_count(void);
/* user32_res.c: resources of a loaded module (hinst NULL = the executable) */
const void *u32_find_resource(HINSTANCE inst, LPCWSTR type, LPCWSTR name, DWORD *size);
HICON u32_icon_from_resource(HINSTANCE inst, LPCWSTR name, int cursor, int cx, int cy);
#endif
