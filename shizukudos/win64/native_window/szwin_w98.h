/* SPDX-License-Identifier: GPL-2.0-only
 * ShizukuOS native Win64 GUI frontend: Windows 98 HWND + CreateDIBSection presenter over szwin.
 * Original code; i486 PE32 subsystem 4.10 compatible (USER32/GDI32/KERNEL32 classic imports only). */
#ifndef SZWIN_W98_H
#define SZWIN_W98_H
#include "szwin.h"

#define SZWIN_W98_E_PLATFORM (-100)  /* a USER/GDI/KERNEL call failed; see *platform_error */

typedef struct szwin_w98_result {
    uint32_t exit_code;              /* valid when exited != 0 */
    int exited;                      /* the W64 process reported exit through the transport */
    int status;                      /* SZWIN_OK or first failure (SZWIN_E_* / SZWIN_W98_E_PLATFORM) */
    uint32_t platform_error;         /* GetLastError() of the failing platform call */
    uint32_t frames, presents, inputs_queued;
} szwin_w98_result;

/* Opens one top-level HWND with a width x height client area, binds a top-down 32bpp DIB section as the szwin
 * framebuffer, and runs the serialized loop: dispatch window messages (WndProc only queues bounded input),
 * szwin_session_step, present a newly committed frame into the DIB and BitBlt it on WM_PAINT. WM_CLOSE becomes a
 * window-scoped CLOSE event; the window is destroyed only after the transport reports process exit, a failure,
 * or `deadline_ms` elapses (then status = SZWIN_E_TRANSPORT, exited = 0, no exit is invented).
 * Only one frontend may run per process. */
int szwin_w98_run(const szwin_transport *tp, void *ctx, const char *title, uint32_t width, uint32_t height,
                  uint32_t deadline_ms, szwin_w98_result *result);
#endif
