/* SPDX-License-Identifier: GPL-2.0-only
 * dwmapi.dll (Wine port, patch 0007): with no desktop compositor the window-attribute calls fail with the documented
 * DWM_E_COMPOSITIONDISABLED instead of pretending to have applied anything, DwmDefWindowProc handles nothing, and bad
 * arguments are rejected first (E_HANDLE for a non-window, E_INVALIDARG for a NULL attribute/margins). */
#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <dwmapi.h>

/* dwmapi.dll is a Wine port (not among the modules the test apps link): resolved at run time */
typedef HRESULT (WINAPI *setattr_t)(HWND, DWORD, LPCVOID, DWORD);
typedef HRESULT (WINAPI *extend_t)(HWND, const MARGINS *);
typedef BOOL (WINAPI *defproc_t)(HWND, UINT, WPARAM, LPARAM, LRESULT *);
static setattr_t DwmSetWindowAttribute_;
static extend_t DwmExtendFrameIntoClientArea_;
static defproc_t DwmDefWindowProc_;
#define DwmSetWindowAttribute DwmSetWindowAttribute_
#define DwmExtendFrameIntoClientArea DwmExtendFrameIntoClientArea_
#define DwmDefWindowProc DwmDefWindowProc_
#include "u_check.h"

#define ST_COMPDISABLED ((HRESULT)0x80263001)

int main(void)
{
    HWND w = CreateWindowExW(0, L"STATIC", L"dwm", 0, 0, 0, 10, 10, 0, 0, 0, 0);
    DWORD dark = 1;
    MARGINS m = { -1, -1, -1, -1 };
    LRESULT lr = 55;
    HMODULE dm = LoadLibraryW(L"dwmapi.dll");
    U_CHECK("dwmapi.dll loads and exports the three functions (patched stubs are now real)", dm && (DwmSetWindowAttribute_ = (setattr_t)GetProcAddress(dm, "DwmSetWindowAttribute")) &&
            (DwmExtendFrameIntoClientArea_ = (extend_t)GetProcAddress(dm, "DwmExtendFrameIntoClientArea")) && (DwmDefWindowProc_ = (defproc_t)GetProcAddress(dm, "DwmDefWindowProc")));
    if (!DwmSetWindowAttribute_ || !DwmExtendFrameIntoClientArea_ || !DwmDefWindowProc_) return u_finish("t_u_dwmapi");
    U_CHECK("DwmSetWindowAttribute(non-window) is E_HANDLE", DwmSetWindowAttribute((HWND)0x1234, 20, &dark, 4) == E_HANDLE);
    U_CHECK("DwmExtendFrameIntoClientArea(non-window) is E_HANDLE", DwmExtendFrameIntoClientArea((HWND)0x1234, &m) == E_HANDLE);
    U_CHECK("DwmDefWindowProc handles nothing and clears the result", !DwmDefWindowProc(w, WM_NCHITTEST, 0, 0, &lr) && lr == 0);
    if (w) {
        U_CHECK("DwmSetWindowAttribute(DWMWA_USE_IMMERSIVE_DARK_MODE) is DWM_E_COMPOSITIONDISABLED", DwmSetWindowAttribute(w, 20, &dark, 4) == ST_COMPDISABLED);
        U_CHECK("DwmSetWindowAttribute(NULL attribute, size 4) is E_INVALIDARG", DwmSetWindowAttribute(w, 20, 0, 4) == E_INVALIDARG);
        U_CHECK("DwmExtendFrameIntoClientArea(margins) is DWM_E_COMPOSITIONDISABLED; NULL margins E_INVALIDARG", DwmExtendFrameIntoClientArea(w, &m) == ST_COMPDISABLED && DwmExtendFrameIntoClientArea(w, 0) == E_INVALIDARG);
        DestroyWindow(w);
    } else {
        printf("INFO: no window (no display device): the window-attribute checks need run_k64_gui.py\n");
    }
    return u_finish("t_u_dwmapi");
}
