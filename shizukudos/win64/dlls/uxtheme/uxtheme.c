/* SPDX-License-Identifier: GPL-2.0-only
 * uxtheme.dll for a system with NO visual styles: the Windows "classic" state that a machine with theming switched off
 * reports. There is no theme engine, no .msstyles loader and no dark-mode setting, and nothing pretends there is.
 *
 *   IsThemeActive / IsAppThemed        FALSE. GetThemeAppProperties / SetThemeAppProperties: the flag word is stored and read
 *                                      back (it is the application's request; with no engine it has no visible effect).
 *   OpenThemeData / OpenThemeDataEx    NULL with last error E_?: ERROR_NOT_FOUND (no theme data for the class list; the
 *                                      documented "cannot open" result, which callers answer by drawing classic controls).
 *                                      An invalid window handle: ERROR_INVALID_WINDOW_HANDLE.
 *   CloseThemeData, DrawThemeBackground(+Ex, ordinal 47), GetThemeBackgroundContentRect, GetThemePartSize,
 *   IsThemePartDefined, GetThemeColor   no theme handle is ever issued, so every handle is invalid: E_HANDLE
 *                                      (IsThemePartDefined: FALSE).
 *   GetCurrentThemeName                E_FAIL-class failure: HRESULT_FROM_WIN32(ERROR_NOT_FOUND) (no current theme).
 *   GetThemeSysColor                   the real system colour (GetSysColor) for a NULL theme, as documented.
 *   Undocumented dark-mode ordinals Chromium/Electron look up by number: 132 ShouldAppsUseDarkMode, 138 ShouldSystemUseDarkMode,
 *                                      137 IsDarkModeAllowedForWindow, 133 AllowDarkModeForWindow: FALSE (no dark-mode setting exists);
 *                                      135 SetPreferredAppMode: stores the mode and returns the previous one (default 0 = Default);
 *                                      104 RefreshImmersiveColorPolicyState, 136 FlushMenuThemes: no-ops, nothing to refresh.
 */
#define WIN32_LEAN_AND_MEAN
#pragma GCC diagnostic ignored "-Wattributes"
#include <windows.h>
#include <uxtheme.h>
#include <string.h>

#ifndef DLLAPI
#define DLLAPI __declspec(dllexport)
#endif
#define E_HANDLE_ ((HRESULT)0x80070006)

static volatile LONG g_props = 0x00000003;      /* STAP_ALLOW_NONCLIENT | STAP_ALLOW_CONTROLS: the default request */
static volatile LONG g_app_mode;

DLLAPI BOOL WINAPI IsThemeActive(void) { return FALSE; }
DLLAPI BOOL WINAPI IsAppThemed(void) { return FALSE; }
DLLAPI DWORD WINAPI GetThemeAppProperties(void) { return (DWORD)g_props; }
DLLAPI void WINAPI SetThemeAppProperties(DWORD flags) { InterlockedExchange(&g_props, (LONG)flags); }

DLLAPI HTHEME WINAPI OpenThemeData(HWND hwnd, LPCWSTR classes)
{
    if (hwnd && !IsWindow(hwnd)) { SetLastError(ERROR_INVALID_WINDOW_HANDLE); return 0; }
    if (!classes) { SetLastError(ERROR_INVALID_PARAMETER); return 0; }
    SetLastError(ERROR_NOT_FOUND);
    return 0;
}

DLLAPI HTHEME WINAPI OpenThemeDataEx(HWND hwnd, LPCWSTR classes, DWORD flags) { (void)flags; return OpenThemeData(hwnd, classes); }

DLLAPI HRESULT WINAPI CloseThemeData(HTHEME t) { (void)t; return E_HANDLE_; }
DLLAPI HRESULT WINAPI DrawThemeBackground(HTHEME t, HDC dc, int part, int state, const RECT *r, const RECT *clip) { (void)t; (void)dc; (void)part; (void)state; (void)r; (void)clip; return E_HANDLE_; }
DLLAPI HRESULT WINAPI DrawThemeBackgroundEx(HTHEME t, HDC dc, int part, int state, const RECT *r, const DTBGOPTS *opts) { (void)t; (void)dc; (void)part; (void)state; (void)r; (void)opts; return E_HANDLE_; }
DLLAPI HRESULT WINAPI GetThemeBackgroundContentRect(HTHEME t, HDC dc, int part, int state, const RECT *b, RECT *c) { (void)t; (void)dc; (void)part; (void)state; (void)b; (void)c; return E_HANDLE_; }
DLLAPI HRESULT WINAPI GetThemePartSize(HTHEME t, HDC dc, int part, int state, RECT *r, enum THEMESIZE size, SIZE *sz) { (void)t; (void)dc; (void)part; (void)state; (void)r; (void)size; (void)sz; return E_HANDLE_; }
DLLAPI HRESULT WINAPI GetThemeColor(HTHEME t, int part, int state, int prop, COLORREF *c) { (void)t; (void)part; (void)state; (void)prop; (void)c; return E_HANDLE_; }
DLLAPI BOOL WINAPI IsThemePartDefined(HTHEME t, int part, int state) { (void)t; (void)part; (void)state; SetLastError(E_HANDLE_ & 0xffff); return FALSE; }

DLLAPI HRESULT WINAPI GetCurrentThemeName(LPWSTR file, int fcap, LPWSTR color, int ccap, LPWSTR size, int scap)
{
    if (file && fcap > 0) file[0] = 0;
    if (color && ccap > 0) color[0] = 0;
    if (size && scap > 0) size[0] = 0;
    return (HRESULT)(0x80070000u | ERROR_NOT_FOUND);
}

DLLAPI COLORREF WINAPI GetThemeSysColor(HTHEME t, int id)
{
    if (t) return 0;                                  /* no theme handle can exist */
    return GetSysColor(id);
}

/* undocumented ordinals (module.json pins them) */
DLLAPI BOOL WINAPI ShouldAppsUseDarkMode(void) { return FALSE; }
DLLAPI BOOL WINAPI ShouldSystemUseDarkMode(void) { return FALSE; }
DLLAPI BOOL WINAPI IsDarkModeAllowedForWindow(HWND hwnd) { (void)hwnd; return FALSE; }
DLLAPI BOOL WINAPI AllowDarkModeForWindow(HWND hwnd, BOOL allow) { (void)hwnd; (void)allow; return FALSE; }
DLLAPI int WINAPI SetPreferredAppMode(int mode) { return (int)InterlockedExchange(&g_app_mode, mode); }
DLLAPI void WINAPI RefreshImmersiveColorPolicyState(void) {}
DLLAPI void WINAPI FlushMenuThemes(void) {}
