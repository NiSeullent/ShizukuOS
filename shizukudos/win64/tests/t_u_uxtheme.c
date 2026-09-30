/* SPDX-License-Identifier: GPL-2.0-only
 * uxtheme.dll on a system without visual styles: the classic-mode answers (IsThemeActive FALSE, OpenThemeData NULL,
 * E_HANDLE for every theme handle, GetThemeSysColor = GetSysColor), the flag word round trip, and the undocumented
 * dark-mode ordinals Chromium looks up by number (present, and answering "no dark mode"). */
#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <uxtheme.h>
#include "u_check.h"

#define ST_HANDLE ((HRESULT)0x80070006)
typedef BOOL (WINAPI *b0_t)(void);
typedef BOOL (WINAPI *bw_t)(HWND);
typedef BOOL (WINAPI *bwb_t)(HWND, BOOL);
typedef int (WINAPI *ii_t)(int);

int main(void)
{
    HMODULE m = LoadLibraryW(L"uxtheme.dll");
    HWND w = CreateWindowExW(0, L"STATIC", L"ux", 0, 0, 0, 10, 10, 0, 0, 0, 0);
    WCHAR name[32] = L"x";
    RECT r = { 0, 0, 10, 10 };
    SIZE sz;
    U_CHECK("uxtheme.dll loads", m != 0);
    U_CHECK("IsThemeActive and IsAppThemed are FALSE (no visual styles)", !IsThemeActive() && !IsAppThemed());
    U_CHECK("GetThemeAppProperties defaults to STAP_ALLOW_NONCLIENT|CONTROLS; SetThemeAppProperties round-trips", GetThemeAppProperties() == 3 && (SetThemeAppProperties(7), GetThemeAppProperties() == 7) && (SetThemeAppProperties(3), 1));
    SetLastError(0);
    U_CHECK("OpenThemeData(NULL window, \"BUTTON\") is NULL with ERROR_NOT_FOUND", OpenThemeData(0, L"BUTTON") == 0 && GetLastError() == ERROR_NOT_FOUND);
    U_CHECK("OpenThemeData(bad window) is ERROR_INVALID_WINDOW_HANDLE; NULL class list ERROR_INVALID_PARAMETER", OpenThemeData((HWND)0x1234, L"BUTTON") == 0 && GetLastError() == ERROR_INVALID_WINDOW_HANDLE && OpenThemeData(0, 0) == 0 && GetLastError() == ERROR_INVALID_PARAMETER);
    if (w) U_CHECK("OpenThemeData(real window, \"WINDOW\") is NULL too", OpenThemeData(w, L"WINDOW") == 0 && GetLastError() == ERROR_NOT_FOUND);
    U_CHECK("CloseThemeData / DrawThemeBackground / GetThemeBackgroundContentRect / GetThemePartSize on any handle are E_HANDLE",
            CloseThemeData((HTHEME)0x10) == ST_HANDLE && DrawThemeBackground((HTHEME)0x10, 0, 1, 1, &r, 0) == ST_HANDLE && GetThemeBackgroundContentRect((HTHEME)0x10, 0, 1, 1, &r, &r) == ST_HANDLE && GetThemePartSize((HTHEME)0x10, 0, 1, 1, &r, TS_TRUE, &sz) == ST_HANDLE);
    U_CHECK("ordinal 47 is DrawThemeBackgroundEx", m && GetProcAddress(m, (LPCSTR)47) == GetProcAddress(m, "DrawThemeBackgroundEx") && GetProcAddress(m, "DrawThemeBackgroundEx"));
    U_CHECK("GetCurrentThemeName fails with HRESULT_FROM_WIN32(ERROR_NOT_FOUND) and empties the buffers", GetCurrentThemeName(name, 32, 0, 0, 0, 0) == (HRESULT)0x80070490 && name[0] == 0);
    U_CHECK("GetThemeSysColor(NULL, COLOR_WINDOW) = GetSysColor(COLOR_WINDOW)", GetThemeSysColor(0, COLOR_WINDOW) == GetSysColor(COLOR_WINDOW));
    {
        b0_t should_dark = m ? (b0_t)GetProcAddress(m, (LPCSTR)132) : 0, sys_dark = m ? (b0_t)GetProcAddress(m, (LPCSTR)138) : 0;
        bwb_t allow = m ? (bwb_t)GetProcAddress(m, (LPCSTR)133) : 0;
        bw_t allowed = m ? (bw_t)GetProcAddress(m, (LPCSTR)137) : 0;
        ii_t setmode = m ? (ii_t)GetProcAddress(m, (LPCSTR)135) : 0;
        U_CHECK("ordinals 132/138: ShouldAppsUseDarkMode / ShouldSystemUseDarkMode are FALSE", should_dark && sys_dark && !should_dark() && !sys_dark());
        U_CHECK("ordinals 133/137: AllowDarkModeForWindow FALSE, IsDarkModeAllowedForWindow FALSE", allow && allowed && !allow(w, TRUE) && !allowed(w));
        U_CHECK("ordinal 135 SetPreferredAppMode returns the previous mode (0, then 2)", setmode && setmode(2) == 0 && setmode(0) == 2);
    }
    if (w) DestroyWindow(w);
    return u_finish("t_u_uxtheme");
}
