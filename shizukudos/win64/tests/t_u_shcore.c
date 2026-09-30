/* SPDX-License-Identifier: GPL-2.0-only
 * shcore.dll: the shellscalingapi.h DPI functions (documented HRESULTs: E_INVALIDARG for bad arguments, E_ACCESSDENIED
 * for a second SetProcessDpiAwareness) over the fixed 96-DPI display, and the api-ms-win-shcore contracts resolving
 * to it (CommandLineToArgvW is shell32's, reached through api-ms-win-shcore-obsolete-l1-1-0). */
#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <shellscalingapi.h>
#include "u_check.h"

typedef HRESULT (WINAPI *set_aw_t)(PROCESS_DPI_AWARENESS);
typedef HRESULT (WINAPI *dpi_t)(HMONITOR, MONITOR_DPI_TYPE, UINT *, UINT *);
typedef LPWSTR *(WINAPI *argv_t)(LPCWSTR, int *);

int main(void)
{
    HMODULE c = LoadLibraryW(L"api-ms-win-shcore-scaling-l1-1-1.dll"), s = GetModuleHandleW(L"shcore.dll");
    HMONITOR mon = MonitorFromPoint((POINT){ 0, 0 }, MONITOR_DEFAULTTOPRIMARY);
    UINT x = 7, y = 7;
    PROCESS_DPI_AWARENESS aw = (PROCESS_DPI_AWARENESS)99;
    DEVICE_SCALE_FACTOR sf = DEVICE_SCALE_FACTOR_INVALID;
    HRESULT hr;

    U_CHECKF("api-ms-win-shcore-scaling-l1-1-1 resolves to shcore.dll's SetProcessDpiAwareness", c && s && GetProcAddress(c, "SetProcessDpiAwareness") == GetProcAddress(s, "SetProcessDpiAwareness") && GetProcAddress(c, "SetProcessDpiAwareness") != 0, "c=%p s=%p", (void *)c, (void *)s);
    U_CHECK("GetProcessDpiAwareness(NULL) before any call: PROCESS_DPI_UNAWARE", GetProcessDpiAwareness(0, &aw) == S_OK && aw == PROCESS_DPI_UNAWARE);
    U_CHECK("GetProcessDpiAwareness(NULL out) is E_INVALIDARG", GetProcessDpiAwareness(0, 0) == E_INVALIDARG);
    U_CHECK("SetProcessDpiAwareness(99) is E_INVALIDARG", SetProcessDpiAwareness((PROCESS_DPI_AWARENESS)99) == E_INVALIDARG);
    hr = SetProcessDpiAwareness(PROCESS_PER_MONITOR_DPI_AWARE);
    U_CHECKF("SetProcessDpiAwareness(PER_MONITOR) succeeds once", hr == S_OK, "hr=%x", (unsigned)hr);
    U_CHECK("...and is reported by GetProcessDpiAwareness and user32's IsProcessDPIAware", GetProcessDpiAwareness(GetCurrentProcess(), &aw) == S_OK && aw == PROCESS_PER_MONITOR_DPI_AWARE && IsProcessDPIAware());
    U_CHECK("a second SetProcessDpiAwareness is E_ACCESSDENIED", SetProcessDpiAwareness(PROCESS_SYSTEM_DPI_AWARE) == E_ACCESSDENIED);
    if (mon) {                                    /* a display device exists (run_k64_gui.py); the standalone profile has none */
        U_CHECKF("GetDpiForMonitor(primary, MDT_EFFECTIVE_DPI) = 96 x 96", GetDpiForMonitor(mon, MDT_EFFECTIVE_DPI, &x, &y) == S_OK && x == 96 && y == 96, "mon=%p x=%u y=%u", (void *)mon, x, y);
        U_CHECK("GetDpiForMonitor with a bad type / NULL out is E_INVALIDARG", GetDpiForMonitor(mon, (MONITOR_DPI_TYPE)7, &x, &y) == E_INVALIDARG && GetDpiForMonitor(mon, MDT_RAW_DPI, 0, &y) == E_INVALIDARG);
        U_CHECK("GetScaleFactorForMonitor(primary) = SCALE_100_PERCENT", GetScaleFactorForMonitor(mon, &sf) == S_OK && sf == SCALE_100_PERCENT);
    } else {
        printf("INFO: no display device, no monitor: the per-monitor checks need run_k64_gui.py\n");
    }
    U_CHECK("GetDpiForMonitor / GetScaleFactorForMonitor with a bad handle are E_INVALIDARG and clear the outputs", GetDpiForMonitor((HMONITOR)0x1234, MDT_RAW_DPI, &x, &y) == E_INVALIDARG && x == 0 && y == 0 && GetScaleFactorForMonitor((HMONITOR)0x1234, &sf) == E_INVALIDARG && sf == DEVICE_SCALE_FACTOR_INVALID);
    U_CHECK("GetScaleFactorForDevice(DEVICE_PRIMARY) = SCALE_100_PERCENT", GetScaleFactorForDevice(DEVICE_PRIMARY) == SCALE_100_PERCENT);
    {
        HMODULE o = LoadLibraryW(L"api-ms-win-shcore-obsolete-l1-1-0.dll");
        argv_t f = o ? (argv_t)GetProcAddress(o, "CommandLineToArgvW") : 0;
        int n = 0;
        LPWSTR *v = f ? f(L"a.exe \"b c\" d", &n) : 0;
        U_CHECK("CommandLineToArgvW through api-ms-win-shcore-obsolete-l1-1-0 (forwarded to shell32) splits 3 arguments", f && v && n == 3 && u_ascii_eq_w(v[1], "b c"));
        if (v) LocalFree(v);
    }
    return u_finish("t_u_shcore");
}
