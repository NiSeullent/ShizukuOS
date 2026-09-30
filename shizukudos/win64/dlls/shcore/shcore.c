/* SPDX-License-Identifier: GPL-2.0-only
 * shcore.dll - the host of the api-ms-win-shcore-* contracts (kernel64/apiset_contracts.txt maps them here): the
 * per-monitor DPI API of shellscalingapi.h over user32's fixed-96-DPI awareness state (dlls/user32/user32_sys.c), and
 * CommandLineToArgvW as a forwarder to shell32 (api-ms-win-shcore-obsolete-l1-1-0), as on Windows.
 *
 *   SetProcessDpiAwareness   PROCESS_DPI_UNAWARE / SYSTEM / PER_MONITOR -> the user32 awareness context; set once per
 *                            process (a second call is E_ACCESSDENIED, as documented), other values E_INVALIDARG.
 *   GetProcessDpiAwareness   the calling process (NULL or its own handle); another process' handle is E_INVALIDARG:
 *                            the kernel keeps no per-process DPI state that could be read from outside.
 *   GetDpiForMonitor         96 x 96 for every valid monitor handle and MDT_* type (the system runs at 96 DPI);
 *                            a bad handle or type, or a NULL out-pointer, is E_INVALIDARG.
 *   GetScaleFactorForMonitor SCALE_100_PERCENT for a valid monitor, E_INVALIDARG otherwise.
 *   GetScaleFactorForDevice  SCALE_100_PERCENT for DEVICE_PRIMARY, DEVICE_IMMERSIVE.
 */
#include "nt.h"
#include <string.h>
#include <shellscalingapi.h>

#define E_INVALIDARG_ ((HRESULT)0x80070057)
#define E_ACCESSDENIED_ ((HRESULT)0x80070005)
DPI_AWARENESS_CONTEXT WINAPI GetDpiAwarenessContextForProcess(HANDLE);   /* user32 (Windows 10 1903+; not in mingw 13 headers) */

DLLAPI HRESULT WINAPI SetProcessDpiAwareness(PROCESS_DPI_AWARENESS value)
{
    DPI_AWARENESS_CONTEXT ctx;
    switch (value) {
    case PROCESS_DPI_UNAWARE: ctx = (DPI_AWARENESS_CONTEXT)-1; break;
    case PROCESS_SYSTEM_DPI_AWARE: ctx = (DPI_AWARENESS_CONTEXT)-2; break;
    case PROCESS_PER_MONITOR_DPI_AWARE: ctx = (DPI_AWARENESS_CONTEXT)-3; break;
    default: return E_INVALIDARG_;
    }
    if (SetProcessDpiAwarenessContext(ctx)) return S_OK;
    return GetLastError() == ERROR_ACCESS_DENIED ? E_ACCESSDENIED_ : E_INVALIDARG_;
}

DLLAPI HRESULT WINAPI GetProcessDpiAwareness(HANDLE process, PROCESS_DPI_AWARENESS *value)
{
    DPI_AWARENESS a;
    if (!value) return E_INVALIDARG_;
    if (process && GetProcessId(process) != GetCurrentProcessId()) return E_INVALIDARG_;
    a = GetAwarenessFromDpiAwarenessContext(GetDpiAwarenessContextForProcess(process));
    *value = a == DPI_AWARENESS_SYSTEM_AWARE ? PROCESS_SYSTEM_DPI_AWARE : a == DPI_AWARENESS_PER_MONITOR_AWARE ? PROCESS_PER_MONITOR_DPI_AWARE : PROCESS_DPI_UNAWARE;
    return S_OK;
}

static int monitor_ok(HMONITOR m)
{
    MONITORINFO mi;
    memset(&mi, 0, sizeof mi);
    mi.cbSize = sizeof mi;
    return m && GetMonitorInfoW(m, &mi);
}

DLLAPI HRESULT WINAPI GetDpiForMonitor(HMONITOR monitor, MONITOR_DPI_TYPE type, UINT *dpi_x, UINT *dpi_y)
{
    if (!dpi_x || !dpi_y) return E_INVALIDARG_;
    *dpi_x = *dpi_y = 0;
    if (type != MDT_EFFECTIVE_DPI && type != MDT_ANGULAR_DPI && type != MDT_RAW_DPI) return E_INVALIDARG_;
    if (!monitor_ok(monitor)) return E_INVALIDARG_;
    *dpi_x = *dpi_y = GetDpiForSystem();
    return S_OK;
}

DLLAPI HRESULT WINAPI GetScaleFactorForMonitor(HMONITOR monitor, DEVICE_SCALE_FACTOR *scale)
{
    if (!scale) return E_INVALIDARG_;
    *scale = DEVICE_SCALE_FACTOR_INVALID;
    if (!monitor_ok(monitor)) return E_INVALIDARG_;
    *scale = SCALE_100_PERCENT;
    return S_OK;
}

DLLAPI DEVICE_SCALE_FACTOR WINAPI GetScaleFactorForDevice(DISPLAY_DEVICE_TYPE type)
{
    return type == DEVICE_PRIMARY || type == DEVICE_IMMERSIVE ? SCALE_100_PERCENT : DEVICE_SCALE_FACTOR_INVALID;
}
