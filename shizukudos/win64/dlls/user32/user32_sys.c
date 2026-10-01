/* SPDX-License-Identifier: GPL-2.0-only
 * user32: the display and the system around the windows.
 *
 *  - Display modes and devices: there is exactly one adapter (the Bochs VBE of QEMU's std VGA, kernel64/gfx_fb.c), one
 *    monitor and one mode, the one the kernel programmed (read back through NtUserQueryDisplay, never assumed).
 *    EnumDisplaySettings/EnumDisplayDevices/QueryDisplayConfig describe it; ChangeDisplaySettings/SetDisplayConfig accept
 *    only that mode (anything else is DISP_CHANGE_BADMODE / ERROR_NOT_SUPPORTED: the kernel cannot switch modes). The
 *    adapter has no refresh rate to report: 1 ("hardware default") is returned where Windows expects one.
 *  - DPI: the system runs at a fixed 96 DPI (USER_DEFAULT_SCREEN_DPI) for every window, monitor and awareness context;
 *    the awareness APIs keep and report the requested state faithfully, scaling is always the identity at 96 DPI and the
 *    *ForDpi functions scale by dpi/96 when asked about another DPI.
 *  - Layered windows, window regions and PrintWindow go to the kernel compositor (NtUserWindowOp, see kernel64/gfx_wm.c).
 *  - One window station (WinSta0) and one desktop (Default) exist; other stations/desktops cannot be created.
 *  - Device, power and suspend/resume notifications can be registered; this system has no hot-plug or power events, so
 *    none is ever delivered. There are no touch or pen devices (the pointer device list is empty).
 *  - UIPI does not exist: every message filter change succeeds and reports MSGFLTINFO_NONE.
 */
#include "user32_int.h"

BOOL WINAPI ShzGdiDCBitmap(HDC hdc, const uint32_t **bits, int *w, int *h, int *topdown);
HWND WINAPI ShzGdiDCWindow(HDC hdc);
BOOL WINAPI ShzGdiSetDeviceOrigin(HDC hdc, int x, int y);
DWORD WINAPI ShzGdiObjectCount(DWORD *peak);

static int32_t winop(shz_winop_t *o)
{
    const int32_t st = NtUserWindowOp(o);
    if (st < 0) u32_err(st);
    return st;
}

/* ---------------------------------------------------------------- display modes and devices */
static const WCHAR k_display1[] = L"\\\\.\\DISPLAY1";
static const WCHAR k_monitor0[] = L"\\\\.\\DISPLAY1\\Monitor0";

static void wcopy(WCHAR *d, const WCHAR *s, int cap)
{
    int i;
    for (i = 0; i < cap - 1 && s[i]; ++i) d[i] = s[i];
    if (cap > 0) d[i] = 0;
}

static int is_display1(LPCWSTR dev)
{
    int i;
    if (!dev) return 1;
    for (i = 0; k_display1[i]; ++i) if ((dev[i] | 0x20) != (k_display1[i] | 0x20)) return 0;
    return dev[i] == 0;
}

static void fill_devmode(DEVMODEW *dm, const shz_display_info_t *di)
{
    const WORD size = dm->dmSize, extra = dm->dmDriverExtra;
    memset(dm, 0, size >= sizeof(DEVMODEW) ? sizeof(DEVMODEW) : size);
    dm->dmSize = size;
    dm->dmDriverExtra = extra;
    wcopy(dm->dmDeviceName, L"Bochs VBE (QEMU std VGA)", CCHDEVICENAME);
    dm->dmSpecVersion = DM_SPECVERSION;
    dm->dmFields = DM_BITSPERPEL | DM_PELSWIDTH | DM_PELSHEIGHT | DM_DISPLAYFREQUENCY | DM_POSITION | DM_DISPLAYORIENTATION | DM_DISPLAYFLAGS;
    dm->dmPosition.x = 0;
    dm->dmPosition.y = 0;
    dm->dmDisplayOrientation = DMDO_DEFAULT;
    dm->dmBitsPerPel = di->bpp;
    dm->dmPelsWidth = di->width;
    dm->dmPelsHeight = di->height;
    dm->dmDisplayFrequency = 1;                                        /* hardware default: the adapter has no refresh rate */
}

DLLAPI BOOL WINAPI EnumDisplaySettingsExW(LPCWSTR dev, DWORD mode, DEVMODEW *dm, DWORD flags)
{
    shz_display_info_t di;
    (void)flags;
    if (!dm || dm->dmSize < offsetof(DEVMODEW, dmFields)) { SetLastError(ERROR_INVALID_PARAMETER); return FALSE; }
    if (!u32_display(&di) || !is_display1(dev)) { SetLastError(ERROR_INVALID_PARAMETER); return FALSE; }
    if (mode != ENUM_CURRENT_SETTINGS && mode != ENUM_REGISTRY_SETTINGS && mode != 0) { SetLastError(ERROR_NO_MORE_FILES); return FALSE; }
    fill_devmode(dm, &di);
    return TRUE;
}

DLLAPI BOOL WINAPI EnumDisplaySettingsW(LPCWSTR dev, DWORD mode, DEVMODEW *dm) { return EnumDisplaySettingsExW(dev, mode, dm, 0); }

static void devmode_w2a(DEVMODEA *a, const DEVMODEW *w)
{
    int i;
    const WORD size = a->dmSize;
    memset(a, 0, size >= sizeof(DEVMODEA) ? sizeof(DEVMODEA) : size);
    for (i = 0; i < CCHDEVICENAME; ++i) a->dmDeviceName[i] = (BYTE)w->dmDeviceName[i];
    a->dmSize = size;
    a->dmSpecVersion = w->dmSpecVersion;
    a->dmFields = w->dmFields;
    a->dmPosition = w->dmPosition;
    a->dmDisplayOrientation = w->dmDisplayOrientation;
    a->dmBitsPerPel = w->dmBitsPerPel;
    a->dmPelsWidth = w->dmPelsWidth;
    a->dmPelsHeight = w->dmPelsHeight;
    a->dmDisplayFrequency = w->dmDisplayFrequency;
}

DLLAPI BOOL WINAPI EnumDisplaySettingsExA(LPCSTR dev, DWORD mode, DEVMODEA *dm, DWORD flags)
{
    DEVMODEW w;
    if (!dm || dm->dmSize < offsetof(DEVMODEA, dmFields)) { SetLastError(ERROR_INVALID_PARAMETER); return FALSE; }
    if (dev && lstrcmpiA(dev, "\\\\.\\DISPLAY1")) { SetLastError(ERROR_INVALID_PARAMETER); return FALSE; }
    memset(&w, 0, sizeof w);
    w.dmSize = sizeof w;
    if (!EnumDisplaySettingsExW(0, mode, &w, flags)) return FALSE;
    devmode_w2a(dm, &w);
    return TRUE;
}

DLLAPI BOOL WINAPI EnumDisplaySettingsA(LPCSTR dev, DWORD mode, DEVMODEA *dm) { return EnumDisplaySettingsExA(dev, mode, dm, 0); }

/* Only the mode that is set can be "set": the kernel has no mode switch. */
DLLAPI LONG WINAPI ChangeDisplaySettingsExW(LPCWSTR dev, DEVMODEW *dm, HWND hwnd, DWORD flags, LPVOID param)
{
    shz_display_info_t di;
    (void)hwnd; (void)param; (void)flags;
    if (!u32_display(&di)) return DISP_CHANGE_FAILED;
    if (!is_display1(dev)) return DISP_CHANGE_BADPARAM;
    if (!dm) return DISP_CHANGE_SUCCESSFUL;                            /* back to the registry mode, which is the current one */
    if (((dm->dmFields & DM_PELSWIDTH) && dm->dmPelsWidth != di.width) || ((dm->dmFields & DM_PELSHEIGHT) && dm->dmPelsHeight != di.height) ||
        ((dm->dmFields & DM_BITSPERPEL) && dm->dmBitsPerPel != di.bpp) ||
        ((dm->dmFields & DM_DISPLAYFREQUENCY) && dm->dmDisplayFrequency > 1) ||
        ((dm->dmFields & DM_POSITION) && (dm->dmPosition.x || dm->dmPosition.y)) ||
        ((dm->dmFields & DM_DISPLAYORIENTATION) && dm->dmDisplayOrientation != DMDO_DEFAULT))
        return DISP_CHANGE_BADMODE;
    return DISP_CHANGE_SUCCESSFUL;
}

DLLAPI LONG WINAPI ChangeDisplaySettingsW(DEVMODEW *dm, DWORD flags) { return ChangeDisplaySettingsExW(0, dm, 0, flags, 0); }

DLLAPI LONG WINAPI ChangeDisplaySettingsExA(LPCSTR dev, DEVMODEA *dm, HWND hwnd, DWORD flags, LPVOID param)
{
    DEVMODEW w;
    if (dev && lstrcmpiA(dev, "\\\\.\\DISPLAY1")) return DISP_CHANGE_BADPARAM;
    if (!dm) return ChangeDisplaySettingsExW(0, 0, hwnd, flags, param);
    memset(&w, 0, sizeof w);
    w.dmSize = sizeof w;
    w.dmFields = dm->dmFields;
    w.dmPelsWidth = dm->dmPelsWidth;
    w.dmPelsHeight = dm->dmPelsHeight;
    w.dmBitsPerPel = dm->dmBitsPerPel;
    w.dmDisplayFrequency = dm->dmDisplayFrequency;
    w.dmPosition = dm->dmPosition;
    w.dmDisplayOrientation = dm->dmDisplayOrientation;
    return ChangeDisplaySettingsExW(0, &w, hwnd, flags, param);
}

DLLAPI LONG WINAPI ChangeDisplaySettingsA(DEVMODEA *dm, DWORD flags) { return ChangeDisplaySettingsExA(0, dm, 0, flags, 0); }

DLLAPI BOOL WINAPI EnumDisplayDevicesW(LPCWSTR dev, DWORD index, PDISPLAY_DEVICEW dd, DWORD flags)
{
    shz_display_info_t di;
    (void)flags;
    if (!dd || dd->cb < offsetof(DISPLAY_DEVICEW, DeviceID)) { SetLastError(ERROR_INVALID_PARAMETER); return FALSE; }
    if (!u32_display(&di) || index != 0) return FALSE;
    if (!dev) {                                                         /* the adapter */
        wcopy(dd->DeviceName, k_display1, 32);
        wcopy(dd->DeviceString, L"Bochs VBE (QEMU std VGA)", 128);
        dd->StateFlags = DISPLAY_DEVICE_ATTACHED_TO_DESKTOP | DISPLAY_DEVICE_PRIMARY_DEVICE;
        if (dd->cb >= sizeof *dd) {
            wcopy(dd->DeviceID, L"PCI\\VEN_1234&DEV_1111", 128);
            wcopy(dd->DeviceKey, L"", 128);
        }
        return TRUE;
    }
    if (!is_display1(dev)) return FALSE;
    wcopy(dd->DeviceName, k_monitor0, 32);                              /* its monitor: no EDID is read */
    wcopy(dd->DeviceString, L"Default Monitor", 128);
    dd->StateFlags = DISPLAY_DEVICE_ACTIVE | DISPLAY_DEVICE_ATTACHED;
    if (dd->cb >= sizeof *dd) {
        wcopy(dd->DeviceID, L"MONITOR\\Default_Monitor", 128);
        wcopy(dd->DeviceKey, L"", 128);
    }
    return TRUE;
}

DLLAPI BOOL WINAPI EnumDisplayDevicesA(LPCSTR dev, DWORD index, PDISPLAY_DEVICEA dd, DWORD flags)
{
    DISPLAY_DEVICEW w;
    int i;
    if (!dd || dd->cb < offsetof(DISPLAY_DEVICEA, DeviceID)) { SetLastError(ERROR_INVALID_PARAMETER); return FALSE; }
    if (dev && lstrcmpiA(dev, "\\\\.\\DISPLAY1")) return FALSE;
    memset(&w, 0, sizeof w);
    w.cb = sizeof w;
    if (!EnumDisplayDevicesW(dev ? k_display1 : 0, index, &w, flags)) return FALSE;
    for (i = 0; i < 32; ++i) dd->DeviceName[i] = (CHAR)w.DeviceName[i];
    for (i = 0; i < 128; ++i) dd->DeviceString[i] = (CHAR)w.DeviceString[i];
    dd->StateFlags = w.StateFlags;
    if (dd->cb >= sizeof *dd) {
        for (i = 0; i < 128; ++i) dd->DeviceID[i] = (CHAR)w.DeviceID[i];
        for (i = 0; i < 128; ++i) dd->DeviceKey[i] = (CHAR)w.DeviceKey[i];
    }
    return TRUE;
}

DLLAPI BOOL WINAPI GetMonitorInfoA(HMONITOR mon, LPMONITORINFO mi)
{
    MONITORINFOEXW w;
    int i;
    if (!mi || (mi->cbSize != sizeof(MONITORINFO) && mi->cbSize != sizeof(MONITORINFOEXA))) { SetLastError(ERROR_INVALID_PARAMETER); return FALSE; }
    w.cbSize = sizeof w;
    if (!GetMonitorInfoW(mon, (LPMONITORINFO)&w)) return FALSE;
    mi->rcMonitor = w.rcMonitor;
    mi->rcWork = w.rcWork;
    mi->dwFlags = w.dwFlags;
    if (mi->cbSize == sizeof(MONITORINFOEXA))
        for (i = 0; i < CCHDEVICENAME; ++i) ((MONITORINFOEXA *)mi)->szDevice[i] = (CHAR)w.szDevice[i];
    return TRUE;
}

/* ---- the CCD API (QueryDisplayConfig & co.): one path, adapter LUID {1, 0}, source 0, target 0 ---- */
static const LUID k_adapter = { 1, 0 };

DLLAPI LONG WINAPI GetDisplayConfigBufferSizes(UINT32 flags, UINT32 *npaths, UINT32 *nmodes)
{
    if (!npaths || !nmodes) return ERROR_INVALID_PARAMETER;
    if (!(flags & (QDC_ALL_PATHS | QDC_ONLY_ACTIVE_PATHS | QDC_DATABASE_CURRENT))) return ERROR_INVALID_PARAMETER;
    if (!u32_display(0)) { *npaths = *nmodes = 0; return ERROR_SUCCESS; }
    *npaths = 1;
    *nmodes = 2;
    return ERROR_SUCCESS;
}

DLLAPI LONG WINAPI QueryDisplayConfig(UINT32 flags, UINT32 *npaths, DISPLAYCONFIG_PATH_INFO *paths, UINT32 *nmodes,
                                      DISPLAYCONFIG_MODE_INFO *modes, DISPLAYCONFIG_TOPOLOGY_ID *topo)
{
    shz_display_info_t di;
    if (!npaths || !nmodes || !paths || !modes) return ERROR_INVALID_PARAMETER;
    if ((flags & QDC_DATABASE_CURRENT) ? !topo : (topo != 0)) return ERROR_INVALID_PARAMETER;
    if (!u32_display(&di)) { *npaths = *nmodes = 0; return ERROR_SUCCESS; }
    if (*npaths < 1 || *nmodes < 2) return ERROR_INSUFFICIENT_BUFFER;
    memset(paths, 0, sizeof *paths);
    memset(modes, 0, 2 * sizeof *modes);
    paths->sourceInfo.adapterId = k_adapter;
    paths->sourceInfo.id = 0;
    paths->sourceInfo.modeInfoIdx = 0;
    paths->sourceInfo.statusFlags = DISPLAYCONFIG_SOURCE_IN_USE;
    paths->targetInfo.adapterId = k_adapter;
    paths->targetInfo.id = 0;
    paths->targetInfo.modeInfoIdx = 1;
    paths->targetInfo.outputTechnology = DISPLAYCONFIG_OUTPUT_TECHNOLOGY_OTHER;
    paths->targetInfo.rotation = DISPLAYCONFIG_ROTATION_IDENTITY;
    paths->targetInfo.scaling = DISPLAYCONFIG_SCALING_IDENTITY;
    paths->targetInfo.scanLineOrdering = DISPLAYCONFIG_SCANLINE_ORDERING_PROGRESSIVE;
    paths->targetInfo.targetAvailable = TRUE;
    paths->targetInfo.statusFlags = DISPLAYCONFIG_TARGET_IN_USE;
    paths->flags = DISPLAYCONFIG_PATH_ACTIVE;
    modes[0].infoType = DISPLAYCONFIG_MODE_INFO_TYPE_SOURCE;
    modes[0].id = 0;
    modes[0].adapterId = k_adapter;
    modes[0].sourceMode.width = di.width;
    modes[0].sourceMode.height = di.height;
    modes[0].sourceMode.pixelFormat = DISPLAYCONFIG_PIXELFORMAT_32BPP;
    modes[1].infoType = DISPLAYCONFIG_MODE_INFO_TYPE_TARGET;
    modes[1].id = 0;
    modes[1].adapterId = k_adapter;
    modes[1].targetMode.targetVideoSignalInfo.activeSize.cx = di.width;     /* no timings or refresh rate exist to report */
    modes[1].targetMode.targetVideoSignalInfo.activeSize.cy = di.height;
    modes[1].targetMode.targetVideoSignalInfo.totalSize.cx = di.width;
    modes[1].targetMode.targetVideoSignalInfo.totalSize.cy = di.height;
    modes[1].targetMode.targetVideoSignalInfo.scanLineOrdering = DISPLAYCONFIG_SCANLINE_ORDERING_PROGRESSIVE;
    *npaths = 1;
    *nmodes = 2;
    if (topo) *topo = DISPLAYCONFIG_TOPOLOGY_INTERNAL;
    return ERROR_SUCCESS;
}

DLLAPI LONG WINAPI DisplayConfigGetDeviceInfo(DISPLAYCONFIG_DEVICE_INFO_HEADER *h)
{
    if (!h) return ERROR_INVALID_PARAMETER;
    if (h->adapterId.LowPart != k_adapter.LowPart || h->adapterId.HighPart != k_adapter.HighPart || h->id != 0) return ERROR_INVALID_PARAMETER;
    switch (h->type) {
    case DISPLAYCONFIG_DEVICE_INFO_GET_SOURCE_NAME: {
        DISPLAYCONFIG_SOURCE_DEVICE_NAME *s = (DISPLAYCONFIG_SOURCE_DEVICE_NAME *)h;
        if (h->size < sizeof *s) return ERROR_INSUFFICIENT_BUFFER;
        wcopy(s->viewGdiDeviceName, k_display1, CCHDEVICENAME);
        return ERROR_SUCCESS;
    }
    case DISPLAYCONFIG_DEVICE_INFO_GET_TARGET_NAME: {
        DISPLAYCONFIG_TARGET_DEVICE_NAME *t = (DISPLAYCONFIG_TARGET_DEVICE_NAME *)h;
        if (h->size < sizeof *t) return ERROR_INSUFFICIENT_BUFFER;
        memset(&t->flags, 0, sizeof *t - offsetof(DISPLAYCONFIG_TARGET_DEVICE_NAME, flags));
        t->outputTechnology = DISPLAYCONFIG_OUTPUT_TECHNOLOGY_OTHER;
        wcopy(t->monitorFriendlyDeviceName, L"", 64);                  /* no EDID: no friendly name, flags say so */
        wcopy(t->monitorDevicePath, L"\\\\?\\DISPLAY#Default_Monitor#0", 128);
        return ERROR_SUCCESS;
    }
    case DISPLAYCONFIG_DEVICE_INFO_GET_ADAPTER_NAME: {
        DISPLAYCONFIG_ADAPTER_NAME *a = (DISPLAYCONFIG_ADAPTER_NAME *)h;
        if (h->size < sizeof *a) return ERROR_INSUFFICIENT_BUFFER;
        wcopy(a->adapterDevicePath, L"\\\\?\\PCI#VEN_1234&DEV_1111#0", 128);
        return ERROR_SUCCESS;
    }
    default:
        return ERROR_NOT_SUPPORTED;                                     /* colour/HDR/SDR white level: no such capability */
    }
}

DLLAPI LONG WINAPI SetDisplayConfig(UINT32 npaths, DISPLAYCONFIG_PATH_INFO *paths, UINT32 nmodes, DISPLAYCONFIG_MODE_INFO *modes, UINT32 flags)
{
    (void)paths; (void)modes;
    if (!(flags & (SDC_APPLY | SDC_VALIDATE))) return ERROR_INVALID_PARAMETER;
    if (npaths == 0 && nmodes == 0 && (flags & (SDC_TOPOLOGY_INTERNAL | SDC_TOPOLOGY_SUPPLIED | SDC_USE_DATABASE_CURRENT)))
        return (flags & (SDC_TOPOLOGY_EXTEND | SDC_TOPOLOGY_CLONE | SDC_TOPOLOGY_EXTERNAL)) ? ERROR_NOT_SUPPORTED : ERROR_SUCCESS;
    return ERROR_NOT_SUPPORTED;                                         /* one fixed path and mode */
}

/* ---------------------------------------------------------------- DPI (fixed 96) */
#define SYS_DPI 96
static volatile LONG g_proc_awareness = -1;                             /* DPI_AWARENESS: -1 not set yet (= unaware) */
static DWORD g_thread_ctx_tls = TLS_OUT_OF_INDEXES;

static int ctx_awareness(DPI_AWARENESS_CONTEXT c)
{
    switch ((INT_PTR)c) {
    case -1: return DPI_AWARENESS_UNAWARE;                              /* DPI_AWARENESS_CONTEXT_UNAWARE */
    case -2: return DPI_AWARENESS_SYSTEM_AWARE;
    case -3: case -4: return DPI_AWARENESS_PER_MONITOR_AWARE;
    case -5: return DPI_AWARENESS_UNAWARE;                              /* UNAWARE_GDISCALED */
    default: return DPI_AWARENESS_INVALID;
    }
}

static DPI_AWARENESS_CONTEXT proc_ctx(void)
{
    const LONG a = g_proc_awareness;
    return (DPI_AWARENESS_CONTEXT)(INT_PTR)(a < 0 ? -1 : a == 100 ? -4 : a == 101 ? -5 : -(a + 1));
}

DLLAPI BOOL WINAPI IsValidDpiAwarenessContext(DPI_AWARENESS_CONTEXT c) { return ctx_awareness(c) != DPI_AWARENESS_INVALID; }
DLLAPI DPI_AWARENESS WINAPI GetAwarenessFromDpiAwarenessContext(DPI_AWARENESS_CONTEXT c) { return (DPI_AWARENESS)ctx_awareness(c); }
DLLAPI UINT WINAPI GetDpiFromDpiAwarenessContext(DPI_AWARENESS_CONTEXT c) { return ctx_awareness(c) == DPI_AWARENESS_SYSTEM_AWARE ? SYS_DPI : 0; }
DLLAPI BOOL WINAPI AreDpiAwarenessContextsEqual(DPI_AWARENESS_CONTEXT a, DPI_AWARENESS_CONTEXT b)
{
    return ctx_awareness(a) != DPI_AWARENESS_INVALID && a == b;
}

DLLAPI BOOL WINAPI SetProcessDpiAwarenessContext(DPI_AWARENESS_CONTEXT c)
{
    const int a = ctx_awareness(c);
    LONG v;
    if (a == DPI_AWARENESS_INVALID) { SetLastError(ERROR_INVALID_PARAMETER); return FALSE; }
    v = (INT_PTR)c == -4 ? 100 : (INT_PTR)c == -5 ? 101 : a;
    if (InterlockedCompareExchange(&g_proc_awareness, v, -1) != -1) { SetLastError(ERROR_ACCESS_DENIED); return FALSE; }   /* set once */
    return TRUE;
}

DLLAPI BOOL WINAPI SetProcessDPIAware(void)
{
    InterlockedCompareExchange(&g_proc_awareness, DPI_AWARENESS_SYSTEM_AWARE, -1);
    return TRUE;
}

DLLAPI BOOL WINAPI IsProcessDPIAware(void) { return ctx_awareness(proc_ctx()) != DPI_AWARENESS_UNAWARE; }

DLLAPI DPI_AWARENESS_CONTEXT WINAPI GetDpiAwarenessContextForProcess(HANDLE proc)
{
    (void)proc;
    return proc_ctx();
}

DLLAPI DPI_AWARENESS_CONTEXT WINAPI GetThreadDpiAwarenessContext(void)
{
    DPI_AWARENESS_CONTEXT c = 0;
    if (g_thread_ctx_tls != TLS_OUT_OF_INDEXES) c = (DPI_AWARENESS_CONTEXT)TlsGetValue(g_thread_ctx_tls);
    return c ? c : proc_ctx();
}

DLLAPI DPI_AWARENESS_CONTEXT WINAPI SetThreadDpiAwarenessContext(DPI_AWARENESS_CONTEXT c)
{
    DPI_AWARENESS_CONTEXT old = GetThreadDpiAwarenessContext();
    if (ctx_awareness(c) == DPI_AWARENESS_INVALID) { SetLastError(ERROR_INVALID_PARAMETER); return 0; }
    if (g_thread_ctx_tls == TLS_OUT_OF_INDEXES) {
        const DWORD t = TlsAlloc();
        if (t == TLS_OUT_OF_INDEXES) return 0;
        if (InterlockedCompareExchange((volatile LONG *)&g_thread_ctx_tls, (LONG)t, (LONG)TLS_OUT_OF_INDEXES) != (LONG)TLS_OUT_OF_INDEXES) TlsFree(t);
    }
    TlsSetValue(g_thread_ctx_tls, (LPVOID)c);
    return old;
}

DLLAPI DPI_AWARENESS_CONTEXT WINAPI GetWindowDpiAwarenessContext(HWND hwnd)
{
    if (!IsWindow(hwnd)) { SetLastError(ERROR_INVALID_WINDOW_HANDLE); return 0; }
    return proc_ctx();                                                  /* windows take the process context when created */
}

DLLAPI DPI_HOSTING_BEHAVIOR WINAPI SetThreadDpiHostingBehavior(DPI_HOSTING_BEHAVIOR v)
{
    static DPI_HOSTING_BEHAVIOR cur = DPI_HOSTING_BEHAVIOR_DEFAULT;
    const DPI_HOSTING_BEHAVIOR old = cur;
    if (v != DPI_HOSTING_BEHAVIOR_DEFAULT && v != DPI_HOSTING_BEHAVIOR_MIXED) { SetLastError(ERROR_INVALID_PARAMETER); return DPI_HOSTING_BEHAVIOR_INVALID; }
    cur = v;
    return old;
}
DLLAPI DPI_HOSTING_BEHAVIOR WINAPI GetThreadDpiHostingBehavior(void) { const DPI_HOSTING_BEHAVIOR o = SetThreadDpiHostingBehavior(DPI_HOSTING_BEHAVIOR_DEFAULT); SetThreadDpiHostingBehavior(o); return o; }
DLLAPI DPI_HOSTING_BEHAVIOR WINAPI GetWindowDpiHostingBehavior(HWND hwnd) { (void)hwnd; return DPI_HOSTING_BEHAVIOR_DEFAULT; }

DLLAPI UINT WINAPI GetDpiForSystem(void) { return SYS_DPI; }
DLLAPI UINT WINAPI GetSystemDpiForProcess(HANDLE proc) { (void)proc; return SYS_DPI; }
DLLAPI UINT WINAPI GetDpiForWindow(HWND hwnd)
{
    if (!IsWindow(hwnd)) { SetLastError(ERROR_INVALID_WINDOW_HANDLE); return 0; }
    return SYS_DPI;
}
DLLAPI BOOL WINAPI EnableNonClientDpiScaling(HWND hwnd) { return IsWindow(hwnd); }   /* at 96 DPI there is nothing to scale */
DLLAPI BOOL WINAPI InheritWindowMonitor(HWND hwnd, HWND from) { return IsWindow(hwnd) && (!from || IsWindow(from)); }   /* one monitor */

int u32_muldiv(int a, int b, int c)
{
    int64_t p = (int64_t)a * b;
    if (!c) return -1;
    if ((p < 0) != (c < 0)) return (int)((p - c / 2) / c);             /* rounds half away from zero, as MulDiv */
    return (int)((p + c / 2) / c);
}

int u32_user_object_count(void) { return u32_icon_count() + u32_menu_count() + u32_accel_count() + u32_hook_count(); }

static int scale(int v, UINT dpi) { return u32_muldiv(v, (int)dpi, SYS_DPI); }

DLLAPI BOOL WINAPI AdjustWindowRectExForDpi(LPRECT rc, DWORD style, BOOL menu, DWORD ex, UINT dpi)
{
    int32_t l, t, r, b;
    (void)menu;
    if (!rc || !dpi) { SetLastError(ERROR_INVALID_PARAMETER); return FALSE; }
    shz_nc_insets(style, ex, &l, &t, &r, &b);
    rc->left -= scale(l, dpi); rc->top -= scale(t, dpi); rc->right += scale(r, dpi); rc->bottom += scale(b, dpi);
    return TRUE;
}

DLLAPI int WINAPI GetSystemMetricsForDpi(int index, UINT dpi)
{
    const int v = u32_metric(index);
    if (!dpi) { SetLastError(ERROR_INVALID_PARAMETER); return 0; }
    switch (index) {                                                    /* counts, flags and the physical screen are not scaled */
    case SM_CXSCREEN: case SM_CYSCREEN: case SM_CXVIRTUALSCREEN: case SM_CYVIRTUALSCREEN: case SM_XVIRTUALSCREEN: case SM_YVIRTUALSCREEN:
    case SM_CXFULLSCREEN: case SM_CYFULLSCREEN: case SM_CXMAXIMIZED: case SM_CYMAXIMIZED: case SM_CXMAXTRACK: case SM_CYMAXTRACK:
    case SM_CMONITORS: case SM_MOUSEPRESENT: case SM_CMOUSEBUTTONS: case SM_MOUSEWHEELPRESENT: case SM_SWAPBUTTON: case SM_SAMEDISPLAYFORMAT:
    case SM_ARRANGE: case SM_REMOTESESSION: case SM_DEBUG: case SM_NETWORK: case SM_SLOWMACHINE: case SM_MIDEASTENABLED: case SM_DBCSENABLED:
        return v;
    default:
        return scale(v, dpi);
    }
}

DLLAPI BOOL WINAPI SystemParametersInfoForDpi(UINT action, UINT param, PVOID pv, UINT winini, UINT dpi)
{
    if (!dpi) { SetLastError(ERROR_INVALID_PARAMETER); return FALSE; }
    switch (action) {
    case SPI_GETNONCLIENTMETRICS: {
        NONCLIENTMETRICSW *m = pv;
        if (!SystemParametersInfoW(action, param, pv, winini)) return FALSE;
        m->iBorderWidth = scale(m->iBorderWidth, dpi); m->iScrollWidth = scale(m->iScrollWidth, dpi); m->iScrollHeight = scale(m->iScrollHeight, dpi);
        m->iCaptionWidth = scale(m->iCaptionWidth, dpi); m->iCaptionHeight = scale(m->iCaptionHeight, dpi);
        m->iSmCaptionWidth = scale(m->iSmCaptionWidth, dpi); m->iSmCaptionHeight = scale(m->iSmCaptionHeight, dpi);
        m->iMenuWidth = scale(m->iMenuWidth, dpi); m->iMenuHeight = scale(m->iMenuHeight, dpi);
        m->lfCaptionFont.lfHeight = scale(m->lfCaptionFont.lfHeight, dpi); m->lfSmCaptionFont.lfHeight = scale(m->lfSmCaptionFont.lfHeight, dpi);
        m->lfMenuFont.lfHeight = scale(m->lfMenuFont.lfHeight, dpi); m->lfStatusFont.lfHeight = scale(m->lfStatusFont.lfHeight, dpi);
        m->lfMessageFont.lfHeight = scale(m->lfMessageFont.lfHeight, dpi);
        return TRUE;
    }
    case SPI_GETICONTITLELOGFONT:
        if (!SystemParametersInfoW(action, param, pv, winini)) return FALSE;
        ((LOGFONTW *)pv)->lfHeight = scale(((LOGFONTW *)pv)->lfHeight, dpi);
        return TRUE;
    case SPI_GETICONMETRICS:
        if (!SystemParametersInfoW(action, param, pv, winini)) return FALSE;
        ((ICONMETRICSW *)pv)->iHorzSpacing = scale(((ICONMETRICSW *)pv)->iHorzSpacing, dpi);
        ((ICONMETRICSW *)pv)->iVertSpacing = scale(((ICONMETRICSW *)pv)->iVertSpacing, dpi);
        ((ICONMETRICSW *)pv)->lfFont.lfHeight = scale(((ICONMETRICSW *)pv)->lfFont.lfHeight, dpi);
        return TRUE;
    default:
        SetLastError(ERROR_INVALID_PARAMETER);                          /* only the three the API is defined for */
        return FALSE;
    }
}

DLLAPI BOOL WINAPI LogicalToPhysicalPoint(HWND hwnd, LPPOINT pt) { return IsWindow(hwnd) && pt; }   /* identity at 96 DPI */
DLLAPI BOOL WINAPI PhysicalToLogicalPoint(HWND hwnd, LPPOINT pt) { return IsWindow(hwnd) && pt; }
DLLAPI BOOL WINAPI LogicalToPhysicalPointForPerMonitorDPI(HWND hwnd, LPPOINT pt) { return (!hwnd || IsWindow(hwnd)) && pt; }
DLLAPI BOOL WINAPI PhysicalToLogicalPointForPerMonitorDPI(HWND hwnd, LPPOINT pt) { return (!hwnd || IsWindow(hwnd)) && pt; }

/* ---------------------------------------------------------------- window station and desktop */
/* Handles are kernel event objects (so CloseHandle/DuplicateHandle on them behave like handles); user32 remembers which
 * value names which object. */
#define UOBJ_MAX 64
static struct { HANDLE h; int desktop; } g_uobj[UOBJ_MAX];
static CRITICAL_SECTION g_uobj_lock;
static volatile LONG g_uobj_init;
static HWINSTA g_winsta;
static HDESK g_desk;

static void uobj_lock(void)
{
    if (InterlockedCompareExchange(&g_uobj_init, 1, 0) == 0) { InitializeCriticalSection(&g_uobj_lock); g_uobj_init = 2; }
    while (g_uobj_init != 2) Sleep(0);
    EnterCriticalSection(&g_uobj_lock);
}

static HANDLE uobj_new(int desktop)
{
    HANDLE h = CreateEventW(0, TRUE, FALSE, 0);
    int i;
    if (!h) return 0;
    uobj_lock();
    for (i = 0; i < UOBJ_MAX; ++i)
        if (!g_uobj[i].h) { g_uobj[i].h = h; g_uobj[i].desktop = desktop; LeaveCriticalSection(&g_uobj_lock); return h; }
    LeaveCriticalSection(&g_uobj_lock);
    CloseHandle(h);
    SetLastError(ERROR_NOT_ENOUGH_MEMORY);
    return 0;
}

static int uobj_kind(HANDLE h)                                          /* 0 station, 1 desktop, -1 unknown */
{
    int i, k = -1;
    if (!h) return -1;
    uobj_lock();
    for (i = 0; i < UOBJ_MAX; ++i) if (g_uobj[i].h == h) { k = g_uobj[i].desktop; break; }
    LeaveCriticalSection(&g_uobj_lock);
    return k;
}

static BOOL uobj_close(HANDLE h, int desktop)
{
    int i;
    uobj_lock();
    for (i = 0; i < UOBJ_MAX; ++i)
        if (g_uobj[i].h == h && g_uobj[i].desktop == desktop) {
            if (h == (HANDLE)g_winsta || h == (HANDLE)g_desk) { LeaveCriticalSection(&g_uobj_lock); return TRUE; }   /* process/thread handles stay */
            g_uobj[i].h = 0;
            LeaveCriticalSection(&g_uobj_lock);
            return CloseHandle(h);
        }
    LeaveCriticalSection(&g_uobj_lock);
    SetLastError(ERROR_INVALID_HANDLE);
    return FALSE;
}

DLLAPI HWINSTA WINAPI GetProcessWindowStation(void)
{
    if (!g_winsta) {
        HANDLE h = uobj_new(0);
        if (h && InterlockedCompareExchangePointer((PVOID *)&g_winsta, h, 0) != 0) uobj_close(h, 0);
    }
    return g_winsta;
}

DLLAPI HDESK WINAPI GetThreadDesktop(DWORD tid)
{
    (void)tid;
    if (!g_desk) {
        HANDLE h = uobj_new(1);
        if (h && InterlockedCompareExchangePointer((PVOID *)&g_desk, h, 0) != 0) uobj_close(h, 1);
    }
    return g_desk;
}

static int name_is(LPCWSTR n, LPCWSTR want)
{
    int i;
    if (!n) return 0;
    for (i = 0; want[i]; ++i) if ((n[i] | 0x20) != (want[i] | 0x20)) return 0;
    return n[i] == 0;
}

DLLAPI HDESK WINAPI OpenInputDesktop(DWORD flags, BOOL inherit, ACCESS_MASK access) { (void)flags; (void)inherit; (void)access; return (HDESK)uobj_new(1); }
DLLAPI HDESK WINAPI OpenDesktopW(LPCWSTR name, DWORD flags, BOOL inherit, ACCESS_MASK access)
{
    (void)flags; (void)inherit; (void)access;
    if (!name_is(name, L"Default")) { SetLastError(ERROR_FILE_NOT_FOUND); return 0; }
    return (HDESK)uobj_new(1);
}
DLLAPI HDESK WINAPI CreateDesktopW(LPCWSTR name, LPCWSTR dev, DEVMODEW *dm, DWORD flags, ACCESS_MASK access, LPSECURITY_ATTRIBUTES sa)
{
    (void)dev; (void)dm; (void)flags; (void)access; (void)sa;
    if (name_is(name, L"Default")) return (HDESK)uobj_new(1);         /* opening the one that exists */
    SetLastError(ERROR_NOT_SUPPORTED);                                  /* no second desktop can exist */
    return 0;
}
DLLAPI HWINSTA WINAPI OpenWindowStationW(LPCWSTR name, BOOL inherit, ACCESS_MASK access)
{
    (void)inherit; (void)access;
    if (!name_is(name, L"WinSta0")) { SetLastError(ERROR_FILE_NOT_FOUND); return 0; }
    return (HWINSTA)uobj_new(0);
}
DLLAPI HWINSTA WINAPI CreateWindowStationW(LPCWSTR name, DWORD flags, ACCESS_MASK access, LPSECURITY_ATTRIBUTES sa)
{
    (void)flags; (void)access; (void)sa;
    if (name_is(name, L"WinSta0")) return (HWINSTA)uobj_new(0);
    SetLastError(ERROR_NOT_SUPPORTED);
    return 0;
}
DLLAPI BOOL WINAPI CloseDesktop(HDESK h) { return uobj_close((HANDLE)h, 1); }
DLLAPI BOOL WINAPI CloseWindowStation(HWINSTA h) { return uobj_close((HANDLE)h, 0); }
DLLAPI BOOL WINAPI SetThreadDesktop(HDESK h) { if (uobj_kind((HANDLE)h) != 1) { SetLastError(ERROR_INVALID_HANDLE); return FALSE; } return TRUE; }
DLLAPI BOOL WINAPI SetProcessWindowStation(HWINSTA h) { if (uobj_kind((HANDLE)h) != 0) { SetLastError(ERROR_INVALID_HANDLE); return FALSE; } return TRUE; }
DLLAPI BOOL WINAPI SwitchDesktop(HDESK h) { if (uobj_kind((HANDLE)h) != 1) { SetLastError(ERROR_INVALID_HANDLE); return FALSE; } return TRUE; }

DLLAPI BOOL WINAPI GetUserObjectInformationW(HANDLE h, int index, PVOID info, DWORD len, LPDWORD needed)
{
    const int k = uobj_kind(h);
    const WCHAR *s = 0;
    DWORD n;
    if (k < 0) { SetLastError(ERROR_INVALID_HANDLE); return FALSE; }
    switch (index) {
    case UOI_FLAGS: {
        USEROBJECTFLAGS f;
        f.fInherit = FALSE; f.fReserved = FALSE; f.dwFlags = k == 0 ? WSF_VISIBLE : 0;
        if (needed) *needed = sizeof f;
        if (len < sizeof f || !info) { SetLastError(ERROR_INSUFFICIENT_BUFFER); return FALSE; }
        memcpy(info, &f, sizeof f);
        return TRUE;
    }
    case UOI_NAME: s = k == 0 ? L"WinSta0" : L"Default"; break;
    case UOI_TYPE: s = k == 0 ? L"WindowStation" : L"Desktop"; break;
    case UOI_IO: {
        BOOL io = TRUE;                                                 /* the only desktop receives all input */
        if (needed) *needed = sizeof io;
        if (len < sizeof io || !info) { SetLastError(ERROR_INSUFFICIENT_BUFFER); return FALSE; }
        memcpy(info, &io, sizeof io);
        return TRUE;
    }
    case UOI_USER_SID:
        if (needed) *needed = 0;                                        /* no logon session is associated */
        return TRUE;
    default:
        SetLastError(ERROR_INVALID_PARAMETER);
        return FALSE;
    }
    n = (DWORD)((wcslen(s) + 1) * sizeof(WCHAR));
    if (needed) *needed = n;
    if (len < n || !info) { SetLastError(ERROR_INSUFFICIENT_BUFFER); return FALSE; }
    memcpy(info, s, n);
    return TRUE;
}

DLLAPI BOOL WINAPI GetUserObjectInformationA(HANDLE h, int index, PVOID info, DWORD len, LPDWORD needed)
{
    WCHAR w[32];
    DWORD n = 0, i;
    if (index != UOI_NAME && index != UOI_TYPE) return GetUserObjectInformationW(h, index, info, len, needed);
    if (!GetUserObjectInformationW(h, index, w, sizeof w, &n)) return FALSE;
    n /= sizeof(WCHAR);
    if (needed) *needed = n;
    if (len < n || !info) { SetLastError(ERROR_INSUFFICIENT_BUFFER); return FALSE; }
    for (i = 0; i < n; ++i) ((CHAR *)info)[i] = (CHAR)w[i];
    return TRUE;
}

DLLAPI BOOL WINAPI SetUserObjectInformationW(HANDLE h, int index, PVOID info, DWORD len)
{
    (void)info; (void)len;
    if (uobj_kind(h) < 0) { SetLastError(ERROR_INVALID_HANDLE); return FALSE; }
    if (index != UOI_FLAGS) { SetLastError(ERROR_INVALID_PARAMETER); return FALSE; }
    return TRUE;
}

/* ---------------------------------------------------------------- notifications that never fire here */
typedef struct notif { struct notif *next; int kind; HANDLE recipient; } notif_t;
static notif_t *g_notifs;
static CRITICAL_SECTION g_notif_lock;
static volatile LONG g_notif_init;

static void notif_lock(void)
{
    if (InterlockedCompareExchange(&g_notif_init, 1, 0) == 0) { InitializeCriticalSection(&g_notif_lock); g_notif_init = 2; }
    while (g_notif_init != 2) Sleep(0);
    EnterCriticalSection(&g_notif_lock);
}

static HANDLE notif_add(int kind, HANDLE recipient)
{
    notif_t *n = HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, sizeof *n);
    if (!n) { SetLastError(ERROR_NOT_ENOUGH_MEMORY); return 0; }
    n->kind = kind;
    n->recipient = recipient;
    notif_lock();
    n->next = g_notifs;
    g_notifs = n;
    LeaveCriticalSection(&g_notif_lock);
    return (HANDLE)n;
}

static BOOL notif_remove(HANDLE h, int kind)
{
    notif_t **pp, *n;
    notif_lock();
    for (pp = &g_notifs; (n = *pp); pp = &n->next)
        if ((HANDLE)n == h && n->kind == kind) {
            *pp = n->next;
            LeaveCriticalSection(&g_notif_lock);
            HeapFree(GetProcessHeap(), 0, n);
            return TRUE;
        }
    LeaveCriticalSection(&g_notif_lock);
    SetLastError(ERROR_INVALID_HANDLE);
    return FALSE;
}

DLLAPI HDEVNOTIFY WINAPI RegisterDeviceNotificationW(HANDLE recipient, LPVOID filter, DWORD flags)
{
    if (!recipient || !filter) { SetLastError(ERROR_INVALID_PARAMETER); return 0; }
    if (!(flags & DEVICE_NOTIFY_SERVICE_HANDLE) && !IsWindow((HWND)recipient)) { SetLastError(ERROR_INVALID_WINDOW_HANDLE); return 0; }
    return (HDEVNOTIFY)notif_add(1, recipient);
}
DLLAPI HDEVNOTIFY WINAPI RegisterDeviceNotificationA(HANDLE recipient, LPVOID filter, DWORD flags) { return RegisterDeviceNotificationW(recipient, filter, flags); }
DLLAPI BOOL WINAPI UnregisterDeviceNotification(HDEVNOTIFY h) { return notif_remove((HANDLE)h, 1); }
DLLAPI HPOWERNOTIFY WINAPI RegisterPowerSettingNotification(HANDLE recipient, LPCGUID guid, DWORD flags)
{
    (void)flags;
    if (!recipient || !guid) { SetLastError(ERROR_INVALID_PARAMETER); return 0; }
    return (HPOWERNOTIFY)notif_add(2, recipient);
}
DLLAPI BOOL WINAPI UnregisterPowerSettingNotification(HPOWERNOTIFY h) { return notif_remove((HANDLE)h, 2); }
DLLAPI HPOWERNOTIFY WINAPI RegisterSuspendResumeNotification(HANDLE recipient, DWORD flags)
{
    (void)flags;
    if (!recipient) { SetLastError(ERROR_INVALID_PARAMETER); return 0; }
    return (HPOWERNOTIFY)notif_add(3, recipient);
}
DLLAPI BOOL WINAPI UnregisterSuspendResumeNotification(HPOWERNOTIFY h) { return notif_remove((HANDLE)h, 3); }

/* ---------------------------------------------------------------- pointer (touch/pen) devices: none exist */
DLLAPI BOOL WINAPI GetPointerDevices(UINT32 *count, POINTER_DEVICE_INFO *devs)
{
    (void)devs;
    if (!count) { SetLastError(ERROR_INVALID_PARAMETER); return FALSE; }
    *count = 0;
    return TRUE;
}
DLLAPI BOOL WINAPI GetPointerDevice(HANDLE dev, POINTER_DEVICE_INFO *info) { (void)dev; (void)info; SetLastError(ERROR_INVALID_PARAMETER); return FALSE; }
DLLAPI BOOL WINAPI GetPointerType(UINT32 id, POINTER_INPUT_TYPE *type) { (void)id; (void)type; SetLastError(ERROR_INVALID_PARAMETER); return FALSE; }
DLLAPI BOOL WINAPI GetPointerPenInfo(UINT32 id, POINTER_PEN_INFO *info) { (void)id; (void)info; SetLastError(ERROR_INVALID_PARAMETER); return FALSE; }
DLLAPI BOOL WINAPI GetPointerTouchInfo(UINT32 id, POINTER_TOUCH_INFO *info) { (void)id; (void)info; SetLastError(ERROR_INVALID_PARAMETER); return FALSE; }
DLLAPI BOOL WINAPI GetPointerInfo(UINT32 id, POINTER_INFO *info) { (void)id; (void)info; SetLastError(ERROR_INVALID_PARAMETER); return FALSE; }
DLLAPI BOOL WINAPI RegisterPointerDeviceNotifications(HWND hwnd, BOOL range) { (void)range; return IsWindow(hwnd); }
DLLAPI BOOL WINAPI CloseTouchInputHandle(HTOUCHINPUT h) { (void)h; SetLastError(ERROR_INVALID_HANDLE); return FALSE; }
DLLAPI BOOL WINAPI GetTouchInputInfo(HTOUCHINPUT h, UINT n, PTOUCHINPUT in, int cb) { (void)h; (void)n; (void)in; (void)cb; SetLastError(ERROR_INVALID_HANDLE); return FALSE; }
DLLAPI BOOL WINAPI RegisterTouchWindow(HWND hwnd, ULONG flags) { (void)flags; return IsWindow(hwnd); }
DLLAPI BOOL WINAPI UnregisterTouchWindow(HWND hwnd) { return IsWindow(hwnd); }
DLLAPI BOOL WINAPI IsTouchWindow(HWND hwnd, PULONG flags) { (void)hwnd; if (flags) *flags = 0; return FALSE; }
DLLAPI BOOL WINAPI EnableMouseInPointer(BOOL enable) { if (!enable) return TRUE; SetLastError(ERROR_NOT_SUPPORTED); return FALSE; }
DLLAPI BOOL WINAPI IsMouseInPointerEnabled(void) { return FALSE; }

/* ---------------------------------------------------------------- message filters (no UIPI) */
DLLAPI BOOL WINAPI ChangeWindowMessageFilterEx(HWND hwnd, UINT msg, DWORD action, PCHANGEFILTERSTRUCT cfs)
{
    (void)msg;
    if (!IsWindow(hwnd) || (action != MSGFLT_ALLOW && action != MSGFLT_DISALLOW && action != MSGFLT_RESET)) { SetLastError(ERROR_INVALID_PARAMETER); return FALSE; }
    if (cfs) {
        if (cfs->cbSize != sizeof *cfs) { SetLastError(ERROR_INVALID_PARAMETER); return FALSE; }
        cfs->ExtStatus = MSGFLTINFO_NONE;
    }
    return TRUE;
}
DLLAPI BOOL WINAPI ChangeWindowMessageFilter(UINT msg, DWORD flag)
{
    (void)msg;
    if (flag != MSGFLT_ADD && flag != MSGFLT_REMOVE) { SetLastError(ERROR_INVALID_PARAMETER); return FALSE; }
    return TRUE;
}

/* ---------------------------------------------------------------- layered windows, regions, printing */
DLLAPI BOOL WINAPI SetLayeredWindowAttributes(HWND hwnd, COLORREF key, BYTE alpha, DWORD flags)
{
    shz_winop_t o;
    U32_NEED_GFX(FALSE);
    memset(&o, 0, sizeof o);
    o.op = SHZ_WOP_SET_LAYERED;
    o.hwnd = H2U(hwnd);
    o.flags = flags & (LWA_COLORKEY | LWA_ALPHA);
    o.key = ((key & 0xff) << 16) | (key & 0xff00) | ((key >> 16) & 0xff);   /* COLORREF -> 0x00RRGGBB */
    o.alpha = alpha;
    return winop(&o) >= 0;
}

DLLAPI BOOL WINAPI GetLayeredWindowAttributes(HWND hwnd, COLORREF *key, BYTE *alpha, DWORD *flags)
{
    shz_winop_t o;
    U32_NEED_GFX(FALSE);
    memset(&o, 0, sizeof o);
    o.op = SHZ_WOP_GET_LAYERED;
    o.hwnd = H2U(hwnd);
    if (winop(&o) < 0) return FALSE;
    if (key) *key = ((o.key >> 16) & 0xff) | (o.key & 0xff00) | ((o.key & 0xff) << 16);
    if (alpha) *alpha = (BYTE)o.alpha;
    if (flags) *flags = o.flags;
    return TRUE;
}

DLLAPI BOOL WINAPI UpdateLayeredWindowIndirect(HWND hwnd, const UPDATELAYEREDWINDOWINFO *ui)
{
    shz_winop_t o;
    RECT wr;
    uint32_t *copy = 0;
    int moved = 0, sized = 0, ok;
    U32_NEED_GFX(FALSE);
    if (!ui || ui->cbSize != sizeof *ui || !GetWindowRect(hwnd, &wr)) { SetLastError(ERROR_INVALID_PARAMETER); return FALSE; }
    if (!(GetWindowLongW(hwnd, GWL_EXSTYLE) & WS_EX_LAYERED)) { SetLastError(ERROR_INVALID_PARAMETER); return FALSE; }
    memset(&o, 0, sizeof o);
    o.op = SHZ_WOP_UPDATE_LAYERED;
    o.hwnd = H2U(hwnd);
    o.flags = ui->dwFlags & (ULW_COLORKEY | ULW_ALPHA | ULW_OPAQUE);
    o.key = ((ui->crKey & 0xff) << 16) | (ui->crKey & 0xff00) | ((ui->crKey >> 16) & 0xff);
    o.alpha = ui->pblend ? ui->pblend->SourceConstantAlpha : 255;
    if (ui->pptDst && (ui->pptDst->x != wr.left || ui->pptDst->y != wr.top)) { o.pos_flags |= 1; o.x = ui->pptDst->x; o.y = ui->pptDst->y; moved = 1; }
    if (ui->psize && (ui->psize->cx != wr.right - wr.left || ui->psize->cy != wr.bottom - wr.top)) {
        o.pos_flags |= 2; o.w = ui->psize->cx; o.h = ui->psize->cy; sized = 1;
    }
    if ((ui->dwFlags & ULW_ALPHA) && ui->pblend && (ui->pblend->AlphaFormat & AC_SRC_ALPHA)) o.pos_flags |= 4;
    if (ui->hdcSrc) {
        const uint32_t *bits;
        int bw, bh, td, y;
        const int w = ui->psize ? ui->psize->cx : wr.right - wr.left, h = ui->psize ? ui->psize->cy : wr.bottom - wr.top;
        const int sx = ui->pptSrc ? ui->pptSrc->x : 0, sy = ui->pptSrc ? ui->pptSrc->y : 0;
        if (!ShzGdiDCBitmap(ui->hdcSrc, &bits, &bw, &bh, &td)) return FALSE;
        if (sx < 0 || sy < 0 || w <= 0 || h <= 0 || sx + w > bw || sy + h > bh) { SetLastError(ERROR_INVALID_PARAMETER); return FALSE; }
        if (td) {
            o.bits = (uint64_t)(uintptr_t)bits;
            o.stride = (uint32_t)bw * 4;
            o.src_x = sx;
            o.src_y = sy;
        } else {                                                        /* bottom-up bitmap: hand over a top-down copy */
            copy = HeapAlloc(GetProcessHeap(), 0, (size_t)w * (size_t)h * 4);
            if (!copy) { SetLastError(ERROR_NOT_ENOUGH_MEMORY); return FALSE; }
            for (y = 0; y < h; ++y) memcpy(copy + (size_t)y * (size_t)w, bits + (size_t)(bh - 1 - (sy + y)) * (size_t)bw + (size_t)sx, (size_t)w * 4);
            o.bits = (uint64_t)(uintptr_t)copy;
            o.stride = (uint32_t)w * 4;
        }
        if (ui->prcDirty) { o.dirty.left = ui->prcDirty->left; o.dirty.top = ui->prcDirty->top; o.dirty.right = ui->prcDirty->right; o.dirty.bottom = ui->prcDirty->bottom; }
    }
    ok = winop(&o) >= 0;
    if (copy) HeapFree(GetProcessHeap(), 0, copy);
    if (ok && (moved || sized)) u32_send_size_move(hwnd, moved, sized);
    return ok;
}

DLLAPI BOOL WINAPI UpdateLayeredWindow(HWND hwnd, HDC dst, POINT *pt, SIZE *size, HDC src, POINT *ptsrc, COLORREF key, BLENDFUNCTION *blend, DWORD flags)
{
    UPDATELAYEREDWINDOWINFO ui;
    memset(&ui, 0, sizeof ui);
    ui.cbSize = sizeof ui;
    ui.hdcDst = dst;
    ui.pptDst = pt;
    ui.psize = size;
    ui.hdcSrc = src;
    ui.pptSrc = ptsrc;
    ui.crKey = key;
    ui.pblend = blend;
    ui.dwFlags = flags;
    return UpdateLayeredWindowIndirect(hwnd, &ui);
}

#define WRGN_MAX 256
DLLAPI int WINAPI SetWindowRgn(HWND hwnd, HRGN rgn, BOOL redraw)
{
    shz_winop_t o;
    RECT rc[WRGN_MAX];
    int n = 0;
    (void)redraw;
    U32_NEED_GFX(0);
    memset(&o, 0, sizeof o);
    o.op = SHZ_WOP_SET_REGION;
    o.hwnd = H2U(hwnd);
    if (rgn) {
        n = ShzGdiRegionRects(rgn, rc, WRGN_MAX);
        if (n < 0) { SetLastError(ERROR_INVALID_HANDLE); return 0; }
        if (n == 0) { rc[0].left = rc[0].top = rc[0].right = rc[0].bottom = 0; n = 1; }   /* an empty region hides the window */
        o.bits = (uint64_t)(uintptr_t)rc;
        o.count = (uint32_t)n;
    }
    if (winop(&o) < 0) return 0;
    if (rgn) DeleteObject(rgn);                                         /* the system owns the region from now on */
    return 1;
}

DLLAPI int WINAPI GetWindowRgn(HWND hwnd, HRGN rgn)
{
    shz_winop_t o;
    RECT rc[WRGN_MAX];
    int32_t st;
    if (!rgn) return ERROR;
    if (!u32_display(0)) return ERROR;
    memset(&o, 0, sizeof o);
    o.op = SHZ_WOP_GET_REGION;
    o.hwnd = H2U(hwnd);
    o.bits = (uint64_t)(uintptr_t)rc;
    o.count = WRGN_MAX;
    st = NtUserWindowOp(&o);
    if (st < 0) return ERROR;                                           /* no region set (or no window) */
    if (!ShzGdiRegionSetRects(rgn, rc, (int)(o.count < WRGN_MAX ? o.count : WRGN_MAX))) return ERROR;
    return o.count == 0 || (o.count == 1 && (rc[0].right <= rc[0].left || rc[0].bottom <= rc[0].top)) ? NULLREGION :
           o.count == 1 ? SIMPLEREGION : COMPLEXREGION;
}

DLLAPI int WINAPI GetWindowRgnBox(HWND hwnd, LPRECT box)
{
    HRGN r = CreateRectRgn(0, 0, 0, 0);
    int t;
    if (!r || !box) { if (r) DeleteObject(r); return ERROR; }
    t = GetWindowRgn(hwnd, r);
    if (t != ERROR) GetRgnBox(r, box);
    DeleteObject(r);
    return t;
}

DLLAPI BOOL WINAPI PrintWindow(HWND hwnd, HDC hdc, UINT flags)
{
    shz_winop_t o;
    RECT r;
    uint32_t *buf;
    BITMAPINFO bi;
    BOOL ok;
    U32_NEED_GFX(FALSE);
    if (!hdc || !((flags & PW_CLIENTONLY) ? GetClientRect(hwnd, &r) : GetWindowRect(hwnd, &r))) { SetLastError(ERROR_INVALID_PARAMETER); return FALSE; }
    if (r.right - r.left <= 0 || r.bottom - r.top <= 0) return TRUE;
    ShzGdiFlushAll();                                                   /* what this process drew must be in the surfaces first */
    buf = HeapAlloc(GetProcessHeap(), 0, (size_t)(r.right - r.left) * (size_t)(r.bottom - r.top) * 4);
    if (!buf) { SetLastError(ERROR_NOT_ENOUGH_MEMORY); return FALSE; }
    memset(&o, 0, sizeof o);
    o.op = SHZ_WOP_PRINT;
    o.hwnd = H2U(hwnd);
    o.flags = (flags & PW_CLIENTONLY) ? 1 : 0;
    o.w = r.right - r.left;
    o.h = r.bottom - r.top;
    o.bits = (uint64_t)(uintptr_t)buf;
    o.stride = (uint32_t)o.w * 4;
    ok = winop(&o) >= 0;
    if (ok && o.w > 0 && o.h > 0) {
        memset(&bi, 0, sizeof bi);
        bi.bmiHeader.biSize = sizeof bi.bmiHeader;
        bi.bmiHeader.biWidth = r.right - r.left;
        bi.bmiHeader.biHeight = -(r.bottom - r.top);
        bi.bmiHeader.biPlanes = 1;
        bi.bmiHeader.biBitCount = 32;
        bi.bmiHeader.biCompression = BI_RGB;
        ok = SetDIBitsToDevice(hdc, 0, 0, (DWORD)o.w, (DWORD)o.h, 0, 0, 0, (UINT)(r.bottom - r.top), buf, &bi, DIB_RGB_COLORS) > 0;
    }
    HeapFree(GetProcessHeap(), 0, buf);
    return ok;
}

DLLAPI BOOL WINAPI SetWindowDisplayAffinity(HWND hwnd, DWORD aff)
{
    shz_winop_t o;
    U32_NEED_GFX(FALSE);
    if (aff != WDA_NONE && aff != WDA_MONITOR && aff != 0x11 /* WDA_EXCLUDEFROMCAPTURE */) { SetLastError(ERROR_INVALID_PARAMETER); return FALSE; }
    memset(&o, 0, sizeof o);
    o.op = SHZ_WOP_SET_AFFINITY;
    o.hwnd = H2U(hwnd);
    o.alpha = aff;
    return winop(&o) >= 0;
}

DLLAPI BOOL WINAPI GetWindowDisplayAffinity(HWND hwnd, DWORD *aff)
{
    shz_winop_t o;
    if (!aff) { SetLastError(ERROR_INVALID_PARAMETER); return FALSE; }
    U32_NEED_GFX(FALSE);
    memset(&o, 0, sizeof o);
    o.op = SHZ_WOP_GET_AFFINITY;
    o.hwnd = H2U(hwnd);
    if (winop(&o) < 0) return FALSE;
    *aff = o.alpha;
    return TRUE;
}

/* ---------------------------------------------------------------- window DC and more window queries */
DLLAPI HDC WINAPI GetWindowDC(HWND hwnd)
{
    shz_wnd_t w, c;
    HDC dc;
    if (!hwnd) return GetDC(0);
    if (!u32_wq(hwnd, SHZ_WQ_RECT, 0, &w) || !u32_wq(hwnd, SHZ_WQ_CLIENT_ORG, 0, &c)) return 0;
    dc = GetDC(hwnd);                                                   /* the non-client pixels belong to the compositor: */
    if (dc) ShzGdiSetDeviceOrigin(dc, w.rect.left - c.rect.left, w.rect.top - c.rect.top);   /* drawing there is clipped */
    return dc;
}

DLLAPI HWND WINAPI WindowFromDC(HDC hdc) { return ShzGdiDCWindow(hdc); }

DLLAPI BOOL WINAPI GetWindowInfo(HWND hwnd, PWINDOWINFO wi)
{
    shz_wnd_t q;
    int32_t l, t, r, b;
    if (!wi) { SetLastError(ERROR_NOACCESS); return FALSE; }
    U32_NEED_GFX(FALSE);
    if (!GetWindowRect(hwnd, &wi->rcWindow) || !u32_wq(hwnd, SHZ_WQ_CLIENT_ORG, 0, &q)) return FALSE;
    wi->rcClient.left = q.rect.left; wi->rcClient.top = q.rect.top; wi->rcClient.right = q.rect.right; wi->rcClient.bottom = q.rect.bottom;
    wi->dwStyle = (DWORD)GetWindowLongW(hwnd, GWL_STYLE);
    wi->dwExStyle = (DWORD)GetWindowLongW(hwnd, GWL_EXSTYLE);
    wi->dwWindowStatus = GetActiveWindow() == GetAncestor(hwnd, GA_ROOT) && GetAncestor(hwnd, GA_ROOT) == hwnd ? WS_ACTIVECAPTION : 0;
    shz_nc_insets(wi->dwStyle, wi->dwExStyle, &l, &t, &r, &b);
    wi->cxWindowBorders = (UINT)l;
    wi->cyWindowBorders = (UINT)b;
    wi->atomWindowType = (ATOM)GetClassLongW(hwnd, GCW_ATOM);
    wi->wCreatorVersion = 0x0400;
    return TRUE;
}

DLLAPI BOOL WINAPI CloseWindow(HWND hwnd)                              /* minimises (it does not destroy) */
{
    if (!IsWindow(hwnd) || (GetWindowLongW(hwnd, GWL_STYLE) & WS_CHILD)) { SetLastError(ERROR_INVALID_WINDOW_HANDLE); return FALSE; }
    ShowWindow(hwnd, SW_MINIMIZE);
    return TRUE;
}

DLLAPI BOOL WINAPI OpenIcon(HWND hwnd) { if (!IsWindow(hwnd)) return FALSE; ShowWindow(hwnd, SW_RESTORE); return TRUE; }

DLLAPI BOOL WINAPI ShowWindowAsync(HWND hwnd, int cmd)
{
    U32_NEED_GFX(FALSE);
    if (GetWindowThreadProcessId(hwnd, 0) == GetCurrentThreadId()) { ShowWindow(hwnd, cmd); return TRUE; }
    if (!IsWindow(hwnd)) { SetLastError(ERROR_INVALID_WINDOW_HANDLE); return FALSE; }
    return PostMessageW(hwnd, SHZ_WM_ASYNCSHOW, (WPARAM)cmd, 0);       /* the owner's GetMessage/PeekMessage runs ShowWindow */
}

/* no window arrangement (snap) feature exists; FlashWindow has no taskbar to flash and does not animate the caption */
DLLAPI BOOL WINAPI IsWindowArranged(HWND hwnd) { (void)hwnd; return FALSE; }
DLLAPI BOOL WINAPI FlashWindowEx(PFLASHWINFO fi)
{
    if (!fi || fi->cbSize != sizeof *fi || !IsWindow(fi->hwnd)) { SetLastError(ERROR_INVALID_PARAMETER); return FALSE; }
    return GetForegroundWindow() == GetAncestor(fi->hwnd, GA_ROOT);     /* "was the caption drawn active before the call" */
}
DLLAPI BOOL WINAPI FlashWindow(HWND hwnd, BOOL invert)
{
    FLASHWINFO fi;
    fi.cbSize = sizeof fi; fi.hwnd = hwnd; fi.dwFlags = invert ? FLASHW_CAPTION : FLASHW_STOP; fi.uCount = 1; fi.dwTimeout = 0;
    return FlashWindowEx(&fi);
}
DLLAPI HWND WINAPI GetShellWindow(void)
{
    shz_wnd_t q;
    return u32_wq(0, SHZ_WQ_SHELL, 0, &q) ? U2H(q.v0) : 0;
}

DLLAPI BOOL WINAPI SetShellWindow(HWND hwnd)
{
    shz_wnd_t s;
    int32_t st;
    U32_NEED_GFX(FALSE);
    memset(&s, 0, sizeof s);
    s.hwnd = H2U(hwnd);
    s.what = SHZ_WS_SET_SHELL;
    st = NtUserWindowSet(&s);
    if (st < 0) { u32_err(st); return FALSE; }
    return TRUE;
}

DLLAPI DWORD WINAPI GetGuiResources(HANDLE proc, DWORD flags)
{
    if (proc != GetCurrentProcess()) { SetLastError(ERROR_ACCESS_DENIED); return 0; }   /* only this process's objects are known */
    switch (flags) {
    case GR_GDIOBJECTS: return ShzGdiObjectCount(0);
    case GR_GDIOBJECTS_PEAK: { DWORD p = 0; ShzGdiObjectCount(&p); return p; }
    case GR_USEROBJECTS: {
        shz_enum_t e;
        uint64_t list[GFX_ENUM_MAX];
        DWORD n = 0, i;
        if (!u32_display(0)) return 0;
        memset(&e, 0, sizeof e);
        e.parent = H2U(u32_desktop());
        e.flags = SHZ_ENUM_RECURSE;
        e.out = (uint64_t)(uintptr_t)list;
        e.max = GFX_ENUM_MAX;
        if (NtUserEnumWindows(&e) < 0) return 0;
        for (i = 0; i < (DWORD)e.count && i < GFX_ENUM_MAX; ++i) {
            DWORD pid = 0;
            GetWindowThreadProcessId(U2H(list[i]), &pid);
            if (pid == GetCurrentProcessId()) ++n;
        }
        return n + (DWORD)u32_user_object_count();
    }
    default:
        SetLastError(ERROR_INVALID_PARAMETER);                          /* the USER peak is not tracked */
        return 0;
    }
}

/* ---------------------------------------------------------------- SendNotifyMessage / SendMessageCallback */
typedef struct { SENDASYNCPROC cb; HWND hwnd; UINT msg; ULONG_PTR data; } sendcb_t;

static BOOL send_nowait(HWND hwnd, UINT msg, WPARAM wp, LPARAM lp, SENDASYNCPROC cb, ULONG_PTR data)
{
    shz_send_t s;
    sendcb_t *rec = 0;
    int32_t st;
    U32_NEED_GFX(FALSE);
    if (hwnd == HWND_BROADCAST) {
        HWND h;
        for (h = GetTopWindow(0); h; h = GetWindow(h, GW_HWNDNEXT)) send_nowait(h, msg, wp, lp, 0, 0);
        return TRUE;
    }
    memset(&s, 0, sizeof s);
    s.hwnd = H2U(hwnd);
    s.message = msg;
    s.wparam = wp;
    s.lparam = (int64_t)lp;
    s.flags = SHZ_SENDF_NOWAIT;
    if (cb) {
        rec = HeapAlloc(GetProcessHeap(), 0, sizeof *rec);
        if (!rec) { SetLastError(ERROR_NOT_ENOUGH_MEMORY); return FALSE; }
        rec->cb = cb; rec->hwnd = hwnd; rec->msg = msg; rec->data = data;
        s.flags |= SHZ_SENDF_CALLBACK;
        s.cookie = (uint64_t)(uintptr_t)rec;
    }
    st = NtUserSendMessage(&s);
    if (st < 0) { if (rec) HeapFree(GetProcessHeap(), 0, rec); u32_err(st); return FALSE; }
    if (s.result_kind == SHZ_SEND_SAME_THREAD) {                        /* own window: call now, callback right after */
        const LRESULT r = u32_call(s.wndproc, hwnd, msg, wp, lp);
        if (rec) { cb(hwnd, msg, data, r); HeapFree(GetProcessHeap(), 0, rec); }
        return TRUE;
    }
    if (s.result_kind == SHZ_SEND_FAILED) { if (rec) HeapFree(GetProcessHeap(), 0, rec); SetLastError(ERROR_INVALID_WINDOW_HANDLE); return FALSE; }
    return TRUE;
}

DLLAPI BOOL WINAPI SendNotifyMessageW(HWND hwnd, UINT msg, WPARAM wp, LPARAM lp) { return send_nowait(hwnd, msg, wp, lp, 0, 0); }
DLLAPI BOOL WINAPI SendNotifyMessageA(HWND hwnd, UINT msg, WPARAM wp, LPARAM lp) { return send_nowait(hwnd, msg, wp, lp, 0, 0); }
DLLAPI BOOL WINAPI SendMessageCallbackW(HWND hwnd, UINT msg, WPARAM wp, LPARAM lp, SENDASYNCPROC cb, ULONG_PTR data)
{
    return send_nowait(hwnd, msg, wp, lp, cb, data);
}

/* GetMessage/PeekMessage hand the private messages here (user32_core.c): a finished SendMessageCallback, a
 * ShowWindowAsync request, an out-of-context WinEvent. */
void u32_private_message(const shz_msg_t *m)
{
    switch (m->message) {
    case SHZ_WM_SENDCB: {
        sendcb_t *rec = (sendcb_t *)(uintptr_t)m->wparam;
        if (rec) { rec->cb(rec->hwnd, rec->msg, rec->data, (LRESULT)m->lparam); HeapFree(GetProcessHeap(), 0, rec); }
        break;
    }
    case SHZ_WM_ASYNCSHOW:
        if (IsWindow(U2H(m->hwnd))) ShowWindow(U2H(m->hwnd), (int)m->wparam);
        break;
    case SHZ_WM_WINEVENT:
        u32_winevent_deliver((void *)(uintptr_t)m->wparam);
        break;
    default:
        break;
    }
}
