/* SPDX-License-Identifier: GPL-2.0-only
 * user32: raw input over the kernel's PS/2 keyboard and mouse (kernel64/gfx_input.c keeps the registrations and the
 * records; see "raw input" there). The two devices are the only ones: GetRawInputDeviceList lists them when present
 * (their handles are SHZ_RAW_HANDLE_KEYBOARD / _MOUSE; input injected with SendInput carries device handle 0, as on
 * Windows). Registrations for other HID usages are accepted and remembered, but no such device exists to produce input.
 * DDE (the DDEML) is at the end of this file.
 */
#include "user32_int.h"
#include <dde.h>
#include <ddeml.h>

#define RAW_OTHER 16
static RAWINPUTDEVICE g_other[RAW_OTHER];                                /* usages without a device */
static int g_nother;

static int32_t in_op(shz_input_t *in) { const int32_t st = NtUserInput(in); if (st < 0) u32_err(st); return st; }

DLLAPI BOOL WINAPI RegisterRawInputDevices(PCRAWINPUTDEVICE devs, UINT n, UINT cb)
{
    UINT i;
    if (!devs || !n || cb != sizeof *devs) { SetLastError(ERROR_INVALID_PARAMETER); return FALSE; }
    U32_NEED_GFX(FALSE);
    for (i = 0; i < n; ++i) {
        const RAWINPUTDEVICE *d = &devs[i];
        uint32_t dev = 0;
        if (d->usUsagePage == 1 && d->usUsage == 6) dev = SHZ_RAW_KEYBOARD;
        else if (d->usUsagePage == 1 && d->usUsage == 2) dev = SHZ_RAW_MOUSE;
        if (dev) {
            shz_input_t in;
            memset(&in, 0, sizeof in);
            in.op = SHZ_IN_RAWREGISTER;
            in.a = dev;
            in.b = d->dwFlags;
            in.c = (int64_t)(uintptr_t)((d->dwFlags & RIDEV_REMOVE) ? 0 : d->hwndTarget);
            if (in_op(&in) < 0) return FALSE;
        } else {
            int k, found = -1;
            for (k = 0; k < g_nother; ++k) if (g_other[k].usUsagePage == d->usUsagePage && g_other[k].usUsage == d->usUsage) found = k;
            if (d->dwFlags & RIDEV_REMOVE) {
                if (found < 0) { SetLastError(ERROR_INVALID_PARAMETER); return FALSE; }
                g_other[found] = g_other[--g_nother];
            } else if (found >= 0) g_other[found] = *d;
            else if (g_nother < RAW_OTHER) g_other[g_nother++] = *d;
            else { SetLastError(ERROR_NOT_ENOUGH_MEMORY); return FALSE; }
        }
    }
    return TRUE;
}

DLLAPI UINT WINAPI GetRegisteredRawInputDevices(PRAWINPUTDEVICE devs, PUINT n, UINT cb)
{
    shz_input_t in;
    uint64_t targets[2] = { 0, 0 };
    RAWINPUTDEVICE all[RAW_OTHER + 2];
    UINT k = 0, i;
    if (!n || cb != sizeof(RAWINPUTDEVICE)) { SetLastError(ERROR_INVALID_PARAMETER); return (UINT)-1; }
    if (u32_display(0)) {
        memset(&in, 0, sizeof in);
        in.op = SHZ_IN_RAWLIST;
        in.buf = (uint64_t)(uintptr_t)targets;
        in.buf_len = sizeof targets;
        if (in_op(&in) >= 0) {
            if (in.out0 & SHZ_RAW_KEYBOARD) { all[k].usUsagePage = 1; all[k].usUsage = 6; all[k].dwFlags = (DWORD)in.out1; all[k].hwndTarget = U2H(targets[0]); ++k; }
            if (in.out0 & SHZ_RAW_MOUSE) { all[k].usUsagePage = 1; all[k].usUsage = 2; all[k].dwFlags = (DWORD)(in.out1 >> 32); all[k].hwndTarget = U2H(targets[1]); ++k; }
        }
    }
    for (i = 0; i < (UINT)g_nother; ++i) all[k++] = g_other[i];
    if (!devs) { *n = k; return 0; }
    if (*n < k) { *n = k; SetLastError(ERROR_INSUFFICIENT_BUFFER); return (UINT)-1; }
    memcpy(devs, all, k * sizeof *devs);
    return k;
}

static int fetch(HRAWINPUT h, shz_rawrec_t *r)
{
    shz_input_t in;
    memset(&in, 0, sizeof in);
    in.op = SHZ_IN_RAWGET;
    in.a = (int64_t)(uintptr_t)h;
    in.buf = (uint64_t)(uintptr_t)r;
    in.buf_len = sizeof *r;
    return NtUserInput(&in) >= 0;
}

static void to_rawinput(const shz_rawrec_t *r, RAWINPUT *o)
{
    memset(o, 0, sizeof *o);
    o->header.dwType = r->type == 1 ? RIM_TYPEKEYBOARD : RIM_TYPEMOUSE;
    o->header.dwSize = r->type == 1 ? (DWORD)(sizeof(RAWINPUTHEADER) + sizeof(RAWKEYBOARD)) : (DWORD)(sizeof(RAWINPUTHEADER) + sizeof(RAWMOUSE));
    o->header.hDevice = (HANDLE)(uintptr_t)r->device;
    o->header.wParam = r->wparam;
    if (r->type == 1) {
        o->data.keyboard.MakeCode = r->kb_make;
        o->data.keyboard.Flags = r->kb_flags;
        o->data.keyboard.VKey = r->kb_vkey;
        o->data.keyboard.Message = r->kb_message;
        o->data.keyboard.ExtraInformation = (ULONG)r->extra;
    } else {
        o->data.mouse.usFlags = r->ms_flags;
        o->data.mouse.usButtonFlags = r->ms_button_flags;
        o->data.mouse.usButtonData = (USHORT)r->ms_button_data;
        o->data.mouse.ulRawButtons = r->ms_buttons;
        o->data.mouse.lLastX = r->ms_x;
        o->data.mouse.lLastY = r->ms_y;
        o->data.mouse.ulExtraInformation = (ULONG)r->extra;
    }
}

DLLAPI UINT WINAPI GetRawInputData(HRAWINPUT h, UINT cmd, LPVOID data, PUINT size, UINT cbh)
{
    shz_rawrec_t r;
    RAWINPUT ri;
    UINT need;
    if (!size || cbh != sizeof(RAWINPUTHEADER) || (cmd != RID_INPUT && cmd != RID_HEADER)) { SetLastError(ERROR_INVALID_PARAMETER); return (UINT)-1; }
    if (!u32_display(0) || !fetch(h, &r)) { SetLastError(ERROR_INVALID_HANDLE); return (UINT)-1; }
    to_rawinput(&r, &ri);
    need = cmd == RID_HEADER ? sizeof(RAWINPUTHEADER) : ri.header.dwSize;
    if (!data) { *size = need; return 0; }
    if (*size < need) { *size = need; SetLastError(ERROR_INSUFFICIENT_BUFFER); return (UINT)-1; }
    memcpy(data, &ri, need);
    return need;
}

/* the WM_INPUT messages waiting in the queue, as packed RAWINPUT records (removed from the queue) */
DLLAPI UINT WINAPI GetRawInputBuffer(PRAWINPUT data, PUINT size, UINT cbh)
{
    MSG m;
    UINT used = 0, count = 0;
    if (!size || cbh != sizeof(RAWINPUTHEADER)) { SetLastError(ERROR_INVALID_PARAMETER); return (UINT)-1; }
    if (!data) {                                                        /* the size of the next record */
        shz_rawrec_t r;
        RAWINPUT ri;
        *size = 0;
        if (PeekMessageW(&m, 0, WM_INPUT, WM_INPUT, PM_NOREMOVE) && fetch((HRAWINPUT)m.lParam, &r)) { to_rawinput(&r, &ri); *size = ri.header.dwSize; }
        return 0;
    }
    while (PeekMessageW(&m, 0, WM_INPUT, WM_INPUT, PM_NOREMOVE)) {
        shz_rawrec_t r;
        RAWINPUT ri;
        UINT rs;
        if (!fetch((HRAWINPUT)m.lParam, &r)) { PeekMessageW(&m, 0, WM_INPUT, WM_INPUT, PM_REMOVE); continue; }
        to_rawinput(&r, &ri);
        rs = (ri.header.dwSize + 7) & ~7u;                              /* NEXTRAWINPUTBLOCK alignment */
        if (used + rs > *size) break;
        memcpy((uint8_t *)data + used, &ri, ri.header.dwSize);
        used += rs;
        ++count;
        PeekMessageW(&m, 0, WM_INPUT, WM_INPUT, PM_REMOVE);
    }
    return count;
}

DLLAPI LRESULT WINAPI DefRawInputProc(PRAWINPUT *raw, INT n, UINT cbh)
{
    (void)raw; (void)n;
    return cbh == sizeof(RAWINPUTHEADER) ? 0 : (LRESULT)-1;
}

DLLAPI UINT WINAPI GetRawInputDeviceList(PRAWINPUTDEVICELIST list, PUINT n, UINT cb)
{
    const uint32_t info = u32_input_info();
    UINT k = 0;
    RAWINPUTDEVICELIST all[2];
    if (!n || cb != sizeof(RAWINPUTDEVICELIST)) { SetLastError(ERROR_INVALID_PARAMETER); return (UINT)-1; }
    if (info & SHZ_INFO_KEYBOARD) { all[k].hDevice = (HANDLE)(uintptr_t)SHZ_RAW_HANDLE_KEYBOARD; all[k].dwType = RIM_TYPEKEYBOARD; ++k; }
    if (info & SHZ_INFO_MOUSE) { all[k].hDevice = (HANDLE)(uintptr_t)SHZ_RAW_HANDLE_MOUSE; all[k].dwType = RIM_TYPEMOUSE; ++k; }
    if (!list) { *n = k; return 0; }
    if (*n < k) { *n = k; SetLastError(ERROR_INSUFFICIENT_BUFFER); return (UINT)-1; }
    memcpy(list, all, k * sizeof *list);
    return k;
}

static const WCHAR k_kbd_name[] = L"\\\\?\\ACPI#PNP0303#0#{884b96c3-56ef-11d1-bc8c-00a0c91405dd}";
static const WCHAR k_mouse_name[] = L"\\\\?\\ACPI#PNP0F13#0#{378de44c-56ef-11d1-bc8c-00a0c91405dd}";

DLLAPI UINT WINAPI GetRawInputDeviceInfoW(HANDLE dev, UINT cmd, LPVOID data, PUINT size)
{
    const uint32_t info = u32_input_info();
    const int kbd = (uintptr_t)dev == SHZ_RAW_HANDLE_KEYBOARD && (info & SHZ_INFO_KEYBOARD);
    const int mouse = (uintptr_t)dev == SHZ_RAW_HANDLE_MOUSE && (info & SHZ_INFO_MOUSE);
    if (!size) { SetLastError(ERROR_NOACCESS); return (UINT)-1; }
    if (!kbd && !mouse) { SetLastError(ERROR_INVALID_HANDLE); return (UINT)-1; }
    switch (cmd) {
    case RIDI_DEVICENAME: {
        const WCHAR *nm = kbd ? k_kbd_name : k_mouse_name;
        const UINT n = (UINT)wcslen(nm) + 1;
        if (!data || *size < n) { const UINT need = n; *size = need; if (!data) return 0; SetLastError(ERROR_INSUFFICIENT_BUFFER); return (UINT)-1; }
        memcpy(data, nm, n * 2);
        return n - 1;
    }
    case RIDI_DEVICEINFO: {
        RID_DEVICE_INFO di;
        memset(&di, 0, sizeof di);
        di.cbSize = sizeof di;
        if (kbd) {
            di.dwType = RIM_TYPEKEYBOARD;
            di.keyboard.dwType = 4;                                     /* enhanced 101/102-key */
            di.keyboard.dwSubType = 0;
            di.keyboard.dwKeyboardMode = 1;
            di.keyboard.dwNumberOfFunctionKeys = 12;
            di.keyboard.dwNumberOfIndicators = 3;
            di.keyboard.dwNumberOfKeysTotal = 101;
        } else {
            di.dwType = RIM_TYPEMOUSE;
            di.mouse.dwId = (info & SHZ_INFO_WHEEL) ? 3 : 0;           /* the PS/2 device id: 3 = IntelliMouse */
            di.mouse.dwNumberOfButtons = 3;
            di.mouse.dwSampleRate = 100;
            di.mouse.fHasHorizontalWheel = FALSE;
        }
        if (!data) { *size = sizeof di; return 0; }
        if (*size < sizeof di) { *size = sizeof di; SetLastError(ERROR_INSUFFICIENT_BUFFER); return (UINT)-1; }
        memcpy(data, &di, sizeof di);
        return sizeof di;
    }
    case RIDI_PREPARSEDDATA:                                            /* PS/2 devices are not HID: no preparsed data */
        *size = 0;
        return 0;
    default:
        SetLastError(ERROR_INVALID_PARAMETER);
        return (UINT)-1;
    }
}

DLLAPI UINT WINAPI GetRawInputDeviceInfoA(HANDLE dev, UINT cmd, LPVOID data, PUINT size)
{
    if (cmd == RIDI_DEVICENAME) {
        WCHAR w[128];
        UINT n = 128, r, i;
        if (!size) { SetLastError(ERROR_NOACCESS); return (UINT)-1; }
        r = GetRawInputDeviceInfoW(dev, cmd, w, &n);
        if (r == (UINT)-1) return r;
        if (!data || *size < r + 1) { *size = r + 1; if (!data) return 0; SetLastError(ERROR_INSUFFICIENT_BUFFER); return (UINT)-1; }
        for (i = 0; i <= r; ++i) ((char *)data)[i] = (char)w[i];
        return r;
    }
    return GetRawInputDeviceInfoW(dev, cmd, data, size);
}

/* ---------------------------------------------------------------- DDE (DDEML) */
/* Instances and string handles are real (string handles are atoms of the window manager's atom table, case-insensitive
 * like Windows' global atoms). A conversation needs a DDE server window that answers WM_DDE_INITIATE; SendMessage does
 * not cross processes in this system and no server is registered in this process's DDEML, so DdeConnect reports
 * DMLERR_NO_CONV_ESTABLISHED, which is exactly the Windows result when no server answers. */
#define NDDE 16
static struct { int used; PFNCALLBACK cb; UINT last_error; DWORD flags; } g_dde[NDDE];

static int dde_index(DWORD inst) { return inst >= 1 && inst <= NDDE && g_dde[inst - 1].used ? (int)inst - 1 : -1; }

DLLAPI UINT WINAPI DdeInitializeW(LPDWORD inst, PFNCALLBACK cb, DWORD flags, DWORD res)
{
    int i;
    (void)res;
    if (!inst) return DMLERR_INVALIDPARAMETER;
    if (*inst) return dde_index(*inst) >= 0 ? DMLERR_NO_ERROR : DMLERR_INVALIDPARAMETER;   /* reinitialising keeps the instance */
    for (i = 0; i < NDDE; ++i)
        if (!g_dde[i].used) { g_dde[i].used = 1; g_dde[i].cb = cb; g_dde[i].flags = flags; g_dde[i].last_error = 0; *inst = (DWORD)i + 1; return DMLERR_NO_ERROR; }
    return DMLERR_SYS_ERROR;
}
DLLAPI UINT WINAPI DdeInitializeA(LPDWORD inst, PFNCALLBACK cb, DWORD flags, DWORD res) { return DdeInitializeW(inst, cb, flags, res); }

DLLAPI BOOL WINAPI DdeUninitialize(DWORD inst)
{
    const int i = dde_index(inst);
    if (i < 0) return FALSE;
    g_dde[i].used = 0;
    return TRUE;
}

DLLAPI UINT WINAPI DdeGetLastError(DWORD inst)
{
    const int i = dde_index(inst);
    UINT e;
    if (i < 0) return DMLERR_INVALIDPARAMETER;
    e = g_dde[i].last_error;
    g_dde[i].last_error = 0;
    return e;
}

static void dde_fail(DWORD inst, UINT e) { const int i = dde_index(inst); if (i >= 0) g_dde[i].last_error = e; }

DLLAPI HSZ WINAPI DdeCreateStringHandleW(DWORD inst, LPCWSTR s, int cp)
{
    UINT a;
    (void)cp;
    if (dde_index(inst) < 0) return 0;
    if (!s || !*s) return 0;
    a = RegisterWindowMessageW(s);
    if (!a) { dde_fail(inst, DMLERR_SYS_ERROR); return 0; }
    return (HSZ)(uintptr_t)a;
}

DLLAPI HSZ WINAPI DdeCreateStringHandleA(DWORD inst, LPCSTR s, int cp)
{
    WCHAR w[256];
    if (!s || !MultiByteToWideChar(CP_ACP, 0, s, -1, w, 256)) return 0;
    return DdeCreateStringHandleW(inst, w, cp);
}

DLLAPI BOOL WINAPI DdeFreeStringHandle(DWORD inst, HSZ h) { return dde_index(inst) >= 0 && h; }   /* atoms stay (the table has no reference counts) */
DLLAPI BOOL WINAPI DdeKeepStringHandle(DWORD inst, HSZ h) { return dde_index(inst) >= 0 && h; }
DLLAPI int WINAPI DdeCmpStringHandles(HSZ a, HSZ b) { return a == b ? 0 : (uintptr_t)a < (uintptr_t)b ? -1 : 1; }   /* same atom = same string */

DLLAPI DWORD WINAPI DdeQueryStringW(DWORD inst, HSZ h, LPWSTR buf, DWORD cap, int cp)
{
    WCHAR tmp[256];
    int n;
    (void)cp;
    if (dde_index(inst) < 0 || !h) return 0;
    n = GetClipboardFormatNameW((UINT)(uintptr_t)h, buf ? buf : tmp, buf ? (int)cap : 256);   /* atom -> name */
    return n > 0 ? (DWORD)n : 0;
}

DLLAPI HCONV WINAPI DdeConnect(DWORD inst, HSZ service, HSZ topic, PCONVCONTEXT cc)
{
    (void)service; (void)topic; (void)cc;
    if (dde_index(inst) < 0) return 0;
    dde_fail(inst, DMLERR_NO_CONV_ESTABLISHED);
    return 0;
}

DLLAPI BOOL WINAPI DdeDisconnect(HCONV c) { (void)c; return FALSE; }

DLLAPI HDDEDATA WINAPI DdeClientTransaction(LPBYTE data, DWORD len, HCONV c, HSZ item, UINT fmt, UINT type, DWORD timeout, LPDWORD result)
{
    (void)data; (void)len; (void)item; (void)fmt; (void)type; (void)timeout;
    if (result) *result = DDE_FNOTPROCESSED;
    (void)c;                                                            /* no conversation handle can exist */
    return 0;
}

DLLAPI HDDEDATA WINAPI DdeNameService(DWORD inst, HSZ s1, HSZ s2, UINT cmd)
{
    (void)s1; (void)s2; (void)cmd;
    dde_fail(inst, DMLERR_DLL_USAGE);                                   /* serving would need cross-process messages */
    return 0;
}
