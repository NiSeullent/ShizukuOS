/* SPDX-License-Identifier: GPL-2.0-only
 * comctl32.dll - common control class registration, without the controls.
 *
 * InitCommonControlsEx registers, for each requested ICC_* family, the window classes Windows registers (SysListView32,
 * tooltips_class32, msctls_progress32, ...). The classes are real: CreateWindowEx creates windows of them and the windows
 * behave as plain windows (DefWindowProc: painting, sizing, destruction). The controls themselves are NOT implemented
 * (the Wine port of comctl32 is not built: wineport/modules.json), so every control-specific message (WM_USER and above)
 * is refused with the value that message documents for failure - LVM_INSERTITEM/TCM_INSERTITEM -1, TVM_INSERTITEM NULL,
 * TTM_ADDTOOL/TB_ADDBUTTONS/SB_SETTEXT FALSE, and 0 for the rest - and reported once per class on the debug console
 * ("K32 unsupported: comctl32 <class> ...") when SHZ_K32TRACE=1. Chromium requires the registration to succeed
 * (content::BrowserMainLoop) even when it never creates such a control.
 * InitCommonControls registers the ICC_WIN95_CLASSES families, as on Windows.
 */
#include "nt.h"
#include <string.h>
#include <winuser.h>

typedef struct { DWORD dwSize, dwICC; } shz_initcommoncontrolsex;

#define ICC_LISTVIEW_CLASSES 0x1
#define ICC_TREEVIEW_CLASSES 0x2
#define ICC_BAR_CLASSES 0x4
#define ICC_TAB_CLASSES 0x8
#define ICC_UPDOWN_CLASS 0x10
#define ICC_PROGRESS_CLASS 0x20
#define ICC_HOTKEY_CLASS 0x40
#define ICC_ANIMATE_CLASS 0x80
#define ICC_WIN95_CLASSES 0xff
#define ICC_DATE_CLASSES 0x100
#define ICC_USEREX_CLASSES 0x200
#define ICC_COOL_CLASSES 0x400
#define ICC_INTERNET_CLASSES 0x800
#define ICC_PAGESCROLLER_CLASS 0x1000
#define ICC_NATIVEFNTCTL_CLASS 0x2000
#define ICC_STANDARD_CLASSES 0x4000
#define ICC_LINK_CLASS 0x8000

static const struct { DWORD icc; const WCHAR *name; } g_classes[] = {
    { ICC_LISTVIEW_CLASSES, L"SysListView32" }, { ICC_LISTVIEW_CLASSES, L"SysHeader32" },
    { ICC_TREEVIEW_CLASSES, L"SysTreeView32" }, { ICC_TREEVIEW_CLASSES, L"tooltips_class32" },
    { ICC_BAR_CLASSES, L"ToolbarWindow32" }, { ICC_BAR_CLASSES, L"msctls_statusbar32" },
    { ICC_BAR_CLASSES, L"msctls_trackbar32" }, { ICC_BAR_CLASSES, L"tooltips_class32" },
    { ICC_TAB_CLASSES, L"SysTabControl32" }, { ICC_TAB_CLASSES, L"tooltips_class32" },
    { ICC_UPDOWN_CLASS, L"msctls_updown32" }, { ICC_PROGRESS_CLASS, L"msctls_progress32" },
    { ICC_HOTKEY_CLASS, L"msctls_hotkey32" }, { ICC_ANIMATE_CLASS, L"SysAnimate32" },
    { ICC_DATE_CLASSES, L"SysMonthCal32" }, { ICC_DATE_CLASSES, L"SysDateTimePick32" },
    { ICC_USEREX_CLASSES, L"ComboBoxEx32" }, { ICC_COOL_CLASSES, L"ReBarWindow32" },
    { ICC_INTERNET_CLASSES, L"SysIPAddress32" }, { ICC_PAGESCROLLER_CLASS, L"SysPager" },
    { ICC_NATIVEFNTCTL_CLASS, L"NativeFontCtl" }, { ICC_LINK_CLASS, L"SysLink" },
};
#define NCLASSES (sizeof g_classes / sizeof g_classes[0])

static volatile LONG g_reported[NCLASSES];

static void trace(const WCHAR *cls, UINT msg)
{
    static const char hex[] = "0123456789abcdef";
    WCHAR v[4];
    char line[160];
    unsigned n = 0, k;
    const char *head = "K32 unsupported: comctl32 ", *mid = " control message 0x";
    if (GetEnvironmentVariableW(L"SHZ_K32TRACE", v, 4) != 1 || v[0] != '1') return;
    while (*head) line[n++] = *head++;
    for (k = 0; cls[k] && n < 100; ++k) line[n++] = (char)cls[k];
    while (*mid) line[n++] = *mid++;
    for (k = 0; k < 4; ++k) line[n++] = hex[(msg >> (12 - 4 * k)) & 15];
    line[n++] = '\n';
    NtShzDebugPrint(line, n);
}

/* The documented failure value of a control message (0 for the rest: FALSE / NULL / "nothing"). */
static LRESULT refusal(UINT msg)
{
    switch (msg) {
    case 0x1007: case 0x104d:                       /* LVM_INSERTITEMA / LVM_INSERTITEMW */
    case 0x1307: case 0x133e:                       /* TCM_INSERTITEMA / TCM_INSERTITEMW */
    case 0x101b: case 0x1061:                       /* LVM_INSERTCOLUMNA / LVM_INSERTCOLUMNW */
        return -1;
    default:
        return 0;
    }
}

static LRESULT CALLBACK control_proc(HWND h, UINT msg, WPARAM w, LPARAM l)
{
    if (msg >= WM_USER && msg < 0x8000) {
        WCHAR cls[64];
        unsigned i;
        if (GetClassNameW(h, cls, 64)) {
            for (i = 0; i < NCLASSES; ++i) {
                const WCHAR *a = g_classes[i].name, *b = cls;
                while (*a && *a == *b) { ++a; ++b; }
                if (!*a && !*b) {
                    if (!InterlockedExchange(&g_reported[i], 1)) trace(cls, msg);
                    break;
                }
            }
        }
        return refusal(msg);
    }
    return DefWindowProcW(h, msg, w, l);
}

static HINSTANCE g_self;

DLLAPI BOOL WINAPI DllMain(HINSTANCE inst, DWORD reason, LPVOID reserved)
{
    (void)reserved;
    if (reason == DLL_PROCESS_ATTACH) g_self = inst;
    return TRUE;
}

DLLAPI BOOL WINAPI InitCommonControlsEx(const shz_initcommoncontrolsex *icc)
{
    unsigned i;
    if (!icc || icc->dwSize != sizeof *icc) { SetLastError(ERROR_INVALID_PARAMETER); return FALSE; }
    for (i = 0; i < NCLASSES; ++i) {
        WNDCLASSEXW wc;
        if (!(icc->dwICC & g_classes[i].icc)) continue;
        if (GetClassInfoExW(g_self, g_classes[i].name, &wc)) continue;      /* registered by an earlier call */
        memset(&wc, 0, sizeof wc);
        wc.cbSize = sizeof wc;
        wc.style = CS_GLOBALCLASS | CS_DBLCLKS;
        wc.lpfnWndProc = control_proc;
        wc.hInstance = g_self;
        wc.hCursor = LoadCursorW(0, (LPCWSTR)IDC_ARROW);
        wc.hbrBackground = (HBRUSH)(COLOR_BTNFACE + 1);
        wc.lpszClassName = g_classes[i].name;
        if (!RegisterClassExW(&wc)) return FALSE;                           /* RegisterClassExW's own error */
    }
    return TRUE;
}

DLLAPI void WINAPI InitCommonControls(void)
{
    const shz_initcommoncontrolsex icc = { sizeof icc, ICC_WIN95_CLASSES };
    InitCommonControlsEx(&icc);
}
