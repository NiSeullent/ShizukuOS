/* SPDX-License-Identifier: GPL-2.0-only
 * user32: window classes (Unicode only). Classes are per process; the system classes (BUTTON, EDIT, STATIC, ...) do not
 * exist, so CreateWindowEx with one of those names fails with ERROR_CANNOT_FIND_WND_CLASS. */
#include "user32_int.h"

static ATOM do_register(UINT style, WNDPROC proc, int cb_cls, int cb_wnd, HINSTANCE inst, HICON icon, HCURSOR cur, HBRUSH br,
                        LPCWSTR menu, LPCWSTR name, HICON small)
{
    shz_classop_t o;
    int32_t st;
    if (!name || (ULONG_PTR)name < 0x10000 || !proc) { SetLastError(ERROR_INVALID_PARAMETER); return 0; }
    U32_NEED_GFX(0);
    memset(&o, 0, sizeof o);
    o.op = SHZ_CLASS_REGISTER;
    o.name = (uint64_t)(uintptr_t)name;
    o.name_len = (uint32_t)wcslen(name);
    o.style = style;
    o.cb_cls = cb_cls;
    o.cb_wnd = cb_wnd;
    o.wndproc = (uint64_t)(uintptr_t)proc;
    o.hinstance = (uint64_t)(uintptr_t)inst;
    o.hicon = (uint64_t)(uintptr_t)icon;
    o.hcursor = (uint64_t)(uintptr_t)cur;
    o.hbrbackground = (uint64_t)(uintptr_t)br;
    o.menu_name = (uint64_t)(uintptr_t)menu;
    o.hicon_sm = (uint64_t)(uintptr_t)small;
    st = NtUserClassOp(&o);
    if (st < 0) { u32_err(st); return 0; }
    return (ATOM)o.atom;
}

DLLAPI ATOM WINAPI RegisterClassExW(const WNDCLASSEXW *wc)
{
    if (!wc || wc->cbSize != sizeof *wc) { SetLastError(ERROR_INVALID_PARAMETER); return 0; }
    return do_register(wc->style, wc->lpfnWndProc, wc->cbClsExtra, wc->cbWndExtra, wc->hInstance, wc->hIcon, wc->hCursor,
                       wc->hbrBackground, wc->lpszMenuName, wc->lpszClassName, wc->hIconSm);
}

DLLAPI ATOM WINAPI RegisterClassW(const WNDCLASSW *wc)
{
    if (!wc) { SetLastError(ERROR_INVALID_PARAMETER); return 0; }
    return do_register(wc->style, wc->lpfnWndProc, wc->cbClsExtra, wc->cbWndExtra, wc->hInstance, wc->hIcon, wc->hCursor,
                       wc->hbrBackground, wc->lpszMenuName, wc->lpszClassName, 0);
}

static void set_name(shz_classop_t *o, LPCWSTR name)
{
    if ((ULONG_PTR)name < 0x10000) { o->atom = (uint32_t)(ULONG_PTR)name; o->name = 0; }
    else { o->name = (uint64_t)(uintptr_t)name; o->name_len = (uint32_t)wcslen(name); }
}

DLLAPI BOOL WINAPI UnregisterClassW(LPCWSTR name, HINSTANCE inst)
{
    shz_classop_t o;
    int32_t st;
    if (!name) { SetLastError(ERROR_INVALID_PARAMETER); return FALSE; }
    U32_NEED_GFX(FALSE);
    memset(&o, 0, sizeof o);
    o.op = SHZ_CLASS_UNREGISTER;
    set_name(&o, name);
    o.hinstance = (uint64_t)(uintptr_t)inst;
    st = NtUserClassOp(&o);
    if (st < 0) {
        if ((uint32_t)st == 0xC0000001) SetLastError(ERROR_CLASS_HAS_WINDOWS);
        else if ((uint32_t)st == 0xC0000034) SetLastError(ERROR_CLASS_DOES_NOT_EXIST);
        else u32_err(st);
        return FALSE;
    }
    return TRUE;
}

static ATOM lookup(HINSTANCE inst, LPCWSTR name, shz_classop_t *o)
{
    int32_t st;
    if (!name) { SetLastError(ERROR_INVALID_PARAMETER); return 0; }
    U32_NEED_GFX(0);
    memset(o, 0, sizeof *o);
    o->op = SHZ_CLASS_LOOKUP;
    set_name(o, name);
    o->hinstance = (uint64_t)(uintptr_t)inst;
    st = NtUserClassOp(o);
    if (st < 0) { if ((uint32_t)st == 0xC0000034) SetLastError(ERROR_CLASS_DOES_NOT_EXIST); else u32_err(st); return 0; }
    return (ATOM)o->atom;
}

DLLAPI BOOL WINAPI GetClassInfoExW(HINSTANCE inst, LPCWSTR name, LPWNDCLASSEXW wc)
{
    shz_classop_t o;
    ATOM a = lookup(inst, name, &o);
    if (!a || !wc) return FALSE;
    wc->cbSize = sizeof *wc;
    wc->style = o.style;
    wc->lpfnWndProc = (WNDPROC)(uintptr_t)o.wndproc;
    wc->cbClsExtra = o.cb_cls;
    wc->cbWndExtra = o.cb_wnd;
    wc->hInstance = (HINSTANCE)(uintptr_t)o.hinstance;
    wc->hIcon = (HICON)(uintptr_t)o.hicon;
    wc->hCursor = (HCURSOR)(uintptr_t)o.hcursor;
    wc->hbrBackground = (HBRUSH)(uintptr_t)o.hbrbackground;
    wc->lpszMenuName = (LPCWSTR)(uintptr_t)o.menu_name;
    wc->lpszClassName = name;
    wc->hIconSm = (HICON)(uintptr_t)o.hicon_sm;
    return TRUE;
}

DLLAPI BOOL WINAPI GetClassInfoW(HINSTANCE inst, LPCWSTR name, LPWNDCLASSW wc)
{
    WNDCLASSEXW ex;
    if (!wc || !GetClassInfoExW(inst, name, &ex)) return FALSE;
    wc->style = ex.style; wc->lpfnWndProc = ex.lpfnWndProc; wc->cbClsExtra = ex.cbClsExtra; wc->cbWndExtra = ex.cbWndExtra;
    wc->hInstance = ex.hInstance; wc->hIcon = ex.hIcon; wc->hCursor = ex.hCursor; wc->hbrBackground = ex.hbrBackground;
    wc->lpszMenuName = ex.lpszMenuName; wc->lpszClassName = ex.lpszClassName;
    return TRUE;
}

DLLAPI int WINAPI GetClassNameW(HWND hwnd, LPWSTR buf, int max)
{
    shz_classop_t o;
    int32_t st;
    if (!buf || max <= 0) { SetLastError(ERROR_INVALID_PARAMETER); return 0; }
    U32_NEED_GFX(0);
    memset(&o, 0, sizeof o);
    o.op = SHZ_CLASS_GETNAME;
    o.hwnd = H2U(hwnd);
    o.buf = (uint64_t)(uintptr_t)buf;
    o.buf_len = (uint32_t)max;
    st = NtUserClassOp(&o);
    if (st < 0) { u32_err(st); return 0; }
    return (int)o.buf_len;
}

static int64_t class_long(HWND hwnd, int index, int set, uint64_t value, int *ok)
{
    shz_classop_t o;
    int32_t st;
    memset(&o, 0, sizeof o);
    o.op = set ? SHZ_CLASS_SETLONG : SHZ_CLASS_GETLONG;
    o.hwnd = H2U(hwnd);
    o.index = index;
    o.value = value;
    st = NtUserClassOp(&o);
    *ok = st >= 0;
    if (st < 0) { u32_err(st); return 0; }
    return (int64_t)o.value;
}

DLLAPI ULONG_PTR WINAPI GetClassLongPtrW(HWND hwnd, int index)
{
    int ok;
    U32_NEED_GFX(0);
    return (ULONG_PTR)class_long(hwnd, index, 0, 0, &ok);
}

DLLAPI ULONG_PTR WINAPI SetClassLongPtrW(HWND hwnd, int index, LONG_PTR v)
{
    int ok;
    U32_NEED_GFX(0);
    return (ULONG_PTR)class_long(hwnd, index, 1, (uint64_t)v, &ok);
}

DLLAPI DWORD WINAPI GetClassLongW(HWND hwnd, int index) { return (DWORD)GetClassLongPtrW(hwnd, index); }
DLLAPI DWORD WINAPI SetClassLongW(HWND hwnd, int index, LONG v) { return (DWORD)SetClassLongPtrW(hwnd, index, (LONG_PTR)v); }
