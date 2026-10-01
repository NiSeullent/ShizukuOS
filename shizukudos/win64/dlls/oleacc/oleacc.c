/* SPDX-License-Identifier: GPL-2.0-only
 * oleacc.dll - Microsoft Active Accessibility client/server plumbing, in-process.
 *
 * There is no system-wide accessibility broker and no standard window proxy (the "IAccessible of any HWND" that real
 * oleacc synthesises from window classes), so:
 *   LresultFromObject / ObjectFromLresult   the WM_GETOBJECT reply channel, implemented for real over an in-process table:
 *                       LresultFromObject(riid, wParam, punk) QueryInterfaces punk for riid, keeps that reference and returns
 *                       a positive token; ObjectFromLresult(token, riid, wParam, &ppv) hands it out once (a token is consumed,
 *                       as a marshaled LRESULT is) after QueryInterface for riid. An unknown token or a wrong riid:
 *                       E_INVALIDARG / E_NOINTERFACE (nothing is consumed on a wrong riid). Windows' negative LRESULTs
 *                       are HRESULT failures and pass through as such.
 *   AccessibleObjectFromWindow   sends WM_GETOBJECT (wParam = 0, lParam = the object id) to the window with a timeout and
 *                       converts the reply with ObjectFromLresult, i.e. it finds exactly what the window's own procedure exposes
 *                       (Chromium answers WM_GETOBJECT for its views); a window that does not answer, or a system object id
 *                       that needs the absent standard proxy: the failure code below.
 *   CreateStdAccessibleObject    needs the standard proxy: HRESULT_FROM_WIN32(ERROR_NOT_SUPPORTED) (after argument checks).
 *   AccessibleChildren           the documented enumeration over IAccessible::get_accChildCount / get_accChild (VT_DISPATCH
 *                       for a child object, VT_I4 for a simple element).
 *   WindowFromAccessibleObject   through IOleWindow::GetWindow when the object exposes it, else E_NOINTERFACE (real oleacc
 *                       also walks the parent chain of proxies; there are none).
 */
#define WIN32_LEAN_AND_MEAN
#pragma GCC diagnostic ignored "-Wattributes"
#define COBJMACROS
#include <windows.h>
#include <ole2.h>
#include <oleacc.h>
#include <string.h>

#ifndef DLLAPI
#define DLLAPI __declspec(dllexport)
#endif
#define E_INVALIDARG_ ((HRESULT)0x80070057)
#define E_NOINTERFACE_ ((HRESULT)0x80004002)
#define E_POINTER_ ((HRESULT)0x80004003)
#define E_FAIL_ ((HRESULT)0x80004005)
static const GUID iid_olewindow = { 0x00000114, 0x0000, 0x0000, { 0xc0, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x46 } };

typedef struct entry { struct entry *next; LRESULT token; IUnknown *obj; IID iid; } entry;
static SRWLOCK g_lock = SRWLOCK_INIT;
static entry *g_list;
static LONG g_next = 1;

DLLAPI LRESULT WINAPI LresultFromObject(REFIID riid, WPARAM wparam, LPUNKNOWN punk)
{
    entry *e;
    IUnknown *itf = 0;
    HRESULT hr;
    (void)wparam;
    if (!riid || !punk) return (LRESULT)E_INVALIDARG_;
    hr = IUnknown_QueryInterface(punk, riid, (void **)&itf);
    if (FAILED(hr)) return (LRESULT)hr;
    e = HeapAlloc(GetProcessHeap(), 0, sizeof *e);
    if (!e) { IUnknown_Release(itf); return (LRESULT)0x8007000E; }
    e->obj = itf;
    e->iid = *riid;
    AcquireSRWLockExclusive(&g_lock);
    e->token = (LRESULT)InterlockedIncrement(&g_next);
    e->next = g_list;
    g_list = e;
    ReleaseSRWLockExclusive(&g_lock);
    return e->token;
}

DLLAPI HRESULT WINAPI ObjectFromLresult(LRESULT lres, REFIID riid, WPARAM wparam, void **out)
{
    entry *e, **pp;
    HRESULT hr;
    (void)wparam;
    if (!out) return E_POINTER_;
    *out = 0;
    if (!riid) return E_INVALIDARG_;
    if (lres < 0) return (HRESULT)lres;                      /* a negative LRESULT is a failure HRESULT */
    AcquireSRWLockExclusive(&g_lock);
    for (pp = &g_list; (e = *pp) != 0; pp = &e->next)
        if (e->token == lres) break;
    if (!e) { ReleaseSRWLockExclusive(&g_lock); return E_INVALIDARG_; }
    hr = IUnknown_QueryInterface(e->obj, riid, out);
    if (SUCCEEDED(hr)) *pp = e->next;                        /* consumed */
    ReleaseSRWLockExclusive(&g_lock);
    if (FAILED(hr)) return hr == E_NOINTERFACE_ ? E_NOINTERFACE_ : hr;
    IUnknown_Release(e->obj);
    HeapFree(GetProcessHeap(), 0, e);
    return S_OK;
}

DLLAPI HRESULT WINAPI AccessibleObjectFromWindow(HWND hwnd, DWORD id, REFIID riid, void **out)
{
    DWORD_PTR res = 0;
    if (!out) return E_POINTER_;
    *out = 0;
    if (!riid) return E_INVALIDARG_;
    if (!IsWindow(hwnd)) return E_INVALIDARG_;
    if (!SendMessageTimeoutW(hwnd, WM_GETOBJECT, 0, (LPARAM)(LONG)id, SMTO_ABORTIFHUNG | SMTO_BLOCK, 2000, &res))
        return HRESULT_FROM_WIN32(GetLastError() ? GetLastError() : ERROR_TIMEOUT);
    if (!res) return HRESULT_FROM_WIN32(ERROR_NOT_SUPPORTED);   /* the window exposes nothing and there is no standard proxy */
    return ObjectFromLresult((LRESULT)res, riid, 0, out);
}

DLLAPI HRESULT WINAPI CreateStdAccessibleObject(HWND hwnd, LONG id, REFIID riid, void **out)
{
    (void)id;
    if (!out) return E_POINTER_;
    *out = 0;
    if (!riid || !IsWindow(hwnd)) return E_INVALIDARG_;
    return HRESULT_FROM_WIN32(ERROR_NOT_SUPPORTED);
}

DLLAPI HRESULT WINAPI AccessibleChildren(IAccessible *acc, LONG start, LONG count, VARIANT *out, LONG *obtained)
{
    LONG total = 0, i, n = 0;
    HRESULT hr;
    if (!acc || !out || !obtained) return E_INVALIDARG_;
    *obtained = 0;
    if (start < 0 || count < 0) return E_INVALIDARG_;
    for (i = 0; i < count; ++i) VariantInit(&out[i]);
    hr = IAccessible_get_accChildCount(acc, &total);
    if (FAILED(hr)) return hr;
    for (i = 0; i < count && start + i < total; ++i) {
        VARIANT self;
        IDispatch *child = 0;
        self.vt = VT_I4;
        self.lVal = start + i + 1;                           /* child ids are 1-based; 0 is the object itself */
        hr = IAccessible_get_accChild(acc, self, &child);
        if (hr == S_OK && child) { out[n].vt = VT_DISPATCH; out[n].pdispVal = child; }
        else { out[n].vt = VT_I4; out[n].lVal = self.lVal; }   /* a simple element addressed by its id */
        ++n;
    }
    *obtained = n;
    return n == count ? S_OK : S_FALSE;
}

DLLAPI HRESULT WINAPI WindowFromAccessibleObject(IAccessible *acc, HWND *phwnd)
{
    IOleWindow *ow = 0;
    HRESULT hr;
    if (!phwnd) return E_POINTER_;
    *phwnd = 0;
    if (!acc) return E_INVALIDARG_;
    hr = IAccessible_QueryInterface(acc, &iid_olewindow, (void **)&ow);
    if (FAILED(hr)) return E_NOINTERFACE_;
    hr = IOleWindow_GetWindow(ow, phwnd);
    IOleWindow_Release(ow);
    return hr;
}
