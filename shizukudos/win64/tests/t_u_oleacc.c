/* SPDX-License-Identifier: GPL-2.0-only
 * oleacc.dll: the WM_GETOBJECT reply channel (LresultFromObject/ObjectFromLresult) over an in-process token table,
 * AccessibleObjectFromWindow against a window procedure that really answers WM_GETOBJECT, AccessibleChildren over a
 * hand-written IAccessible, WindowFromAccessibleObject through IOleWindow, and the explicit failures of what needs the
 * absent standard proxy. */
#define WIN32_LEAN_AND_MEAN
#define COBJMACROS
#include <windows.h>
#include <ole2.h>
#include <oleacc.h>
#include "u_check.h"

#define ST_NOTSUP ((HRESULT)0x80070032)
static const GUID IID_UNK_ = { 0x00000000, 0x0000, 0x0000, { 0xc0, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x46 } };
static const GUID IID_IDisp_ = { 0x00020400, 0x0000, 0x0000, { 0xc0, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x46 } };
static const GUID IID_OLEWND = { 0x00000114, 0x0000, 0x0000, { 0xc0, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x46 } };
static const GUID IID_IPicture_ = { 0x7bf80980, 0xbf32, 0x101a, { 0x8b, 0xbb, 0x00, 0xaa, 0x00, 0x30, 0x0c, 0xab } };
static const GUID IID_IAcc = { 0x618736e0, 0x3c3d, 0x11cf, { 0x81, 0x0c, 0x00, 0xaa, 0x00, 0x38, 0x9b, 0x71 } };

/* a counted object that is IUnknown + IAccessible + IOleWindow */
typedef struct { const IAccessibleVtbl *acc; const IOleWindowVtbl *ow; LONG refs; HWND hwnd; LONG children; } acc_t;
#define FROM_ACC(p) ((acc_t *)(p))
#define FROM_OW(p) ((acc_t *)((BYTE *)(p) - offsetof(acc_t, ow)))
static HRESULT STDMETHODCALLTYPE a_qi(IAccessible *self, REFIID iid, void **out)
{
    acc_t *a = FROM_ACC(self);
    if (!memcmp(iid, &IID_UNK_, sizeof(IID)) || !memcmp(iid, &IID_IAcc, sizeof(IID)) || !memcmp(iid, &IID_IDisp_, sizeof(IID))) { *out = &a->acc; }
    else if (!memcmp(iid, &IID_OLEWND, sizeof(IID))) { *out = &a->ow; }
    else { *out = 0; return E_NOINTERFACE; }
    InterlockedIncrement(&a->refs);
    return S_OK;
}
static ULONG STDMETHODCALLTYPE a_addref(IAccessible *self) { return (ULONG)InterlockedIncrement(&FROM_ACC(self)->refs); }
static ULONG STDMETHODCALLTYPE a_release(IAccessible *self) { return (ULONG)InterlockedDecrement(&FROM_ACC(self)->refs); }
static HRESULT STDMETHODCALLTYPE a_cnt(IAccessible *self, UINT *n) { (void)self; (void)n; return E_NOTIMPL; }
static HRESULT STDMETHODCALLTYPE a_ti(IAccessible *s, UINT i, LCID l, ITypeInfo **o) { (void)s; (void)i; (void)l; *o = 0; return E_NOTIMPL; }
static HRESULT STDMETHODCALLTYPE a_ids(IAccessible *s, REFIID r, LPOLESTR *n, UINT c, LCID l, DISPID *d) { (void)s; (void)r; (void)n; (void)c; (void)l; (void)d; return E_NOTIMPL; }
static HRESULT STDMETHODCALLTYPE a_inv(IAccessible *s, DISPID d, REFIID r, LCID l, WORD f, DISPPARAMS *p, VARIANT *v, EXCEPINFO *e, UINT *u) { (void)s; (void)d; (void)r; (void)l; (void)f; (void)p; (void)v; (void)e; (void)u; return E_NOTIMPL; }
static HRESULT STDMETHODCALLTYPE a_parent(IAccessible *s, IDispatch **o) { (void)s; *o = 0; return S_FALSE; }
static HRESULT STDMETHODCALLTYPE a_childcount(IAccessible *s, LONG *n) { *n = FROM_ACC(s)->children; return S_OK; }
static HRESULT STDMETHODCALLTYPE a_child(IAccessible *s, VARIANT v, IDispatch **o)
{
    /* child 2 is an object (this one, for the test), the others are simple elements */
    if (v.lVal == 2) { *o = (IDispatch *)&FROM_ACC(s)->acc; IAccessible_AddRef(s); return S_OK; }
    *o = 0;
    return S_FALSE;
}
#define NI(name, ...) static HRESULT STDMETHODCALLTYPE name(IAccessible *s, __VA_ARGS__) { (void)s; return E_NOTIMPL; }
NI(a_name, VARIANT v, BSTR *o) NI(a_value, VARIANT v, BSTR *o) NI(a_desc, VARIANT v, BSTR *o) NI(a_role, VARIANT v, VARIANT *o)
NI(a_state, VARIANT v, VARIANT *o) NI(a_help, VARIANT v, BSTR *o) NI(a_helptopic, BSTR *f, VARIANT v, LONG *o) NI(a_key, VARIANT v, BSTR *o)
NI(a_selection, VARIANT *o) NI(a_default, VARIANT v, BSTR *o) NI(a_focus, VARIANT *o)
static HRESULT STDMETHODCALLTYPE a_select(IAccessible *s, LONG f, VARIANT v) { (void)s; (void)f; (void)v; return E_NOTIMPL; }
static HRESULT STDMETHODCALLTYPE a_loc(IAccessible *s, LONG *l, LONG *t, LONG *w, LONG *h, VARIANT v) { (void)s; (void)l; (void)t; (void)w; (void)h; (void)v; return E_NOTIMPL; }
static HRESULT STDMETHODCALLTYPE a_nav(IAccessible *s, LONG d, VARIANT v, VARIANT *o) { (void)s; (void)d; (void)v; (void)o; return E_NOTIMPL; }
static HRESULT STDMETHODCALLTYPE a_hit(IAccessible *s, LONG x, LONG y, VARIANT *o) { (void)s; (void)x; (void)y; (void)o; return E_NOTIMPL; }
static HRESULT STDMETHODCALLTYPE a_dodef(IAccessible *s, VARIANT v) { (void)s; (void)v; return E_NOTIMPL; }
static HRESULT STDMETHODCALLTYPE a_putname(IAccessible *s, VARIANT v, BSTR n) { (void)s; (void)v; (void)n; return E_NOTIMPL; }
static const IAccessibleVtbl acc_vtbl = { a_qi, a_addref, a_release, a_cnt, a_ti, a_ids, a_inv, a_parent, a_childcount, a_child, (void *)a_name, (void *)a_value, (void *)a_desc, (void *)a_role, (void *)a_state,
    (void *)a_help, (void *)a_helptopic, (void *)a_key, (void *)a_focus, (void *)a_selection, (void *)a_default, a_select, a_loc, a_nav, a_hit, a_dodef, a_putname, (void *)a_putname };

static HRESULT STDMETHODCALLTYPE o_qi(IOleWindow *s, REFIID i, void **o) { return a_qi((IAccessible *)FROM_OW(s), i, o); }
static ULONG STDMETHODCALLTYPE o_addref(IOleWindow *s) { return (ULONG)InterlockedIncrement(&FROM_OW(s)->refs); }
static ULONG STDMETHODCALLTYPE o_release(IOleWindow *s) { return (ULONG)InterlockedDecrement(&FROM_OW(s)->refs); }
static HRESULT STDMETHODCALLTYPE o_getwindow(IOleWindow *s, HWND *h) { *h = FROM_OW(s)->hwnd; return S_OK; }
static HRESULT STDMETHODCALLTYPE o_ctx(IOleWindow *s, BOOL b) { (void)s; (void)b; return E_NOTIMPL; }
static const IOleWindowVtbl ow_vtbl = { o_qi, o_addref, o_release, o_getwindow, o_ctx };

static acc_t g_obj = { &acc_vtbl, &ow_vtbl, 1, 0, 3 };

static LRESULT CALLBACK proc(HWND h, UINT m, WPARAM w, LPARAM l)
{
    if (m == WM_GETOBJECT && (LONG)l == OBJID_CLIENT) return LresultFromObject(&IID_IAcc, w, (IUnknown *)&g_obj.acc);
    return DefWindowProcW(h, m, w, l);
}

int main(void)
{
    void *p = 0;
    LRESULT tok;
    HRESULT hr;
    WNDCLASSW wc;
    HWND w;
    memset(&wc, 0, sizeof wc);
    wc.lpfnWndProc = proc;
    wc.hInstance = GetModuleHandleW(0);
    wc.lpszClassName = L"ShzAccTest";
    CoInitializeEx(0, COINIT_APARTMENTTHREADED);

    tok = LresultFromObject(&IID_IAcc, 0, (IUnknown *)&g_obj.acc);
    U_CHECKF("LresultFromObject gives a positive token and keeps one reference", tok > 0 && g_obj.refs == 2, "tok=%d refs=%d", (int)tok, (int)g_obj.refs);
    U_CHECK("ObjectFromLresult with a wrong IID fails with E_NOINTERFACE and keeps the token", ObjectFromLresult(tok, &IID_IPicture_, 0, &p) == E_NOINTERFACE && p == 0);
    hr = ObjectFromLresult(tok, &IID_IAcc, 0, &p);
    U_CHECKF("ObjectFromLresult returns the object, consuming the token (the token's reference moves to the caller)", hr == S_OK && p == &g_obj.acc && g_obj.refs == 2, "hr=%x refs=%d", (unsigned)hr, (int)g_obj.refs);
    if (p) IAccessible_Release((IAccessible *)p);
    U_CHECK("a consumed token is E_INVALIDARG", ObjectFromLresult(tok, &IID_IAcc, 0, &p) == E_INVALIDARG);
    U_CHECK("a negative LRESULT is the failure HRESULT it carries", ObjectFromLresult((LRESULT)(LONG)0x80004005, &IID_IAcc, 0, &p) == (HRESULT)0x80004005);
    U_CHECK("LresultFromObject(NULL object) fails with E_INVALIDARG", (HRESULT)LresultFromObject(&IID_IAcc, 0, 0) == E_INVALIDARG);

    RegisterClassW(&wc);
    w = CreateWindowExW(0, L"ShzAccTest", L"acc", 0, 0, 0, 10, 10, 0, 0, wc.hInstance, 0);
    if (w) {
        g_obj.hwnd = w;
        hr = AccessibleObjectFromWindow(w, OBJID_CLIENT, &IID_IAcc, &p);
        U_CHECKF("AccessibleObjectFromWindow(OBJID_CLIENT) gets what the window procedure answers to WM_GETOBJECT", hr == S_OK && p == &g_obj.acc, "hr=%x", (unsigned)hr);
        if (p) IAccessible_Release((IAccessible *)p);
        p = 0;
        U_CHECK("...an object id the window does not answer is HRESULT_FROM_WIN32(ERROR_NOT_SUPPORTED)", AccessibleObjectFromWindow(w, OBJID_WINDOW, &IID_IAcc, &p) == ST_NOTSUP && p == 0);
        U_CHECK("CreateStdAccessibleObject (no standard proxy) is HRESULT_FROM_WIN32(ERROR_NOT_SUPPORTED)", CreateStdAccessibleObject(w, OBJID_CLIENT, &IID_IAcc, &p) == ST_NOTSUP);
        {
            HWND got = 0;
            U_CHECK("WindowFromAccessibleObject uses IOleWindow::GetWindow", WindowFromAccessibleObject((IAccessible *)&g_obj.acc, &got) == S_OK && got == w);
        }
        DestroyWindow(w);
    } else {
        printf("INFO: no window (no display device): the window checks need run_k64_gui.py\n");
    }
    U_CHECK("AccessibleObjectFromWindow(bad window) is E_INVALIDARG", AccessibleObjectFromWindow((HWND)0x1234, OBJID_CLIENT, &IID_IAcc, &p) == E_INVALIDARG);
    {
        VARIANT v[4];
        LONG got = 0;
        hr = AccessibleChildren((IAccessible *)&g_obj.acc, 0, 3, v, &got);
        U_CHECK("AccessibleChildren(0..3): S_OK, three children: id 1 simple (VT_I4), 2 an object (VT_DISPATCH), 3 simple", hr == S_OK && got == 3 && v[0].vt == VT_I4 && v[0].lVal == 1 && v[1].vt == VT_DISPATCH && v[1].pdispVal && v[2].vt == VT_I4 && v[2].lVal == 3);
        if (v[1].vt == VT_DISPATCH && v[1].pdispVal) IDispatch_Release(v[1].pdispVal);
        hr = AccessibleChildren((IAccessible *)&g_obj.acc, 2, 4, v, &got);
        U_CHECK("asking for more than exist returns S_FALSE with the count that does", hr == S_FALSE && got == 1);
        U_CHECK("AccessibleChildren with a NULL object is E_INVALIDARG", AccessibleChildren(0, 0, 1, v, &got) == E_INVALIDARG);
    }
    U_CHECK("every reference the test took was released", g_obj.refs == 1);
    CoUninitialize();
    return u_finish("t_u_oleacc");
}
