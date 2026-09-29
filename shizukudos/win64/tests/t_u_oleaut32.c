/* SPDX-License-Identifier: GPL-2.0-only
 * oleaut32.dll core: BSTR, VARIANT, SAFEARRAY. Expected values come from the documented automation contracts (MSDN:
 * BSTR layout, SysAlloc*, SafeArray*, VariantClear/Copy/ChangeType, VarI4FromR8 banker's rounding, VARIANT_ALPHABOOL,
 * VARIANT_TRUE = -1, DISP_E_* codes) and from reference-counting behaviour observed with a test COM object.
 * The multi-dimensional element order asserted below is the convention described in dlls/oleaut32/safearray.c (dimension 1 =
 * leftmost = rgsabound[cDims-1], idx[0] indexes dimension 1, column-major storage); it has not been compared with a real
 * Windows. */
#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <oleauto.h>
#include "u_check.h"

#define ST_BADVARTYPE ((HRESULT)0x80020008)
#define ST_OVERFLOW ((HRESULT)0x8002000A)
#define ST_BADINDEX ((HRESULT)0x8002000B)
#define ST_TYPEMISMATCH ((HRESULT)0x80020005)
#define ST_LOCKED ((HRESULT)0x8002000D)

/* ---- a COM object that counts references (IDispatch layout is a superset of IUnknown's) ---- */
typedef struct { const IDispatchVtbl *lpVtbl; LONG refs; } fake_t;
static HRESULT STDMETHODCALLTYPE f_qi(IDispatch *t, REFIID r, void **o) { (void)t; (void)r; *o = 0; return E_NOINTERFACE; }
static ULONG STDMETHODCALLTYPE f_addref(IDispatch *t) { return (ULONG)++((fake_t *)t)->refs; }
static ULONG STDMETHODCALLTYPE f_release(IDispatch *t) { return (ULONG)--((fake_t *)t)->refs; }
static HRESULT STDMETHODCALLTYPE f_count(IDispatch *t, UINT *n) { (void)t; *n = 0; return S_OK; }
static HRESULT STDMETHODCALLTYPE f_typeinfo(IDispatch *t, UINT i, LCID l, ITypeInfo **o) { (void)t; (void)i; (void)l; *o = 0; return E_NOTIMPL; }
static HRESULT STDMETHODCALLTYPE f_ids(IDispatch *t, REFIID r, LPOLESTR *n, UINT c, LCID l, DISPID *d) { (void)t; (void)r; (void)n; (void)c; (void)l; (void)d; return E_NOTIMPL; }
static HRESULT STDMETHODCALLTYPE f_invoke(IDispatch *t, DISPID d, REFIID r, LCID l, WORD f, DISPPARAMS *p, VARIANT *v, EXCEPINFO *e, UINT *u)
{ (void)t; (void)d; (void)r; (void)l; (void)f; (void)p; (void)v; (void)e; (void)u; return E_NOTIMPL; }
static const IDispatchVtbl fake_vtbl = { f_qi, f_addref, f_release, f_count, f_typeinfo, f_ids, f_invoke };

static int wide_is(BSTR b, const char *s) { return b && u_ascii_eq_w((const unsigned short *)b, s); }
static BSTR mk(const char *s) { unsigned short w[80]; u_wide(s, w, 80); return SysAllocString((const OLECHAR *)w); }

int main(void)
{
    /* ================================================================ BSTR */
    {
        BSTR b = SysAllocString(L"hello");
        U_CHECK("SysAllocString returns a BSTR", b != 0);
        U_CHECK("SysStringLen = 5 and SysStringByteLen = 10", SysStringLen(b) == 5 && SysStringByteLen(b) == 10);
        U_CHECK("the DWORD before the string holds the byte length (documented layout)", *(DWORD *)((BYTE *)b - 4) == 10);
        U_CHECK("the data is followed by a NUL that is not counted", b[5] == 0 && !memcmp(b, L"hello", 12));
        SysFreeString(b);
        U_CHECK("SysAllocString(NULL) = NULL", SysAllocString(0) == 0);
        U_CHECK("SysStringLen(NULL) = 0, SysStringByteLen(NULL) = 0", SysStringLen(0) == 0 && SysStringByteLen(0) == 0);
        SysFreeString(0);
        b = SysAllocString(L"");
        U_CHECK("SysAllocString(\"\") is a real, empty BSTR", b && SysStringLen(b) == 0 && b[0] == 0);
        SysFreeString(b);
        b = SysAllocStringLen(L"abc\0def", 7);
        U_CHECK("SysAllocStringLen keeps embedded NULs (length 7)", b && SysStringLen(b) == 7 && !memcmp(b, L"abc\0def", 14) && b[7] == 0);
        SysFreeString(b);
        b = SysAllocStringLen(L"abcdef", 3);
        U_CHECK("SysAllocStringLen(\"abcdef\", 3) copies 3 characters and terminates", b && SysStringLen(b) == 3 && b[0] == 'a' && b[2] == 'c' && b[3] == 0);
        SysFreeString(b);
        b = SysAllocStringLen(0, 4);
        U_CHECK("SysAllocStringLen(NULL, 4) allocates 4 characters plus the terminator", b && SysStringLen(b) == 4 && b[4] == 0);
        SysFreeString(b);
        b = SysAllocStringByteLen("abcde", 5);
        U_CHECK("SysAllocStringByteLen(\"abcde\", 5): 5 bytes, 2 characters, bytes kept, wide NUL after",
                b && SysStringByteLen(b) == 5 && SysStringLen(b) == 2 && !memcmp(b, "abcde", 5) && ((BYTE *)b)[5] == 0 && ((BYTE *)b)[6] == 0);
        SysFreeString(b);
        b = SysAllocStringByteLen(0, 6);
        U_CHECK("SysAllocStringByteLen(NULL, 6) reserves 6 bytes", b && SysStringByteLen(b) == 6 && SysStringLen(b) == 3);
        SysFreeString(b);
    }
    {
        BSTR b = mk("short");
        U_CHECK("SysReAllocString to a longer string", SysReAllocString(&b, L"a much longer replacement") && wide_is(b, "a much longer replacement") && SysStringLen(b) == 25);
        U_CHECK("SysReAllocString with a source inside the old string", SysReAllocString(&b, b + 7) && wide_is(b, "longer replacement"));
        U_CHECK("SysReAllocStringLen(&b, NULL, 6) keeps the old text prefix", SysReAllocStringLen(&b, 0, 6) && SysStringLen(b) == 6 && !memcmp(b, L"longer", 12) && b[6] == 0);
        U_CHECK("SysReAllocStringLen(&b, \"xy\\0z\", 4) copies embedded NULs", SysReAllocStringLen(&b, L"xy\0z", 4) && SysStringLen(b) == 4 && b[2] == 0 && b[3] == 'z');
        SysFreeString(b);
        b = 0;
        U_CHECK("SysReAllocString on a NULL BSTR allocates", SysReAllocString(&b, L"fresh") && wide_is(b, "fresh"));
        U_CHECK("SysReAllocString(NULL ptr) fails", !SysReAllocString(0, L"x"));
        U_CHECK("SysReAllocString(psz NULL) fails", !SysReAllocString(&b, 0));
        SysFreeString(b);
    }
    {
        BSTR a = mk("foo"), c = mk("bar"), r = 0;
        U_CHECK("VarBstrCat(foo, bar) = foobar", VarBstrCat(a, c, &r) == S_OK && wide_is(r, "foobar") && SysStringLen(r) == 6);
        SysFreeString(r); r = 0;
        U_CHECK("VarBstrCat(NULL, bar) = bar", VarBstrCat(0, c, &r) == S_OK && wide_is(r, "bar"));
        SysFreeString(r); r = 0;
        U_CHECK("VarBstrCat(foo, NULL) = foo", VarBstrCat(a, 0, &r) == S_OK && wide_is(r, "foo"));
        SysFreeString(r); r = 0;
        U_CHECK("VarBstrCat(NULL, NULL) is an empty string", VarBstrCat(0, 0, &r) == S_OK && SysStringLen(r) == 0);
        SysFreeString(r);
        U_CHECK("VarBstrCat with a NULL output pointer is E_POINTER", VarBstrCat(a, c, 0) == E_POINTER);
        SysFreeString(a); SysFreeString(c);
    }

    /* ================================================================ VARIANT clear / copy */
    {
        VARIANT v, w;
        v.vt = 0x1234;
        VariantInit(&v);
        U_CHECK("VariantInit sets VT_EMPTY", V_VT(&v) == VT_EMPTY);
        U_CHECK("VariantClear(NULL) is E_INVALIDARG", VariantClear(0) == E_INVALIDARG);
        V_VT(&v) = (VARTYPE)(VT_I4 | VT_VECTOR);
        U_CHECKF("VariantClear rejects VT_VECTOR|VT_I4 (DISP_E_BADVARTYPE)", VariantClear(&v) == ST_BADVARTYPE, "hr=%x", (unsigned)VariantClear(&v));
        V_VT(&v) = 0x8002;
        U_CHECK("VariantClear rejects VT_RESERVED types", VariantClear(&v) == ST_BADVARTYPE);
        V_VT(&v) = VT_VARIANT;
        U_CHECK("a bare VT_VARIANT is not a legal VARIANT type", VariantClear(&v) == ST_BADVARTYPE);
        V_VT(&v) = 200;
        U_CHECK("an undefined type number is rejected", VariantClear(&v) == ST_BADVARTYPE);

        VariantInit(&v);
        V_VT(&v) = VT_BSTR;
        V_BSTR(&v) = mk("owned string");
        VariantInit(&w);
        U_CHECK("VariantCopy of a BSTR", VariantCopy(&w, &v) == S_OK && V_VT(&w) == VT_BSTR && V_BSTR(&w) != V_BSTR(&v) && wide_is(V_BSTR(&w), "owned string"));
        V_BSTR(&v)[0] = 'X';
        U_CHECK("the copy is independent of the original", wide_is(V_BSTR(&w), "owned string") && wide_is(V_BSTR(&v), "Xwned string"));
        U_CHECK("VariantClear(BSTR) leaves VT_EMPTY", VariantClear(&v) == S_OK && V_VT(&v) == VT_EMPTY && VariantClear(&w) == S_OK && V_VT(&w) == VT_EMPTY);
        V_VT(&v) = VT_BSTR;
        V_BSTR(&v) = 0;
        U_CHECK("VariantCopy of a NULL BSTR stays NULL", VariantCopy(&w, &v) == S_OK && V_VT(&w) == VT_BSTR && V_BSTR(&w) == 0);
        V_VT(&v) = VT_I4; V_I4(&v) = -123456;
        U_CHECK("VariantCopy replaces (and frees) the destination's old value", VariantCopy(&w, &v) == S_OK && V_VT(&w) == VT_I4 && V_I4(&w) == -123456);
        V_VT(&v) = VT_R8; V_R8(&v) = 2.5;
        U_CHECK("VariantCopy R8", VariantCopy(&w, &v) == S_OK && V_VT(&w) == VT_R8 && V_R8(&w) == 2.5);
        V_VT(&v) = VT_I8; V_I8(&v) = 0x123456789abcdefLL;
        U_CHECK("VariantCopy I8", VariantCopy(&w, &v) == S_OK && V_I8(&w) == 0x123456789abcdefLL);
        U_CHECK("VariantCopy(x, x) is a no-op success", VariantCopy(&v, &v) == S_OK && V_I8(&v) == 0x123456789abcdefLL);
        {
            long target = 77;
            V_VT(&v) = VT_I4 | VT_BYREF;
            V_I4REF(&v) = (LONG *)&target;
            U_CHECK("VariantCopy of a VT_BYREF copies only the pointer", VariantCopy(&w, &v) == S_OK && V_VT(&w) == (VT_I4 | VT_BYREF) && V_I4REF(&w) == (LONG *)&target);
            U_CHECK("VariantCopyInd dereferences a by-reference I4", VariantCopyInd(&w, &v) == S_OK && V_VT(&w) == VT_I4 && V_I4(&w) == 77);
            {
                VARIANT inner;
                VariantInit(&inner);
                V_VT(&inner) = VT_BSTR;
                V_BSTR(&inner) = mk("inner");
                V_VT(&v) = VT_VARIANT | VT_BYREF;
                V_VARIANTREF(&v) = &inner;
                U_CHECK("VariantCopyInd through VT_VARIANT|VT_BYREF duplicates the inner BSTR",
                        VariantCopyInd(&w, &v) == S_OK && V_VT(&w) == VT_BSTR && V_BSTR(&w) != V_BSTR(&inner) && wide_is(V_BSTR(&w), "inner"));
                VariantClear(&w);
                VariantClear(&inner);
            }
        }
        VariantClear(&w);
    }
    {
        fake_t obj = { &fake_vtbl, 1 };
        VARIANT a, b;
        VariantInit(&a); VariantInit(&b);
        V_VT(&a) = VT_UNKNOWN;
        V_UNKNOWN(&a) = (IUnknown *)&obj;
        U_CHECK("VariantCopy(VT_UNKNOWN) AddRefs", VariantCopy(&b, &a) == S_OK && obj.refs == 2 && V_UNKNOWN(&b) == (IUnknown *)&obj);
        U_CHECK("VariantClear(VT_UNKNOWN) Releases", VariantClear(&b) == S_OK && obj.refs == 1);
        V_VT(&a) = VT_DISPATCH;
        V_DISPATCH(&a) = (IDispatch *)&obj;
        U_CHECK("VariantCopy(VT_DISPATCH) AddRefs", VariantCopy(&b, &a) == S_OK && obj.refs == 2 && V_VT(&b) == VT_DISPATCH);
        U_CHECK("VariantClear(VT_DISPATCH) Releases", VariantClear(&b) == S_OK && obj.refs == 1);
        V_UNKNOWN(&a) = 0;
        U_CHECK("a NULL interface pointer is copied and cleared without a call", VariantCopy(&b, &a) == S_OK && VariantClear(&b) == S_OK && VariantClear(&a) == S_OK);
        V_VT(&a) = VT_UNKNOWN;
        V_UNKNOWN(&a) = (IUnknown *)&obj;
        obj.refs = 1;
        {
            SAFEARRAYBOUND sb = { 3, 0 };
            SAFEARRAY *sa = SafeArrayCreate(VT_UNKNOWN, 1, &sb);
            LONG i = 0;
            U_CHECK("SafeArrayCreate(VT_UNKNOWN, 3)", sa != 0);
            U_CHECK("PutElement AddRefs the interface pointer (pv is the pointer itself)", SafeArrayPutElement(sa, &i, &obj) == S_OK && obj.refs == 2);
            {
                IUnknown *got = 0;
                U_CHECK("GetElement AddRefs for the caller", SafeArrayGetElement(sa, &i, &got) == S_OK && got == (IUnknown *)&obj && obj.refs == 3);
                got->lpVtbl->Release(got);
            }
            i = 1;
            SafeArrayPutElement(sa, &i, &obj);
            U_CHECK("two elements hold two references", obj.refs == 3);
            {
                SAFEARRAY *copy = 0;
                U_CHECK("SafeArrayCopy AddRefs every non-NULL element", SafeArrayCopy(sa, &copy) == S_OK && copy && obj.refs == 5);
                U_CHECK("destroying the copy releases them", SafeArrayDestroy(copy) == S_OK && obj.refs == 3);
            }
            U_CHECK("SafeArrayDestroy releases the elements", SafeArrayDestroy(sa) == S_OK && obj.refs == 1);
        }
    }

    /* ================================================================ VariantChangeType */
    {
        struct { VARTYPE from; LONGLONG i; VARTYPE to; HRESULT hr; LONGLONG expect; const char *name; } t[] = {
            { VT_I4, 200, VT_UI1, S_OK, 200, "I4 200 -> UI1" },
            { VT_I4, 256, VT_UI1, ST_OVERFLOW, 0, "I4 256 -> UI1 overflows" },
            { VT_I4, -1, VT_UI1, ST_OVERFLOW, 0, "I4 -1 -> UI1 overflows" },
            { VT_I4, -128, VT_I1, S_OK, -128, "I4 -128 -> I1" },
            { VT_I4, -129, VT_I1, ST_OVERFLOW, 0, "I4 -129 -> I1 overflows" },
            { VT_I4, 32767, VT_I2, S_OK, 32767, "I4 32767 -> I2" },
            { VT_I4, 32768, VT_I2, ST_OVERFLOW, 0, "I4 32768 -> I2 overflows" },
            { VT_I4, 65535, VT_UI2, S_OK, 65535, "I4 65535 -> UI2" },
            { VT_I4, -1, VT_UI2, ST_OVERFLOW, 0, "I4 -1 -> UI2 overflows" },
            { VT_UI4, 4294967295LL, VT_I4, ST_OVERFLOW, 0, "UI4 4294967295 -> I4 overflows" },
            { VT_UI4, 4294967295LL, VT_I8, S_OK, 4294967295LL, "UI4 4294967295 -> I8" },
            { VT_I8, -5, VT_I4, S_OK, -5, "I8 -5 -> I4" },
            { VT_I8, 3000000000LL, VT_I4, ST_OVERFLOW, 0, "I8 3e9 -> I4 overflows" },
            { VT_I8, -1, VT_UI8, ST_OVERFLOW, 0, "I8 -1 -> UI8 overflows" },
            { VT_I2, -7, VT_INT, S_OK, -7, "I2 -7 -> INT" },
            { VT_I4, 0, VT_BOOL, S_OK, 0, "I4 0 -> BOOL FALSE" },
            { VT_I4, 5, VT_BOOL, S_OK, -1, "I4 5 -> BOOL VARIANT_TRUE (-1)" },
            { VT_I8, 0x100000000LL, VT_BOOL, S_OK, -1, "I8 2^32 -> BOOL TRUE" },
            { VT_BOOL, -1, VT_I4, S_OK, -1, "BOOL TRUE -> I4 = -1" },
            { VT_BOOL, -1, VT_I2, S_OK, -1, "BOOL TRUE -> I2 = -1" },
            { VT_BOOL, 0, VT_I4, S_OK, 0, "BOOL FALSE -> I4 = 0" },
            { VT_EMPTY, 0, VT_I4, S_OK, 0, "EMPTY -> I4 = 0" },
            { VT_EMPTY, 0, VT_BOOL, S_OK, 0, "EMPTY -> BOOL FALSE" },
        };
        unsigned i;
        for (i = 0; i < sizeof t / sizeof t[0]; ++i) {
            VARIANT s, d;
            HRESULT hr;
            LONGLONG got = 0;
            VariantInit(&s); VariantInit(&d);
            V_VT(&s) = t[i].from;
            switch (t[i].from) {
            case VT_I2: case VT_BOOL: V_I2(&s) = (SHORT)t[i].i; break;
            case VT_I4: V_I4(&s) = (LONG)t[i].i; break;
            case VT_UI4: V_UI4(&s) = (ULONG)t[i].i; break;
            case VT_I8: V_I8(&s) = t[i].i; break;
            default: break;
            }
            hr = VariantChangeType(&d, &s, 0, t[i].to);
            if (hr == S_OK) {
                switch (V_VT(&d)) {
                case VT_I1: got = V_I1(&d); break;
                case VT_UI1: got = V_UI1(&d); break;
                case VT_I2: case VT_BOOL: got = V_I2(&d); break;
                case VT_UI2: got = V_UI2(&d); break;
                case VT_I4: case VT_INT: got = V_I4(&d); break;
                case VT_I8: got = V_I8(&d); break;
                }
            }
            U_CHECKF(t[i].name, hr == t[i].hr && (hr != S_OK || (V_VT(&d) == t[i].to && got == t[i].expect)), "hr=%x got=%d", (unsigned)hr, (int)got);
        }
    }
    {
        /* float -> integer: round to nearest, ties to even (VarI4FromR8 documentation) */
        static const struct { double in; LONG out; } r[] = {
            { 0.4, 0 }, { 0.5, 0 }, { 0.6, 1 }, { 1.5, 2 }, { 2.5, 2 }, { 3.5, 4 }, { -0.5, 0 }, { -1.5, -2 }, { -2.5, -2 }, { -2.6, -3 },
            { 2147483647.0, 2147483647 }, { -2147483648.0, (LONG)0x80000000 }, { 2147483646.5, 2147483646 },
        };
        unsigned i;
        VARIANT s, d;
        for (i = 0; i < sizeof r / sizeof r[0]; ++i) {
            char nm[64];
            VariantInit(&s); VariantInit(&d);
            V_VT(&s) = VT_R8; V_R8(&s) = r[i].in;
            snprintf(nm, sizeof nm, "R8 rounding case #%u to I4", i);
            U_CHECKF(nm, VariantChangeType(&d, &s, 0, VT_I4) == S_OK && V_VT(&d) == VT_I4 && V_I4(&d) == r[i].out, "got=%d expect=%d", (int)V_I4(&d), (int)r[i].out);
        }
        VariantInit(&s); VariantInit(&d);
        V_VT(&s) = VT_R8; V_R8(&s) = 2147483648.0;
        U_CHECK("R8 2^31 -> I4 overflows", VariantChangeType(&d, &s, 0, VT_I4) == ST_OVERFLOW);
        V_R8(&s) = -2147483649.0;
        U_CHECK("R8 -2^31-1 -> I4 overflows", VariantChangeType(&d, &s, 0, VT_I4) == ST_OVERFLOW);
        V_R8(&s) = 1e20;
        U_CHECK("R8 1e20 -> I8 overflows", VariantChangeType(&d, &s, 0, VT_I8) == ST_OVERFLOW);
        V_R8(&s) = 1e20;
        U_CHECK("R8 1e20 -> UI8 overflows", VariantChangeType(&d, &s, 0, VT_UI8) == ST_OVERFLOW);
        V_R8(&s) = 18446744073709549568.0;
        U_CHECK("R8 just below 2^64 -> UI8 succeeds", VariantChangeType(&d, &s, 0, VT_UI8) == S_OK && V_UI8(&d) == 18446744073709549568ull);
        {
            union { unsigned long long u; double f; } nan = { 0x7ff8000000000000ull };
            V_R8(&s) = nan.f;
            U_CHECK("R8 NaN -> I4 overflows", VariantChangeType(&d, &s, 0, VT_I4) == ST_OVERFLOW);
        }
        V_R8(&s) = -1.0;
        U_CHECK("R8 -1 -> UI2 overflows", VariantChangeType(&d, &s, 0, VT_UI2) == ST_OVERFLOW);
        V_R8(&s) = 0.1;
        U_CHECK("R8 0.1 -> BOOL is TRUE (nonzero)", VariantChangeType(&d, &s, 0, VT_BOOL) == S_OK && V_BOOL(&d) == VARIANT_TRUE);
        V_R8(&s) = 1e300;
        U_CHECK("R8 1e300 -> R4 overflows", VariantChangeType(&d, &s, 0, VT_R4) == ST_OVERFLOW);
        V_R8(&s) = 1.25;
        U_CHECK("R8 1.25 -> R4 is exact", VariantChangeType(&d, &s, 0, VT_R4) == S_OK && V_VT(&d) == VT_R4 && V_R4(&d) == 1.25f);
        VariantInit(&s);
        V_VT(&s) = VT_I4; V_I4(&s) = 16777217;
        U_CHECK("I4 -> R8 is exact", VariantChangeType(&d, &s, 0, VT_R8) == S_OK && V_VT(&d) == VT_R8 && V_R8(&d) == 16777217.0);
        V_VT(&s) = VT_UI8; V_UI8(&s) = 18446744073709551615ull;
        U_CHECK("UI8 max -> R8 = 2^64", VariantChangeType(&d, &s, 0, VT_R8) == S_OK && V_R8(&d) == 18446744073709551616.0);
    }
    {
        /* integers / BOOL / EMPTY -> BSTR */
        VARIANT s, d;
        VariantInit(&s); VariantInit(&d);
        V_VT(&s) = VT_I4; V_I4(&s) = 12345;
        U_CHECK("I4 12345 -> BSTR \"12345\"", VariantChangeType(&d, &s, 0, VT_BSTR) == S_OK && V_VT(&d) == VT_BSTR && wide_is(V_BSTR(&d), "12345"));
        V_I4(&s) = -7;
        U_CHECK("I4 -7 -> BSTR \"-7\" (destination cleared first)", VariantChangeType(&d, &s, 0, VT_BSTR) == S_OK && wide_is(V_BSTR(&d), "-7"));
        V_I4(&s) = 0;
        U_CHECK("I4 0 -> BSTR \"0\"", VariantChangeType(&d, &s, 0, VT_BSTR) == S_OK && wide_is(V_BSTR(&d), "0"));
        V_VT(&s) = VT_I8; V_I8(&s) = (LONGLONG)0x8000000000000000ull;
        U_CHECK("I8 min -> BSTR", VariantChangeType(&d, &s, 0, VT_BSTR) == S_OK && wide_is(V_BSTR(&d), "-9223372036854775808"));
        V_VT(&s) = VT_UI8; V_UI8(&s) = 18446744073709551615ull;
        U_CHECK("UI8 max -> BSTR", VariantChangeType(&d, &s, 0, VT_BSTR) == S_OK && wide_is(V_BSTR(&d), "18446744073709551615"));
        V_VT(&s) = VT_BOOL; V_BOOL(&s) = VARIANT_TRUE;
        U_CHECK("BOOL TRUE -> BSTR \"-1\" by default", VariantChangeType(&d, &s, 0, VT_BSTR) == S_OK && wide_is(V_BSTR(&d), "-1"));
        U_CHECK("BOOL TRUE -> \"True\" with VARIANT_ALPHABOOL", VariantChangeType(&d, &s, VARIANT_ALPHABOOL, VT_BSTR) == S_OK && wide_is(V_BSTR(&d), "True"));
        V_BOOL(&s) = VARIANT_FALSE;
        U_CHECK("BOOL FALSE -> \"False\" with VARIANT_ALPHABOOL", VariantChangeType(&d, &s, VARIANT_ALPHABOOL, VT_BSTR) == S_OK && wide_is(V_BSTR(&d), "False"));
        U_CHECK("BOOL FALSE -> \"0\" by default", VariantChangeType(&d, &s, 0, VT_BSTR) == S_OK && wide_is(V_BSTR(&d), "0"));
        VariantClear(&s);
        U_CHECK("EMPTY -> BSTR is the empty string", VariantChangeType(&d, &s, 0, VT_BSTR) == S_OK && V_VT(&d) == VT_BSTR && V_BSTR(&d) && SysStringLen(V_BSTR(&d)) == 0);
        VariantClear(&d);
    }
    {
        /* BSTR -> integers / BOOL / floats */
        static const struct { const char *text; VARTYPE to; HRESULT hr; LONGLONG expect; } bt[] = {
            { "123", VT_I4, S_OK, 123 },
            { " -42 ", VT_I4, S_OK, -42 },
            { "+7", VT_I2, S_OK, 7 },
            { "0", VT_UI1, S_OK, 0 },
            { "255", VT_UI1, S_OK, 255 },
            { "256", VT_UI1, ST_OVERFLOW, 0 },
            { "-1", VT_UI1, ST_OVERFLOW, 0 },
            { "99999999999", VT_I4, ST_OVERFLOW, 0 },
            { "2147483647", VT_I4, S_OK, 2147483647 },
            { "2147483648", VT_I4, ST_OVERFLOW, 0 },
            { "-2147483648", VT_I4, S_OK, (LONGLONG)-2147483647 - 1 },
            { "9223372036854775807", VT_I8, S_OK, 9223372036854775807LL },
            { "9223372036854775808", VT_I8, ST_OVERFLOW, 0 },
            { "1.5", VT_I4, S_OK, 2 },
            { "2.5", VT_I4, S_OK, 2 },
            { "3.5", VT_I4, S_OK, 4 },
            { "-2.5", VT_I4, S_OK, -2 },
            { "0.5", VT_I4, S_OK, 0 },
            { "2.4999999999", VT_I4, S_OK, 2 },
            { "2.5000000001", VT_I4, S_OK, 3 },
            { "1e3", VT_I4, S_OK, 1000 },
            { "1.5e1", VT_I4, S_OK, 15 },
            { "25E-1", VT_I4, S_OK, 2 },
            { "abc", VT_I4, ST_TYPEMISMATCH, 0 },
            { "12abc", VT_I4, ST_TYPEMISMATCH, 0 },
            { "", VT_I4, ST_TYPEMISMATCH, 0 },
            { "   ", VT_I4, ST_TYPEMISMATCH, 0 },
            { "1 2", VT_I4, ST_TYPEMISMATCH, 0 },
            { "--1", VT_I4, ST_TYPEMISMATCH, 0 },
            { "1e", VT_I4, ST_TYPEMISMATCH, 0 },
            { "True", VT_BOOL, S_OK, -1 },
            { "TRUE", VT_BOOL, S_OK, -1 },
            { "false", VT_BOOL, S_OK, 0 },
            { "#TRUE#", VT_BOOL, S_OK, -1 },
            { "#FALSE#", VT_BOOL, S_OK, 0 },
            { "1", VT_BOOL, S_OK, -1 },
            { "0", VT_BOOL, S_OK, 0 },
            { "2", VT_BOOL, S_OK, -1 },
            { "yes", VT_BOOL, ST_TYPEMISMATCH, 0 },
        };
        unsigned i;
        for (i = 0; i < sizeof bt / sizeof bt[0]; ++i) {
            VARIANT s, d;
            HRESULT hr;
            LONGLONG got = 0;
            char nm[96];
            VariantInit(&s); VariantInit(&d);
            V_VT(&s) = VT_BSTR;
            V_BSTR(&s) = mk(bt[i].text);
            hr = VariantChangeType(&d, &s, 0, bt[i].to);
            if (hr == S_OK) {
                switch (V_VT(&d)) {
                case VT_I2: case VT_BOOL: got = V_I2(&d); break;
                case VT_UI1: got = V_UI1(&d); break;
                case VT_I4: got = V_I4(&d); break;
                case VT_I8: got = V_I8(&d); break;
                }
            }
            snprintf(nm, sizeof nm, "BSTR \"%s\" -> vt %u", bt[i].text, (unsigned)bt[i].to);
            U_CHECKF(nm, hr == bt[i].hr && (hr != S_OK || (V_VT(&d) == bt[i].to && got == bt[i].expect)), "hr=%x got=%d", (unsigned)hr, (int)got);
            VariantClear(&s);
        }
        {
            static const struct { const char *text; double v; } ft[] = {
                { "1.5", 1.5 }, { "-0.25", -0.25 }, { "1e2", 100.0 }, { "123.456", 123.456 }, { "0.1", 0.1 }, { "0.000001", 0.000001 },
                { "100", 100.0 }, { "3.14159", 3.14159 }, { " 7 ", 7.0 }, { "1.5e-3", 1.5e-3 }, { "123456789012345", 123456789012345.0 },
            };
            for (i = 0; i < sizeof ft / sizeof ft[0]; ++i) {
                VARIANT s, d;
                char nm[64];
                VariantInit(&s); VariantInit(&d);
                V_VT(&s) = VT_BSTR;
                V_BSTR(&s) = mk(ft[i].text);
                snprintf(nm, sizeof nm, "BSTR \"%s\" -> R8", ft[i].text);
                U_CHECK(nm, VariantChangeType(&d, &s, 0, VT_R8) == S_OK && V_VT(&d) == VT_R8 && V_R8(&d) == ft[i].v);
                VariantClear(&s);
            }
        }
        {
            VARIANT s, d;
            VariantInit(&s); VariantInit(&d);
            V_VT(&s) = VT_BSTR; V_BSTR(&s) = mk("1.0000000000000000000001");
            U_CHECK("a decimal that the exact fast path cannot represent is refused (E_NOTIMPL), not approximated", VariantChangeType(&d, &s, 0, VT_R8) == E_NOTIMPL);
            VariantClear(&s);
            V_VT(&s) = VT_BSTR; V_BSTR(&s) = mk("&H10");
            U_CHECK("&H hex text is refused (E_NOTIMPL)", VariantChangeType(&d, &s, 0, VT_I4) == E_NOTIMPL);
            VariantClear(&s);
            V_VT(&s) = VT_BSTR; V_BSTR(&s) = mk("1,000");
            U_CHECK("thousands separators are refused (E_NOTIMPL)", VariantChangeType(&d, &s, 0, VT_I4) == E_NOTIMPL);
            VariantClear(&s);
        }
    }
    {
        VARIANT s, d;
        VariantInit(&s); VariantInit(&d);
        V_VT(&s) = VT_NULL;
        U_CHECK("NULL -> I4 is DISP_E_TYPEMISMATCH", VariantChangeType(&d, &s, 0, VT_I4) == ST_TYPEMISMATCH);
        V_VT(&s) = VT_I4; V_I4(&s) = 1;
        U_CHECK("anything -> VT_EMPTY is DISP_E_TYPEMISMATCH", VariantChangeType(&d, &s, 0, VT_EMPTY) == ST_TYPEMISMATCH);
        U_CHECK("target VT_I4|VT_ARRAY is DISP_E_BADVARTYPE", VariantChangeType(&d, &s, 0, VT_I4 | VT_ARRAY) == ST_BADVARTYPE);
        U_CHECK("target VT_VARIANT (bare) is DISP_E_BADVARTYPE", VariantChangeType(&d, &s, 0, VT_VARIANT) == ST_BADVARTYPE);
        V_VT(&s) = VT_R8; V_R8(&s) = 0.5;
        U_CHECK("R8 -> BSTR is refused (E_NOTIMPL): no shortest-round-trip printer", VariantChangeType(&d, &s, 0, VT_BSTR) == E_NOTIMPL);
        V_VT(&s) = VT_CY;
        U_CHECK("CY -> I4 is refused (E_NOTIMPL)", VariantChangeType(&d, &s, 0, VT_I4) == E_NOTIMPL);
        {
            fake_t obj = { &fake_vtbl, 1 };
            V_VT(&s) = VT_UNKNOWN; V_UNKNOWN(&s) = (IUnknown *)&obj;
            U_CHECK("UNKNOWN -> I4 is DISP_E_TYPEMISMATCH", VariantChangeType(&d, &s, 0, VT_I4) == ST_TYPEMISMATCH);
            U_CHECK("UNKNOWN -> UNKNOWN is a reference-counted copy", VariantChangeType(&d, &s, 0, VT_UNKNOWN) == S_OK && obj.refs == 2);
            VariantClear(&d);
            U_CHECK("...and clearing it releases", obj.refs == 1);
        }
        /* in place */
        VariantInit(&s);
        V_VT(&s) = VT_I4; V_I4(&s) = 314;
        U_CHECK("in-place I4 -> BSTR", VariantChangeType(&s, &s, 0, VT_BSTR) == S_OK && V_VT(&s) == VT_BSTR && wide_is(V_BSTR(&s), "314"));
        U_CHECK("in-place BSTR -> I2", VariantChangeType(&s, &s, 0, VT_I2) == S_OK && V_VT(&s) == VT_I2 && V_I2(&s) == 314);
        U_CHECK("in-place to the same type is a no-op", VariantChangeType(&s, &s, 0, VT_I2) == S_OK && V_I2(&s) == 314);
        V_VT(&s) = VT_I4; V_I4(&s) = 300;
        U_CHECK("a failed in-place conversion leaves the source untouched", VariantChangeType(&s, &s, 0, VT_UI1) == ST_OVERFLOW && V_VT(&s) == VT_I4 && V_I4(&s) == 300);
        /* by-reference source */
        {
            LONG x = 42;
            V_VT(&s) = VT_I4 | VT_BYREF; V_I4REF(&s) = &x;
            VariantInit(&d);
            U_CHECK("by-reference I4 -> R8 converts the referenced value", VariantChangeType(&d, &s, 0, VT_R8) == S_OK && V_VT(&d) == VT_R8 && V_R8(&d) == 42.0);
        }
        /* failure with a distinct destination: destination emptied */
        VariantInit(&d);
        V_VT(&d) = VT_BSTR; V_BSTR(&d) = mk("old value");
        V_VT(&s) = VT_I4; V_I4(&s) = -1;
        U_CHECK("failed conversion into a different destination leaves it VT_EMPTY", VariantChangeType(&d, &s, 0, VT_UI1) == ST_OVERFLOW && V_VT(&d) == VT_EMPTY);
    }

    /* ================================================================ SAFEARRAY */
    {
        SAFEARRAYBOUND b = { 5, 1 };                    /* {cElements, lLbound} */
        SAFEARRAY *sa = SafeArrayCreate(VT_I4, 1, &b);
        LONG lb = -1, ub = -1, i, val;
        VARTYPE vt = 0;
        void *data = 0;
        U_CHECK("SafeArrayCreate(VT_I4, 1 dim)", sa != 0);
        U_CHECK("GetDim = 1, GetElemsize = 4", SafeArrayGetDim(sa) == 1 && SafeArrayGetElemsize(sa) == 4);
        U_CHECK("bounds are [1, 5]", SafeArrayGetLBound(sa, 1, &lb) == S_OK && SafeArrayGetUBound(sa, 1, &ub) == S_OK && lb == 1 && ub == 5);
        U_CHECK("GetVartype = VT_I4 and FADF_HAVEVARTYPE is set", SafeArrayGetVartype(sa, &vt) == S_OK && vt == VT_I4 && (sa->fFeatures & FADF_HAVEVARTYPE));
        U_CHECK("the hidden vartype DWORD precedes the descriptor", *(DWORD *)((BYTE *)sa - 4) == VT_I4);
        U_CHECK("elements start zeroed", sa->pvData && ((LONG *)sa->pvData)[0] == 0 && ((LONG *)sa->pvData)[4] == 0);
        U_CHECK("GetLBound(dim 0) is DISP_E_BADINDEX", SafeArrayGetLBound(sa, 0, &lb) == ST_BADINDEX);
        U_CHECK("GetUBound(dim 2 of a vector) is DISP_E_BADINDEX", SafeArrayGetUBound(sa, 2, &ub) == ST_BADINDEX);
        U_CHECK("GetLBound(NULL array) is E_INVALIDARG", SafeArrayGetLBound(0, 1, &lb) == E_INVALIDARG);
        for (i = 1; i <= 5; ++i) { val = i * 10; SafeArrayPutElement(sa, &i, &val); }
        val = 0; i = 3;
        U_CHECK("PutElement/GetElement round trip", SafeArrayGetElement(sa, &i, &val) == S_OK && val == 30);
        U_CHECK("data is contiguous in index order", ((LONG *)sa->pvData)[0] == 10 && ((LONG *)sa->pvData)[4] == 50);
        i = 0;
        U_CHECK("index below the lower bound is DISP_E_BADINDEX", SafeArrayGetElement(sa, &i, &val) == ST_BADINDEX && SafeArrayPutElement(sa, &i, &val) == ST_BADINDEX);
        i = 6;
        U_CHECK("index above the upper bound is DISP_E_BADINDEX", SafeArrayGetElement(sa, &i, &val) == ST_BADINDEX);
        i = 2;
        U_CHECK("SafeArrayPtrOfIndex addresses the element", SafeArrayPtrOfIndex(sa, &i, &data) == S_OK && data == (BYTE *)sa->pvData + 4);
        U_CHECK("GetElement with NULL destination is E_INVALIDARG", SafeArrayGetElement(sa, &i, 0) == E_INVALIDARG);
        /* locking */
        U_CHECK("AccessData returns the data pointer and locks", SafeArrayAccessData(sa, &data) == S_OK && data == sa->pvData && sa->cLocks == 1);
        ((LONG *)data)[1] = 777;
        i = 2;
        U_CHECK("writes through AccessData are visible to GetElement", SafeArrayGetElement(sa, &i, &val) == S_OK && val == 777);
        U_CHECK("Destroy of a locked array is DISP_E_ARRAYISLOCKED", SafeArrayDestroy(sa) == ST_LOCKED);
        U_CHECK("Redim of a locked array is DISP_E_ARRAYISLOCKED", SafeArrayRedim(sa, &b) == ST_LOCKED);
        U_CHECK("UnaccessData unlocks", SafeArrayUnaccessData(sa) == S_OK && sa->cLocks == 0);
        U_CHECK("Unlock without a lock is E_UNEXPECTED", SafeArrayUnlock(sa) == E_UNEXPECTED);
        {
            SAFEARRAYBOUND nb = { 8, 1 };
            LONG j;
            U_CHECK("Redim grows the rightmost (only) dimension to 8", SafeArrayRedim(sa, &nb) == S_OK && SafeArrayGetUBound(sa, 1, &ub) == S_OK && ub == 8);
            for (j = 1; j <= 5; ++j) { val = -1; SafeArrayGetElement(sa, &j, &val); if (j == 2 ? val != 777 : val != j * 10) break; }
            U_CHECK("...old elements are preserved", j == 6);
            j = 7; val = -1;
            U_CHECK("...new elements are zero", SafeArrayGetElement(sa, &j, &val) == S_OK && val == 0);
            nb.cElements = 2;
            U_CHECK("Redim shrinks to 2 and keeps the first elements", SafeArrayRedim(sa, &nb) == S_OK && SafeArrayGetUBound(sa, 1, &ub) == S_OK && ub == 2);
            j = 1;
            U_CHECK("...", SafeArrayGetElement(sa, &j, &val) == S_OK && val == 10);
            j = 3;
            U_CHECK("...and the removed ones are gone", SafeArrayGetElement(sa, &j, &val) == ST_BADINDEX);
        }
        U_CHECK("SafeArrayDestroy succeeds", SafeArrayDestroy(sa) == S_OK);
        U_CHECK("SafeArrayDestroy(NULL) is S_OK", SafeArrayDestroy(0) == S_OK);
        U_CHECK("GetDim(NULL) = 0 and GetElemsize(NULL) = 0", SafeArrayGetDim(0) == 0 && SafeArrayGetElemsize(0) == 0);
    }
    {
        SAFEARRAYBOUND bad[1] = { { 3, 0 } };
        U_CHECK("SafeArrayCreate(VT_EMPTY) fails", SafeArrayCreate(VT_EMPTY, 1, bad) == 0);
        U_CHECK("SafeArrayCreate(VT_NULL) fails", SafeArrayCreate(VT_NULL, 1, bad) == 0);
        U_CHECK("SafeArrayCreate(VT_RECORD without IRecordInfo) fails", SafeArrayCreate(VT_RECORD, 1, bad) == 0);
        U_CHECK("SafeArrayCreate with 0 dimensions fails", SafeArrayCreate(VT_I4, 0, bad) == 0);
        U_CHECK("SafeArrayCreate with NULL bounds fails", SafeArrayCreate(VT_I4, 1, 0) == 0);
        {
            SAFEARRAYBOUND huge = { 0x7fffffffu, 0 };
            U_CHECK("SafeArrayCreate of an unsatisfiably large array fails cleanly", SafeArrayCreate(VT_I8, 1, &huge) == 0);
        }
        {
            SAFEARRAYBOUND empty = { 0, 5 };
            SAFEARRAY *sa = SafeArrayCreate(VT_I4, 1, &empty);
            LONG ub = 0;
            U_CHECK("a zero-element array is legal (UBound = LBound - 1)", sa && SafeArrayGetUBound(sa, 1, &ub) == S_OK && ub == 4);
            SafeArrayDestroy(sa);
        }
    }
    {
        /* two dimensions: rgsabound[0] is the rightmost dimension (3 elements from 0), rgsabound[1] the leftmost (2 elements from 10) */
        SAFEARRAYBOUND b[2] = { { 3, 0 }, { 2, 10 } };
        SAFEARRAY *sa = SafeArrayCreate(VT_I4, 2, b);
        LONG lb, ub, idx[2], val, *raw = 0;
        int i, j;
        U_CHECK("2-D array: GetDim = 2, 6 elements", sa && SafeArrayGetDim(sa) == 2);
        U_CHECK("dimension 1 is the leftmost: [10, 11]", SafeArrayGetLBound(sa, 1, &lb) == S_OK && SafeArrayGetUBound(sa, 1, &ub) == S_OK && lb == 10 && ub == 11);
        U_CHECK("dimension 2 is the rightmost: [0, 2]", SafeArrayGetLBound(sa, 2, &lb) == S_OK && SafeArrayGetUBound(sa, 2, &ub) == S_OK && lb == 0 && ub == 2);
        for (i = 10; i <= 11; ++i)
            for (j = 0; j <= 2; ++j) { idx[0] = i; idx[1] = j; val = i * 10 + j; SafeArrayPutElement(sa, idx, &val); }
        idx[0] = 11; idx[1] = 1; val = 0;
        U_CHECK("GetElement({11, 1}) = 111", SafeArrayGetElement(sa, idx, &val) == S_OK && val == 111);
        SafeArrayAccessData(sa, (void **)&raw);
        U_CHECK("memory order: leftmost index varies fastest (column-major)",
                raw[0] == 100 && raw[1] == 110 && raw[2] == 101 && raw[3] == 111 && raw[4] == 102 && raw[5] == 112);
        SafeArrayUnaccessData(sa);
        idx[0] = 12; idx[1] = 0;
        U_CHECK("out-of-range in dimension 1 is DISP_E_BADINDEX", SafeArrayGetElement(sa, idx, &val) == ST_BADINDEX);
        idx[0] = 10; idx[1] = 3;
        U_CHECK("out-of-range in dimension 2 is DISP_E_BADINDEX", SafeArrayGetElement(sa, idx, &val) == ST_BADINDEX);
        {
            SAFEARRAYBOUND nb = { 4, 0 };
            U_CHECK("Redim grows only the rightmost dimension: 8 elements", SafeArrayRedim(sa, &nb) == S_OK);
            idx[0] = 11; idx[1] = 3; val = -1;
            U_CHECK("...the new row is addressable and zero", SafeArrayGetElement(sa, idx, &val) == S_OK && val == 0);
            idx[0] = 10; idx[1] = 1;
            U_CHECK("...old elements survive", SafeArrayGetElement(sa, idx, &val) == S_OK && val == 101);
        }
        SafeArrayDestroy(sa);
    }
    {
        /* BSTR arrays own copies */
        SAFEARRAYBOUND b = { 3, 0 };
        SAFEARRAY *sa = SafeArrayCreate(VT_BSTR, 1, &b);
        BSTR s = mk("first"), got = 0;
        LONG i = 0;
        U_CHECK("BSTR array has FADF_BSTR and element size 8", sa && (sa->fFeatures & FADF_BSTR) && SafeArrayGetElemsize(sa) == 8);
        U_CHECK("PutElement(BSTR) stores a copy", SafeArrayPutElement(sa, &i, s) == S_OK && ((BSTR *)sa->pvData)[0] != s && wide_is(((BSTR *)sa->pvData)[0], "first"));
        SysFreeString(s);
        U_CHECK("the array survives the caller freeing its BSTR", wide_is(((BSTR *)sa->pvData)[0], "first"));
        U_CHECK("GetElement returns a fresh copy", SafeArrayGetElement(sa, &i, &got) == S_OK && got != ((BSTR *)sa->pvData)[0] && wide_is(got, "first"));
        SysFreeString(got);
        i = 1;
        s = mk("second");
        SafeArrayPutElement(sa, &i, s);
        SysFreeString(s);
        i = 1; s = mk("replaced");
        U_CHECK("overwriting an element frees the old string and stores the new one", SafeArrayPutElement(sa, &i, s) == S_OK && wide_is(((BSTR *)sa->pvData)[1], "replaced"));
        SysFreeString(s);
        i = 2;
        U_CHECK("an untouched element is NULL and reads back as NULL", SafeArrayGetElement(sa, &i, &got) == S_OK && got == 0);
        U_CHECK("PutElement(NULL BSTR) stores NULL", SafeArrayPutElement(sa, &i, 0) == S_OK && ((BSTR *)sa->pvData)[2] == 0);
        {
            SAFEARRAY *copy = 0;
            U_CHECK("SafeArrayCopy of a BSTR array is deep", SafeArrayCopy(sa, &copy) == S_OK && copy && copy != sa && ((BSTR *)copy->pvData)[0] != ((BSTR *)sa->pvData)[0] &&
                    wide_is(((BSTR *)copy->pvData)[0], "first") && wide_is(((BSTR *)copy->pvData)[1], "replaced") && ((BSTR *)copy->pvData)[2] == 0);
            U_CHECK("the copy has the same shape and type", SafeArrayGetDim(copy) == 1 && SafeArrayGetElemsize(copy) == 8 && (copy->fFeatures & FADF_BSTR));
            U_CHECK("destroying the copy leaves the original intact", SafeArrayDestroy(copy) == S_OK && wide_is(((BSTR *)sa->pvData)[0], "first"));
        }
        U_CHECK("SafeArrayDestroy of a BSTR array", SafeArrayDestroy(sa) == S_OK);
        {
            SAFEARRAY *n = 0;
            U_CHECK("SafeArrayCopy(NULL) yields NULL and S_OK", SafeArrayCopy(0, &n) == S_OK && n == 0);
        }
    }
    {
        /* VARIANT arrays */
        SAFEARRAYBOUND b = { 2, 0 };
        SAFEARRAY *sa = SafeArrayCreate(VT_VARIANT, 1, &b);
        VARIANT v, out;
        LONG i = 0;
        U_CHECK("VARIANT array element size = sizeof(VARIANT) = 24 on x64", sa && SafeArrayGetElemsize(sa) == 24 && sizeof(VARIANT) == 24 && (sa->fFeatures & FADF_VARIANT));
        VariantInit(&v); VariantInit(&out);
        V_VT(&v) = VT_BSTR; V_BSTR(&v) = mk("in a variant");
        U_CHECK("PutElement(VARIANT) copies the variant deeply", SafeArrayPutElement(sa, &i, &v) == S_OK && V_VT(&((VARIANT *)sa->pvData)[0]) == VT_BSTR &&
                V_BSTR(&((VARIANT *)sa->pvData)[0]) != V_BSTR(&v));
        VariantClear(&v);
        U_CHECK("GetElement(VARIANT) copies out", SafeArrayGetElement(sa, &i, &out) == S_OK && V_VT(&out) == VT_BSTR && wide_is(V_BSTR(&out), "in a variant"));
        VariantClear(&out);
        i = 1;
        U_CHECK("untouched VARIANT elements are VT_EMPTY", SafeArrayGetElement(sa, &i, &out) == S_OK && V_VT(&out) == VT_EMPTY);
        U_CHECK("PutElement(VARIANT, NULL) is E_INVALIDARG", SafeArrayPutElement(sa, &i, 0) == E_INVALIDARG);
        U_CHECK("SafeArrayDestroy clears the VARIANT elements", SafeArrayDestroy(sa) == S_OK);
        /* a VARIANT holding an array is cleared/copied deeply */
        {
            SAFEARRAYBOUND vb = { 3, 0 };
            SAFEARRAY *inner = SafeArrayCreate(VT_I2, 1, &vb);
            VARIANT a, c;
            SHORT *p = 0;
            LONG k = 1;
            SHORT sv = 99;
            SafeArrayPutElement(inner, &k, &sv);
            VariantInit(&a); VariantInit(&c);
            V_VT(&a) = VT_ARRAY | VT_I2;
            V_ARRAY(&a) = inner;
            U_CHECK("VariantCopy of a VT_ARRAY variant copies the array", VariantCopy(&c, &a) == S_OK && V_VT(&c) == (VT_ARRAY | VT_I2) && V_ARRAY(&c) != inner);
            SafeArrayAccessData(V_ARRAY(&c), (void **)&p);
            U_CHECK("...with equal contents", p[1] == 99);
            SafeArrayUnaccessData(V_ARRAY(&c));
            U_CHECK("VariantClear of a VT_ARRAY variant destroys the array", VariantClear(&c) == S_OK && V_VT(&c) == VT_EMPTY && VariantClear(&a) == S_OK);
        }
    }
    {
        /* vectors, manual descriptors, CopyData */
        SAFEARRAY *v = SafeArrayCreateVector(VT_UI1, 0, 8), *m = 0, *c = 0;
        LONG lb = -1, ub = -1, i;
        BYTE *raw = 0;
        U_CHECK("SafeArrayCreateVector(VT_UI1, 0, 8)", v && SafeArrayGetDim(v) == 1 && SafeArrayGetElemsize(v) == 1);
        U_CHECK("...bounds [0, 7]", SafeArrayGetLBound(v, 1, &lb) == S_OK && SafeArrayGetUBound(v, 1, &ub) == S_OK && lb == 0 && ub == 7);
        SafeArrayAccessData(v, (void **)&raw);
        for (i = 0; i < 8; ++i) raw[i] = (BYTE)(i * 3);
        SafeArrayUnaccessData(v);
        U_CHECK("SafeArrayCopy of a vector", SafeArrayCopy(v, &c) == S_OK && c && SafeArrayGetElemsize(c) == 1 && ((BYTE *)c->pvData)[5] == 15);
        SafeArrayDestroy(c);
        {
            SAFEARRAYBOUND b = { 8, 0 }, b2 = { 7, 0 };
            SAFEARRAY *same = SafeArrayCreate(VT_UI1, 1, &b), *other = SafeArrayCreate(VT_UI1, 1, &b2);
            U_CHECK("SafeArrayCopyData into an identically shaped array", SafeArrayCopyData(v, same) == S_OK && ((BYTE *)same->pvData)[7] == 21);
            U_CHECK("SafeArrayCopyData into a differently sized array is E_INVALIDARG", SafeArrayCopyData(v, other) == E_INVALIDARG);
            SafeArrayDestroy(same); SafeArrayDestroy(other);
        }
        SafeArrayDestroy(v);
        /* AllocDescriptorEx + AllocData + DestroyData + DestroyDescriptor */
        U_CHECK("SafeArrayAllocDescriptorEx(VT_I2, 1)", SafeArrayAllocDescriptorEx(VT_I2, 1, &m) == S_OK && m && m->cDims == 1 && m->cbElements == 2 && m->pvData == 0);
        m->rgsabound[0].cElements = 4; m->rgsabound[0].lLbound = 0;
        U_CHECK("SafeArrayAllocData allocates zeroed data", SafeArrayAllocData(m) == S_OK && m->pvData && ((SHORT *)m->pvData)[3] == 0);
        U_CHECK("SafeArrayDestroyData frees the data and NULLs pvData", SafeArrayDestroyData(m) == S_OK && m->pvData == 0);
        U_CHECK("SafeArrayDestroyDescriptor frees the descriptor", SafeArrayDestroyDescriptor(m) == S_OK);
        U_CHECK("SafeArrayAllocDescriptor(0 dims) is E_INVALIDARG", SafeArrayAllocDescriptor(0, &m) == E_INVALIDARG);
        {
            VARTYPE vt = 0;
            U_CHECK("a descriptor without FADF_HAVEVARTYPE reports its type from the FADF_BSTR flag", SafeArrayAllocDescriptor(1, &m) == S_OK && (m->fFeatures = FADF_BSTR, m->cbElements = 8,
                    SafeArrayGetVartype(m, &vt) == S_OK && vt == VT_BSTR));
            SafeArrayDestroyDescriptor(m);
        }
    }
    return u_finish("t_u_oleaut32");
}
