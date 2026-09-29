/* SPDX-License-Identifier: GPL-2.0-only
 * combase.dll: HSTRING (WindowsCreateString ... WindowsPromoteStringBuffer) and RoInitialize/RoUninitialize. Expected
 * values are the documented Windows Runtime string semantics (NULL HSTRING = empty string, reference-counted duplicates,
 * fast-pass strings living in the caller's HSTRING_HEADER, E_BOUNDS for bad substring ranges, ordinal comparison result
 * -1/0/1) and, for RoInitialize, the CoInitializeEx apartment results (checked against ole32's CoGetApartmentType). */
#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <roapi.h>
#include <winstring.h>
#include <objbase.h>
#include "u_check.h"

#define ST_BOUNDS ((HRESULT)0x8000000B)
#define ST_CHANGED_MODE ((HRESULT)0x80010106)

static int hs_is(HSTRING s, const char *lit)
{
    UINT32 n = 0, i;
    PCWSTR p = WindowsGetStringRawBuffer(s, &n);
    for (i = 0; i < n; ++i)
        if (!lit[i] || p[i] != (WCHAR)(unsigned char)lit[i]) return 0;
    return !lit[n] && p[n] == 0;
}

static HSTRING g_shared;
static volatile LONG g_bad;
static DWORD WINAPI dup_thread(LPVOID unused)
{
    int i;
    (void)unused;
    for (i = 0; i < 5000; ++i) {
        HSTRING d = 0;
        if (WindowsDuplicateString(g_shared, &d) != S_OK || d != g_shared) InterlockedIncrement((LONG *)&g_bad);
        if (WindowsGetStringLen(d) != 5) InterlockedIncrement((LONG *)&g_bad);
        WindowsDeleteString(d);
    }
    return 0;
}

int main(void)
{
    HSTRING s = 0, t = 0, u = 0;
    UINT32 n = 99;
    BOOL b = 5;
    INT32 cmp = 99;

    /* ---- creation / basic properties ---- */
    U_CHECK("WindowsCreateString(hello, 5)", WindowsCreateString(L"hello", 5, &s) == S_OK && s);
    U_CHECK("WindowsGetStringLen = 5", WindowsGetStringLen(s) == 5);
    U_CHECK("raw buffer is \"hello\", NUL-terminated, length out-parameter = 5", hs_is(s, "hello") && WindowsGetStringRawBuffer(s, &n) && n == 5);
    U_CHECK("WindowsGetStringRawBuffer accepts a NULL length pointer", WindowsGetStringRawBuffer(s, 0) != 0);
    { static const WCHAR hello_src[] = L"hello"; U_CHECK("the string is a copy (source buffer is not aliased)", WindowsCreateString(hello_src, 5, &t) == S_OK && WindowsGetStringRawBuffer(t, 0) != hello_src); WindowsDeleteString(t); t = 0; }
    U_CHECK("WindowsIsStringEmpty(non-empty) is FALSE", !WindowsIsStringEmpty(s));
    U_CHECK("WindowsStringHasEmbeddedNull(hello) is FALSE", WindowsStringHasEmbeddedNull(s, &b) == S_OK && b == FALSE);
    U_CHECK("WindowsDeleteString frees", WindowsDeleteString(s) == S_OK);
    s = 0;
    U_CHECK("WindowsCreateString(src, 0) yields NULL (the empty string)", WindowsCreateString(L"abc", 0, &s) == S_OK && s == 0);
    U_CHECK("WindowsCreateString(NULL, 0) yields NULL", WindowsCreateString(0, 0, &s) == S_OK && s == 0);
    U_CHECK("WindowsCreateString(NULL, 3) is E_POINTER", WindowsCreateString(0, 3, &s) == E_POINTER);
    U_CHECK("WindowsCreateString with a NULL output is E_INVALIDARG", WindowsCreateString(L"a", 1, 0) == E_INVALIDARG);
    U_CHECK("NULL HSTRING: empty, length 0, raw buffer L\"\"", WindowsIsStringEmpty(0) && WindowsGetStringLen(0) == 0 && WindowsGetStringRawBuffer(0, &n) && n == 0 && *WindowsGetStringRawBuffer(0, 0) == 0);
    U_CHECK("WindowsDeleteString(NULL) is S_OK", WindowsDeleteString(0) == S_OK);
    U_CHECK("embedded NUL characters are kept and detected", WindowsCreateString(L"a\0b", 3, &s) == S_OK && WindowsGetStringLen(s) == 3 && WindowsStringHasEmbeddedNull(s, &b) == S_OK && b == TRUE);
    WindowsDeleteString(s);
    U_CHECK("WindowsStringHasEmbeddedNull(NULL string) is FALSE", WindowsStringHasEmbeddedNull(0, &b) == S_OK && b == FALSE);
    U_CHECK("WindowsStringHasEmbeddedNull(NULL output) is E_INVALIDARG", WindowsStringHasEmbeddedNull(0, 0) == E_INVALIDARG);

    /* ---- reference counting ---- */
    WindowsCreateString(L"shared", 6, &s);
    U_CHECK("WindowsDuplicateString of a heap string returns the same handle", WindowsDuplicateString(s, &t) == S_OK && t == s);
    U_CHECK("deleting one reference keeps the string alive", WindowsDeleteString(t) == S_OK && hs_is(s, "shared"));
    U_CHECK("WindowsDuplicateString(NULL) yields NULL", WindowsDuplicateString(0, &u) == S_OK && u == 0);
    U_CHECK("WindowsDuplicateString with NULL output is E_INVALIDARG", WindowsDuplicateString(s, 0) == E_INVALIDARG);
    WindowsDeleteString(s);

    /* ---- fast-pass (reference) strings ---- */
    {
        static const WCHAR src[] = L"reference me";
        HSTRING_HEADER hdr;
        HSTRING r = 0, d = 0;
        U_CHECK("sizeof(HSTRING_HEADER) is 24 on x64 (documented)", sizeof(HSTRING_HEADER) == 24);
        U_CHECK("WindowsCreateStringReference", WindowsCreateStringReference(src, 12, &hdr, &r) == S_OK && r && (void *)r == (void *)&hdr);
        U_CHECK("the reference string exposes the caller's buffer and its length", WindowsGetStringRawBuffer(r, &n) == src && n == 12 && WindowsGetStringLen(r) == 12);
        U_CHECK("WindowsDuplicateString of a reference makes an independent copy", WindowsDuplicateString(r, &d) == S_OK && d != r && WindowsGetStringRawBuffer(d, 0) != src && hs_is(d, "reference me"));
        U_CHECK("WindowsDeleteString of a reference string is a no-op", WindowsDeleteString(r) == S_OK && hs_is(r, "reference me"));
        WindowsDeleteString(d);
        U_CHECK("WindowsCreateStringReference(src, 0) yields NULL", WindowsCreateStringReference(src, 0, &hdr, &r) == S_OK && r == 0);
        U_CHECK("WindowsCreateStringReference(NULL, 3, ...) is E_POINTER", WindowsCreateStringReference(0, 3, &hdr, &r) == E_POINTER);
        U_CHECK("WindowsCreateStringReference without a header is E_INVALIDARG", WindowsCreateStringReference(src, 12, 0, &r) == E_INVALIDARG);
    }

    /* ---- comparison ---- */
    {
        static const struct { const WCHAR *a, *b; INT32 expect; const char *name; } c[] = {
            { L"abc", L"abc", 0, "equal strings compare 0" },
            { L"abc", L"abd", -1, "abc < abd" },
            { L"b", L"a", 1, "b > a" },
            { L"ab", L"abc", -1, "a prefix is smaller" },
            { L"abc", L"ab", 1, "the longer string is larger" },
            { L"a", L"A", 1, "the comparison is ordinal (case-sensitive): 'a' (0x61) > 'A' (0x41)" },
            { L"\xd7ff", L"\xe000", -1, "compares UTF-16 code units, not code points" },
        };
        unsigned i;
        for (i = 0; i < sizeof c / sizeof c[0]; ++i) {
            HSTRING x = 0, y = 0;
            WindowsCreateString(c[i].a, (UINT32)lstrlenW(c[i].a), &x);
            WindowsCreateString(c[i].b, (UINT32)lstrlenW(c[i].b), &y);
            cmp = 99;
            U_CHECK(c[i].name, WindowsCompareStringOrdinal(x, y, &cmp) == S_OK && cmp == c[i].expect);
            WindowsDeleteString(x); WindowsDeleteString(y);
        }
        WindowsCreateString(L"a", 1, &s);
        U_CHECK("NULL equals NULL", WindowsCompareStringOrdinal(0, 0, &cmp) == S_OK && cmp == 0);
        U_CHECK("NULL < \"a\" and \"a\" > NULL", WindowsCompareStringOrdinal(0, s, &cmp) == S_OK && cmp == -1 && WindowsCompareStringOrdinal(s, 0, &cmp) == S_OK && cmp == 1);
        U_CHECK("same handle compares 0", WindowsCompareStringOrdinal(s, s, &cmp) == S_OK && cmp == 0);
        U_CHECK("NULL result pointer is E_INVALIDARG", WindowsCompareStringOrdinal(s, s, 0) == E_INVALIDARG);
        WindowsDeleteString(s);
    }

    /* ---- concatenation and substrings ---- */
    {
        HSTRING a = 0, bb = 0, r = 0;
        WindowsCreateString(L"foo", 3, &a);
        WindowsCreateString(L"bar", 3, &bb);
        U_CHECK("WindowsConcatString(foo, bar) = foobar", WindowsConcatString(a, bb, &r) == S_OK && hs_is(r, "foobar") && WindowsGetStringLen(r) == 6);
        WindowsDeleteString(r);
        U_CHECK("Concat(NULL, bar) is a duplicate of bar", WindowsConcatString(0, bb, &r) == S_OK && hs_is(r, "bar"));
        WindowsDeleteString(r);
        U_CHECK("Concat(foo, NULL) is a duplicate of foo", WindowsConcatString(a, 0, &r) == S_OK && hs_is(r, "foo"));
        WindowsDeleteString(r);
        U_CHECK("Concat(NULL, NULL) is NULL", WindowsConcatString(0, 0, &r) == S_OK && r == 0);
        U_CHECK("Concat with a NULL output is E_INVALIDARG", WindowsConcatString(a, bb, 0) == E_INVALIDARG);
        WindowsDeleteString(a); WindowsDeleteString(bb);

        WindowsCreateString(L"hello", 5, &a);
        U_CHECK("WindowsSubstring(hello, 1) = ello", WindowsSubstring(a, 1, &r) == S_OK && hs_is(r, "ello"));
        WindowsDeleteString(r);
        U_CHECK("WindowsSubstring(hello, 0) = hello", WindowsSubstring(a, 0, &r) == S_OK && hs_is(r, "hello"));
        WindowsDeleteString(r);
        U_CHECK("WindowsSubstring(hello, 5) is the empty string (NULL)", WindowsSubstring(a, 5, &r) == S_OK && r == 0);
        U_CHECK("WindowsSubstring(hello, 6) is E_BOUNDS", WindowsSubstring(a, 6, &r) == ST_BOUNDS && r == 0);
        U_CHECK("WindowsSubstringWithSpecifiedLength(hello, 1, 3) = ell", WindowsSubstringWithSpecifiedLength(a, 1, 3, &r) == S_OK && hs_is(r, "ell"));
        WindowsDeleteString(r);
        U_CHECK("WindowsSubstringWithSpecifiedLength(hello, 2, 4) is E_BOUNDS", WindowsSubstringWithSpecifiedLength(a, 2, 4, &r) == ST_BOUNDS);
        U_CHECK("WindowsSubstringWithSpecifiedLength(hello, 5, 0) is NULL", WindowsSubstringWithSpecifiedLength(a, 5, 0, &r) == S_OK && r == 0);
        U_CHECK("WindowsSubstring(NULL, 0) is NULL, (NULL, 1) is E_BOUNDS", WindowsSubstring(0, 0, &r) == S_OK && r == 0 && WindowsSubstring(0, 1, &r) == ST_BOUNDS);
        WindowsDeleteString(a);
    }

    /* ---- preallocated buffers ---- */
    {
        WCHAR *buf = 0;
        HSTRING_BUFFER hb = 0;
        HSTRING r = 0;
        U_CHECK("WindowsPreallocateStringBuffer(4)", WindowsPreallocateStringBuffer(4, &buf, &hb) == S_OK && buf && hb);
        buf[0] = 'w'; buf[1] = 'x'; buf[2] = 'y'; buf[3] = 'z';
        U_CHECK("WindowsPromoteStringBuffer yields the immutable string", WindowsPromoteStringBuffer(hb, &r) == S_OK && hs_is(r, "wxyz") && WindowsGetStringLen(r) == 4);
        WindowsDeleteString(r);
        buf = 0; hb = 0;
        U_CHECK("WindowsPreallocateStringBuffer(3) then WindowsDeleteStringBuffer", WindowsPreallocateStringBuffer(3, &buf, &hb) == S_OK && WindowsDeleteStringBuffer(hb) == S_OK);
        U_CHECK("WindowsPreallocateStringBuffer(0): no buffer, promotes to NULL", WindowsPreallocateStringBuffer(0, &buf, &hb) == S_OK && hb == 0 && WindowsPromoteStringBuffer(hb, &r) == S_OK && r == 0);
        U_CHECK("WindowsDeleteStringBuffer(NULL) is S_OK", WindowsDeleteStringBuffer(0) == S_OK);
    }

    /* ---- reference counting is atomic across threads ---- */
    {
        HANDLE th[4];
        int i, ok = 1;
        WindowsCreateString(L"hello", 5, &g_shared);
        for (i = 0; i < 4; ++i) th[i] = CreateThread(0, 0, dup_thread, 0, 0, 0);
        for (i = 0; i < 4; ++i) { if (WaitForSingleObject(th[i], 60000) != WAIT_OBJECT_0) ok = 0; CloseHandle(th[i]); }
        U_CHECK("4 threads x 5000 duplicate/delete pairs finished", ok);
        U_CHECK("no thread saw a wrong handle or length", g_bad == 0);
        U_CHECK("the string is intact after 20000 balanced duplicate/delete pairs", hs_is(g_shared, "hello"));
        U_CHECK("the last reference frees it", WindowsDeleteString(g_shared) == S_OK);
    }

    /* ---- RoInitialize / RoUninitialize ---- */
    {
        APTTYPE t = (APTTYPE)-9;
        APTTYPEQUALIFIER q = (APTTYPEQUALIFIER)-9;
        U_CHECK("RoInitialize with an undefined type is E_INVALIDARG", RoInitialize((RO_INIT_TYPE)5) == E_INVALIDARG);
        U_CHECK("RoInitialize(RO_INIT_MULTITHREADED) is S_OK", RoInitialize(RO_INIT_MULTITHREADED) == S_OK);
        U_CHECK("the thread is now in the MTA (ole32 agrees)", CoGetApartmentType(&t, &q) == S_OK && t == APTTYPE_MTA);
        U_CHECK("a second RoInitialize(MTA) is S_FALSE", RoInitialize(RO_INIT_MULTITHREADED) == S_FALSE);
        U_CHECK("RoInitialize(RO_INIT_SINGLETHREADED) on an MTA thread is RPC_E_CHANGED_MODE", RoInitialize(RO_INIT_SINGLETHREADED) == ST_CHANGED_MODE);
        RoUninitialize();
        RoUninitialize();
        U_CHECK("balanced RoUninitialize leaves the apartment", CoGetApartmentType(&t, &q) == (HRESULT)0x800401F0);
        U_CHECK("RoInitialize(RO_INIT_SINGLETHREADED) is S_OK and makes the main STA", RoInitialize(RO_INIT_SINGLETHREADED) == S_OK && CoGetApartmentType(&t, &q) == S_OK && t == APTTYPE_MAINSTA);
        RoUninitialize();
        U_CHECK("...and RoUninitialize leaves it", CoGetApartmentType(&t, &q) == (HRESULT)0x800401F0);
    }
    return u_finish("t_u_combase");
}
