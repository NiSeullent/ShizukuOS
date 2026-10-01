/* SPDX-License-Identifier: GPL-2.0-only
 * Shizuku checks of tridentrt.dll: VARIANT conversions (Wine's oleaut32 variant.c/vartype.c compiled into tridentrt,
 * over the BSTR/SAFEARRAY allocator of the Shizuku oleaut32). Expected values are Windows' (the en-US ones Wine's
 * vartype.c tests use, e.g. test_VarBstrFromR8 and test_VarBstrFromDate):
 *  - numbers to text: VariantChangeTypeEx VT_R8 -> VT_BSTR ("1.5"), VarBstrFromR8/R4/I4, VT_BOOL -> "True"/"False"
 *    (strings from tridentrt's resources);
 *  - text to numbers: VarI4FromStr / VT_BSTR -> VT_I4 incl. rounding, type mismatch and overflow, VarR8FromStr;
 *  - dates: SystemTimeToVariantTime, VariantTimeToSystemTime, VarUdateFromDate/VarDateFromUdate, VarBstrFromDate,
 *    VarDateFromStr, VT_DATE <-> VT_BSTR, DosDateTimeToVariantTime;
 *  - BSTR <-> VT_ARRAY|VT_UI1 (BstrFromVector/VectorFromBstr), VarCmp, VarAdd, VarCat.
 */
#include <stdarg.h>
#include <stdio.h>
#include <math.h>
#include "windef.h"
#include "winbase.h"
#include "objbase.h"
#include "oleauto.h"
#include "wine/test.h"

#define EN_US MAKELCID(MAKELANGID(LANG_ENGLISH, SUBLANG_ENGLISH_US), SORT_DEFAULT)

static void expect_bstr(HRESULT hr, BSTR b, const WCHAR *want, const char *what)
{
    ok(hr == S_OK && b && !lstrcmpW(b, want), "%s: hr %#lx, got %s, expected %s\n", what, hr, wine_dbgstr_w(b),
       wine_dbgstr_w(want));
    SysFreeString(b);
}

static void test_to_text(void)
{
    static const struct { double val; const WCHAR *text; } r8[] =
    {
        { 1.5, L"1.5" }, { 0.56789, L"0.56789" }, { 5.6789e-12, L"5.6789E-12" }, { 999999999999999.0, L"999999999999999" },
        { 1.0e15, L"1E+15" }, { 1.234e16, L"1.234E+16" }, { 3.141592653589793, L"3.14159265358979" },
        { 12.345678901234567, L"12.3456789012346" }, { -0.25, L"-0.25" },
    };
    VARIANT src, dst;
    BSTR b;
    unsigned int i;
    HRESULT hr;

    VariantInit(&src);
    VariantInit(&dst);
    V_VT(&src) = VT_R8;
    V_R8(&src) = 1.5;
    hr = VariantChangeTypeEx(&dst, &src, EN_US, 0, VT_BSTR);
    ok(hr == S_OK && V_VT(&dst) == VT_BSTR && !lstrcmpW(V_BSTR(&dst), L"1.5"), "VT_R8 1.5 -> VT_BSTR: %#lx %s\n", hr,
       V_VT(&dst) == VT_BSTR ? wine_dbgstr_w(V_BSTR(&dst)) : "");
    VariantClear(&dst);

    for (i = 0; i < ARRAY_SIZE(r8); i++)
    {
        b = NULL;
        hr = VarBstrFromR8(r8[i].val, EN_US, 0, &b);
        expect_bstr(hr, b, r8[i].text, "VarBstrFromR8");
    }
    b = NULL;
    hr = VarBstrFromR4(1.5f, EN_US, 0, &b);
    expect_bstr(hr, b, L"1.5", "VarBstrFromR4(1.5)");
    b = NULL;
    hr = VarBstrFromR4(0.1f, EN_US, 0, &b);
    expect_bstr(hr, b, L"0.1", "VarBstrFromR4(0.1)");
    b = NULL;
    hr = VarBstrFromI4(-42, EN_US, 0, &b);
    expect_bstr(hr, b, L"-42", "VarBstrFromI4(-42)");
    b = NULL;
    hr = VarBstrFromBool(VARIANT_TRUE, EN_US, 0, &b);
    expect_bstr(hr, b, L"True", "VarBstrFromBool(TRUE)");
    b = NULL;
    hr = VarBstrFromBool(VARIANT_FALSE, EN_US, 0, &b);
    expect_bstr(hr, b, L"False", "VarBstrFromBool(FALSE)");

    V_VT(&src) = VT_I4;
    V_I4(&src) = 2147483647;
    hr = VariantChangeTypeEx(&dst, &src, EN_US, 0, VT_BSTR);
    ok(hr == S_OK && V_VT(&dst) == VT_BSTR && !lstrcmpW(V_BSTR(&dst), L"2147483647"), "VT_I4 -> VT_BSTR: %#lx\n", hr);
    VariantClear(&dst);
}

static void test_from_text(void)
{
    VARIANT_BOOL bval;
    VARIANT src, dst;
    LONG l;
    double d;
    HRESULT hr;

    hr = VarI4FromStr((OLECHAR *)L"123", EN_US, 0, &l);
    ok(hr == S_OK && l == 123, "VarI4FromStr(123): %#lx %ld\n", hr, l);
    hr = VarI4FromStr((OLECHAR *)L"-17", EN_US, 0, &l);
    ok(hr == S_OK && l == -17, "VarI4FromStr(-17): %#lx %ld\n", hr, l);
    hr = VarI4FromStr((OLECHAR *)L"2.5", EN_US, 0, &l);
    ok(hr == S_OK && l == 2, "VarI4FromStr(2.5) rounds to even: %#lx %ld\n", hr, l);
    hr = VarI4FromStr((OLECHAR *)L"3.5", EN_US, 0, &l);
    ok(hr == S_OK && l == 4, "VarI4FromStr(3.5) rounds to even: %#lx %ld\n", hr, l);
    hr = VarI4FromStr((OLECHAR *)L"abc", EN_US, 0, &l);
    ok(hr == DISP_E_TYPEMISMATCH, "VarI4FromStr(abc): %#lx\n", hr);
    hr = VarI4FromStr((OLECHAR *)L"4294967296", EN_US, 0, &l);
    ok(hr == DISP_E_OVERFLOW, "VarI4FromStr(4294967296): %#lx\n", hr);
    hr = VarR8FromStr((OLECHAR *)L"2.5e3", EN_US, 0, &d);
    ok(hr == S_OK && d == 2500.0, "VarR8FromStr(2.5e3): %#lx\n", hr);
    hr = VarBoolFromStr((OLECHAR *)L"True", EN_US, 0, &bval);
    ok(hr == S_OK && bval == VARIANT_TRUE, "VarBoolFromStr(True): %#lx %d\n", hr, bval);

    VariantInit(&src);
    VariantInit(&dst);
    V_VT(&src) = VT_BSTR;
    V_BSTR(&src) = SysAllocString(L"77");
    hr = VariantChangeTypeEx(&dst, &src, EN_US, 0, VT_I4);
    ok(hr == S_OK && V_VT(&dst) == VT_I4 && V_I4(&dst) == 77, "VT_BSTR 77 -> VT_I4: %#lx\n", hr);
    hr = VariantChangeTypeEx(&dst, &src, EN_US, 0, VT_R8);
    ok(hr == S_OK && V_VT(&dst) == VT_R8 && V_R8(&dst) == 77.0, "VT_BSTR 77 -> VT_R8: %#lx\n", hr);
    VariantClear(&src);
}

static void test_dates(void)
{
    SYSTEMTIME st = { 2000, 1, 0, 1, 12, 0, 0, 0 }, out;
    UDATE ud;
    VARIANT src, dst;
    DATE date;
    BSTR b;
    HRESULT hr;
    INT ret;

    date = 0;
    ret = SystemTimeToVariantTime(&st, &date);
    ok(ret && date == 36526.5, "SystemTimeToVariantTime: %d %.6f\n", ret, date);
    memset(&out, 0, sizeof(out));
    ret = VariantTimeToSystemTime(36526.5, &out);
    ok(ret && out.wYear == 2000 && out.wMonth == 1 && out.wDay == 1 && out.wHour == 12 && out.wMinute == 0 &&
       out.wDayOfWeek == 6, "VariantTimeToSystemTime: %d %u-%u-%u %u:%u dow %u\n", ret, out.wYear, out.wMonth, out.wDay,
       out.wHour, out.wMinute, out.wDayOfWeek);
    memset(&ud, 0, sizeof(ud));
    hr = VarUdateFromDate(3339.34, 0, &ud);
    ok(hr == S_OK && ud.st.wYear == 1909 && ud.st.wMonth == 2 && ud.st.wDay == 20 && ud.st.wHour == 8 &&
       ud.st.wMinute == 9 && ud.st.wSecond == 36 && ud.wDayOfYear == 51, "VarUdateFromDate: %#lx %u-%u-%u %u:%u:%u yday %u\n",
       hr, ud.st.wYear, ud.st.wMonth, ud.st.wDay, ud.st.wHour, ud.st.wMinute, ud.st.wSecond, ud.wDayOfYear);
    date = 0;
    hr = VarDateFromUdate(&ud, 0, &date);
    ok(hr == S_OK && fabs(date - 3339.34) < 1e-6, "VarDateFromUdate: %#lx %.8f\n", hr, date);
    ret = DosDateTimeToVariantTime(0x2821, 0x4a20, &date);          /* 2000-01-01 09:17:00 */
    ok(ret && fabs(date - (36526.0 + (9 * 60 + 17) / 1440.0)) < 1e-6, "DosDateTimeToVariantTime: %d %.8f\n", ret, date);

    b = NULL;
    hr = VarBstrFromDate(365.0, EN_US, LOCALE_NOUSEROVERRIDE, &b);
    expect_bstr(hr, b, L"12/30/1900", "VarBstrFromDate(365)");
    b = NULL;
    hr = VarBstrFromDate(3339.34, EN_US, LOCALE_NOUSEROVERRIDE, &b);
    expect_bstr(hr, b, L"2/20/1909 8:09:36 AM", "VarBstrFromDate(3339.34)");
    date = 0;
    hr = VarDateFromStr((OLECHAR *)L"2/20/1909 8:09:36 AM", EN_US, 0, &date);
    ok(hr == S_OK && fabs(date - 3339.34) < 1e-6, "VarDateFromStr: %#lx %.8f\n", hr, date);

    VariantInit(&src);
    VariantInit(&dst);
    V_VT(&src) = VT_DATE;
    V_DATE(&src) = 36526.5;
    hr = VariantChangeTypeEx(&dst, &src, EN_US, 0, VT_BSTR);
    ok(hr == S_OK && V_VT(&dst) == VT_BSTR && !lstrcmpW(V_BSTR(&dst), L"1/1/2000 12:00:00 PM"), "VT_DATE -> VT_BSTR: %#lx %s\n",
       hr, V_VT(&dst) == VT_BSTR ? wine_dbgstr_w(V_BSTR(&dst)) : "");
    hr = VariantChangeTypeEx(&src, &dst, EN_US, 0, VT_DATE);
    ok(hr == S_OK && V_VT(&src) == VT_DATE && V_DATE(&src) == 36526.5, "VT_BSTR -> VT_DATE: %#lx %.6f\n", hr, V_DATE(&src));
    VariantClear(&dst);
}

static void test_misc(void)
{
    VARIANT a, b, r;
    HRESULT hr;

    /* BSTR <-> byte vector */
    VariantInit(&a);
    VariantInit(&r);
    V_VT(&a) = VT_BSTR;
    V_BSTR(&a) = SysAllocString(L"AB");
    hr = VariantChangeType(&r, &a, 0, VT_ARRAY | VT_UI1);
    ok(hr == S_OK && V_VT(&r) == (VT_ARRAY | VT_UI1), "VT_BSTR -> VT_ARRAY|VT_UI1: %#lx vt %#x\n", hr, V_VT(&r));
    if (hr == S_OK)
    {
        const BYTE *p = V_ARRAY(&r)->pvData;
        ok(V_ARRAY(&r)->rgsabound[0].cElements == 4 && p[0] == 'A' && p[1] == 0 && p[2] == 'B' && p[3] == 0,
           "vector contents\n");
        VariantClear(&a);
        hr = VariantChangeType(&a, &r, 0, VT_BSTR);
        ok(hr == S_OK && V_VT(&a) == VT_BSTR && !lstrcmpW(V_BSTR(&a), L"AB"), "VT_ARRAY|VT_UI1 -> VT_BSTR: %#lx\n", hr);
        VariantClear(&r);
    }
    VariantClear(&a);

    V_VT(&a) = VT_I4;
    V_I4(&a) = 5;
    V_VT(&b) = VT_R8;
    V_R8(&b) = 5.0;
    ok(VarCmp(&a, &b, EN_US, 0) == VARCMP_EQ, "VarCmp(5, 5.0)\n");
    V_R8(&b) = 0.5;
    hr = VarAdd(&a, &b, &r);
    ok(hr == S_OK && V_VT(&r) == VT_R8 && V_R8(&r) == 5.5, "VarAdd(5, 0.5): %#lx vt %d\n", hr, V_VT(&r));
    V_VT(&a) = VT_BSTR;
    V_BSTR(&a) = SysAllocString(L"a");
    V_VT(&b) = VT_BSTR;
    V_BSTR(&b) = SysAllocString(L"b");
    ok(VarCmp(&a, &b, EN_US, 0) == VARCMP_LT, "VarCmp(a, b)\n");
    VariantClear(&b);
    V_VT(&b) = VT_I4;
    V_I4(&b) = 1;
    VariantInit(&r);
    hr = VarCat(&a, &b, &r);
    ok(hr == S_OK && V_VT(&r) == VT_BSTR && !lstrcmpW(V_BSTR(&r), L"a1"), "VarCat(a, 1): %#lx\n", hr);
    VariantClear(&r);
    VariantClear(&a);
}

START_TEST(variant)
{
    test_to_text();
    test_from_text();
    test_dates();
    test_misc();
}
