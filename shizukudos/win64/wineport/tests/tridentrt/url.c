/* SPDX-License-Identifier: GPL-2.0-only
 * Shizuku checks of tridentrt.dll: the shlwapi and kernel32 functions it adds for the browser modules.
 *  - URL functions (Wine's kernelbase/path.c): UrlCanonicalizeW, UrlCombineW, UrlCreateFromPathW, PathCreateFromUrlW
 *    (file URLs), PathIsURLW, UrlIsW, UrlGetPartW, ParseURLW, UrlEscapeW/UrlUnescapeW, UrlApplySchemeW (its guesses
 *    come from the ...\CurrentVersion\URL\Prefixes keys tridentrt seeds), UrlCompareW, the ANSI UrlCanonicalizeA /
 *    UrlCombineA wininet uses. Expected values are from Wine's shlwapi url.c/path.c tests (Windows behaviour);
 *  - SHRegOpenUSKeyW/SHRegQueryUSValueW/SHRegGetUSValueW/SHRegEnumUSValueW/SHRegCloseUSKey (HKCU before HKLM),
 *    IStream_Read/IStream_Write, StrStrIA, GetMIMETypeSubKeyW, SHStrDupW;
 *  - kernel32: MulDiv, IdnToAscii/IdnToUnicode (Wine's kernel32 locale.c test vectors), DosDateTimeToFileTime /
 *    FileTimeToDosDateTime, GetComputerNameExA.
 */
#include <stdarg.h>
#include <stdio.h>
#include <string.h>
#include "windef.h"
#include "winbase.h"
#include "winreg.h"
#include "winnls.h"
#include "objbase.h"
#include "shlwapi.h"
#include "wine/test.h"

BOOL WINAPI GetMIMETypeSubKeyW(const WCHAR *type, WCHAR *buffer, DWORD len);
HRESULT WINAPI IStream_Read(IStream *stream, void *data, ULONG size);
HRESULT WINAPI IStream_Write(IStream *stream, const void *data, ULONG size);
HRESULT WINAPI ShzTridentRegister(void);

static void check_url(HRESULT hr, const WCHAR *got, DWORD len, const WCHAR *want, const char *what)
{
    ok(hr == S_OK && !lstrcmpW(got, want) && len == (DWORD)lstrlenW(want), "%s: hr %#lx len %lu, got %s, expected %s\n",
       what, hr, len, wine_dbgstr_w(got), wine_dbgstr_w(want));
}

static void test_urls(void)
{
    static const struct { const WCHAR *base, *rel, *want; } combine[] =
    {
        { L"http://www.winehq.org/tests", L"tests1", L"http://www.winehq.org/tests1" },
        { L"http://www.winehq.org/tests/", L"../tests3", L"http://www.winehq.org/tests3" },
        { L"http://www.winehq.org/tests/test1", L"test2", L"http://www.winehq.org/tests/test2" },
        { L"http://www.winehq.org/tests/../tests/", L"/tests6/..", L"http://www.winehq.org/" },
        { L"http://www.winehq.org/test13#aaa", L"#bbb", L"http://www.winehq.org/test13#bbb" },
        { L"file:///C:/SHZ/TESTS/page.htm", L"img/a.png", L"file:///C:/SHZ/TESTS/img/a.png" },
    };
    static const struct { const WCHAR *url, *path; } from_url[] =
    {
        { L"file:///c:/foo/bar", L"c:\\foo\\bar" },
        { L"file:///c:/foo%20ba%2fr", L"c:\\foo ba/r" },
        { L"file://localhost/c:/foo/bar", L"c:\\foo\\bar" },
        { L"file:c|/foo/bar", L"c:\\foo\\bar" },
        { L"file:///C:/SHZ/TESTS/a%20b.htm", L"C:\\SHZ\\TESTS\\a b.htm" },
    };
    WCHAR buf[2084];
    char bufA[2084];
    PARSEDURLW parsed;
    DWORD len;
    unsigned int i;
    HRESULT hr;

    hr = ShzTridentRegister();                      /* the URL prefix keys UrlApplySchemeW reads (ieframe.rgs) */
    ok(hr == S_OK, "ShzTridentRegister: %#lx\n", hr);
    len = ARRAY_SIZE(buf);
    hr = UrlCanonicalizeW(L"http://www.winehq.org/a/b/../c/./d", buf, &len, 0);
    check_url(hr, buf, len, L"http://www.winehq.org/a/c/d", "UrlCanonicalizeW(dots)");
    len = ARRAY_SIZE(buf);
    hr = UrlCanonicalizeW(L"file:///c:/tests/foo%20bar", buf, &len, URL_UNESCAPE);
    check_url(hr, buf, len, L"file:///c:/tests/foo bar", "UrlCanonicalizeW(URL_UNESCAPE)");
    len = ARRAY_SIZE(buf);
    hr = UrlCanonicalizeW(L"file:///c:/tests/foo%20bar", buf, &len, URL_FILE_USE_PATHURL);
    check_url(hr, buf, len, L"file://c:\\tests\\foo bar", "UrlCanonicalizeW(URL_FILE_USE_PATHURL)");
    len = 5;
    hr = UrlCanonicalizeW(L"http://www.winehq.org/", buf, &len, 0);
    ok(hr == E_POINTER && len == 23, "UrlCanonicalizeW with a short buffer: %#lx %lu\n", hr, len);
    len = sizeof(bufA);
    hr = UrlCanonicalizeA("http://www.winehq.org/a/b/../c", bufA, &len, 0);
    ok(hr == S_OK && !strcmp(bufA, "http://www.winehq.org/a/c"), "UrlCanonicalizeA: %#lx %s\n", hr, bufA);

    for (i = 0; i < ARRAY_SIZE(combine); i++)
    {
        len = ARRAY_SIZE(buf);
        hr = UrlCombineW(combine[i].base, combine[i].rel, buf, &len, 0);
        check_url(hr, buf, len, combine[i].want, "UrlCombineW");
    }
    len = sizeof(bufA);
    hr = UrlCombineA("http://www.winehq.org/tests/", "../tests3", bufA, &len, 0);
    ok(hr == S_OK && !strcmp(bufA, "http://www.winehq.org/tests3"), "UrlCombineA: %#lx %s\n", hr, bufA);

    for (i = 0; i < ARRAY_SIZE(from_url); i++)
    {
        len = ARRAY_SIZE(buf);
        hr = PathCreateFromUrlW(from_url[i].url, buf, &len, 0);
        check_url(hr, buf, len, from_url[i].path, "PathCreateFromUrlW");
    }
    len = ARRAY_SIZE(buf);
    hr = UrlCreateFromPathW(L"c:\\foo\\foo bar", buf, &len, 0);
    check_url(hr, buf, len, L"file:///c:/foo/foo%20bar", "UrlCreateFromPathW");
    len = ARRAY_SIZE(buf);
    hr = UrlCreateFromPathW(L"file:///c:/foo/bar", buf, &len, 0);
    ok(hr == S_FALSE && !lstrcmpW(buf, L"file:///c:/foo/bar"), "UrlCreateFromPathW(URL): %#lx %s\n", hr, wine_dbgstr_w(buf));

    ok(PathIsURLW(L"http://www.winehq.org"), "PathIsURLW(http)\n");
    ok(PathIsURLW(L"file:///c:/x"), "PathIsURLW(file)\n");
    ok(!PathIsURLW(L"c:\\foo\\bar"), "PathIsURLW(path)\n");
    ok(UrlIsW(L"file:///c:/x", URLIS_FILEURL), "UrlIsW(URLIS_FILEURL)\n");
    ok(!UrlIsW(L"http://x/", URLIS_FILEURL), "UrlIsW(http, URLIS_FILEURL)\n");

    len = ARRAY_SIZE(buf);
    hr = UrlGetPartW(L"http://foo:bar@localhost:21/internal.php?query=x&return=y", buf, &len, URL_PART_HOSTNAME, 0);
    check_url(hr, buf, len, L"localhost", "UrlGetPartW(HOSTNAME)");
    len = ARRAY_SIZE(buf);
    hr = UrlGetPartW(L"http://foo:bar@localhost:21/internal.php?query=x&return=y", buf, &len, URL_PART_PORT, 0);
    check_url(hr, buf, len, L"21", "UrlGetPartW(PORT)");
    len = ARRAY_SIZE(buf);
    hr = UrlGetPartW(L"http://foo:bar@localhost:21/internal.php?query=x&return=y", buf, &len, URL_PART_SCHEME, 0);
    check_url(hr, buf, len, L"http", "UrlGetPartW(SCHEME)");

    memset(&parsed, 0, sizeof(parsed));
    parsed.cbSize = sizeof(parsed);
    hr = ParseURLW(L"http://www.winehq.org/", &parsed);
    ok(hr == S_OK && parsed.nScheme == URL_SCHEME_HTTP && parsed.cchProtocol == 4 && parsed.cchSuffix == 17,
       "ParseURLW: %#lx scheme %u protocol %u suffix %u\n", hr, parsed.nScheme, parsed.cchProtocol, parsed.cchSuffix);

    len = ARRAY_SIZE(buf);
    hr = UrlEscapeW(L"http://www.winehq.org/a b%c", buf, &len, 0);            /* '%' is kept unless asked for */
    check_url(hr, buf, len, L"http://www.winehq.org/a%20b%c", "UrlEscapeW");
    len = ARRAY_SIZE(buf);
    hr = UrlEscapeW(L"http://www.winehq.org/a b%c", buf, &len, URL_ESCAPE_PERCENT);
    check_url(hr, buf, len, L"http://www.winehq.org/a%20b%25c", "UrlEscapeW(URL_ESCAPE_PERCENT)");
    len = ARRAY_SIZE(buf);
    hr = UrlUnescapeW((WCHAR *)L"file://fo%20o%5Ca/bar", buf, &len, 0);
    check_url(hr, buf, len, L"file://fo o\\a/bar", "UrlUnescapeW");

    len = ARRAY_SIZE(buf);
    hr = UrlApplySchemeW(L"www.winehq.org", buf, &len, URL_APPLY_GUESSSCHEME);
    check_url(hr, buf, len, L"http://www.winehq.org", "UrlApplySchemeW(GUESSSCHEME www)");
    len = ARRAY_SIZE(buf);
    hr = UrlApplySchemeW(L"ftp.winehq.org", buf, &len, URL_APPLY_GUESSSCHEME);
    check_url(hr, buf, len, L"ftp://ftp.winehq.org", "UrlApplySchemeW(GUESSSCHEME ftp)");
    len = ARRAY_SIZE(buf);
    hr = UrlApplySchemeW(L"winehq.org", buf, &len, URL_APPLY_GUESSSCHEME | URL_APPLY_DEFAULT);
    check_url(hr, buf, len, L"http://winehq.org", "UrlApplySchemeW(DEFAULT)");

    ok(!UrlCompareW(L"http://www.winehq.org/", L"http://www.winehq.org", TRUE), "UrlCompareW(ignore slash)\n");
    ok(UrlCompareW(L"http://www.winehq.org/", L"http://www.winehq.org", FALSE), "UrlCompareW\n");
}

static void set_dword(HKEY root, const WCHAR *path, const WCHAR *name, DWORD value)
{
    HKEY key;
    if (RegCreateKeyExW(root, path, 0, NULL, 0, KEY_ALL_ACCESS, NULL, &key, NULL)) return;
    RegSetValueExW(key, name, 0, REG_DWORD, (const BYTE *)&value, sizeof(value));
    RegCloseKey(key);
}

static void test_shlwapi_misc(void)
{
    static const WCHAR path[] = L"Software\\Shizuku\\TridentTest\\US";
    WCHAR name[64], buf[128];
    HUSKEY key = NULL, sub = NULL;
    DWORD value, size, type, def = 77, n;
    IStream *stream = NULL;
    LARGE_INTEGER zero;
    const char *s;
    WCHAR *dup = NULL;
    char data[8];
    LONG res;
    HRESULT hr;

    set_dword(HKEY_LOCAL_MACHINE, path, L"v", 1);
    set_dword(HKEY_LOCAL_MACHINE, path, L"lm", 3);
    set_dword(HKEY_CURRENT_USER, path, L"v", 2);
    res = SHRegOpenUSKeyW(path, KEY_READ, NULL, &key, FALSE);
    ok(!res && key, "SHRegOpenUSKeyW: %ld\n", res);
    if (key)
    {
        size = sizeof(value);
        res = SHRegQueryUSValueW(key, L"v", &type, &value, &size, FALSE, NULL, 0);
        ok(!res && type == REG_DWORD && value == 2, "HKCU first: %ld %lu\n", res, value);
        size = sizeof(value);
        res = SHRegQueryUSValueW(key, L"v", &type, &value, &size, TRUE, NULL, 0);
        ok(!res && value == 1, "ignoring HKCU: %ld %lu\n", res, value);
        size = sizeof(value);
        res = SHRegQueryUSValueW(key, L"lm", &type, &value, &size, FALSE, NULL, 0);
        ok(!res && value == 3, "HKLM only value: %ld %lu\n", res, value);
        size = sizeof(value);
        value = 0;
        res = SHRegQueryUSValueW(key, L"missing", &type, &value, &size, FALSE, &def, sizeof(def));
        ok(!res && value == 77, "default data: %ld %lu\n", res, value);
        n = ARRAY_SIZE(name);
        size = sizeof(value);
        res = SHRegEnumUSValueW(key, 0, name, &n, &type, &value, &size, SHREGENUM_HKLM);
        ok(!res && !lstrcmpW(name, L"v") && value == 1, "SHRegEnumUSValueW(HKLM): %ld %s\n", res, wine_dbgstr_w(name));
        res = SHRegOpenUSKeyW(L"..", KEY_READ, key, &sub, TRUE);
        ok(res, "a relative key that does not exist opened: %ld\n", res);
        ok(!SHRegCloseUSKey(key), "SHRegCloseUSKey\n");
    }
    size = sizeof(value);
    res = SHRegGetUSValueW(path, L"v", &type, &value, &size, FALSE, NULL, 0);
    ok(!res && value == 2, "SHRegGetUSValueW: %ld %lu\n", res, value);
    RegDeleteTreeW(HKEY_LOCAL_MACHINE, L"Software\\Shizuku\\TridentTest");
    RegDeleteTreeW(HKEY_CURRENT_USER, L"Software\\Shizuku\\TridentTest");

    hr = CreateStreamOnHGlobal(NULL, TRUE, &stream);
    ok(hr == S_OK, "CreateStreamOnHGlobal: %#lx\n", hr);
    if (stream)
    {
        hr = IStream_Write(stream, "abcd", 4);
        ok(hr == S_OK, "IStream_Write: %#lx\n", hr);
        zero.QuadPart = 0;
        stream->lpVtbl->Seek(stream, zero, STREAM_SEEK_SET, NULL);
        memset(data, 0, sizeof(data));
        hr = IStream_Read(stream, data, 4);
        ok(hr == S_OK && !memcmp(data, "abcd", 4), "IStream_Read: %#lx\n", hr);
        hr = IStream_Read(stream, data, 1);
        ok(hr == E_FAIL, "IStream_Read past the end: %#lx\n", hr);
        stream->lpVtbl->Release(stream);
    }

    s = StrStrIA("Shizuku Trident", "TRIDENT");
    ok(s && !strcmp(s, "Trident"), "StrStrIA: %s\n", s ? s : "(null)");
    ok(!StrStrIA("Shizuku", "x"), "StrStrIA(no match)\n");
    ok(GetMIMETypeSubKeyW(L"text/html", buf, ARRAY_SIZE(buf)) && !lstrcmpW(buf, L"MIME\\Database\\Content Type\\text/html"),
       "GetMIMETypeSubKeyW: %s\n", wine_dbgstr_w(buf));
    ok(!GetMIMETypeSubKeyW(L"text/html", buf, 20), "GetMIMETypeSubKeyW with a short buffer\n");
    hr = SHStrDupW(L"dup", &dup);
    ok(hr == S_OK && dup && !lstrcmpW(dup, L"dup"), "SHStrDupW: %#lx\n", hr);
    CoTaskMemFree(dup);
}

static void test_kernel32(void)
{
    static const struct { int in_len; const WCHAR *in; DWORD ret; const WCHAR *out; } to_ascii[] =
    {
        { 5, L"Test", 5, L"Test" },
        { 5, L"Te\x017cst", 12, L"xn--test-cbb" },
        { 12, L"te\x0105st.te\x017cst", 26, L"xn--test-cta.xn--test-cbb" },
        { 3, L"\x0105.", 9, L"xn--2da." },
        { 10, L"http://t\x106", 17, L"xn--http://t-78a" },
        { 63, L"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", 63,
          L"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa" },
        { 64, L"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", 0, NULL },
        { -1, L"\xe4z123456789012345678901234567890123456789012345678901234", 64,
          L"xn--z123456789012345678901234567890123456789012345678901234-9te" },
    };
    static const struct { int in_len; const WCHAR *in; DWORD ret; const WCHAR *out; } to_unicode[] =
    {
        { 5, L"Tes.", 5, L"Tes." },
        { 2, L"\x105", 0, NULL },
        { 33, L"xn--4dbcagdahymbxekheh6e0a7fei0b", 23,
          L"\x05dc\x05de\x05d4\x05d4\x05dd\x05e4\x05e9\x05d5\x05d8\x05dc\x05d0\x05de\x05d3\x05d1\x05e8\x05d9\x05dd\x05e2\x05d1\x05e8\x05d9\x05ea" },
        { 34, L"test.xn--kda9ag5e9jnfsj.xn--pz-fna", 16, L"test.\x0105\x0119\x015b\x0107\x0142\x00f3\x017c.p\x0119z" },
        { 64, L"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", 0, NULL },
    };
    WCHAR buf[128];
    FILETIME ft;
    WORD date = 0, time = 0;
    char name[256];
    DWORD size;
    unsigned int i;
    int ret;

    ok(MulDiv(3, 5, 2) == 8, "MulDiv(3, 5, 2) = %d\n", MulDiv(3, 5, 2));
    ok(MulDiv(-3, 5, 2) == -8, "MulDiv(-3, 5, 2) = %d\n", MulDiv(-3, 5, 2));
    ok(MulDiv(96, 72, 96) == 72, "MulDiv(96, 72, 96) = %d\n", MulDiv(96, 72, 96));
    ok(MulDiv(1, 2, 0) == -1, "MulDiv(1, 2, 0) = %d\n", MulDiv(1, 2, 0));
    ok(MulDiv(0x7fffffff, 2, 1) == -1, "MulDiv overflow = %d\n", MulDiv(0x7fffffff, 2, 1));

    for (i = 0; i < ARRAY_SIZE(to_ascii); i++)
    {
        memset(buf, 0, sizeof(buf));
        SetLastError(0xdeadbeef);
        ret = IdnToAscii(0, to_ascii[i].in, to_ascii[i].in_len, buf, ARRAY_SIZE(buf));
        ok(ret == to_ascii[i].ret, "IdnToAscii %u: %d, expected %lu\n", i, ret, to_ascii[i].ret);
        if (to_ascii[i].out) ok(!_wcsnicmp(buf, to_ascii[i].out, ret), "IdnToAscii %u: %s\n", i, wine_dbgstr_wn(buf, ret));
        else ok(GetLastError() == ERROR_INVALID_NAME, "IdnToAscii %u: error %lu\n", i, GetLastError());
    }
    ret = IdnToAscii(0, L"Te\x017cst", -1, NULL, 0);
    ok(ret == 13, "IdnToAscii size query: %d\n", ret);
    for (i = 0; i < ARRAY_SIZE(to_unicode); i++)
    {
        memset(buf, 0, sizeof(buf));
        ret = IdnToUnicode(0, to_unicode[i].in, to_unicode[i].in_len, buf, ARRAY_SIZE(buf));
        ok(ret == to_unicode[i].ret, "IdnToUnicode %u: %d, expected %lu\n", i, ret, to_unicode[i].ret);
        if (to_unicode[i].out) ok(!wcsncmp(buf, to_unicode[i].out, ret), "IdnToUnicode %u: %s\n", i, wine_dbgstr_wn(buf, ret));
    }

    ok(DosDateTimeToFileTime(0x2821, 0x4a20, &ft), "DosDateTimeToFileTime\n");       /* 2000-01-01 09:17:00 */
    ok(FileTimeToDosDateTime(&ft, &date, &time) && date == 0x2821 && time == 0x4a20,
       "FileTimeToDosDateTime: %#x %#x\n", date, time);
    ft.dwLowDateTime = ft.dwHighDateTime = 0;                                        /* 1601 */
    ok(!FileTimeToDosDateTime(&ft, &date, &time) && GetLastError() == ERROR_INVALID_PARAMETER, "year 1601 accepted\n");

    size = sizeof(name);
    ok(GetComputerNameExA(ComputerNameNetBIOS, name, &size) && size == strlen(name) && size,
       "GetComputerNameExA: %lu %s\n", size, name);
}

START_TEST(url)
{
    CoInitializeEx(NULL, COINIT_APARTMENTTHREADED);
    test_urls();
    test_shlwapi_misc();
    test_kernel32();
    CoUninitialize();
}
