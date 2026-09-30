/* SPDX-License-Identifier: GPL-2.0-only
 * Shizuku checks of tridentrt.dll: registry seeding (trident/comrt/register.c). After ShzTridentRegister (and after
 * the first activation of a process) the keys the Wine browser modules' registration would write exist: in-process
 * servers of the ported DLLs under C:\SHZ\SYS64, the MIME database and file associations of mshtml.inf, the protocol
 * handlers, urlmon.inf's ZoneMap, the type library registrations, the ProgIDs (resolved through CLSIDFromProgID) and
 * mshtml's Gecko path. The expected CLSIDs are the documented Windows ones. Existing values are never overwritten.
 */
#include <stdarg.h>
#include <stdio.h>
#include "windef.h"
#include "winbase.h"
#include "winreg.h"
#include "objbase.h"
#include "wine/test.h"

HRESULT WINAPI ShzTridentRegister(void);

static void check_sz(HKEY root, const WCHAR *path, const WCHAR *name, const WCHAR *want)
{
    WCHAR buf[512];
    DWORD size = sizeof(buf) - sizeof(WCHAR), type = 0;
    HKEY key;
    LONG res = RegOpenKeyExW(root, path, 0, KEY_READ, &key);

    ok(!res, "key %s missing: %ld\n", wine_dbgstr_w(path), res);
    if (res) return;
    res = RegQueryValueExW(key, name, NULL, &type, (BYTE *)buf, &size);
    RegCloseKey(key);
    buf[size / sizeof(WCHAR)] = 0;
    ok(!res && type == REG_SZ && !lstrcmpiW(buf, want), "%s [%s]: %ld type %lu %s, expected %s\n", wine_dbgstr_w(path),
       wine_dbgstr_w(name), res, type, wine_dbgstr_w(buf), wine_dbgstr_w(want));
}

static void check_dword(HKEY root, const WCHAR *path, const WCHAR *name, DWORD want)
{
    DWORD value = 0, size = sizeof(value), type = 0;
    HKEY key;
    LONG res = RegOpenKeyExW(root, path, 0, KEY_READ, &key);

    ok(!res, "key %s missing: %ld\n", wine_dbgstr_w(path), res);
    if (res) return;
    res = RegQueryValueExW(key, name, NULL, &type, (BYTE *)&value, &size);
    RegCloseKey(key);
    ok(!res && type == REG_DWORD && value == want, "%s [%s]: %ld type %lu value %lu, expected %lu\n", wine_dbgstr_w(path),
       wine_dbgstr_w(name), res, type, value, want);
}

static void check_progid(const WCHAR *progid, const WCHAR *want)
{
    WCHAR str[40];
    CLSID clsid;
    HRESULT hr = CLSIDFromProgID(progid, &clsid);
    StringFromGUID2(&clsid, str, ARRAY_SIZE(str));
    ok(hr == S_OK && !lstrcmpiW(str, want), "CLSIDFromProgID(%s): %#lx %s, expected %s\n", wine_dbgstr_w(progid), hr,
       wine_dbgstr_w(str), wine_dbgstr_w(want));
}

static void test_seeded_keys(void)
{
    static const WCHAR zonemap[] = L"Software\\Microsoft\\Windows\\CurrentVersion\\Internet Settings\\ZoneMap\\ProtocolDefaults";
    HRESULT hr = ShzTridentRegister();
    ok(hr == S_OK, "ShzTridentRegister: %#lx\n", hr);

    /* in-process servers */
    check_sz(HKEY_CLASSES_ROOT, L"CLSID\\{25336920-03F9-11CF-8FD0-00AA00686F13}\\InprocServer32", NULL,
             L"C:\\SHZ\\SYS64\\mshtml.dll");                                                            /* HTMLDocument */
    check_sz(HKEY_CLASSES_ROOT, L"CLSID\\{25336920-03F9-11CF-8FD0-00AA00686F13}\\InprocServer32", L"ThreadingModel",
             L"Apartment");
    check_sz(HKEY_CLASSES_ROOT, L"CLSID\\{3050F406-98B5-11CF-BB82-00AA00BDCE0B}\\InprocServer32", NULL,
             L"C:\\SHZ\\SYS64\\mshtml.dll");                                                            /* AboutProtocol */
    check_sz(HKEY_CLASSES_ROOT, L"CLSID\\{3050F3BC-98B5-11CF-BB82-00AA00BDCE0B}\\InprocServer32", NULL,
             L"C:\\SHZ\\SYS64\\mshtml.dll");                                                            /* ResProtocol */
    check_sz(HKEY_CLASSES_ROOT, L"CLSID\\{3050F3B2-98B5-11CF-BB82-00AA00BDCE0B}\\InprocServer32", NULL,
             L"C:\\SHZ\\SYS64\\mshtml.dll");                                                            /* JSProtocol */
    check_sz(HKEY_CLASSES_ROOT, L"CLSID\\{79EAC9E2-BAF9-11CE-8C82-00AA004BA90B}\\InprocServer32", NULL,
             L"C:\\SHZ\\SYS64\\urlmon.dll");                                                            /* HttpProtocol */
    check_sz(HKEY_CLASSES_ROOT, L"CLSID\\{79EAC9E7-BAF9-11CE-8C82-00AA004BA90B}\\InprocServer32", NULL,
             L"C:\\SHZ\\SYS64\\urlmon.dll");                                                            /* FileProtocol */
    check_sz(HKEY_CLASSES_ROOT, L"CLSID\\{8856F961-340A-11D0-A96B-00C04FD705A2}\\InprocServer32", NULL,
             L"C:\\SHZ\\SYS64\\ieframe.dll");                                                           /* WebBrowser */
    check_sz(HKEY_CLASSES_ROOT, L"CLSID\\{EAB22AC3-30C1-11CF-A7EB-0000C05BAE0B}\\InprocServer32", NULL,
             L"C:\\SHZ\\SYS64\\ieframe.dll");                                                           /* WebBrowser_V1 */
    check_sz(HKEY_CLASSES_ROOT, L"CLSID\\{F414C260-6AC0-11CF-B6D1-00AA00BBBB58}\\InprocServer32", NULL,
             L"C:\\SHZ\\SYS64\\jscript.dll");                                                           /* JScript */
    check_sz(HKEY_CLASSES_ROOT, L"CLSID\\{F5078F32-C551-11D3-89B9-0000F81FE221}\\InprocServer32", NULL,
             L"C:\\SHZ\\SYS64\\msxml3.dll");                                                            /* DOMDocument30 */
    check_sz(HKEY_CLASSES_ROOT, L"CLSID\\{F6D90F16-9C73-11D3-B32E-00C04F990BB4}\\InprocServer32", NULL,
             L"C:\\SHZ\\SYS64\\msxml3.dll");                                                            /* XMLHTTP */

    /* mshtml.inf: MIME database, extensions, protocol handlers */
    check_sz(HKEY_CLASSES_ROOT, L"MIME\\Database\\Content Type\\text/html", L"CLSID", L"{25336920-03F9-11CF-8FD0-00AA00686F13}");
    check_sz(HKEY_CLASSES_ROOT, L".htm", L"Content Type", L"text/html");
    check_sz(HKEY_CLASSES_ROOT, L".html", L"Content Type", L"text/html");
    check_sz(HKEY_CLASSES_ROOT, L".txt", L"Content Type", L"text/plain");
    check_sz(HKEY_CLASSES_ROOT, L"PROTOCOLS\\Handler\\about", L"CLSID", L"{3050F406-98B5-11CF-BB82-00AA00BDCE0B}");
    check_sz(HKEY_CLASSES_ROOT, L"PROTOCOLS\\Handler\\res", L"CLSID", L"{3050F3BC-98B5-11CF-BB82-00AA00BDCE0B}");
    check_sz(HKEY_CLASSES_ROOT, L"PROTOCOLS\\Handler\\javascript", L"CLSID", L"{3050F3B2-98B5-11CF-BB82-00AA00BDCE0B}");
    check_sz(HKEY_CLASSES_ROOT, L"PROTOCOLS\\Handler\\http", L"CLSID", L"{79EAC9E2-BAF9-11CE-8C82-00AA004BA90B}");

    /* urlmon.inf ZoneMap: http/https/ftp/file in the Internet zone (3) */
    check_dword(HKEY_CURRENT_USER, zonemap, L"http", 3);
    check_dword(HKEY_LOCAL_MACHINE, zonemap, L"http", 3);
    check_dword(HKEY_LOCAL_MACHINE, zonemap, L"file", 3);

    /* type libraries */
    check_sz(HKEY_CLASSES_ROOT, L"TypeLib\\{00020430-0000-0000-C000-000000000046}\\2.0\\0\\win64", NULL,
             L"C:\\SHZ\\SYS64\\stdole2.tlb");
    check_sz(HKEY_CLASSES_ROOT, L"TypeLib\\{3050F1C5-98B5-11CF-BB82-00AA00BDCE0B}\\4.0\\0\\win64", NULL,
             L"C:\\SHZ\\SYS64\\mshtml.tlb");
    check_sz(HKEY_CLASSES_ROOT, L"TypeLib\\{EAB22AC0-30C1-11CF-A7EB-0000C05BAE0B}\\1.1\\0\\win64", NULL,
             L"C:\\SHZ\\SYS64\\ieframe.dll");
    check_sz(HKEY_CLASSES_ROOT, L"TypeLib\\{F5078F18-C551-11D3-89B9-0000F81FE221}\\3.0\\0\\win64", NULL,
             L"C:\\SHZ\\SYS64\\msxml3.dll");

    /* mshtml's Gecko location */
    check_sz(HKEY_LOCAL_MACHINE, L"Software\\Wine\\MSHTML\\2.47.4", L"GeckoPath", L"C:\\SHZ\\SYS64\\gecko");

    /* ProgIDs */
    check_progid(L"Shell.Explorer", L"{8856F961-340A-11D0-A96B-00C04FD705A2}");
    check_progid(L"Shell.Explorer.2", L"{8856F961-340A-11D0-A96B-00C04FD705A2}");
    check_progid(L"Shell.Explorer.1", L"{EAB22AC3-30C1-11CF-A7EB-0000C05BAE0B}");
    check_progid(L"JScript", L"{F414C260-6AC0-11CF-B6D1-00AA00BBBB58}");
    check_progid(L"JavaScript", L"{F414C260-6AC0-11CF-B6D1-00AA00BBBB58}");
    check_progid(L"Msxml2.XMLHTTP", L"{F6D90F16-9C73-11D3-B32E-00C04F990BB4}");
    check_progid(L"Msxml2.XMLHTTP.3.0", L"{F5078F35-C551-11D3-89B9-0000F81FE221}");
    check_progid(L"Microsoft.XMLHTTP", L"{ED8C108E-4349-11D2-91A4-00C04F7969E8}");
    check_progid(L"Msxml2.DOMDocument", L"{F6D90F11-9C73-11D3-B32E-00C04F990BB4}");
    check_progid(L"Msxml2.DOMDocument.3.0", L"{F5078F32-C551-11D3-89B9-0000F81FE221}");
    check_progid(L"Microsoft.XMLDOM", L"{2933BF90-7B36-11D2-B20E-00C04F983E60}");
    check_progid(L"htmlfile", L"{25336920-03F9-11CF-8FD0-00AA00686F13}");
}

/* seeding writes missing values only */
static void test_keeps_values(void)
{
    static const WCHAR custom[] = L"text/x-shizuku-test";
    HKEY key;
    LONG res;

    res = RegOpenKeyExW(HKEY_CLASSES_ROOT, L".htm", 0, KEY_ALL_ACCESS, &key);
    ok(!res, "RegOpenKeyExW(.htm): %ld\n", res);
    if (res) return;
    RegSetValueExW(key, L"Content Type", 0, REG_SZ, (const BYTE *)custom, sizeof(custom));
    ok(ShzTridentRegister() == S_OK, "ShzTridentRegister\n");
    check_sz(HKEY_CLASSES_ROOT, L".htm", L"Content Type", custom);
    RegDeleteValueW(key, L"Content Type");
    ok(ShzTridentRegister() == S_OK, "ShzTridentRegister\n");
    check_sz(HKEY_CLASSES_ROOT, L".htm", L"Content Type", L"text/html");
    RegCloseKey(key);

    /* the table version seeded in this boot, which lets later processes skip the walk */
    res = RegOpenKeyExW(HKEY_LOCAL_MACHINE, L"Software\\Shizuku\\Trident", 0, KEY_READ, &key);
    ok(!res, "stamp key: %ld\n", res);
    if (!res)
    {
        DWORD stamp = 0, size = sizeof(stamp), type = 0;
        res = RegQueryValueExW(key, L"RegistryStamp", NULL, &type, (BYTE *)&stamp, &size);
        ok(!res && type == REG_DWORD && stamp, "RegistryStamp: %ld type %lu %#lx\n", res, type, stamp);
        RegCloseKey(key);
    }
}

START_TEST(register)
{
    test_seeded_keys();
    test_keeps_values();
}
