/* SPDX-License-Identifier: GPL-2.0-only
 * OFNLSPRB.EXE: native Windows 98 probe for OFFNLS.DLL. Loads the provider
 * with LoadLibraryA/GetProcAddress, runs LibreOffice SAL's exact locale
 * sequence and writes C:\VXDLAB\OFNLS.LOG. Exit 0 only if every call
 * succeeded; the log, not this source, is runtime evidence once run natively.
 */
#define WIN32_LEAN_AND_MEAN
#include <windows.h>

typedef int (WINAPI *name_fn)(LPWSTR, int);
typedef int (WINAPI *info_fn)(LPCWSTR, LCTYPE, LPWSTR, int);
typedef int (WINAPI *resolve_fn)(LPCWSTR, LPWSTR, int);

static HANDLE log_file;
static void put(const char *s) { DWORD n = (DWORD)lstrlenA(s), w; WriteFile(log_file, s, n, &w, 0); }
static void put_wide(const WCHAR *s) { char b[96]; int i; for (i = 0; i < 95 && s[i]; ++i) b[i] = s[i] < 0x80 ? (char)s[i] : '?'; b[i] = 0; put(b); }
static void put_num(const char *k, DWORD v) { char b[64]; wsprintfA(b, "%s=%lu\r\n", k, (unsigned long)v); put(b); }

void WINAPI probe_entry(void)
{
    HMODULE dll; name_fn user; info_fn info; resolve_fn resolve;
    WCHAR locale[85], lang[4], ctry[3], resolved[85]; DWORD cp = 0; UINT code = 1;
    log_file = CreateFileA("C:\\VXDLAB\\OFNLS.LOG", GENERIC_WRITE, 0, 0, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, 0);
    if (log_file == INVALID_HANDLE_VALUE) ExitProcess(2);
    put_num("system_lcid", GetSystemDefaultLCID());
    put_num("user_lcid", GetUserDefaultLCID());
    dll = LoadLibraryA("OFFNLS.DLL");
    if (!dll) { put_num("load_error", GetLastError()); goto done; }
    user = (name_fn)GetProcAddress(dll, "OfnGetUserDefaultLocaleName");
    info = (info_fn)GetProcAddress(dll, "OfnGetLocaleInfoEx");
    resolve = (resolve_fn)GetProcAddress(dll, "OfnResolveLocaleName");
    if (!user || !info || !resolve) { put("export_missing\r\n"); goto done; }
    if (!user(locale, 85)) { put_num("user_name_error", GetLastError()); goto done; }
    put("user_locale="); put_wide(locale); put("\r\n");
    if (!info(locale, 0x59, lang, 4) || !info(locale, 0x5a, ctry, 3)) { put_num("iso_error", GetLastError()); goto done; }
    put("iso="); put_wide(lang); put("-"); put_wide(ctry); put("\r\n");
    if (!info(locale, 0x20001004u, (LPWSTR)&cp, 2)) { put_num("acp_error", GetLastError()); goto done; }
    put_num("locale_acp", cp);
    put_num("system_acp", GetACP());
    if (!resolve(locale, resolved, 85)) { put_num("resolve_error", GetLastError()); goto done; }
    put("resolved="); put_wide(resolved); put("\r\n");
    code = 0;
done:
    put_num("exit", code);
    CloseHandle(log_file);
    ExitProcess(code);
}
