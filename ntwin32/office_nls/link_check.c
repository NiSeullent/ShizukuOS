/* SPDX-License-Identifier: GPL-2.0-only
 * Link-only control: the declarations used by the LIBO_WIN98 SAL patch must
 * bind through the OFFNLS import library to the undecorated DLL exports.
 */
#define WIN32_LEAN_AND_MEAN
#include <windows.h>
int WINAPI OfnGetUserDefaultLocaleName(LPWSTR, int);
int WINAPI OfnGetLocaleInfoEx(LPCWSTR, LCTYPE, LPWSTR, int);
int WINAPI OfnResolveLocaleName(LPCWSTR, LPWSTR, int);
void WINAPI link_entry(void)
{
    WCHAR name[85], out[85];
    DWORD cp = 0;
    UINT ok = OfnGetUserDefaultLocaleName(name, 85) && OfnGetLocaleInfoEx(name, 0x20001004u, (LPWSTR)&cp, 2)
              && OfnResolveLocaleName(name, out, 85);
    ExitProcess(ok ? 0u : 1u);
}
