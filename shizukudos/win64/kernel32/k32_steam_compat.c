/* SPDX-License-Identifier: GPL-2.0-only
 * ANSI version query and checked integer scaling imported by current Steam.
 * Contract references: Microsoft GetVersionExA and MulDiv API documentation.
 * Version reporting follows the existing wide manifest-aware query.
 */
#include "k32.h"
#include "k32_muldiv.h"

K32API BOOL WINAPI GetVersionExA(LPOSVERSIONINFOA out)
{
    OSVERSIONINFOEXW wide;
    DWORD size;
    if (!out) { SetLastError(ERROR_INVALID_PARAMETER); return FALSE; }
    size = out->dwOSVersionInfoSize;
    if (size != sizeof(OSVERSIONINFOA) && size != sizeof(OSVERSIONINFOEXA)) {
        SetLastError(ERROR_INSUFFICIENT_BUFFER);
        return FALSE;
    }
    memset(&wide, 0, sizeof wide);
    wide.dwOSVersionInfoSize = size == sizeof(OSVERSIONINFOEXA)
        ? sizeof(OSVERSIONINFOEXW) : sizeof(OSVERSIONINFOW);
    if (!GetVersionExW((LPOSVERSIONINFOW)&wide)) return FALSE;
    if (!WideCharToMultiByte(CP_ACP, 0, wide.szCSDVersion, -1,
                            out->szCSDVersion, sizeof out->szCSDVersion, 0, 0))
        return FALSE;
    out->dwMajorVersion = wide.dwMajorVersion;
    out->dwMinorVersion = wide.dwMinorVersion;
    out->dwBuildNumber = wide.dwBuildNumber;
    out->dwPlatformId = wide.dwPlatformId;
    if (size == sizeof(OSVERSIONINFOEXA)) {
        LPOSVERSIONINFOEXA ex = (LPOSVERSIONINFOEXA)out;
        ex->wServicePackMajor = wide.wServicePackMajor;
        ex->wServicePackMinor = wide.wServicePackMinor;
        ex->wSuiteMask = wide.wSuiteMask;
        ex->wProductType = wide.wProductType;
        ex->wReserved = wide.wReserved;
    }
    return TRUE;
}

K32API int WINAPI MulDiv(int number, int numerator, int denominator)
{
    return shz_muldiv(number, numerator, denominator);
}
