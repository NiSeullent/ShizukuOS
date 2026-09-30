/* SPDX-License-Identifier: GPL-2.0-only
 * Interim stand-ins, linked into jsc.exe only, for Windows functions JavaScriptCore/WTF import that the Shizuku runtime
 * does not export yet (the import check of webkit/build.py lists them). Each is asked from its owner in
 * docs/shizukudos10/reports/W1.md ("Needed from K4" / "Needed from K5") and is to be DELETED here once the runtime
 * exports it. WebKit calls these through dllimport declarations, i.e. through the __imp_<name> slot; defining that slot
 * here (and the plain symbol, for direct calls) makes the link use the function below instead of an import the
 * loader could not resolve. Each stand-in first asks the system DLL for the real export (GetProcAddress, cached, as
 * W3's deps/compat/shzwkcompat.c does) and forwards to it, so a runtime that exports the name takes over without a
 * rebuild; only when it is missing does the fallback below run.
 *
 * Fallback behaviour, and how it differs from Windows:
 *   GetTimeZoneInformationForYear  GetTimeZoneInformation (the Shizuku time zone has no per-year rules); a dynamic
 *                                  time zone argument is rejected with ERROR_NOT_SUPPORTED
 *   K32QueryWorkingSet             fails with ERROR_CALL_NOT_IMPLEMENTED (WTF's memoryFootprint() then reports 0)
 *   CreateMemoryResourceNotification  a manual-reset event that is never set: "low memory" is never signalled
 *   QueryMemoryResourceNotification   reports "not low"
 *   CryptAcquireContextW/CryptGenRandom/CryptReleaseContext  WTF's RandomDevice only: CryptGenRandom fills the buffer
 *                                  from ProcessPrng (bcryptprimitives.dll), what Windows' CSPs use underneath */
#include <windows.h>

__declspec(dllimport) BOOL WINAPI ProcessPrng(PBYTE data, SIZE_T len);

static FARPROC real(const char *dll, const char *name)
{
    HMODULE m = GetModuleHandleA(dll);
    return m ? GetProcAddress(m, name) : NULL;       /* kernel32 and advapi32 are always loaded in jsc.exe */
}

/* forward to <dll>!<name> when the runtime exports it (looked up once) */
#define FORWARD(dll, name, ...) \
    do { \
        static __typeof__(&shz_##name) fn_; static volatile LONG looked_; \
        if (!looked_) { fn_ = (__typeof__(&shz_##name))(void (*)(void))real(dll, #name); InterlockedExchange(&looked_, 1); } \
        if (fn_) return fn_(__VA_ARGS__); \
    } while (0)

BOOL WINAPI shz_GetTimeZoneInformationForYear(USHORT year, PDYNAMIC_TIME_ZONE_INFORMATION pdtzi,
                                                     LPTIME_ZONE_INFORMATION ptzi)
{
    FORWARD("kernel32.dll", GetTimeZoneInformationForYear, year, pdtzi, ptzi);
    (void)year;
    if (pdtzi || !ptzi) {
        SetLastError(pdtzi ? ERROR_NOT_SUPPORTED : ERROR_INVALID_PARAMETER);
        return FALSE;
    }
    return GetTimeZoneInformation(ptzi) != TIME_ZONE_ID_INVALID;
}

BOOL WINAPI shz_K32QueryWorkingSet(HANDLE process, PVOID buffer, DWORD size)
{
    FORWARD("kernel32.dll", K32QueryWorkingSet, process, buffer, size);
    (void)process; (void)buffer; (void)size;
    SetLastError(ERROR_CALL_NOT_IMPLEMENTED);
    return FALSE;
}

HANDLE WINAPI shz_CreateMemoryResourceNotification(MEMORY_RESOURCE_NOTIFICATION_TYPE type)
{
    FORWARD("kernel32.dll", CreateMemoryResourceNotification, type);
    (void)type;
    return CreateEventW(NULL, TRUE, FALSE, NULL);
}

BOOL WINAPI shz_QueryMemoryResourceNotification(HANDLE handle, PBOOL state)
{
    FORWARD("kernel32.dll", QueryMemoryResourceNotification, handle, state);
    if (!handle || !state) {
        SetLastError(ERROR_INVALID_PARAMETER);
        return FALSE;
    }
    *state = FALSE;
    return TRUE;
}

BOOL WINAPI shz_CryptAcquireContextW(HCRYPTPROV *prov, LPCWSTR container, LPCWSTR provider, DWORD type, DWORD flags)
{
    FORWARD("advapi32.dll", CryptAcquireContextW, prov, container, provider, type, flags);
    (void)container; (void)provider; (void)type; (void)flags;
    if (!prov) {
        SetLastError(ERROR_INVALID_PARAMETER);
        return FALSE;
    }
    *prov = (HCRYPTPROV)0x5348;                         /* any non-zero handle; only CryptGenRandom takes it */
    return TRUE;
}

BOOL WINAPI shz_CryptGenRandom(HCRYPTPROV prov, DWORD len, BYTE *buffer)
{
    FORWARD("advapi32.dll", CryptGenRandom, prov, len, buffer);
    if (!prov || (len && !buffer)) {
        SetLastError(ERROR_INVALID_PARAMETER);
        return FALSE;
    }
    return ProcessPrng(buffer, len);
}

BOOL WINAPI shz_CryptReleaseContext(HCRYPTPROV prov, DWORD flags)
{
    FORWARD("advapi32.dll", CryptReleaseContext, prov, flags);
    (void)prov; (void)flags;
    return TRUE;
}

/* the import slots WebKit's dllimport calls go through */
void *__imp_GetTimeZoneInformationForYear = (void *)shz_GetTimeZoneInformationForYear;
void *__imp_K32QueryWorkingSet = (void *)shz_K32QueryWorkingSet;
void *__imp_CreateMemoryResourceNotification = (void *)shz_CreateMemoryResourceNotification;
void *__imp_QueryMemoryResourceNotification = (void *)shz_QueryMemoryResourceNotification;
void *__imp_CryptAcquireContextW = (void *)shz_CryptAcquireContextW;
void *__imp_CryptGenRandom = (void *)shz_CryptGenRandom;
void *__imp_CryptReleaseContext = (void *)shz_CryptReleaseContext;

/* the plain names, for calls that do not go through the import slot (asm labels: windows.h declares these dllimport) */
__asm__(".globl GetTimeZoneInformationForYear\n.set GetTimeZoneInformationForYear, shz_GetTimeZoneInformationForYear");
__asm__(".globl K32QueryWorkingSet\n.set K32QueryWorkingSet, shz_K32QueryWorkingSet");
__asm__(".globl CreateMemoryResourceNotification\n.set CreateMemoryResourceNotification, shz_CreateMemoryResourceNotification");
__asm__(".globl QueryMemoryResourceNotification\n.set QueryMemoryResourceNotification, shz_QueryMemoryResourceNotification");
__asm__(".globl CryptAcquireContextW\n.set CryptAcquireContextW, shz_CryptAcquireContextW");
__asm__(".globl CryptGenRandom\n.set CryptGenRandom, shz_CryptGenRandom");
__asm__(".globl CryptReleaseContext\n.set CryptReleaseContext, shz_CryptReleaseContext");
