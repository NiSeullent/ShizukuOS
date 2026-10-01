/* SPDX-License-Identifier: GPL-2.0-only
 * userenv.dll - environment blocks, profile type, group policy notification and critical sections, AppContainer SIDs.
 *
 * This system has one user (advapi32 token.c: SHZ_USER_NAME_W) and no managed user profile directories (shell32.c reports every
 * profile folder as not found), no group policy engine and no AppContainers. What that means for each function:
 *   CreateEnvironmentBlock   bInherit TRUE: a copy of the calling process's environment; FALSE: the system variables of
 *                            the calling process's environment (the ones the Kernel64 loader gives every process:
 *                            SystemRoot, SystemDrive, PATH, TEMP, TMP, COMPUTERNAME, OS, PROCESSOR_ARCHITECTURE,
 *                            NUMBER_OF_PROCESSORS). USERNAME is added in both cases. No profile variables (USERPROFILE,
 *                            APPDATA, ...) are invented: no profile exists. The block is sorted, as Windows builds it.
 *   DestroyEnvironmentBlock  frees such a block.
 *   GetProfileType           no profile is loaded for the user: FALSE with ERROR_FILE_NOT_FOUND.
 *   GetUserProfileDirectoryA/W   the process USERPROFILE, if explicitly supplied; otherwise ERROR_FILE_NOT_FOUND.
 *                            No directory is created and no managed profile is implied. A valid TOKEN_QUERY token is required.
 *   RegisterGPNotification / UnregisterGPNotification   a real registration table; the events are never signaled
 *                            because no policy is ever applied.
 *   EnterCriticalPolicySection / LeaveCriticalPolicySection   named mutexes (one for machine, one for user policy): a
 *                            reader holds policy application off, as on Windows (nothing applies policy here).
 *   DeriveAppContainerSidFromAppContainerName   the AppContainer SID S-1-15-2-d0-...-d6 whose seven sub-authorities are
 *                            the first 28 bytes of SHA-256 over the lower-cased name (UTF-16LE), as Windows derives it;
 *                            the SID is released with FreeSid.
 */
#define _USERENV_
#include "nt.h"
#include "ntreg.h"
#include <string.h>
#include <userenv.h>

static size_t wlen(const WCHAR *s) { size_t n = 0; while (s[n]) ++n; return n; }

extern NTSTATUS WINAPI BCryptHash(PVOID alg, PUCHAR secret, ULONG cbsecret, PUCHAR in, ULONG cbin, PUCHAR out, ULONG cbout);
#define BCRYPT_SHA256_ALG_HANDLE_ ((PVOID)(ULONG_PTR)0x41)

/* ---------------------------------------------------------------- environment blocks */
typedef struct { const WCHAR *s; size_t n; } var_t;              /* "NAME=value" (n characters, no NUL) */

static int wci_cmp(const WCHAR *a, size_t an, const WCHAR *b, size_t bn)   /* by name, case-insensitive, then '=' */
{
    size_t i;
    for (i = 0; i < an && i < bn; ++i) {
        WCHAR x = a[i], y = b[i];
        if (x >= 'a' && x <= 'z') x = (WCHAR)(x - 32);
        if (y >= 'a' && y <= 'z') y = (WCHAR)(y - 32);
        if (x == '=' && y != '=') return -1;
        if (y == '=' && x != '=') return 1;
        if (x != y) return x < y ? -1 : 1;
        if (x == '=') return 0;
    }
    return an < bn ? -1 : an > bn ? 1 : 0;
}

static size_t name_len(const WCHAR *s, size_t n)
{
    size_t i = s[0] == '=' ? 1 : 0;                             /* "=C:=C:\..." drive variables start with '=' */
    while (i < n && s[i] != '=') ++i;
    return i;
}

static int is_system_var(const WCHAR *s, size_t n)
{
    static const char *const names[] = { "SystemRoot", "SystemDrive", "PATH", "TEMP", "TMP", "COMPUTERNAME", "OS",
                                         "PROCESSOR_ARCHITECTURE", "NUMBER_OF_PROCESSORS", "windir", "ComSpec", "PATHEXT", 0 };
    const size_t nl = name_len(s, n);
    unsigned k;
    for (k = 0; names[k]; ++k) {
        size_t i;
        const size_t kl = strlen(names[k]);
        if (kl != nl) continue;
        for (i = 0; i < kl; ++i) {
            WCHAR a = s[i], b = (WCHAR)(unsigned char)names[k][i];
            if (a >= 'a' && a <= 'z') a = (WCHAR)(a - 32);
            if (b >= 'a' && b <= 'z') b = (WCHAR)(b - 32);
            if (a != b) break;
        }
        if (i == kl) return 1;
    }
    return 0;
}

DLLAPI BOOL WINAPI CreateEnvironmentBlock(LPVOID *out, HANDLE token, BOOL inherit)
{
    static const WCHAR user_var[] = L"USERNAME=shizuku";
    WCHAR *env, *p, *block;
    var_t *vars;
    size_t count = 0, total = 0, i, j, have_user = 0;
    (void)token;                                                /* one user: every token names it */
    if (!out) { SetLastError(ERROR_INVALID_PARAMETER); return FALSE; }
    *out = 0;
    env = GetEnvironmentStringsW();
    if (!env) { SetLastError(ERROR_NOT_ENOUGH_MEMORY); return FALSE; }
    for (p = env; *p; p += wlen(p) + 1) ++count;
    vars = HeapAlloc(GetProcessHeap(), 0, (count + 1) * sizeof *vars);
    if (!vars) { FreeEnvironmentStringsW(env); SetLastError(ERROR_NOT_ENOUGH_MEMORY); return FALSE; }
    count = 0;
    for (p = env; *p; p += wlen(p) + 1) {
        const size_t n = wlen(p);
        if (p[0] == '=') continue;                              /* per-drive current directories: process state, not environment */
        if (!inherit && !is_system_var(p, n)) continue;
        if (!wci_cmp(p, n, user_var, 16)) have_user = 1;
        vars[count].s = p; vars[count].n = n; ++count;
    }
    if (!have_user) { vars[count].s = user_var; vars[count].n = 16; ++count; }
    for (i = 1; i < count; ++i) {                               /* insertion sort by name, as Windows' blocks are sorted */
        var_t v = vars[i];
        for (j = i; j > 0 && wci_cmp(vars[j - 1].s, vars[j - 1].n, v.s, v.n) > 0; --j) vars[j] = vars[j - 1];
        vars[j] = v;
    }
    for (i = 0; i < count; ++i) total += vars[i].n + 1;
    block = HeapAlloc(GetProcessHeap(), 0, (total + 2) * sizeof(WCHAR));
    if (!block) { HeapFree(GetProcessHeap(), 0, vars); FreeEnvironmentStringsW(env); SetLastError(ERROR_NOT_ENOUGH_MEMORY); return FALSE; }
    p = block;
    for (i = 0; i < count; ++i) { memcpy(p, vars[i].s, vars[i].n * sizeof(WCHAR)); p += vars[i].n; *p++ = 0; }
    *p++ = 0;
    if (!count) *p = 0;                                         /* an empty block is two NULs (total + 2 characters) */
    HeapFree(GetProcessHeap(), 0, vars);
    FreeEnvironmentStringsW(env);
    *out = block;
    return TRUE;
}

DLLAPI BOOL WINAPI DestroyEnvironmentBlock(LPVOID block)
{
    if (!block) { SetLastError(ERROR_INVALID_PARAMETER); return FALSE; }
    return HeapFree(GetProcessHeap(), 0, block);
}

/* ---------------------------------------------------------------- profile */
/* ---- managed profile contract: real handles, absent hive backend ---- */
/* Kernel64 has a volatile registry but no hive file load/unload provider.
 * Validate an owned snapshot of the caller's actual token before reporting
 * that limitation. Never return HKCU as a fabricated loaded profile. */
static BOOL managed_profile_token(HANDLE token, DWORD required)
{
    HANDLE owned = NULL;
    ULONG basic[14] = {0}, returned = 0;
    union { SHZ_UNICODE_STRING name; BYTE bytes[256]; } type = {0};
    NTSTATUS status;
    DWORD error = ERROR_SUCCESS;
    ULONG_PTR begin, end, text;
    static const WCHAR token_type[] = L"Token";
    if (!DuplicateHandle(GetCurrentProcess(), token, GetCurrentProcess(), &owned,
                         0, FALSE, DUPLICATE_SAME_ACCESS)) return FALSE;
    status = NtQueryObject(owned, SHZ_ObjectBasicInformation, basic, sizeof basic, &returned);
    if (status < 0) error = RtlNtStatusToDosError(status);
    else if (returned != sizeof basic) error = ERROR_INVALID_DATA;
    if (!error) {
        status = NtQueryObject(owned, SHZ_ObjectTypeInformation, &type, sizeof type, &returned);
        if (status < 0) error = RtlNtStatusToDosError(status);
        else {
            begin = (ULONG_PTR)&type;
            end = begin + returned;
            text = (ULONG_PTR)type.name.Buffer;
            if (returned > sizeof type || returned < sizeof type.name ||
                text < begin + sizeof type.name || text > end - (sizeof token_type - sizeof(WCHAR)))
                error = ERROR_INVALID_DATA;
            else if (type.name.Length != sizeof token_type - sizeof(WCHAR) ||
                     memcmp(type.name.Buffer, token_type, sizeof token_type - sizeof(WCHAR)))
                error = ERROR_INVALID_HANDLE;
            else if ((basic[1] & required) != required) error = ERROR_ACCESS_DENIED;
        }
    }
    /* Only this private duplicate is closed. Caller token/profile handles
     * remain owned by their caller, even on every validation failure. */
    if (!CloseHandle(owned) && !error) error = GetLastError();
    if (error) { SetLastError(error); return FALSE; }
    return TRUE;
}

DLLAPI BOOL WINAPI LoadUserProfileW(HANDLE token, LPPROFILEINFOW profile)
{
    if (!profile || profile->dwSize != sizeof *profile) {
        SetLastError(ERROR_INVALID_PARAMETER); return FALSE;
    }
    profile->hProfile = NULL;
    if (!profile->lpUserName) { SetLastError(ERROR_INVALID_PARAMETER); return FALSE; }
    if (!managed_profile_token(token, TOKEN_QUERY | TOKEN_IMPERSONATE | TOKEN_DUPLICATE)) return FALSE;
    SetLastError(ERROR_CALL_NOT_IMPLEMENTED);
    return FALSE;
}

DLLAPI BOOL WINAPI LoadUserProfileA(HANDLE token, LPPROFILEINFOA profile)
{
    if (!profile || profile->dwSize != sizeof *profile) {
        SetLastError(ERROR_INVALID_PARAMETER); return FALSE;
    }
    profile->hProfile = NULL;
    if (!profile->lpUserName) { SetLastError(ERROR_INVALID_PARAMETER); return FALSE; }
    if (!managed_profile_token(token, TOKEN_QUERY | TOKEN_IMPERSONATE | TOKEN_DUPLICATE)) return FALSE;
    /* No string reaches a backend: neither encoding can load a hive here. */
    SetLastError(ERROR_CALL_NOT_IMPLEMENTED);
    return FALSE;
}

DLLAPI BOOL WINAPI UnloadUserProfile(HANDLE token, HANDLE profile)
{
    if (!profile) { SetLastError(ERROR_INVALID_HANDLE); return FALSE; }
    if (!managed_profile_token(token, TOKEN_IMPERSONATE | TOKEN_DUPLICATE)) return FALSE;
    /* This provider has never issued a loaded-profile handle. An unrelated
     * key, event, token or predefined HKCU cannot be a matching profile. */
    SetLastError(ERROR_INVALID_HANDLE);
    return FALSE;
}
/* ---- end managed profile contract ---- */

/* Original single-user implementation, following Microsoft Learn's size-in-TCHARs contract (including NUL).
 * References reviewed: Wine df15af3652511150490934682202d45af892f887 dlls/userenv/userenv_main.c;
 * ReactOS 9dc3ca87209fd8ebabd96c8ea95d439c13e7fdf8 dll/win32/userenv/profile.c. No upstream code copied.
 * There is no profile registry here. Only an explicitly configured USERPROFILE is returned. A snapshot avoids
 * a size-query/read race with SetEnvironmentVariableW; A is converted with CP_ACP, never by truncating WCHARs. */
static WCHAR *profile_environment(HANDLE token, const WCHAR **path)
{
    TOKEN_TYPE type;
    DWORD ret;
    WCHAR *env, *p;
    if (!GetTokenInformation(token, TokenType, &type, sizeof type, &ret)) return 0;
    env = GetEnvironmentStringsW();
    if (!env) { SetLastError(ERROR_NOT_ENOUGH_MEMORY); return 0; }
    for (p = env; *p; p += wlen(p) + 1) {
        if (!wci_cmp(p, wlen(p), L"USERPROFILE=", 12) && p[12]) {
            *path = p + 12;
            return env;
        }
    }
    FreeEnvironmentStringsW(env);
    SetLastError(ERROR_FILE_NOT_FOUND);
    return 0;
}

DLLAPI BOOL WINAPI GetUserProfileDirectoryW(HANDLE token, LPWSTR out, LPDWORD size)
{
    const WCHAR *path;
    WCHAR *env;
    DWORD need;
    BOOL fits;
    if (!size) { SetLastError(ERROR_INVALID_PARAMETER); return FALSE; }
    env = profile_environment(token, &path);
    if (!env) return FALSE;
    need = (DWORD)wlen(path) + 1;
    fits = out && *size >= need;
    if (fits) memcpy(out, path, need * sizeof *out);
    *size = need;
    FreeEnvironmentStringsW(env);
    if (!fits) SetLastError(ERROR_INSUFFICIENT_BUFFER);
    return fits;
}

DLLAPI BOOL WINAPI GetUserProfileDirectoryA(HANDLE token, LPSTR out, LPDWORD size)
{
    const WCHAR *path;
    WCHAR *env;
    int need;
    DWORD error = ERROR_SUCCESS;
    if (!size) { SetLastError(ERROR_INVALID_PARAMETER); return FALSE; }
    env = profile_environment(token, &path);
    if (!env) return FALSE;
    need = WideCharToMultiByte(CP_ACP, 0, path, -1, 0, 0, 0, 0);
    if (!need) error = GetLastError();
    else if (!out || *size < (DWORD)need) error = ERROR_INSUFFICIENT_BUFFER;
    else if (!WideCharToMultiByte(CP_ACP, 0, path, -1, out, need, 0, 0)) error = GetLastError();
    if (need) *size = (DWORD)need;
    FreeEnvironmentStringsW(env);
    if (error) { SetLastError(error); return FALSE; }
    return TRUE;
}

DLLAPI BOOL WINAPI GetProfileType(DWORD *flags)
{
    if (!flags) { SetLastError(ERROR_INVALID_PARAMETER); return FALSE; }
    SetLastError(ERROR_FILE_NOT_FOUND);                         /* no profile is loaded: this system has none */
    return FALSE;
}

/* ---------------------------------------------------------------- group policy */
#define GP_MAX 64
static HANDLE g_gp_events[GP_MAX];
static BOOL g_gp_machine[GP_MAX];
static volatile LONG g_gp_lock;

static void gp_lock(void) { while (InterlockedExchange(&g_gp_lock, 1)) SwitchToThread(); }
static void gp_unlock(void) { InterlockedExchange(&g_gp_lock, 0); }

DLLAPI BOOL WINAPI RegisterGPNotification(HANDLE event, BOOL machine)
{
    unsigned i;
    DWORD flags;
    if (!event || !GetHandleInformation(event, &flags)) { SetLastError(ERROR_INVALID_HANDLE); return FALSE; }
    gp_lock();
    for (i = 0; i < GP_MAX && g_gp_events[i]; ++i) { }
    if (i < GP_MAX) { g_gp_events[i] = event; g_gp_machine[i] = machine != 0; }
    gp_unlock();
    if (i == GP_MAX) { SetLastError(ERROR_NOT_ENOUGH_MEMORY); return FALSE; }
    return TRUE;                                                /* no policy is ever applied: the event stays unsignaled */
}

DLLAPI BOOL WINAPI UnregisterGPNotification(HANDLE event)
{
    unsigned i;
    BOOL found = FALSE;
    gp_lock();
    for (i = 0; i < GP_MAX; ++i) if (event && g_gp_events[i] == event) { g_gp_events[i] = 0; found = TRUE; break; }
    gp_unlock();
    if (!found) SetLastError(ERROR_INVALID_PARAMETER);
    return found;
}

DLLAPI HANDLE WINAPI EnterCriticalPolicySection(BOOL machine)
{
    HANDLE m = CreateMutexW(0, FALSE, machine ? L"ShzGroupPolicyMachine" : L"ShzGroupPolicyUser");
    if (!m) return 0;
    if (WaitForSingleObject(m, 600000) != WAIT_OBJECT_0) {      /* Windows' limit: 10 minutes */
        CloseHandle(m);
        SetLastError(ERROR_TIMEOUT);
        return 0;
    }
    return m;
}

DLLAPI BOOL WINAPI LeaveCriticalPolicySection(HANDLE section)
{
    if (!section) { SetLastError(ERROR_INVALID_PARAMETER); return FALSE; }
    if (!ReleaseMutex(section)) return FALSE;
    return CloseHandle(section);
}

/* ---------------------------------------------------------------- AppContainer SIDs */
DLLAPI HRESULT WINAPI DeriveAppContainerSidFromAppContainerName(PCWSTR name, PSID *sid)
{
    static SID_IDENTIFIER_AUTHORITY app_package = { { 0, 0, 0, 0, 0, 15 } };   /* SECURITY_APP_PACKAGE_AUTHORITY */
    WCHAR low[64];
    BYTE digest[32];
    DWORD sub[7];
    size_t n, i;
    NTSTATUS st;
    if (!name || !sid) return E_INVALIDARG;
    *sid = 0;
    n = wlen(name);
    if (!n || n >= 64) return E_INVALIDARG;                     /* package family names are 2..64 characters */
    for (i = 0; i < n; ++i) low[i] = name[i] >= 'A' && name[i] <= 'Z' ? (WCHAR)(name[i] + 32) : name[i];
    st = BCryptHash(BCRYPT_SHA256_ALG_HANDLE_, 0, 0, (PUCHAR)low, (ULONG)(n * sizeof(WCHAR)), digest, sizeof digest);
    if (st) return HRESULT_FROM_NT(st);
    for (i = 0; i < 7; ++i) memcpy(&sub[i], digest + i * 4, 4);
    if (!AllocateAndInitializeSid(&app_package, 8, 2 /* SECURITY_APP_PACKAGE_BASE_RID */, sub[0], sub[1], sub[2], sub[3], sub[4],
                                  sub[5], sub[6], sid))
        return HRESULT_FROM_WIN32(GetLastError());
    return S_OK;
}
