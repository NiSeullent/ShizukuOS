/* SPDX-License-Identifier: GPL-2.0-only
 * userenv.dll - environment blocks, profile type, group policy notification and critical sections, AppContainer SIDs.
 *
 * This system has one user (advapi32 token.c: SHZ_USER_NAME_W) and no user profile directories (shell32.c reports every
 * profile folder as not found), no group policy engine and no AppContainers. What that means for each function:
 *   CreateEnvironmentBlock   bInherit TRUE: a copy of the calling process's environment; FALSE: the system variables of
 *                            the calling process's environment (the ones the Kernel64 loader gives every process:
 *                            SystemRoot, SystemDrive, PATH, TEMP, TMP, COMPUTERNAME, OS, PROCESSOR_ARCHITECTURE,
 *                            NUMBER_OF_PROCESSORS). USERNAME is added in both cases. No profile variables (USERPROFILE,
 *                            APPDATA, ...) are invented: no profile exists. The block is sorted, as Windows builds it.
 *   DestroyEnvironmentBlock  frees such a block.
 *   GetProfileType           no profile is loaded for the user: FALSE with ERROR_FILE_NOT_FOUND.
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
