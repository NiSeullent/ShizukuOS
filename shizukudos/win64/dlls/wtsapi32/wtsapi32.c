/* SPDX-License-Identifier: GPL-2.0-only
 * wtsapi32.dll - Remote Desktop Services API for a machine with exactly one session: the console session the kernel
 * reports (PEB SessionId, ProcessIdToSessionId), with the single system user logged on at it, no RDP listener and no
 * other session ever appearing.
 *
 *   WTSOpenServerW/A, WTSCloseServer      only the local server exists: a non-NULL machine name is refused with
 *                                         RPC_S_SERVER_UNAVAILABLE; the local handle is WTS_CURRENT_SERVER_HANDLE.
 *   WTSEnumerateSessionsW/A               one WTS_SESSION_INFO: the console session, WTSActive, name "Console".
 *   WTSQuerySessionInformationW/A         for WTS_CURRENT_SESSION or that session's id: WTSSessionId, WTSUserName
 *                                         (GetUserNameW), WTSDomainName (the computer name), WTSWinStationName "Console",
 *                                         WTSConnectState WTSActive, WTSClientProtocolType 0 (console),
 *                                         WTSIsRemoteSession FALSE, WTSClientName/WTSClientAddress (empty: no client),
 *                                         WTSSessionInfo (WTSINFOW). Any other class: ERROR_NOT_SUPPORTED; an unknown
 *                                         session id: ERROR_INVALID_PARAMETER (the code Windows gives for one that does not exist).
 *   WTSFreeMemory                         frees what the two above allocate.
 *   WTSRegisterSessionNotification(Ex) / WTSUnRegisterSessionNotification(Ex)
 *                                         a per-window registration table (NOTIFY_FOR_THIS_SESSION / NOTIFY_FOR_ALL_SESSIONS
 *                                         validated). The session never changes here (no logon, lock, disconnect or
 *                                         remote connect can happen), so no WM_WTSSESSION_CHANGE is ever posted -
 *                                         exactly what a Windows console session that stays as it is delivers.
 *                                         Unregistering a window that is not registered: ERROR_INVALID_PARAMETER.
 *   WTSQueryUserToken                     ERROR_NO_TOKEN unless the id is this session's; then the process token
 *                                         (OpenProcessToken) - the single user's primary token.
 */
#include "nt.h"
#include <string.h>
#include <wtsapi32.h>

#define RPC_S_SERVER_UNAVAILABLE_ 1722
#define ERROR_NO_TOKEN_ 1008
static const WCHAR CONSOLE_NAME[] = L"Console";

static DWORD console_session(void)
{
    DWORD s = 0;
    if (!ProcessIdToSessionId(GetCurrentProcessId(), &s)) s = 0;
    return s;
}

static void *wts_alloc(SIZE_T n) { return HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, n); }
DLLAPI void WINAPI WTSFreeMemory(PVOID p) { if (p) HeapFree(GetProcessHeap(), 0, p); }

DLLAPI HANDLE WINAPI WTSOpenServerW(LPWSTR server)
{
    if (server && *server) { SetLastError(RPC_S_SERVER_UNAVAILABLE_); return 0; }
    return WTS_CURRENT_SERVER_HANDLE;
}

DLLAPI HANDLE WINAPI WTSOpenServerA(LPSTR server)
{
    if (server && *server) { SetLastError(RPC_S_SERVER_UNAVAILABLE_); return 0; }
    return WTS_CURRENT_SERVER_HANDLE;
}

DLLAPI void WINAPI WTSCloseServer(HANDLE server) { (void)server; }

static int server_ok(HANDLE h) { return h == WTS_CURRENT_SERVER_HANDLE; }

DLLAPI BOOL WINAPI WTSEnumerateSessionsW(HANDLE server, DWORD reserved, DWORD version, PWTS_SESSION_INFOW *out, DWORD *count)
{
    WTS_SESSION_INFOW *si;
    if (!out || !count || reserved || version != 1) { SetLastError(ERROR_INVALID_PARAMETER); return FALSE; }
    if (!server_ok(server)) { SetLastError(ERROR_INVALID_HANDLE); return FALSE; }
    si = wts_alloc(sizeof *si + sizeof CONSOLE_NAME);
    if (!si) { SetLastError(ERROR_NOT_ENOUGH_MEMORY); return FALSE; }
    si->SessionId = console_session();
    si->pWinStationName = (LPWSTR)(si + 1);
    memcpy(si->pWinStationName, CONSOLE_NAME, sizeof CONSOLE_NAME);
    si->State = WTSActive;
    *out = si;
    *count = 1;
    return TRUE;
}

DLLAPI BOOL WINAPI WTSEnumerateSessionsA(HANDLE server, DWORD reserved, DWORD version, PWTS_SESSION_INFOA *out, DWORD *count)
{
    WTS_SESSION_INFOA *si;
    if (!out || !count || reserved || version != 1) { SetLastError(ERROR_INVALID_PARAMETER); return FALSE; }
    if (!server_ok(server)) { SetLastError(ERROR_INVALID_HANDLE); return FALSE; }
    si = wts_alloc(sizeof *si + 8);
    if (!si) { SetLastError(ERROR_NOT_ENOUGH_MEMORY); return FALSE; }
    si->SessionId = console_session();
    si->pWinStationName = (LPSTR)(si + 1);
    memcpy(si->pWinStationName, "Console", 8);
    si->State = WTSActive;
    *out = si;
    *count = 1;
    return TRUE;
}

static BOOL give_wstr(const WCHAR *s, LPWSTR *out, DWORD *bytes)
{
    size_t n = 0;
    while (s[n]) ++n;
    *out = wts_alloc((n + 1) * sizeof(WCHAR));
    if (!*out) { SetLastError(ERROR_NOT_ENOUGH_MEMORY); return FALSE; }
    memcpy(*out, s, (n + 1) * sizeof(WCHAR));
    *bytes = (DWORD)((n + 1) * sizeof(WCHAR));
    return TRUE;
}

static BOOL give_blob(const void *p, DWORD n, LPWSTR *out, DWORD *bytes)
{
    *out = wts_alloc(n);
    if (!*out) { SetLastError(ERROR_NOT_ENOUGH_MEMORY); return FALSE; }
    memcpy(*out, p, n);
    *bytes = n;
    return TRUE;
}

DLLAPI BOOL WINAPI WTSQuerySessionInformationW(HANDLE server, DWORD session, WTS_INFO_CLASS cls, LPWSTR *out, DWORD *bytes)
{
    WCHAR name[257];
    DWORD n;
    if (!out || !bytes) { SetLastError(ERROR_INVALID_PARAMETER); return FALSE; }
    *out = 0;
    *bytes = 0;
    if (!server_ok(server)) { SetLastError(ERROR_INVALID_HANDLE); return FALSE; }
    if (session != WTS_CURRENT_SESSION && session != console_session()) { SetLastError(ERROR_INVALID_PARAMETER); return FALSE; }
    switch ((int)cls) {                                    /* int: WTSIsRemoteSession (29) postdates mingw's enum */
    case WTSSessionId: { DWORD id = console_session(); return give_blob(&id, sizeof id, out, bytes); }
    case WTSUserName:
        n = 257;
        if (!GetUserNameW(name, &n)) return FALSE;
        return give_wstr(name, out, bytes);
    case WTSDomainName:
        n = 257;
        if (!GetComputerNameW(name, &n)) return FALSE;
        return give_wstr(name, out, bytes);
    case WTSWinStationName: return give_wstr(CONSOLE_NAME, out, bytes);
    case WTSConnectState: { WTS_CONNECTSTATE_CLASS st = WTSActive; return give_blob(&st, sizeof st, out, bytes); }
    case WTSClientProtocolType: { USHORT t = 0; return give_blob(&t, sizeof t, out, bytes); }
    case 29 /* WTSIsRemoteSession (newer SDKs) */: { BOOLEAN r = FALSE; return give_blob(&r, sizeof r, out, bytes); }
    case WTSClientName: case WTSClientDirectory: case WTSInitialProgram: case WTSWorkingDirectory: case WTSApplicationName:
        return give_wstr(L"", out, bytes);
    case WTSClientAddress: { WTS_CLIENT_ADDRESS a; memset(&a, 0, sizeof a); return give_blob(&a, sizeof a, out, bytes); }
    case WTSClientBuildNumber: { ULONG b = 0; return give_blob(&b, sizeof b, out, bytes); }
    case WTSSessionInfo: {
        WTSINFOW info;
        FILETIME now;
        memset(&info, 0, sizeof info);
        info.State = WTSActive;
        info.SessionId = console_session();
        memcpy(info.WinStationName, CONSOLE_NAME, sizeof CONSOLE_NAME);
        n = sizeof info.UserName / sizeof(WCHAR);
        GetUserNameW(info.UserName, &n);
        n = sizeof info.Domain / sizeof(WCHAR);
        GetComputerNameW(info.Domain, &n);
        GetSystemTimeAsFileTime(&now);
        info.CurrentTime.LowPart = now.dwLowDateTime;
        info.CurrentTime.HighPart = (LONG)now.dwHighDateTime;
        return give_blob(&info, sizeof info, out, bytes);
    }
    default:
        SetLastError(ERROR_NOT_SUPPORTED);
        return FALSE;
    }
}

DLLAPI BOOL WINAPI WTSQuerySessionInformationA(HANDLE server, DWORD session, WTS_INFO_CLASS cls, LPSTR *out, DWORD *bytes)
{
    LPWSTR w = 0;
    DWORD wb = 0;
    if (!out || !bytes) { SetLastError(ERROR_INVALID_PARAMETER); return FALSE; }
    *out = 0; *bytes = 0;
    if (!WTSQuerySessionInformationW(server, session, cls, &w, &wb)) return FALSE;
    switch (cls) {
    case WTSUserName: case WTSDomainName: case WTSWinStationName: case WTSClientName: case WTSClientDirectory:
    case WTSInitialProgram: case WTSWorkingDirectory: case WTSApplicationName: {
        DWORD n = wb / sizeof(WCHAR), i;
        *out = wts_alloc(n);
        if (!*out) { WTSFreeMemory(w); SetLastError(ERROR_NOT_ENOUGH_MEMORY); return FALSE; }
        for (i = 0; i < n; ++i) (*out)[i] = w[i] < 128 ? (char)w[i] : '?';
        *bytes = n;
        WTSFreeMemory(w);
        return TRUE;
    }
    default:
        *out = (LPSTR)w;
        *bytes = wb;
        return TRUE;
    }
}

/* ---------------------------------------------------------------- session change notification */
typedef struct notify { struct notify *next; HWND hwnd; DWORD flags; } notify;
static SRWLOCK g_lock = SRWLOCK_INIT;
static notify *g_notify;

DLLAPI BOOL WINAPI WTSRegisterSessionNotificationEx(HANDLE server, HWND hwnd, DWORD flags)
{
    notify *e;
    if (!server_ok(server)) { SetLastError(ERROR_INVALID_HANDLE); return FALSE; }
    if (!hwnd || (flags != NOTIFY_FOR_THIS_SESSION && flags != NOTIFY_FOR_ALL_SESSIONS)) { SetLastError(ERROR_INVALID_PARAMETER); return FALSE; }
    AcquireSRWLockExclusive(&g_lock);
    for (e = g_notify; e; e = e->next) if (e->hwnd == hwnd) { e->flags = flags; ReleaseSRWLockExclusive(&g_lock); return TRUE; }
    e = HeapAlloc(GetProcessHeap(), 0, sizeof *e);
    if (!e) { ReleaseSRWLockExclusive(&g_lock); SetLastError(ERROR_NOT_ENOUGH_MEMORY); return FALSE; }
    e->hwnd = hwnd; e->flags = flags; e->next = g_notify; g_notify = e;
    ReleaseSRWLockExclusive(&g_lock);
    return TRUE;
}

DLLAPI BOOL WINAPI WTSRegisterSessionNotification(HWND hwnd, DWORD flags) { return WTSRegisterSessionNotificationEx(WTS_CURRENT_SERVER_HANDLE, hwnd, flags); }

DLLAPI BOOL WINAPI WTSUnRegisterSessionNotificationEx(HANDLE server, HWND hwnd)
{
    notify *e, **pp;
    if (!server_ok(server)) { SetLastError(ERROR_INVALID_HANDLE); return FALSE; }
    AcquireSRWLockExclusive(&g_lock);
    for (pp = &g_notify; (e = *pp) != 0; pp = &e->next) if (e->hwnd == hwnd) { *pp = e->next; break; }
    ReleaseSRWLockExclusive(&g_lock);
    if (!e) { SetLastError(ERROR_INVALID_PARAMETER); return FALSE; }
    HeapFree(GetProcessHeap(), 0, e);
    return TRUE;
}

DLLAPI BOOL WINAPI WTSUnRegisterSessionNotification(HWND hwnd) { return WTSUnRegisterSessionNotificationEx(WTS_CURRENT_SERVER_HANDLE, hwnd); }

DLLAPI BOOL WINAPI WTSQueryUserToken(ULONG session, PHANDLE token)
{
    if (!token) { SetLastError(ERROR_INVALID_PARAMETER); return FALSE; }
    *token = 0;
    if (session != console_session()) { SetLastError(ERROR_NO_TOKEN_); return FALSE; }
    return OpenProcessToken(GetCurrentProcess(), TOKEN_ALL_ACCESS, token);
}
