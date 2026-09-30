/* SPDX-License-Identifier: GPL-2.0-only
 * wtsapi32.dll on a one-session machine: the session enumeration and queries must agree with what the kernel reports
 * through kernel32 (ProcessIdToSessionId, GetUserNameW, GetComputerNameW), the notification registration must follow the
 * documented contract, and every unsupported query must fail explicitly. */
#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <wtsapi32.h>
#include "u_check.h"

int main(void)
{
    DWORD mine = 0, n = 0, bytes = 0;
    PWTS_SESSION_INFOW si = 0;
    LPWSTR buf = 0;
    WCHAR user[257], comp[257];
    DWORD ulen = 257, clen = 257;
    HANDLE tok = 0;

    ProcessIdToSessionId(GetCurrentProcessId(), &mine);
    GetUserNameW(user, &ulen);
    GetComputerNameW(comp, &clen);
    U_CHECK("WTSOpenServerW(NULL) is the local server handle; a remote name is RPC_S_SERVER_UNAVAILABLE", WTSOpenServerW(0) == WTS_CURRENT_SERVER_HANDLE && WTSOpenServerW(L"OTHER") == 0 && GetLastError() == 1722);
    U_CHECK("WTSEnumerateSessionsW lists exactly the console session, active, named Console", WTSEnumerateSessionsW(WTS_CURRENT_SERVER_HANDLE, 0, 1, &si, &n) && n == 1 && si && si[0].SessionId == mine && si[0].State == WTSActive && u_ascii_eq_w(si[0].pWinStationName, "Console"));
    WTSFreeMemory(si);
    U_CHECK("WTSEnumerateSessionsW with version 2 is ERROR_INVALID_PARAMETER", !WTSEnumerateSessionsW(WTS_CURRENT_SERVER_HANDLE, 0, 2, &si, &n) && GetLastError() == ERROR_INVALID_PARAMETER);
    U_CHECK("WTSQuerySessionInformationW(WTSSessionId) = the process' session id (4 bytes)", WTSQuerySessionInformationW(WTS_CURRENT_SERVER_HANDLE, WTS_CURRENT_SESSION, WTSSessionId, &buf, &bytes) && bytes == 4 && *(DWORD *)buf == mine);
    WTSFreeMemory(buf);
    U_CHECK("WTSQuerySessionInformationW(WTSUserName) = GetUserNameW", WTSQuerySessionInformationW(WTS_CURRENT_SERVER_HANDLE, mine, WTSUserName, &buf, &bytes) && u_wide_eq(buf, user) && bytes == (ulen + 1) * 2 - 2);
    WTSFreeMemory(buf);
    U_CHECK("WTSQuerySessionInformationW(WTSDomainName) = the computer name", WTSQuerySessionInformationW(WTS_CURRENT_SERVER_HANDLE, WTS_CURRENT_SESSION, WTSDomainName, &buf, &bytes) && u_wide_eq(buf, comp));
    WTSFreeMemory(buf);
    U_CHECK("WTSConnectState = WTSActive, WTSClientProtocolType = 0 (console)", WTSQuerySessionInformationW(WTS_CURRENT_SERVER_HANDLE, WTS_CURRENT_SESSION, WTSConnectState, &buf, &bytes) && bytes == sizeof(WTS_CONNECTSTATE_CLASS) && *(WTS_CONNECTSTATE_CLASS *)buf == WTSActive && (WTSFreeMemory(buf), 1) && WTSQuerySessionInformationW(WTS_CURRENT_SERVER_HANDLE, WTS_CURRENT_SESSION, WTSClientProtocolType, &buf, &bytes) && bytes == 2 && *(USHORT *)buf == 0);
    WTSFreeMemory(buf);
    U_CHECK("WTSSessionInfo: a WTSINFOW with the session id, WTSActive, the user name", WTSQuerySessionInformationW(WTS_CURRENT_SERVER_HANDLE, WTS_CURRENT_SESSION, WTSSessionInfo, &buf, &bytes) && bytes == sizeof(WTSINFOW) && ((WTSINFOW *)buf)->SessionId == mine && ((WTSINFOW *)buf)->State == WTSActive && u_wide_eq(((WTSINFOW *)buf)->UserName, user));
    WTSFreeMemory(buf);
    U_CHECK("an unknown session id is ERROR_INVALID_PARAMETER", !WTSQuerySessionInformationW(WTS_CURRENT_SERVER_HANDLE, mine + 7, WTSUserName, &buf, &bytes) && GetLastError() == ERROR_INVALID_PARAMETER && buf == 0);
    U_CHECK("an unsupported class (WTSIdleTime) is ERROR_NOT_SUPPORTED", !WTSQuerySessionInformationW(WTS_CURRENT_SERVER_HANDLE, WTS_CURRENT_SESSION, WTSIdleTime, &buf, &bytes) && GetLastError() == ERROR_NOT_SUPPORTED);
    U_CHECK("a bad server handle is ERROR_INVALID_HANDLE", !WTSQuerySessionInformationW((HANDLE)0x55, WTS_CURRENT_SESSION, WTSUserName, &buf, &bytes) && GetLastError() == ERROR_INVALID_HANDLE);
    {
        LPSTR a = 0;
        U_CHECK("WTSQuerySessionInformationA(WTSWinStationName) = \"Console\"", WTSQuerySessionInformationA(WTS_CURRENT_SERVER_HANDLE, WTS_CURRENT_SESSION, WTSWinStationName, &a, &bytes) && a && !strcmp(a, "Console") && bytes == 8);
        WTSFreeMemory(a);
    }
    U_CHECK("WTSRegisterSessionNotification(hwnd, THIS_SESSION) succeeds; unregistering twice fails with ERROR_INVALID_PARAMETER",
            WTSRegisterSessionNotification((HWND)0x77, NOTIFY_FOR_THIS_SESSION) && WTSUnRegisterSessionNotification((HWND)0x77) && !WTSUnRegisterSessionNotification((HWND)0x77) && GetLastError() == ERROR_INVALID_PARAMETER);
    U_CHECK("WTSRegisterSessionNotification with bad flags / a NULL window is ERROR_INVALID_PARAMETER", !WTSRegisterSessionNotification((HWND)0x77, 5) && GetLastError() == ERROR_INVALID_PARAMETER && !WTSRegisterSessionNotification(0, NOTIFY_FOR_ALL_SESSIONS) && GetLastError() == ERROR_INVALID_PARAMETER);
    U_CHECK("WTSQueryUserToken(this session) gives a token; another session is ERROR_NO_TOKEN", WTSQueryUserToken(mine, &tok) && tok && (CloseHandle(tok), 1) && !WTSQueryUserToken(mine + 9, &tok) && GetLastError() == 1008 && tok == 0);
    WTSCloseServer(WTS_CURRENT_SERVER_HANDLE);
    return u_finish("t_u_wtsapi32");
}
