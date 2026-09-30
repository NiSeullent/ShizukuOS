/* SPDX-License-Identifier: GPL-2.0-only
 * winhttp.dll: handle typing and lifetime, timeouts/options, URL cracking and creation (RFC 3986 http/https, MSDN
 * WinHttpCrackUrl rules), the proxy answers of a machine without proxy configuration or auto-detection, the
 * asynchronous proxy resolver completing through the status callback, RFC 1123 dates, and the explicit failure of the
 * request engine that does not exist. Expected codes are the documented WinHTTP ones. */
#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <winhttp.h>
#include "u_check.h"

static volatile LONG g_done, g_err;
static void CALLBACK cb(HINTERNET h, DWORD_PTR ctx, DWORD status, LPVOID info, DWORD len)
{
    (void)h;
    if (status == WINHTTP_CALLBACK_STATUS_GETPROXYFORURL_COMPLETE && ctx == 0x77 && len == sizeof(WINHTTP_ASYNC_RESULT)) {
        g_err = (LONG)((WINHTTP_ASYNC_RESULT *)info)->dwError;
        g_done = 1;
    }
}

int main(void)
{
    HINTERNET s = WinHttpOpen(L"shz-test", WINHTTP_ACCESS_TYPE_NO_PROXY, 0, 0, 0), c, r, res = 0;
    U_CHECK("WinHttpOpen(NO_PROXY) gives a session", s != 0);
    U_CHECK("WinHttpOpen(NAMED_PROXY without a proxy name) is ERROR_INVALID_PARAMETER", WinHttpOpen(L"x", WINHTTP_ACCESS_TYPE_NAMED_PROXY, 0, 0, 0) == 0 && GetLastError() == ERROR_INVALID_PARAMETER);
    U_CHECK("WinHttpConnect / WinHttpOpenRequest chain", (c = WinHttpConnect(s, L"example.test", 0, 0)) != 0 && (r = WinHttpOpenRequest(c, 0, L"/x?y=1", 0, 0, 0, 0)) != 0);
    U_CHECK("WinHttpConnect on a request handle is ERROR_WINHTTP_INCORRECT_HANDLE_TYPE", WinHttpConnect(r, L"a", 80, 0) == 0 && GetLastError() == ERROR_WINHTTP_INCORRECT_HANDLE_TYPE);
    U_CHECK("WinHttpConnect on a bogus handle is ERROR_INVALID_HANDLE", WinHttpConnect((HINTERNET)0x10, L"a", 80, 0) == 0 && GetLastError() == ERROR_INVALID_HANDLE);
    {
        DWORD v = 0, n = 4, want = 1234;
        U_CHECK("WinHttpSetTimeouts(-1 invalid) fails; valid values read back through QueryOption", !WinHttpSetTimeouts(s, -5, 0, 0, 0) && WinHttpSetTimeouts(s, 0, 1111, 2222, 3333) &&
                WinHttpQueryOption(s, WINHTTP_OPTION_CONNECT_TIMEOUT, &v, &n) && v == 1111 && WinHttpQueryOption(s, WINHTTP_OPTION_RECEIVE_TIMEOUT, &v, &n) && v == 3333);
        U_CHECK("SetOption(SEND_TIMEOUT) then QueryOption; a too-small buffer is ERROR_INSUFFICIENT_BUFFER with the size; an unknown option ERROR_WINHTTP_INVALID_OPTION",
                WinHttpSetOption(s, WINHTTP_OPTION_SEND_TIMEOUT, &want, 4) && WinHttpQueryOption(s, WINHTTP_OPTION_SEND_TIMEOUT, &v, &n) && v == 1234 &&
                (n = 1, !WinHttpQueryOption(s, WINHTTP_OPTION_SEND_TIMEOUT, &v, &n)) && GetLastError() == ERROR_INSUFFICIENT_BUFFER && n == 4 &&
                !WinHttpSetOption(s, 0xdead, &v, 4) && GetLastError() == ERROR_WINHTTP_INVALID_OPTION);
    }
    /* ---- URLs ---- */
    {
        URL_COMPONENTS uc;
        WCHAR host[64], path[64], extra[64], user[16];
        static const WCHAR u1[] = L"https://bob@www.example.com:8443/a/b.html?q=1#f";
        memset(&uc, 0, sizeof uc);
        uc.dwStructSize = sizeof uc;
        uc.lpszHostName = host; uc.dwHostNameLength = 64;
        uc.lpszUrlPath = path; uc.dwUrlPathLength = 64;
        uc.lpszExtraInfo = extra; uc.dwExtraInfoLength = 64;
        uc.lpszUserName = user; uc.dwUserNameLength = 16;
        U_CHECK("WinHttpCrackUrl(https with user, port, path, query) fills every component", WinHttpCrackUrl(u1, 0, 0, &uc) && uc.nScheme == INTERNET_SCHEME_HTTPS && uc.nPort == 8443 &&
                u_ascii_eq_w((const unsigned short *)host, "www.example.com") && u_ascii_eq_w((const unsigned short *)path, "/a/b.html") && u_ascii_eq_w((const unsigned short *)extra, "?q=1#f") && u_ascii_eq_w((const unsigned short *)user, "bob"));
        memset(&uc, 0, sizeof uc);
        uc.dwStructSize = sizeof uc;
        uc.dwHostNameLength = 1; uc.dwUrlPathLength = 1;
        U_CHECK("with NULL buffers and non-zero lengths the components point into the URL", WinHttpCrackUrl(L"http://h.test/p", 0, 0, &uc) && uc.nScheme == INTERNET_SCHEME_HTTP && uc.nPort == 80 && uc.dwHostNameLength == 6 && uc.dwUrlPathLength == 2 && uc.lpszHostName && uc.lpszHostName[0] == 'h');
        uc.lpszHostName = host; uc.dwHostNameLength = 3; uc.lpszUrlPath = 0; uc.dwUrlPathLength = 0;
        U_CHECK("a too-small host buffer is ERROR_INSUFFICIENT_BUFFER with the size needed", !WinHttpCrackUrl(L"http://h.test/p", 0, 0, &uc) && GetLastError() == ERROR_INSUFFICIENT_BUFFER && uc.dwHostNameLength == 7);
        U_CHECK("ftp:// is ERROR_WINHTTP_UNRECOGNIZED_SCHEME; a wrong dwStructSize is ERROR_INVALID_PARAMETER", (uc.dwStructSize = sizeof uc, !WinHttpCrackUrl(L"ftp://x/", 0, 0, &uc)) && GetLastError() == ERROR_WINHTTP_UNRECOGNIZED_SCHEME && (uc.dwStructSize = 3, !WinHttpCrackUrl(L"http://x/", 0, 0, &uc)) && GetLastError() == ERROR_INVALID_PARAMETER);
        {
            WCHAR out[128];
            DWORD n = 128;
            memset(&uc, 0, sizeof uc);
            uc.dwStructSize = sizeof uc; uc.nScheme = INTERNET_SCHEME_HTTPS; uc.lpszHostName = L"h.test"; uc.nPort = 8443; uc.lpszUrlPath = L"/x"; uc.lpszExtraInfo = L"?a=1";
            U_CHECK("WinHttpCreateUrl builds https://h.test:8443/x?a=1; the default port is omitted", WinHttpCreateUrl(&uc, 0, out, &n) && u_ascii_eq_w((const unsigned short *)out, "https://h.test:8443/x?a=1") && n == 25 && (uc.nPort = 443, n = 128, WinHttpCreateUrl(&uc, 0, out, &n)) && u_ascii_eq_w((const unsigned short *)out, "https://h.test/x?a=1"));
        }
    }
    /* ---- proxy ---- */
    {
        WINHTTP_CURRENT_USER_IE_PROXY_CONFIG ie;
        WINHTTP_PROXY_INFO pi;
        WINHTTP_AUTOPROXY_OPTIONS ao;
        LPWSTR url = (LPWSTR)1;
        memset(&ie, 0xcc, sizeof ie);
        U_CHECK("WinHttpGetIEProxyConfigForCurrentUser: no auto-detect, no config URL, no proxy", WinHttpGetIEProxyConfigForCurrentUser(&ie) && !ie.fAutoDetect && !ie.lpszAutoConfigUrl && !ie.lpszProxy && !ie.lpszProxyBypass);
        U_CHECK("WinHttpGetDefaultProxyConfiguration is WINHTTP_ACCESS_TYPE_NO_PROXY; setting it is ERROR_ACCESS_DENIED", WinHttpGetDefaultProxyConfiguration(&pi) && pi.dwAccessType == WINHTTP_ACCESS_TYPE_NO_PROXY && !WinHttpSetDefaultProxyConfiguration(&pi) && GetLastError() == ERROR_ACCESS_DENIED);
        U_CHECK("WinHttpDetectAutoProxyConfigUrl fails with ERROR_WINHTTP_AUTODETECTION_FAILED", !WinHttpDetectAutoProxyConfigUrl(WINHTTP_AUTO_DETECT_TYPE_DHCP, &url) && GetLastError() == ERROR_WINHTTP_AUTODETECTION_FAILED && url == 0);
        memset(&ao, 0, sizeof ao);
        ao.dwFlags = WINHTTP_AUTOPROXY_AUTO_DETECT;
        U_CHECK("WinHttpGetProxyForUrl(AUTO_DETECT) is ERROR_WINHTTP_AUTODETECTION_FAILED", !WinHttpGetProxyForUrl(s, L"http://x/", &ao, &pi) && GetLastError() == ERROR_WINHTTP_AUTODETECTION_FAILED);
        ao.dwFlags = 0;
        U_CHECK("WinHttpGetProxyForUrl with no flag is ERROR_INVALID_PARAMETER", !WinHttpGetProxyForUrl(s, L"http://x/", &ao, &pi) && GetLastError() == ERROR_INVALID_PARAMETER);
        /* the asynchronous resolver */
        U_CHECK("WinHttpCreateProxyResolver gives a resolver; a request handle is refused", WinHttpCreateProxyResolver(s, &res) == 0 && res && WinHttpCreateProxyResolver(r, &(HINTERNET){0}) == ERROR_WINHTTP_INCORRECT_HANDLE_TYPE);
        U_CHECK("WinHttpSetStatusCallback stores it and returns the previous one (NULL)", WinHttpSetStatusCallback(res, cb, WINHTTP_CALLBACK_FLAG_GETPROXYFORURL_COMPLETE, 0) == 0);
        {
            WINHTTP_PROXY_RESULT pr;
            DWORD i;
            ao.dwFlags = WINHTTP_AUTOPROXY_AUTO_DETECT;
            g_done = 0;
            U_CHECK("GetProxyForUrlEx returns ERROR_IO_PENDING and the callback reports ERROR_WINHTTP_AUTODETECTION_FAILED", WinHttpGetProxyForUrlEx(res, L"http://x/", &ao, 0x77) == ERROR_IO_PENDING && ((void)(i = 0), 1));
            for (i = 0; i < 200 && !g_done; ++i) Sleep(10);
            U_CHECK("...completed through GETPROXYFORURL_COMPLETE", g_done == 1 && g_err == (LONG)ERROR_WINHTTP_AUTODETECTION_FAILED);
            U_CHECK("GetProxyResult after a failed detection reports that error", WinHttpGetProxyResult(res, &pr) == ERROR_WINHTTP_AUTODETECTION_FAILED);
            memset(&ao, 0, sizeof ao);
            ao.dwFlags = 0x8;                                         /* neither detect nor URL: nothing to fail; direct */
            g_done = 0;
            WinHttpGetProxyForUrlEx(res, L"http://x/", &ao, 0x77);
            for (i = 0; i < 200 && !g_done; ++i) Sleep(10);
            U_CHECK("with nothing to detect the result is one direct entry (fProxy FALSE), freed by WinHttpFreeProxyResult", g_done && WinHttpGetProxyResult(res, &pr) == 0 && pr.cEntries == 1 && !pr.pEntries[0].fProxy && (WinHttpFreeProxyResult(&pr), pr.cEntries == 0 && pr.pEntries == 0));
        }
    }
    /* ---- requests: no engine ---- */
    {
        DWORD n = 5;
        U_CHECK("WinHttpAddRequestHeaders accepts a header with ADD; a bad flag word is ERROR_INVALID_PARAMETER", WinHttpAddRequestHeaders(r, L"X-A: 1", (DWORD)-1L, WINHTTP_ADDREQ_FLAG_ADD) && !WinHttpAddRequestHeaders(r, L"X-A: 1", (DWORD)-1L, 0) && GetLastError() == ERROR_INVALID_PARAMETER);
        U_CHECK("WinHttpSendRequest fails with ERROR_NOT_SUPPORTED (no HTTP engine); on a session handle it is a wrong-type error", !WinHttpSendRequest(r, 0, 0, 0, 0, 0, 0) && GetLastError() == ERROR_NOT_SUPPORTED && !WinHttpSendRequest(s, 0, 0, 0, 0, 0, 0) && GetLastError() == ERROR_WINHTTP_INCORRECT_HANDLE_TYPE);
        U_CHECK("ReceiveResponse / ReadData / QueryDataAvailable fail with ERROR_NOT_SUPPORTED and report 0 bytes", !WinHttpReceiveResponse(r, 0) && GetLastError() == ERROR_NOT_SUPPORTED && !WinHttpReadData(r, &n, 4, &n) && n == 0 && GetLastError() == ERROR_NOT_SUPPORTED && !WinHttpQueryDataAvailable(r, &n) && GetLastError() == ERROR_NOT_SUPPORTED);
    }
    /* ---- dates ---- */
    {
        WCHAR d[64];
        SYSTEMTIME t, u;
        memset(&t, 0, sizeof t);
        t.wYear = 1994; t.wMonth = 11; t.wDay = 6; t.wDayOfWeek = 0; t.wHour = 8; t.wMinute = 49; t.wSecond = 37;
        U_CHECK("WinHttpTimeFromSystemTime gives the RFC 1123 example \"Sun, 06 Nov 1994 08:49:37 GMT\"", WinHttpTimeFromSystemTime(&t, d) && u_ascii_eq_w((const unsigned short *)d, "Sun, 06 Nov 1994 08:49:37 GMT"));
        U_CHECK("WinHttpTimeToSystemTime parses it back", WinHttpTimeToSystemTime(d, &u) && u.wYear == 1994 && u.wMonth == 11 && u.wDay == 6 && u.wDayOfWeek == 0 && u.wHour == 8 && u.wMinute == 49 && u.wSecond == 37);
        U_CHECK("a malformed date is ERROR_INVALID_PARAMETER", !WinHttpTimeToSystemTime(L"Sunday, 6 Nov 94", &u) && GetLastError() == ERROR_INVALID_PARAMETER);
    }
    /* ---- close ---- */
    U_CHECK("WinHttpCloseHandle closes request, connection, resolver, session; a closed handle is ERROR_INVALID_HANDLE", WinHttpCloseHandle(r) && WinHttpCloseHandle(c) && WinHttpCloseHandle(res) && WinHttpCloseHandle(s) && !WinHttpCloseHandle(r) && GetLastError() == ERROR_INVALID_HANDLE);
    return u_finish("t_u_winhttp");
}
