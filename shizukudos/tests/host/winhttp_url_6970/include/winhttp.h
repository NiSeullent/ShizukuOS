/* SPDX-License-Identifier: GPL-2.0-only
 * Test-only WinHTTP declarations. Values/layout follow the Windows Win64 ABI.
 * They permit the unchanged full production TU; no HTTP/TLS engine is added.
 */
#ifndef SHZ_WINHTTP_URL_6970_WINHTTP_H
#define SHZ_WINHTTP_URL_6970_WINHTTP_H
#include <windows.h>

typedef void *HINTERNET;
typedef WORD INTERNET_PORT;
typedef int INTERNET_SCHEME;
typedef VOID (CALLBACK *WINHTTP_STATUS_CALLBACK)(HINTERNET, DWORD_PTR, DWORD, LPVOID, DWORD);
typedef struct {
    DWORD dwStructSize;
    LPWSTR lpszScheme;
    DWORD dwSchemeLength;
    INTERNET_SCHEME nScheme;
    LPWSTR lpszHostName;
    DWORD dwHostNameLength;
    INTERNET_PORT nPort;
    LPWSTR lpszUserName;
    DWORD dwUserNameLength;
    LPWSTR lpszPassword;
    DWORD dwPasswordLength;
    LPWSTR lpszUrlPath;
    DWORD dwUrlPathLength;
    LPWSTR lpszExtraInfo;
    DWORD dwExtraInfoLength;
} URL_COMPONENTS, *LPURL_COMPONENTS;
typedef struct {
    BOOL fAutoDetect;
    LPWSTR lpszAutoConfigUrl, lpszProxy, lpszProxyBypass;
} WINHTTP_CURRENT_USER_IE_PROXY_CONFIG;
typedef struct { DWORD dwAccessType; LPWSTR lpszProxy, lpszProxyBypass; } WINHTTP_PROXY_INFO;
typedef struct {
    DWORD dwFlags, dwAutoDetectFlags;
    LPCWSTR lpszAutoConfigUrl;
    LPVOID lpvReserved;
    DWORD dwReserved;
    BOOL fAutoLogonIfChallenged;
} WINHTTP_AUTOPROXY_OPTIONS;
typedef struct { DWORD_PTR dwResult; DWORD dwError; } WINHTTP_ASYNC_RESULT;
typedef struct {
    BOOL fProxy, fBypass;
    INTERNET_SCHEME ProxyScheme;
    LPWSTR pwszProxy;
    INTERNET_PORT ProxyPort;
} WINHTTP_PROXY_RESULT_ENTRY;
typedef struct { DWORD cEntries; WINHTTP_PROXY_RESULT_ENTRY *pEntries; } WINHTTP_PROXY_RESULT;

#define INTERNET_SCHEME_HTTP 1
#define INTERNET_SCHEME_HTTPS 2
#define INTERNET_DEFAULT_HTTP_PORT 80u
#define INTERNET_DEFAULT_HTTPS_PORT 443u
#define WINHTTP_ACCESS_TYPE_NO_PROXY 1u
#define WINHTTP_ACCESS_TYPE_NAMED_PROXY 3u
#define WINHTTP_FLAG_ASYNC 0x10000000u
#define WINHTTP_OPTION_RESOLVE_TIMEOUT 2u
#define WINHTTP_OPTION_CONNECT_TIMEOUT 3u
#define WINHTTP_OPTION_CONNECT_RETRIES 4u
#define WINHTTP_OPTION_SEND_TIMEOUT 5u
#define WINHTTP_OPTION_RECEIVE_TIMEOUT 6u
#define WINHTTP_OPTION_CONTEXT_VALUE 45u
#define WINHTTP_OPTION_MAX_CONNS_PER_SERVER 73u
#define WINHTTP_OPTION_REDIRECT_POLICY 88u
#define WINHTTP_OPTION_REDIRECT_POLICY_DISALLOW_HTTPS_TO_HTTP 1u
#define WINHTTP_CALLBACK_STATUS_HANDLE_CLOSING 0x00000800u
#define WINHTTP_CALLBACK_FLAG_HANDLES 0x00000c00u
#define WINHTTP_CALLBACK_STATUS_GETPROXYFORURL_COMPLETE 0x01000000u
#define WINHTTP_CALLBACK_FLAG_GETPROXYFORURL_COMPLETE 0x01000000u
#define WINHTTP_INVALID_STATUS_CALLBACK ((WINHTTP_STATUS_CALLBACK)(intptr_t)-1)
#define WINHTTP_AUTOPROXY_AUTO_DETECT 1u
#define WINHTTP_AUTOPROXY_CONFIG_URL 2u
#define WINHTTP_ADDREQ_FLAG_ADD_IF_NEW 0x10000000u
#define WINHTTP_ADDREQ_FLAG_ADD 0x20000000u
#define WINHTTP_ADDREQ_FLAG_REPLACE 0x80000000u
#define WINHTTP_ADDREQ_FLAG_COALESCE 0x40000000u
#define ERROR_WINHTTP_INVALID_URL 12005u
#define ERROR_WINHTTP_UNRECOGNIZED_SCHEME 12006u
#define ERROR_WINHTTP_INVALID_OPTION 12009u
#define ERROR_WINHTTP_INCORRECT_HANDLE_TYPE 12018u
#define ERROR_WINHTTP_AUTODETECTION_FAILED 12180u

_Static_assert(sizeof(URL_COMPONENTS) == 104, "Win64 URL_COMPONENTS size changed");
_Static_assert(offsetof(URL_COMPONENTS, lpszScheme) == 8 &&
               offsetof(URL_COMPONENTS, dwSchemeLength) == 16 &&
               offsetof(URL_COMPONENTS, nScheme) == 20 &&
               offsetof(URL_COMPONENTS, lpszHostName) == 24 &&
               offsetof(URL_COMPONENTS, nPort) == 36 &&
               offsetof(URL_COMPONENTS, lpszUserName) == 40 &&
               offsetof(URL_COMPONENTS, lpszPassword) == 56 &&
               offsetof(URL_COMPONENTS, lpszUrlPath) == 72 &&
               offsetof(URL_COMPONENTS, lpszExtraInfo) == 88 &&
               offsetof(URL_COMPONENTS, dwExtraInfoLength) == 96,
               "Win64 URL_COMPONENTS field offsets changed");
#endif
