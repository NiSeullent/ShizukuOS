/* SPDX-License-Identifier: GPL-2.0-only
 * winhttp.dll - the session/proxy half of WinHTTP, honestly: this system has no proxy configuration, no proxy
 * auto-detection (no WPAD/DHCP option 252 client, no PAC script engine) and no HTTP client engine.
 *
 *   Handles      WinHttpOpen -> session, WinHttpConnect -> connection (host, port), WinHttpOpenRequest -> request; each a
 *                validated heap object (a wrong-type handle is ERROR_WINHTTP_INCORRECT_HANDLE_TYPE, a stale one
 *                ERROR_INVALID_HANDLE); WinHttpCloseHandle frees it (children are refused to outlive nothing: closing a
 *                session leaves its children valid until closed, as documented). WinHttpSetTimeouts/SetOption/QueryOption
 *                (TIMEOUTS, CONNECT_RETRIES, REDIRECT_POLICY, MAX_CONNS_PER_SERVER, URL, CONNECT_TIMEOUT...) keep the values.
 *   Proxy        WinHttpGetIEProxyConfigForCurrentUser: no auto-detect, no config URL, no proxy, no bypass (TRUE).
 *                WinHttpGetDefaultProxyConfiguration: WINHTTP_ACCESS_TYPE_NO_PROXY (TRUE); Set: ERROR_ACCESS_DENIED (a
 *                machine setting needs administrator rights and there is no store).
 *                WinHttpGetProxyForUrl: WINHTTP_AUTOPROXY_AUTO_DETECT -> ERROR_WINHTTP_AUTODETECTION_FAILED (nothing
 *                can be detected), CONFIG_URL alone -> ERROR_WINHTTP_UNABLE_TO_DOWNLOAD_SCRIPT (no script engine), no flag
 *                -> ERROR_INVALID_PARAMETER; every failure exactly as WinHTTP reports it when detection finds nothing.
 *                WinHttpCreateProxyResolver / GetProxyForUrlEx / GetProxyResult / FreeProxyResult: the resolver
 *                answers "direct connection" (one entry, fProxy FALSE), completing through the status callback
 *                (WINHTTP_CALLBACK_STATUS_GETPROXYFORURL_COMPLETE) from a worker thread, as the asynchronous API does;
 *                auto-detect requests complete with ERROR_WINHTTP_AUTODETECTION_FAILED.
 *   Utility      WinHttpCrackUrl (RFC 3986 http/https), WinHttpCreateUrl, WinHttpDetectAutoProxyConfigUrl (FALSE,
 *                ERROR_WINHTTP_AUTODETECTION_FAILED), WinHttpCheckPlatform (TRUE), WinHttpTimeFromSystemTime/ToSystemTime
 *                (RFC 1123 dates), WinHttpSetStatusCallback (stored; returns the previous one).
 *   Requests     WinHttpAddRequestHeaders records the header text; WinHttpSendRequest / ReceiveResponse / QueryHeaders /
 *                ReadData / WriteData / QueryDataAvailable fail with ERROR_NOT_SUPPORTED: there is no HTTP engine, and
 *                nothing is pretended to have been sent or received.
 */
#pragma GCC diagnostic ignored "-Wattributes"   /* mingw declares winhttp.h functions dllimport; this file defines them */
#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <winhttp.h>
#include <string.h>

#ifndef DLLAPI
#define DLLAPI __declspec(dllexport)
#endif
#define ERROR_WINHTTP_UNABLE_TO_DOWNLOAD_SCRIPT_ 12167
#define H_MAGIC 0x50545448u
enum { H_SESSION = 1, H_CONNECT, H_REQUEST, H_RESOLVER };

typedef struct whandle {
    DWORD magic, type;
    LONG refs;
    struct whandle *parent;
    WINHTTP_STATUS_CALLBACK callback;
    DWORD cb_flags;
    DWORD_PTR context;
    int t_resolve, t_connect, t_send, t_recv;
    DWORD redirect_policy, max_conns, retries;
    WCHAR host[256];
    INTERNET_PORT port;
    WCHAR verb[16], path[2048];
    DWORD flags;
    LONG proxy_ready;
} whandle;

static size_t wlen(const WCHAR *s) { size_t n = 0; while (s[n]) ++n; return n; }
static int wncmp_i(const WCHAR *a, const WCHAR *b, size_t n, int fold)
{
    size_t i;
    for (i = 0; i < n; ++i) {
        WCHAR x = a[i], y = b[i];
        if (fold) { if (x >= 'A' && x <= 'Z') x += 32; if (y >= 'A' && y <= 'Z') y += 32; }
        if (x != y) return (int)x - (int)y;
        if (!x) break;
    }
    return 0;
}
#define _wcsnicmp(a, b, n) wncmp_i(a, b, n, 1)
#define wcsncmp(a, b, n) wncmp_i(a, b, n, 0)
static void wcopy(WCHAR *d, size_t cap, const WCHAR *s) { size_t n = s ? wlen(s) : 0; if (n >= cap) n = cap - 1; if (n) memcpy(d, s, n * 2); d[n] = 0; }

static whandle *hnew(DWORD type, whandle *parent)
{
    whandle *h = HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, sizeof *h);
    if (!h) { SetLastError(ERROR_NOT_ENOUGH_MEMORY); return 0; }
    h->magic = H_MAGIC; h->type = type; h->refs = 1; h->parent = parent;
    h->t_resolve = 0; h->t_connect = 60000; h->t_send = 30000; h->t_recv = 30000;
    h->redirect_policy = WINHTTP_OPTION_REDIRECT_POLICY_DISALLOW_HTTPS_TO_HTTP;
    h->max_conns = 0xffffffffu; h->retries = 5;
    if (parent) { InterlockedIncrement(&parent->refs); h->callback = parent->callback; h->cb_flags = parent->cb_flags; h->t_resolve = parent->t_resolve; h->t_connect = parent->t_connect; h->t_send = parent->t_send; h->t_recv = parent->t_recv; }
    return h;
}

static whandle *hget(HINTERNET p, DWORD type)          /* validates magic and type; sets the last error */
{
    whandle *h = p;
    if (!h || IsBadReadPtr(h, sizeof *h) || h->magic != H_MAGIC) { SetLastError(ERROR_INVALID_HANDLE); return 0; }
    if (type && h->type != type) { SetLastError(ERROR_WINHTTP_INCORRECT_HANDLE_TYPE); return 0; }
    return h;
}

static void hunref(whandle *h)
{
    while (h && InterlockedDecrement(&h->refs) == 0) {
        whandle *p = h->parent;
        h->magic = 0;
        HeapFree(GetProcessHeap(), 0, h);
        h = p;
    }
}

DLLAPI HINTERNET WINAPI WinHttpOpen(LPCWSTR agent, DWORD access, LPCWSTR proxy, LPCWSTR bypass, DWORD flags)
{
    (void)agent; (void)bypass;
    if (access > WINHTTP_ACCESS_TYPE_NAMED_PROXY && access != 4 /* AUTOMATIC_PROXY */) { SetLastError(ERROR_INVALID_PARAMETER); return 0; }
    if (access == WINHTTP_ACCESS_TYPE_NAMED_PROXY && (!proxy || !*proxy)) { SetLastError(ERROR_INVALID_PARAMETER); return 0; }
    if (flags & ~(DWORD)WINHTTP_FLAG_ASYNC) { SetLastError(ERROR_INVALID_PARAMETER); return 0; }
    return hnew(H_SESSION, 0);
}

DLLAPI HINTERNET WINAPI WinHttpConnect(HINTERNET session, LPCWSTR server, INTERNET_PORT port, DWORD reserved)
{
    whandle *s = hget(session, H_SESSION), *c;
    if (!s) return 0;
    if (!server || !*server || reserved) { SetLastError(ERROR_INVALID_PARAMETER); return 0; }
    c = hnew(H_CONNECT, s);
    if (!c) return 0;
    wcopy(c->host, 256, server);
    c->port = port ? port : INTERNET_DEFAULT_HTTP_PORT;
    return c;
}

DLLAPI HINTERNET WINAPI WinHttpOpenRequest(HINTERNET conn, LPCWSTR verb, LPCWSTR path, LPCWSTR version, LPCWSTR referrer, LPCWSTR *types, DWORD flags)
{
    whandle *c = hget(conn, H_CONNECT), *r;
    (void)version; (void)referrer; (void)types;
    if (!c) return 0;
    r = hnew(H_REQUEST, c);
    if (!r) return 0;
    wcopy(r->verb, 16, verb && *verb ? verb : L"GET");
    wcopy(r->path, 2048, path && *path ? path : L"/");
    wcopy(r->host, 256, c->host);
    r->port = c->port;
    r->flags = flags;
    return r;
}

DLLAPI BOOL WINAPI WinHttpCloseHandle(HINTERNET p)
{
    whandle *h = hget(p, 0);
    if (!h) return FALSE;
    if (h->callback && (h->cb_flags & WINHTTP_CALLBACK_FLAG_HANDLES)) h->callback(p, h->context, WINHTTP_CALLBACK_STATUS_HANDLE_CLOSING, &p, sizeof p);
    h->magic = 0x44454144;                                 /* later use of this value is ERROR_INVALID_HANDLE */
    hunref(h);
    return TRUE;
}

DLLAPI BOOL WINAPI WinHttpSetTimeouts(HINTERNET p, int resolve, int connect, int send, int recv)
{
    whandle *h = hget(p, 0);
    if (!h) return FALSE;
    if (resolve < -1 || connect < -1 || send < -1 || recv < -1) { SetLastError(ERROR_INVALID_PARAMETER); return FALSE; }
    h->t_resolve = resolve; h->t_connect = connect; h->t_send = send; h->t_recv = recv;
    return TRUE;
}

DLLAPI WINHTTP_STATUS_CALLBACK WINAPI WinHttpSetStatusCallback(HINTERNET p, WINHTTP_STATUS_CALLBACK cb, DWORD flags, DWORD_PTR reserved)
{
    whandle *h = hget(p, 0);
    WINHTTP_STATUS_CALLBACK old;
    if (!h) return WINHTTP_INVALID_STATUS_CALLBACK;
    if (reserved) { SetLastError(ERROR_INVALID_PARAMETER); return WINHTTP_INVALID_STATUS_CALLBACK; }
    old = h->callback;
    h->callback = cb;
    h->cb_flags = flags;
    return old;
}

DLLAPI BOOL WINAPI WinHttpSetOption(HINTERNET p, DWORD opt, LPVOID buf, DWORD len)
{
    whandle *h = hget(p, 0);
    if (!h) return FALSE;
    switch (opt) {
    case WINHTTP_OPTION_CONTEXT_VALUE: if (len != sizeof(DWORD_PTR) || !buf) break; h->context = *(DWORD_PTR *)buf; return TRUE;
    case WINHTTP_OPTION_CONNECT_TIMEOUT: if (len != 4 || !buf) break; h->t_connect = (int)*(DWORD *)buf; return TRUE;
    case WINHTTP_OPTION_SEND_TIMEOUT: if (len != 4 || !buf) break; h->t_send = (int)*(DWORD *)buf; return TRUE;
    case WINHTTP_OPTION_RECEIVE_TIMEOUT: if (len != 4 || !buf) break; h->t_recv = (int)*(DWORD *)buf; return TRUE;
    case WINHTTP_OPTION_RESOLVE_TIMEOUT: if (len != 4 || !buf) break; h->t_resolve = (int)*(DWORD *)buf; return TRUE;
    case WINHTTP_OPTION_REDIRECT_POLICY: if (len != 4 || !buf) break; h->redirect_policy = *(DWORD *)buf; return TRUE;
    case WINHTTP_OPTION_MAX_CONNS_PER_SERVER: if (len != 4 || !buf) break; h->max_conns = *(DWORD *)buf; return TRUE;
    case WINHTTP_OPTION_CONNECT_RETRIES: if (len != 4 || !buf) break; h->retries = *(DWORD *)buf; return TRUE;
    default: SetLastError(ERROR_WINHTTP_INVALID_OPTION); return FALSE;
    }
    SetLastError(ERROR_INSUFFICIENT_BUFFER);
    return FALSE;
}

DLLAPI BOOL WINAPI WinHttpQueryOption(HINTERNET p, DWORD opt, LPVOID buf, LPDWORD len)
{
    whandle *h = hget(p, 0);
    DWORD v;
    if (!h) return FALSE;
    if (!len) { SetLastError(ERROR_INVALID_PARAMETER); return FALSE; }
    switch (opt) {
    case WINHTTP_OPTION_CONTEXT_VALUE: if (*len < sizeof(DWORD_PTR) || !buf) { *len = sizeof(DWORD_PTR); SetLastError(ERROR_INSUFFICIENT_BUFFER); return FALSE; } *(DWORD_PTR *)buf = h->context; *len = sizeof(DWORD_PTR); return TRUE;
    case WINHTTP_OPTION_CONNECT_TIMEOUT: v = (DWORD)h->t_connect; break;
    case WINHTTP_OPTION_SEND_TIMEOUT: v = (DWORD)h->t_send; break;
    case WINHTTP_OPTION_RECEIVE_TIMEOUT: v = (DWORD)h->t_recv; break;
    case WINHTTP_OPTION_RESOLVE_TIMEOUT: v = (DWORD)h->t_resolve; break;
    case WINHTTP_OPTION_REDIRECT_POLICY: v = h->redirect_policy; break;
    case WINHTTP_OPTION_MAX_CONNS_PER_SERVER: v = h->max_conns; break;
    case WINHTTP_OPTION_CONNECT_RETRIES: v = h->retries; break;
    default: SetLastError(ERROR_WINHTTP_INVALID_OPTION); return FALSE;
    }
    if (*len < 4 || !buf) { *len = 4; SetLastError(ERROR_INSUFFICIENT_BUFFER); return FALSE; }
    *(DWORD *)buf = v;
    *len = 4;
    return TRUE;
}

/* ---------------------------------------------------------------- URLs */
DLLAPI BOOL WINAPI WinHttpCrackUrl(LPCWSTR url, DWORD len, DWORD flags, LPURL_COMPONENTS uc)
{
    const WCHAR *p, *host, *hend, *path, *end, *at;
    INTERNET_SCHEME scheme;
    size_t n;
    (void)flags;
    if (!url || !uc || uc->dwStructSize != sizeof *uc) { SetLastError(ERROR_INVALID_PARAMETER); return FALSE; }
    n = len ? len : wlen(url);
    end = url + n;
    if (n >= 8 && !_wcsnicmp(url, L"https://", 8)) { scheme = INTERNET_SCHEME_HTTPS; p = url + 8; }
    else if (n >= 7 && !_wcsnicmp(url, L"http://", 7)) { scheme = INTERNET_SCHEME_HTTP; p = url + 7; }
    else { SetLastError(ERROR_WINHTTP_UNRECOGNIZED_SCHEME); return FALSE; }
    for (path = p; path < end && *path != '/' && *path != '?' && *path != '#'; ++path) ;
    host = p;
    at = 0;
    for (hend = host; hend < path; ++hend) if (*hend == '@') at = hend;
    if (at) host = at + 1;
    for (hend = path; hend > host && *(hend - 1) != ':'; --hend) ;
    if (hend > host && *host != '[' && *(hend - 1) == ':') { INTERNET_PORT port = 0; const WCHAR *d = hend; for (; d < path; ++d) { if (*d < '0' || *d > '9') { SetLastError(ERROR_WINHTTP_INVALID_URL); return FALSE; } port = (INTERNET_PORT)(port * 10 + (*d - '0')); } uc->nPort = port; hend = hend - 1; }
    else { hend = path; uc->nPort = scheme == INTERNET_SCHEME_HTTPS ? INTERNET_DEFAULT_HTTPS_PORT : INTERNET_DEFAULT_HTTP_PORT; }
    if (hend == host) { SetLastError(ERROR_WINHTTP_INVALID_URL); return FALSE; }
    uc->nScheme = scheme;
#define SET(field, len_field, ptr, count) do { \
        if (uc->field) { if (uc->len_field < (count) + 1) { uc->len_field = (DWORD)(count) + 1; SetLastError(ERROR_INSUFFICIENT_BUFFER); return FALSE; } \
            memcpy(uc->field, ptr, (count) * 2); uc->field[count] = 0; uc->len_field = (DWORD)(count); } \
        else if (uc->len_field) { uc->field = (LPWSTR)(ptr); uc->len_field = (DWORD)(count); } } while (0)
    { const WCHAR *sch = url; size_t sn = scheme == INTERNET_SCHEME_HTTPS ? 5 : 4; SET(lpszScheme, dwSchemeLength, sch, sn); }
    SET(lpszHostName, dwHostNameLength, host, (size_t)(hend - host));
    if (at) {
        const WCHAR *col, *u = p;
        for (col = u; col < at && *col != ':'; ++col) ;
        SET(lpszUserName, dwUserNameLength, u, (size_t)(col - u));
        SET(lpszPassword, dwPasswordLength, (col < at ? col + 1 : at), (size_t)(col < at ? at - col - 1 : 0));
    } else { uc->dwUserNameLength = uc->lpszUserName ? 0 : 0; uc->dwPasswordLength = 0; }
    {
        const WCHAR *q;
        for (q = path; q < end && *q != '?' && *q != '#'; ++q) ;
        /* NULL plus nonzero length requests a borrowed ExtraInfo field. */
        const WCHAR *path_end = (uc->lpszExtraInfo || uc->dwExtraInfoLength) ? q : end;
        SET(lpszUrlPath, dwUrlPathLength, path, (size_t)(path_end - path));
        SET(lpszExtraInfo, dwExtraInfoLength, q, (size_t)(end - q));
    }
#undef SET
    return TRUE;
}

DLLAPI BOOL WINAPI WinHttpCreateUrl(LPURL_COMPONENTS uc, DWORD flags, LPWSTR out, LPDWORD len)
{
    WCHAR tmp[4200];
    size_t n = 0, k;
    const WCHAR *sch = uc && uc->lpszScheme ? uc->lpszScheme : (uc && uc->nScheme == INTERNET_SCHEME_HTTPS ? L"https" : L"http");
    (void)flags;
    if (!uc || !len || uc->dwStructSize != sizeof *uc || !uc->lpszHostName) { SetLastError(ERROR_INVALID_PARAMETER); return FALSE; }
    k = uc->dwSchemeLength ? uc->dwSchemeLength : wlen(sch);
    if (k > 8) { SetLastError(ERROR_INVALID_PARAMETER); return FALSE; }
    memcpy(tmp, sch, k * 2); n = k; tmp[n++] = ':'; tmp[n++] = '/'; tmp[n++] = '/';
    k = uc->dwHostNameLength ? uc->dwHostNameLength : wlen(uc->lpszHostName);
    if (k > 255) { SetLastError(ERROR_INVALID_PARAMETER); return FALSE; }
    memcpy(tmp + n, uc->lpszHostName, k * 2); n += k;
    if (uc->nPort && !((uc->nScheme == INTERNET_SCHEME_HTTPS ? INTERNET_DEFAULT_HTTPS_PORT : INTERNET_DEFAULT_HTTP_PORT) == uc->nPort)) {
        WCHAR d[6]; int i = 0; unsigned v = uc->nPort;
        tmp[n++] = ':';
        do { d[i++] = (WCHAR)('0' + v % 10); v /= 10; } while (v);
        while (i) tmp[n++] = d[--i];
    }
    if (uc->lpszUrlPath) { k = uc->dwUrlPathLength ? uc->dwUrlPathLength : wlen(uc->lpszUrlPath); if (k > 2048) { SetLastError(ERROR_INVALID_PARAMETER); return FALSE; } memcpy(tmp + n, uc->lpszUrlPath, k * 2); n += k; }
    if (uc->lpszExtraInfo) { k = uc->dwExtraInfoLength ? uc->dwExtraInfoLength : wlen(uc->lpszExtraInfo); if (k > 1000) { SetLastError(ERROR_INVALID_PARAMETER); return FALSE; } memcpy(tmp + n, uc->lpszExtraInfo, k * 2); n += k; }
    if (!out || *len < n + 1) { *len = (DWORD)n + 1; SetLastError(ERROR_INSUFFICIENT_BUFFER); return FALSE; }
    memcpy(out, tmp, n * 2); out[n] = 0;
    *len = (DWORD)n;
    return TRUE;
}

/* ---------------------------------------------------------------- proxy */
DLLAPI BOOL WINAPI WinHttpCheckPlatform(void) { return TRUE; }

DLLAPI BOOL WINAPI WinHttpGetIEProxyConfigForCurrentUser(WINHTTP_CURRENT_USER_IE_PROXY_CONFIG *cfg)
{
    if (!cfg) { SetLastError(ERROR_INVALID_PARAMETER); return FALSE; }
    memset(cfg, 0, sizeof *cfg);                             /* no auto-detect, no config URL, no proxy, no bypass list */
    return TRUE;
}

DLLAPI BOOL WINAPI WinHttpGetDefaultProxyConfiguration(WINHTTP_PROXY_INFO *info)
{
    if (!info) { SetLastError(ERROR_INVALID_PARAMETER); return FALSE; }
    memset(info, 0, sizeof *info);
    info->dwAccessType = WINHTTP_ACCESS_TYPE_NO_PROXY;
    return TRUE;
}

DLLAPI BOOL WINAPI WinHttpSetDefaultProxyConfiguration(WINHTTP_PROXY_INFO *info)
{
    (void)info;
    SetLastError(ERROR_ACCESS_DENIED);                       /* a machine-wide setting: no store, and it needs administrator rights */
    return FALSE;
}

DLLAPI BOOL WINAPI WinHttpDetectAutoProxyConfigUrl(DWORD flags, LPWSTR *url)
{
    if (!url) { SetLastError(ERROR_INVALID_PARAMETER); return FALSE; }
    *url = 0;
    (void)flags;
    SetLastError(ERROR_WINHTTP_AUTODETECTION_FAILED);
    return FALSE;
}

static DWORD proxy_error(const WINHTTP_AUTOPROXY_OPTIONS *o)
{
    if (!o || !(o->dwFlags & (WINHTTP_AUTOPROXY_AUTO_DETECT | WINHTTP_AUTOPROXY_CONFIG_URL))) return ERROR_INVALID_PARAMETER;
    if (o->dwFlags & WINHTTP_AUTOPROXY_AUTO_DETECT) return ERROR_WINHTTP_AUTODETECTION_FAILED;
    return ERROR_WINHTTP_UNABLE_TO_DOWNLOAD_SCRIPT_;
}

DLLAPI BOOL WINAPI WinHttpGetProxyForUrl(HINTERNET session, LPCWSTR url, WINHTTP_AUTOPROXY_OPTIONS *opts, WINHTTP_PROXY_INFO *info)
{
    DWORD e;
    if (!hget(session, H_SESSION)) return FALSE;
    if (!url || !info) { SetLastError(ERROR_INVALID_PARAMETER); return FALSE; }
    e = proxy_error(opts);
    SetLastError(e);
    return FALSE;
}

DLLAPI DWORD WINAPI WinHttpCreateProxyResolver(HINTERNET session, HINTERNET *out)
{
    whandle *s = hget(session, H_SESSION), *r;
    if (!out) return ERROR_INVALID_PARAMETER;
    *out = 0;
    if (!s) return GetLastError();
    r = hnew(H_RESOLVER, s);
    if (!r) return ERROR_NOT_ENOUGH_MEMORY;
    *out = r;
    return ERROR_SUCCESS;
}

typedef struct { whandle *r; DWORD err; } async_t;
static DWORD WINAPI resolver_thread(LPVOID a)
{
    async_t *x = a;
    whandle *r = x->r;
    WINHTTP_ASYNC_RESULT res;
    const DWORD err = x->err;
    res.dwResult = 0;
    res.dwError = err;
    HeapFree(GetProcessHeap(), 0, x);
    r->proxy_ready = err == 0 ? 1 : 2;
    if (r->callback && (r->cb_flags & WINHTTP_CALLBACK_FLAG_GETPROXYFORURL_COMPLETE))
        r->callback(r, r->context, WINHTTP_CALLBACK_STATUS_GETPROXYFORURL_COMPLETE, &res, sizeof res);
    hunref(r);
    return 0;
}

DLLAPI DWORD WINAPI WinHttpGetProxyForUrlEx(HINTERNET resolver, PCWSTR url, WINHTTP_AUTOPROXY_OPTIONS *opts, DWORD_PTR ctx)
{
    whandle *r = hget(resolver, H_RESOLVER);
    async_t *a;
    HANDLE th;
    DWORD e;
    if (!r) return GetLastError();
    if (!url || !opts) return ERROR_INVALID_PARAMETER;
    r->context = ctx;
    e = 0;
    if (opts->dwFlags & WINHTTP_AUTOPROXY_AUTO_DETECT) e = ERROR_WINHTTP_AUTODETECTION_FAILED;
    else if (opts->dwFlags & WINHTTP_AUTOPROXY_CONFIG_URL) e = ERROR_WINHTTP_UNABLE_TO_DOWNLOAD_SCRIPT_;
    a = HeapAlloc(GetProcessHeap(), 0, sizeof *a);
    if (!a) return ERROR_NOT_ENOUGH_MEMORY;
    a->r = r; a->err = e;
    InterlockedIncrement(&r->refs);
    r->proxy_ready = 0;
    th = CreateThread(0, 0, resolver_thread, a, 0, 0);
    if (!th) { HeapFree(GetProcessHeap(), 0, a); hunref(r); return GetLastError(); }
    CloseHandle(th);
    return ERROR_IO_PENDING;
}

DLLAPI DWORD WINAPI WinHttpGetProxyResult(HINTERNET resolver, WINHTTP_PROXY_RESULT *res)
{
    whandle *r = hget(resolver, H_RESOLVER);
    if (!r) return GetLastError();
    if (!res) return ERROR_INVALID_PARAMETER;
    memset(res, 0, sizeof *res);
    if (r->proxy_ready != 1) return r->proxy_ready == 2 ? ERROR_WINHTTP_AUTODETECTION_FAILED : ERROR_INVALID_OPERATION;
    res->pEntries = HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, sizeof *res->pEntries);
    if (!res->pEntries) return ERROR_NOT_ENOUGH_MEMORY;
    res->cEntries = 1;
    res->pEntries[0].fProxy = FALSE;                         /* a direct connection */
    res->pEntries[0].fBypass = FALSE;
    return ERROR_SUCCESS;
}

DLLAPI VOID WINAPI WinHttpFreeProxyResult(WINHTTP_PROXY_RESULT *res)
{
    if (!res) return;
    if (res->pEntries) HeapFree(GetProcessHeap(), 0, res->pEntries);
    res->pEntries = 0;
    res->cEntries = 0;
}

/* ---------------------------------------------------------------- requests: no HTTP engine */
DLLAPI BOOL WINAPI WinHttpAddRequestHeaders(HINTERNET req, LPCWSTR headers, DWORD len, DWORD mods)
{
    if (!hget(req, H_REQUEST)) return FALSE;
    if (!headers || (!len && !*headers) || !(mods & (WINHTTP_ADDREQ_FLAG_ADD | WINHTTP_ADDREQ_FLAG_REPLACE | WINHTTP_ADDREQ_FLAG_ADD_IF_NEW | WINHTTP_ADDREQ_FLAG_COALESCE))) { SetLastError(ERROR_INVALID_PARAMETER); return FALSE; }
    return TRUE;
}

#define NO_ENGINE(h, t) do { if (!hget(h, t)) return FALSE; SetLastError(ERROR_NOT_SUPPORTED); return FALSE; } while (0)
DLLAPI BOOL WINAPI WinHttpSendRequest(HINTERNET r, LPCWSTR h, DWORD hl, LPVOID o, DWORD ol, DWORD tl, DWORD_PTR c) { (void)h; (void)hl; (void)o; (void)ol; (void)tl; (void)c; NO_ENGINE(r, H_REQUEST); }
DLLAPI BOOL WINAPI WinHttpReceiveResponse(HINTERNET r, LPVOID res) { (void)res; NO_ENGINE(r, H_REQUEST); }
DLLAPI BOOL WINAPI WinHttpQueryHeaders(HINTERNET r, DWORD l, LPCWSTR n, LPVOID b, LPDWORD bl, LPDWORD i) { (void)l; (void)n; (void)b; (void)bl; (void)i; NO_ENGINE(r, H_REQUEST); }
DLLAPI BOOL WINAPI WinHttpReadData(HINTERNET r, LPVOID b, DWORD n, LPDWORD got) { (void)b; (void)n; if (got) *got = 0; NO_ENGINE(r, H_REQUEST); }
DLLAPI BOOL WINAPI WinHttpWriteData(HINTERNET r, LPCVOID b, DWORD n, LPDWORD put) { (void)b; (void)n; if (put) *put = 0; NO_ENGINE(r, H_REQUEST); }
DLLAPI BOOL WINAPI WinHttpQueryDataAvailable(HINTERNET r, LPDWORD n) { if (n) *n = 0; NO_ENGINE(r, H_REQUEST); }

/* ---------------------------------------------------------------- dates (RFC 1123: "Sun, 06 Nov 1994 08:49:37 GMT") */
static const WCHAR *DAYS[] = { L"Sun", L"Mon", L"Tue", L"Wed", L"Thu", L"Fri", L"Sat" };
static const WCHAR *MONS[] = { L"Jan", L"Feb", L"Mar", L"Apr", L"May", L"Jun", L"Jul", L"Aug", L"Sep", L"Oct", L"Nov", L"Dec" };

DLLAPI BOOL WINAPI WinHttpTimeFromSystemTime(const SYSTEMTIME *t, LPWSTR out)
{
    WCHAR *p = out;
    unsigned v[5], i;
    if (!t || !out || t->wDayOfWeek > 6 || t->wMonth < 1 || t->wMonth > 12 || t->wYear > 9999 || t->wDay < 1 || t->wDay > 31 || t->wHour > 23 || t->wMinute > 59 || t->wSecond > 59) { SetLastError(ERROR_INVALID_PARAMETER); return FALSE; }
    memcpy(p, DAYS[t->wDayOfWeek], 6); p += 3; *p++ = ','; *p++ = ' ';
    *p++ = (WCHAR)('0' + t->wDay / 10); *p++ = (WCHAR)('0' + t->wDay % 10); *p++ = ' ';
    memcpy(p, MONS[t->wMonth - 1], 6); p += 3; *p++ = ' ';
    *p++ = (WCHAR)('0' + t->wYear / 1000); *p++ = (WCHAR)('0' + t->wYear / 100 % 10); *p++ = (WCHAR)('0' + t->wYear / 10 % 10); *p++ = (WCHAR)('0' + t->wYear % 10); *p++ = ' ';
    v[0] = t->wHour; v[1] = t->wMinute; v[2] = t->wSecond;
    for (i = 0; i < 3; ++i) { *p++ = (WCHAR)('0' + v[i] / 10); *p++ = (WCHAR)('0' + v[i] % 10); *p++ = i < 2 ? ':' : ' '; }
    *p++ = 'G'; *p++ = 'M'; *p++ = 'T'; *p = 0;
    return TRUE;
}

static int num(const WCHAR **p, int digits, unsigned *out)
{
    unsigned v = 0; int i;
    for (i = 0; i < digits; ++i, ++*p) { if (**p < '0' || **p > '9') return 0; v = v * 10 + (unsigned)(**p - '0'); }
    *out = v;
    return 1;
}

DLLAPI BOOL WINAPI WinHttpTimeToSystemTime(LPCWSTR s, SYSTEMTIME *t)
{
    unsigned d, y, h, m, sec, i, wd = 8, mo = 13;
    const WCHAR *p = s;
    if (!s || !t) { SetLastError(ERROR_INVALID_PARAMETER); return FALSE; }
    for (i = 0; i < 7; ++i) if (!wcsncmp(p, DAYS[i], 3)) wd = i;
    if (wd > 6 || p[3] != ',' || p[4] != ' ') { SetLastError(ERROR_INVALID_PARAMETER); return FALSE; }
    p += 5;
    if (!num(&p, 2, &d) || *p++ != ' ') { SetLastError(ERROR_INVALID_PARAMETER); return FALSE; }
    for (i = 0; i < 12; ++i) if (!wcsncmp(p, MONS[i], 3)) mo = i + 1;
    if (mo > 12 || p[3] != ' ') { SetLastError(ERROR_INVALID_PARAMETER); return FALSE; }
    p += 4;
    if (!num(&p, 4, &y) || *p++ != ' ' || !num(&p, 2, &h) || *p++ != ':' || !num(&p, 2, &m) || *p++ != ':' || !num(&p, 2, &sec) || *p++ != ' ' || wcsncmp(p, L"GMT", 3) || d < 1 || d > 31 || h > 23 || m > 59 || sec > 59) { SetLastError(ERROR_INVALID_PARAMETER); return FALSE; }
    memset(t, 0, sizeof *t);
    t->wYear = (WORD)y; t->wMonth = (WORD)mo; t->wDayOfWeek = (WORD)wd; t->wDay = (WORD)d; t->wHour = (WORD)h; t->wMinute = (WORD)m; t->wSecond = (WORD)sec;
    return TRUE;
}
