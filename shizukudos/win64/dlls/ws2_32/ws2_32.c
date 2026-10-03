/* SPDX-License-Identifier: GPL-2.0-only
 * ws2_32.dll for the Shizuku Win64 runtime: the Winsock 2 API over the Kernel64 socket system calls
 * (kernel64/net_sock.c, SYSCALL_LIST_NET 0x80-0x8f, reached through the ntdll stubs NtShzSock*).
 *
 * Imports only ntdll and kernel32. A SOCKET is the kernel handle of the socket object, so CloseHandle/NtClose work too.
 * Implemented exactly what has a body here; everything else is simply absent from the export table.
 *
 * Deliberate limits (all documented, none silent):
 *  - IPv4 only. socket(AF_INET6) fails with WSAEAFNOSUPPORT; inet_pton/inet_ntop still convert IPv6 text (pure formatting).
 *  - WSASend/WSARecv/WSASendTo/WSARecvFrom/WSAIoctl are synchronous and fail with WSAEOPNOTSUPP when
 *    an OVERLAPPED or completion routine is supplied. WSAEventSelect/WSAEnumNetworkEvents are implemented (kernel side).
 *  - ConnectEx/DisconnectEx/AcceptEx (overlapped only) use real IPv4 TCP and native IRPs with events/IOCP. No raw sockets or extension APCs.
 *  - inet_ntoa uses a process-wide static buffer (Windows uses per-thread storage).
 *  - gethostbyaddr reads genuine IPv4 records from system drivers\\etc\\hosts only; no PTR, NetBIOS or IPv6 reverse provider.
 *    Missing hosts database is WSANO_RECOVERY; an absent address is WSAHOST_NOT_FOUND. No numeric-name fallback.
 *  - getprotobyname/getprotobynumber read the actual system drivers\\etc\\protocols database.
 *    Protocol, host and service structures belong to the calling thread; host-name/address calls share one hostent.
 *  - getaddrinfo: numeric hosts, "localhost", and A-record DNS lookups; service names come from a small built-in table.
 *  - getservbyname reads the actual system drivers\\etc\\services database. No database means WSANO_RECOVERY;
 *    an unknown name means WSAHOST_NOT_FOUND, a known name without the requested protocol means WSANO_DATA.
 *    Returned storage belongs to the calling thread.
 *  - GetNameInfoW: numeric IPv4/IPv6 (including scope IDs), table service names and decimal fallback; no reverse DNS.
 *  - Winsock error codes are the standard values; the kernel reports them as NTSTATUS 0xE0A0xxxx (net.h NET_ERR).
 *  - Catalog: one transport provider built into this DLL ("Shizuku Tcpip", entries TCP/IPv4 and UDP/IPv4) and one namespace
 *    provider (NS_DNS, the kernel resolver). WSAEnumProtocols / WSCEnumProtocols / WSCGetProviderPath / WSAEnumNameSpaceProviders
 *    describe exactly these. The DNS namespace answers host-name lookups (WSALookupService*, GetAddrInfoExW) and cannot register
 *    services (WSASetService fails with WSAEOPNOTSUPP); other namespaces (NLA, NTDS, ...) have no provider.
 *  - GetAddrInfoExW: synchronous, or asynchronous with an OVERLAPPED event (a worker thread resolves; GetAddrInfoExCancel,
 *    GetAddrInfoExOverlappedResult). A completion routine would have to run as an APC in the caller's thread, which this system
 *    cannot queue: it is refused with WSAEOPNOTSUPP.
 *  - WSADuplicateSocketW duplicates for the calling process only (Kernel64 offers no handle duplication into another process).
 */
#define WIN32_LEAN_AND_MEAN
#define WINSOCK_API_LINKAGE
#include <winsock2.h>
#include <ws2tcpip.h>
#include <string.h>
#include <stddef.h>
#include "ws2_extensions.h"
#include "ws2_trace.h"

#ifndef DLLAPI
#define DLLAPI __declspec(dllexport)
#endif

typedef LONG NTSTATUS;
#define NTAPI_ __stdcall

/* ---- kernel interface (ntdll stubs generated from kernel64/ntsys.h SYSCALL_LIST_NET) ---- */
NTSTATUS NTAPI_ NtClose(HANDLE);
NTSTATUS NTAPI_ NtShzSocket(ULONG_PTR family, ULONG_PTR type, ULONG_PTR proto, PHANDLE out);
NTSTATUS NTAPI_ NtShzSockBind(ULONG_PTR s, const void *sa, ULONG_PTR len);
NTSTATUS NTAPI_ NtShzSockListen(ULONG_PTR s, ULONG_PTR backlog);
NTSTATUS NTAPI_ NtShzSockAccept(ULONG_PTR s, PHANDLE out, void *sa, PULONG len);
NTSTATUS NTAPI_ NtShzSockConnect(ULONG_PTR s, const void *sa, ULONG_PTR len);
NTSTATUS NTAPI_ NtShzSockSend(ULONG_PTR s, const void *buf, ULONG_PTR len, ULONG_PTR flags, const void *to, ULONG_PTR tolen, PULONG sent);
NTSTATUS NTAPI_ NtShzSockRecv(ULONG_PTR s, void *buf, ULONG_PTR len, ULONG_PTR flags, void *from, PULONG fromlen, PULONG got);
NTSTATUS NTAPI_ NtShzSockShutdown(ULONG_PTR s, ULONG_PTR how);
NTSTATUS NTAPI_ NtShzSockName(ULONG_PTR s, ULONG_PTR which, void *sa, PULONG len);
NTSTATUS NTAPI_ NtShzSockSetOpt(ULONG_PTR s, ULONG_PTR level, ULONG_PTR opt, const void *val, ULONG_PTR len);
NTSTATUS NTAPI_ NtShzSockGetOpt(ULONG_PTR s, ULONG_PTR level, ULONG_PTR opt, void *val, PULONG len);
NTSTATUS NTAPI_ NtShzSockIoctl(ULONG_PTR s, ULONG_PTR cmd, const void *in, ULONG_PTR inlen, void *out, ULONG_PTR outlen, PULONG ret);
NTSTATUS NTAPI_ NtShzSockPoll(void *entries, ULONG_PTR count, ULONG_PTR timeout_ms, PULONG ready);
NTSTATUS NTAPI_ NtShzNetResolve(const char *name, ULONG_PTR namelen, ULONG *results, ULONG_PTR max, PULONG count, ULONG_PTR server_be, ULONG_PTR port);
NTSTATUS NTAPI_ NtShzNetQuery(ULONG_PTR cls, void *buf, ULONG_PTR len, PULONG ret);

/* ---- compiler support (no C runtime here) ---- */
void *memcpy(void *d, const void *s, size_t n) { unsigned char *a = d; const unsigned char *b = s; while (n--) *a++ = *b++; return d; }
void *memset(void *d, int c, size_t n) { unsigned char *a = d; while (n--) *a++ = (unsigned char)c; return d; }
int memcmp(const void *a, const void *b, size_t n)
{
    const unsigned char *x = a, *y = b;
    while (n--) { if (*x != *y) return *x - *y; ++x; ++y; }
    return 0;
}
size_t strlen(const char *s) { size_t n = 0; while (s[n]) ++n; return n; }

#define STATUS_INVALID_HANDLE_ ((NTSTATUS)0xC0000008)
#define STATUS_ACCESS_VIOLATION_ ((NTSTATUS)0xC0000005)
#define STATUS_NO_MEMORY_ ((NTSTATUS)0xC0000017)
#define STATUS_INVALID_PARAMETER_ ((NTSTATUS)0xC000000D)
#define STATUS_BUFFER_TOO_SMALL_ ((NTSTATUS)0xC0000023)

static volatile LONG g_started;
int shz_ws2_extensions_started(void) { return g_started != 0; }

/* NTSTATUS -> Winsock error. Network statuses carry the code in the low 16 bits (customer range 0xE0A0xxxx). */
static int map_status(NTSTATUS st)
{
    if (((ULONG)st & 0xffff0000u) == 0xE0A00000u)
        return (int)((ULONG)st & 0xffffu);
    switch (st) {
    case STATUS_INVALID_HANDLE_: return WSAENOTSOCK;
    case STATUS_ACCESS_VIOLATION_: return WSAEFAULT;
    case STATUS_NO_MEMORY_: return WSAENOBUFS;
    case (NTSTATUS)0xC000009A: return WSAENOBUFS;
    case (NTSTATUS)0xC0000120: return WSA_OPERATION_ABORTED;
    case STATUS_BUFFER_TOO_SMALL_: return WSAEFAULT;
    case STATUS_INVALID_PARAMETER_: return WSAEINVAL;
    default: return WSAEINVAL;
    }
}
static int fail_at(NTSTATUS st, const char *function)
{ DWORD error = (DWORD)map_status(st); SetLastError(error); ws2_trace_failure(function, error); return SOCKET_ERROR; }
static int fail_code_at(int code, const char *function)
{ SetLastError((DWORD)code); ws2_trace_failure(function, (unsigned)code); return SOCKET_ERROR; }
#define fail(st) fail_at((st), __func__)
#define fail_code(code) fail_code_at((code), __func__)
#define NEED_INIT(ret) do { if (!g_started) { SetLastError(WSANOTINITIALISED); return (ret); } } while (0)

/* ---------------------------------------------------------------- startup / errors */
DLLAPI int WSAAPI WSAStartup(WORD wVersionRequested, LPWSADATA lpWSAData)
{
    static const char desc[] = "Shizuku Winsock 2.2", status[] = "Running";
    const BYTE major = LOBYTE(wVersionRequested), minor = HIBYTE(wVersionRequested);
    WORD ver;
    if (!lpWSAData)
        return WSAEFAULT;
    if (major < 1 || major > 2)
        return WSAVERNOTSUPPORTED;
    ver = major == 2 && minor > 2 ? MAKEWORD(2, 2) : wVersionRequested;
    if (major == 1 && minor > 1) ver = MAKEWORD(1, 1);
    memset(lpWSAData, 0, sizeof *lpWSAData);
    lpWSAData->wVersion = ver;
    lpWSAData->wHighVersion = MAKEWORD(2, 2);
    memcpy(lpWSAData->szDescription, desc, sizeof desc);
    memcpy(lpWSAData->szSystemStatus, status, sizeof status);
    InterlockedIncrement(&g_started);
    return 0;
}

DLLAPI int WSAAPI WSACleanup(void)
{
    if (!g_started) { SetLastError(WSANOTINITIALISED); return SOCKET_ERROR; }
    InterlockedDecrement(&g_started);
    return 0;
}

DLLAPI int WSAAPI WSAGetLastError(void) { return (int)GetLastError(); }
DLLAPI void WSAAPI WSASetLastError(int iError) { SetLastError((DWORD)iError); }

/* ---------------------------------------------------------------- byte order */
DLLAPI u_short WSAAPI htons(u_short v) { return (u_short)((v << 8) | (v >> 8)); }
DLLAPI u_short WSAAPI ntohs(u_short v) { return (u_short)((v << 8) | (v >> 8)); }
DLLAPI u_long WSAAPI htonl(u_long v) { return ((v & 0xffu) << 24) | ((v & 0xff00u) << 8) | ((v >> 8) & 0xff00u) | ((v >> 24) & 0xffu); }
DLLAPI u_long WSAAPI ntohl(u_long v) { return htonl(v); }
DLLAPI int WSAAPI WSAHtons(SOCKET s, u_short h, u_short *out) { NEED_INIT(SOCKET_ERROR); (void)s; if (!out) return fail_code(WSAEFAULT); *out = htons(h); return 0; }
DLLAPI int WSAAPI WSANtohs(SOCKET s, u_short n, u_short *out) { NEED_INIT(SOCKET_ERROR); (void)s; if (!out) return fail_code(WSAEFAULT); *out = ntohs(n); return 0; }
DLLAPI int WSAAPI WSAHtonl(SOCKET s, u_long h, u_long *out) { NEED_INIT(SOCKET_ERROR); (void)s; if (!out) return fail_code(WSAEFAULT); *out = htonl(h); return 0; }
DLLAPI int WSAAPI WSANtohl(SOCKET s, u_long n, u_long *out) { NEED_INIT(SOCKET_ERROR); (void)s; if (!out) return fail_code(WSAEFAULT); *out = ntohl(n); return 0; }

/* ---------------------------------------------------------------- address text */
/* classic inet_aton: 1-4 numbers (decimal, 0octal, 0xhex), the last one fills the remaining bytes */
static int parse_ipv4_loose(const char *s, ULONG *out)
{
    ULONGLONG parts[4], v;
    unsigned n = 0, i;
    for (;;) {
        unsigned base = 10;
        int digits = 0;
        v = 0;
        if (s[0] == '0' && (s[1] == 'x' || s[1] == 'X')) { base = 16; s += 2; }
        else if (s[0] == '0' && s[1] >= '0' && s[1] <= '9') { base = 8; s += 1; }
        for (;; ++s) {
            unsigned d;
            if (*s >= '0' && *s <= '9') d = (unsigned)(*s - '0');
            else if (base == 16 && *s >= 'a' && *s <= 'f') d = (unsigned)(*s - 'a' + 10);
            else if (base == 16 && *s >= 'A' && *s <= 'F') d = (unsigned)(*s - 'A' + 10);
            else break;
            if (d >= base) return 0;
            v = v * base + d;
            if (v > 0xffffffffull) return 0;
            ++digits;
        }
        if (!digits && !(base == 8 && s[-1] == '0')) return 0;
        if (n == 4) return 0;
        parts[n++] = v;
        if (*s == '.') { ++s; continue; }
        break;
    }
    while (*s == ' ' || *s == '\t' || *s == '\n' || *s == '\r') ++s;
    if (*s) return 0;
    for (i = 0; i + 1 < n; ++i)
        if (parts[i] > 255) return 0;
    switch (n) {
    case 1: v = parts[0]; break;
    case 2: if (parts[1] > 0xffffff) return 0; v = (parts[0] << 24) | parts[1]; break;
    case 3: if (parts[2] > 0xffff) return 0; v = (parts[0] << 24) | (parts[1] << 16) | parts[2]; break;
    default: if (parts[3] > 255) return 0; v = (parts[0] << 24) | (parts[1] << 16) | (parts[2] << 8) | parts[3]; break;
    }
    *out = (ULONG)v;
    return 1;
}

DLLAPI unsigned long WSAAPI inet_addr(const char *cp)
{
    ULONG host;
    if (!cp || !parse_ipv4_loose(cp, &host))
        return INADDR_NONE;
    return htonl(host);
}

static int fmt_ipv4(const unsigned char *b, char *out)
{
    int n = 0, i;
    for (i = 0; i < 4; ++i) {
        unsigned v = b[i];
        char t[3];
        int k = 0;
        do { t[k++] = (char)('0' + v % 10); v /= 10; } while (v);
        while (k) out[n++] = t[--k];
        if (i < 3) out[n++] = '.';
    }
    out[n] = 0;
    return n;
}

DLLAPI char *WSAAPI inet_ntoa(struct in_addr in)
{
    static char buf[16];
    fmt_ipv4((const unsigned char *)&in, buf);
    return buf;
}

static int pton4(const char *s, unsigned char *out)
{
    int part = 0;
    for (;;) {
        unsigned v = 0, digits = 0;
        while (*s >= '0' && *s <= '9') { v = v * 10 + (unsigned)(*s++ - '0'); if (++digits > 3 || v > 255) return 0; }
        if (!digits) return 0;
        out[part++] = (unsigned char)v;
        if (part == 4) return *s == 0;
        if (*s++ != '.') return 0;
    }
}

static int pton6(const char *s, unsigned char *out)
{
    unsigned short g[8];
    int n = 0, gap = -1;
    unsigned char v4[4];
    memset(g, 0, sizeof g);
    if (s[0] == ':') { if (s[1] != ':') return 0; s += 2; gap = 0; if (!*s) { memset(out, 0, 16); return 1; } }
    for (;;) {
        unsigned v = 0, digits = 0;
        const char *st = s;
        while ((*s >= '0' && *s <= '9') || (*s >= 'a' && *s <= 'f') || (*s >= 'A' && *s <= 'F')) {
            v = v * 16 + (unsigned)(*s <= '9' ? *s - '0' : (*s | 32) - 'a' + 10);
            ++s;
            if (++digits > 4) return 0;
        }
        if (*s == '.' && digits) {                          /* trailing dotted quad */
            if (n > 6 || !pton4(st, v4)) return 0;
            g[n++] = (unsigned short)((v4[0] << 8) | v4[1]);
            g[n++] = (unsigned short)((v4[2] << 8) | v4[3]);
            s += strlen(s);
            break;
        }
        if (!digits) return 0;
        if (n >= 8) return 0;
        g[n++] = (unsigned short)v;
        if (!*s) break;
        if (*s++ != ':') return 0;
        if (*s == ':') {
            if (gap >= 0) return 0;
            gap = n;
            ++s;
            if (!*s) break;
        } else if (!*s) {
            return 0;
        }
    }
    if (gap >= 0) {
        int tail = n - gap, i;
        if (n > 7) return 0;
        for (i = 0; i < tail; ++i) g[8 - tail + i] = g[gap + i];
        for (i = gap; i < 8 - tail; ++i) g[i] = 0;
    } else if (n != 8) {
        return 0;
    }
    { int i; for (i = 0; i < 8; ++i) { out[2 * i] = (unsigned char)(g[i] >> 8); out[2 * i + 1] = (unsigned char)g[i]; } }
    return 1;
}

DLLAPI INT WSAAPI inet_pton(INT Family, LPCSTR pStringBuf, PVOID pAddr)
{
    if (!pStringBuf || !pAddr) { SetLastError(WSAEFAULT); return -1; }
    if (Family == AF_INET) return pton4(pStringBuf, pAddr);
    if (Family == AF_INET6) return pton6(pStringBuf, pAddr);
    SetLastError(WSAEAFNOSUPPORT);
    return -1;
}

DLLAPI LPCSTR WSAAPI inet_ntop(INT Family, LPCVOID pAddr, LPSTR pStringBuf, size_t StringBufSize)
{
    char tmp[64];
    const unsigned char *b = pAddr;
    size_t n;
    if (!pAddr || !pStringBuf) { SetLastError(WSAEFAULT); return 0; }
    if (Family == AF_INET) {
        n = (size_t)fmt_ipv4(b, tmp);
    } else if (Family == AF_INET6) {
        unsigned short g[8];
        int i, best = -1, best_len = 0, cur = -1, cur_len = 0, pos = 0, mapped;
        static const char hex[] = "0123456789abcdef";
        for (i = 0; i < 8; ++i) g[i] = (unsigned short)((b[2 * i] << 8) | b[2 * i + 1]);
        for (i = 0; i < 8; ++i) {                           /* RFC 5952: compress the longest run of at least two zero groups */
            if (g[i] == 0) { if (cur < 0) { cur = i; cur_len = 0; } ++cur_len; if (cur_len > best_len) { best = cur; best_len = cur_len; } }
            else cur = -1;
        }
        if (best_len < 2) best = -1;
        mapped = best == 0 && best_len == 5 && g[5] == 0xffff;      /* ::ffff:a.b.c.d */
        for (i = 0; i < 8; ++i) {
            if (i == best) { tmp[pos++] = ':'; i += best_len - 1; if (i == 7) tmp[pos++] = ':'; continue; }
            if (mapped && i >= 6) { tmp[pos++] = ':'; pos += fmt_ipv4(b + 12, tmp + pos); break; }
            if (i) tmp[pos++] = ':';
            {
                unsigned v = g[i];
                int started = 0, sh;
                for (sh = 12; sh >= 0; sh -= 4) {
                    unsigned d = (v >> sh) & 15;
                    if (d || started || sh == 0) { tmp[pos++] = hex[d]; started = 1; }
                }
            }
        }
        tmp[pos] = 0;
        n = (size_t)pos;
    } else {
        SetLastError(WSAEAFNOSUPPORT);
        return 0;
    }
    if (n + 1 > StringBufSize) { SetLastError(WSAENOBUFS); return 0; }
    memcpy(pStringBuf, tmp, n + 1);
    return pStringBuf;
}

DLLAPI INT WSAAPI InetPtonW(INT Family, LPCWSTR pStringBuf, PVOID pAddr)
{
    char a[64];
    size_t i;
    if (!pStringBuf) { SetLastError(WSAEFAULT); return -1; }
    for (i = 0; pStringBuf[i]; ++i) {
        if (i >= sizeof a - 1 || pStringBuf[i] > 0x7f) return 0;
        a[i] = (char)pStringBuf[i];
    }
    a[i] = 0;
    return inet_pton(Family, a, pAddr);
}

DLLAPI LPCWSTR WSAAPI InetNtopW(INT Family, LPCVOID pAddr, LPWSTR pStringBuf, size_t StringBufSize)
{
    char a[64];
    size_t i;
    if (!pStringBuf || !inet_ntop(Family, pAddr, a, sizeof a))
        return 0;
    for (i = 0; a[i]; ++i) {
        if (i + 1 >= StringBufSize) { SetLastError(WSAENOBUFS); return 0; }
        pStringBuf[i] = (WCHAR)(unsigned char)a[i];
    }
    pStringBuf[i] = 0;
    return pStringBuf;
}

/* ---------------------------------------------------------------- sockets */
static int sockaddr_in_check(const struct sockaddr *sa, int len)
{
    if (!sa || len < (int)sizeof(struct sockaddr_in))
        return fail_code(WSAEFAULT);
    if (sa->sa_family != AF_INET)
        return fail_code(WSAEAFNOSUPPORT);
    return 0;
}

DLLAPI SOCKET WSAAPI WSASocketW(int af, int type, int protocol, LPWSAPROTOCOL_INFOW lpProtocolInfo, GROUP g, DWORD dwFlags)
{
    HANDLE h = 0;
    NTSTATUS st;
    NEED_INIT(INVALID_SOCKET);
    if (g || (dwFlags & ~0x81u)) { SetLastError(WSAEOPNOTSUPP); return INVALID_SOCKET; }
    if (lpProtocolInfo) {
        if (lpProtocolInfo->dwProviderReserved) {           /* from WSADuplicateSocketW: the duplicated handle of that socket */
            ULONG v = 0, n = 4;
            const SOCKET dup = (SOCKET)lpProtocolInfo->dwProviderReserved;
            if (NtShzSockGetOpt(dup, SOL_SOCKET, SO_TYPE, &v, &n)) { SetLastError(WSAEINVAL); return INVALID_SOCKET; }
            lpProtocolInfo->dwProviderReserved = 0;         /* the handle now belongs to the caller */
            return dup;
        }
        af = lpProtocolInfo->iAddressFamily; type = lpProtocolInfo->iSocketType; protocol = lpProtocolInfo->iProtocol;
    }
    if (af == AF_UNSPEC && protocol) {
        if (protocol == IPPROTO_TCP || protocol == IPPROTO_UDP) af = AF_INET;
    }
    if (af != AF_INET) { SetLastError(WSAEAFNOSUPPORT); return INVALID_SOCKET; }
    st = NtShzSocket((ULONG_PTR)af, (ULONG_PTR)(ULONG)type, (ULONG_PTR)(ULONG)protocol, &h);
    if (st) { SetLastError((DWORD)map_status(st)); return INVALID_SOCKET; }
    { ULONG attributes = dwFlags;                         /* default inheritable; NO_HANDLE_INHERIT explicitly clears it */
      st = NtShzSockIoctl((ULONG_PTR)h, SHZ_SOCK_SET_OVERLAPPED, &attributes, 4, NULL, 0, NULL);
      if (st) { NtClose(h); SetLastError((DWORD)map_status(st)); return INVALID_SOCKET; } }
    return (SOCKET)h;
}

DLLAPI SOCKET WSAAPI socket(int af, int type, int protocol) { return WSASocketW(af, type, protocol, 0, 0, WSA_FLAG_OVERLAPPED); }

DLLAPI int WSAAPI closesocket(SOCKET s)
{
    ULONG v = 0, n = 4;
    NTSTATUS st;
    NEED_INIT(SOCKET_ERROR);
    st = NtShzSockGetOpt(s, SOL_SOCKET, SO_TYPE, &v, &n);   /* proves the handle is a socket before NtClose (closesocket on a file must fail) */
    if (st) return fail(st);
    st = NtClose((HANDLE)s);
    return st ? fail(st) : 0;
}

DLLAPI int WSAAPI bind(SOCKET s, const struct sockaddr *name, int namelen)
{
    NEED_INIT(SOCKET_ERROR);
    if (sockaddr_in_check(name, namelen)) return SOCKET_ERROR;
    { NTSTATUS st = NtShzSockBind(s, name, (ULONG_PTR)(ULONG)namelen); return st ? fail(st) : 0; }
}

DLLAPI int WSAAPI listen(SOCKET s, int backlog)
{
    NEED_INIT(SOCKET_ERROR);
    { NTSTATUS st = NtShzSockListen(s, (ULONG_PTR)(ULONG)backlog); return st ? fail(st) : 0; }
}

DLLAPI SOCKET WSAAPI accept(SOCKET s, struct sockaddr *addr, int *addrlen)
{
    HANDLE h = 0;
    NTSTATUS st;
    NEED_INIT(INVALID_SOCKET);
    st = NtShzSockAccept(s, &h, addr, (PULONG)addrlen);
    if (st) { SetLastError((DWORD)map_status(st)); return INVALID_SOCKET; }
    return (SOCKET)h;
}

DLLAPI int WSAAPI connect(SOCKET s, const struct sockaddr *name, int namelen)
{
    NEED_INIT(SOCKET_ERROR);
    if (!name || namelen < 2) return fail_code(WSAEFAULT);
    if (name->sa_family != AF_UNSPEC && sockaddr_in_check(name, namelen)) return SOCKET_ERROR;
    { NTSTATUS st = NtShzSockConnect(s, name, (ULONG_PTR)(ULONG)namelen); return st ? fail(st) : 0; }
}

DLLAPI int WSAAPI WSAConnect(SOCKET s, const struct sockaddr *name, int namelen, LPWSABUF lpCallerData, LPWSABUF lpCalleeData,
                             LPQOS lpSQOS, LPQOS lpGQOS)
{
    if (lpCallerData || lpCalleeData || lpSQOS || lpGQOS) return fail_code(WSAEOPNOTSUPP);
    return connect(s, name, namelen);
}

DLLAPI int WSAAPI shutdown(SOCKET s, int how)
{
    NEED_INIT(SOCKET_ERROR);
    { NTSTATUS st = NtShzSockShutdown(s, (ULONG_PTR)(ULONG)how); return st ? fail(st) : 0; }
}

static int do_send(SOCKET s, const char *buf, int len, int flags, const struct sockaddr *to, int tolen)
{
    ULONG sent = 0;
    NTSTATUS st;
    NEED_INIT(SOCKET_ERROR);
    if (len < 0 || (len && !buf)) return fail_code(WSAEFAULT);
    if (to && sockaddr_in_check(to, tolen)) return SOCKET_ERROR;
    st = NtShzSockSend(s, buf, (ULONG_PTR)(ULONG)len, (ULONG_PTR)(ULONG)flags, to, (ULONG_PTR)(ULONG)tolen, &sent);
    if (st) return fail(st);
    return (int)sent;
}

static int do_recv(SOCKET s, char *buf, int len, int flags, struct sockaddr *from, int *fromlen)
{
    ULONG got = 0;
    NTSTATUS st;
    NEED_INIT(SOCKET_ERROR);
    if (len < 0 || (len && !buf)) return fail_code(WSAEFAULT);
    if (from && (!fromlen || *fromlen < 0)) return fail_code(WSAEFAULT);
    st = NtShzSockRecv(s, buf, (ULONG_PTR)(ULONG)len, (ULONG_PTR)(ULONG)flags, from, from ? (PULONG)fromlen : 0, &got);
    if (st) return fail(st);
    return (int)got;
}

DLLAPI int WSAAPI send(SOCKET s, const char *buf, int len, int flags) { return do_send(s, buf, len, flags, 0, 0); }
DLLAPI int WSAAPI sendto(SOCKET s, const char *buf, int len, int flags, const struct sockaddr *to, int tolen) { return do_send(s, buf, len, flags, to, tolen); }
DLLAPI int WSAAPI recv(SOCKET s, char *buf, int len, int flags) { return do_recv(s, buf, len, flags, 0, 0); }
DLLAPI int WSAAPI recvfrom(SOCKET s, char *buf, int len, int flags, struct sockaddr *from, int *fromlen) { return do_recv(s, buf, len, flags, from, fromlen); }

DLLAPI int WSAAPI WSASendTo(SOCKET s, LPWSABUF bufs, DWORD count, LPDWORD sent, DWORD flags, const struct sockaddr *to, int tolen,
                            LPWSAOVERLAPPED ov, LPWSAOVERLAPPED_COMPLETION_ROUTINE cr)
{
    DWORD i, total = 0;
    NEED_INIT(SOCKET_ERROR);
    if (ov || cr) return fail_code(WSAEOPNOTSUPP);          /* synchronous only */
    if (!bufs || !count) return fail_code(WSAEINVAL);
    for (i = 0; i < count; ++i) {
        int n = do_send(s, bufs[i].buf, (int)bufs[i].len, (int)flags, to, tolen);
        if (n == SOCKET_ERROR) {
            if (total) break;                               /* partial progress is reported as success, like Winsock */
            return SOCKET_ERROR;
        }
        total += (DWORD)n;
        if ((DWORD)n < bufs[i].len) break;
    }
    if (sent) *sent = total;
    return 0;
}

DLLAPI int WSAAPI WSASend(SOCKET s, LPWSABUF bufs, DWORD count, LPDWORD sent, DWORD flags, LPWSAOVERLAPPED ov, LPWSAOVERLAPPED_COMPLETION_ROUTINE cr)
{
    return WSASendTo(s, bufs, count, sent, flags, 0, 0, ov, cr);
}

DLLAPI int WSAAPI WSARecvFrom(SOCKET s, LPWSABUF bufs, DWORD count, LPDWORD got, LPDWORD flags, struct sockaddr *from, LPINT fromlen,
                              LPWSAOVERLAPPED ov, LPWSAOVERLAPPED_COMPLETION_ROUTINE cr)
{
    DWORD i, total = 0;
    int fl = flags ? (int)*flags : 0;
    NEED_INIT(SOCKET_ERROR);
    if (ov || cr) return fail_code(WSAEOPNOTSUPP);          /* synchronous only */
    if (!bufs || !count) return fail_code(WSAEINVAL);
    for (i = 0; i < count; ++i) {
        int n;
        if (i > 0) {                                        /* further buffers only take what is already queued */
            ULONG avail = 0;
            if (NtShzSockIoctl(s, 0x4004667f, 0, 0, &avail, 4, 0) || !avail) break;
        }
        n = do_recv(s, bufs[i].buf, (int)bufs[i].len, fl, i == 0 ? from : 0, i == 0 ? fromlen : 0);
        if (n == SOCKET_ERROR) {
            if (total || (int)GetLastError() == WSAEWOULDBLOCK) { if (total) break; }
            if (!total) return SOCKET_ERROR;
            break;
        }
        total += (DWORD)n;
        if ((DWORD)n < bufs[i].len) break;
    }
    if (got) *got = total;
    if (flags) *flags = 0;
    return 0;
}

DLLAPI int WSAAPI WSARecv(SOCKET s, LPWSABUF bufs, DWORD count, LPDWORD got, LPDWORD flags, LPWSAOVERLAPPED ov, LPWSAOVERLAPPED_COMPLETION_ROUTINE cr)
{
    return WSARecvFrom(s, bufs, count, got, flags, 0, 0, ov, cr);
}

DLLAPI int WSAAPI getsockname(SOCKET s, struct sockaddr *name, int *namelen)
{
    NEED_INIT(SOCKET_ERROR);
    if (!name || !namelen || *namelen < 0) return fail_code(WSAEFAULT);
    { NTSTATUS st = NtShzSockName(s, 0, name, (PULONG)namelen); return st ? fail(st) : 0; }
}

DLLAPI int WSAAPI getpeername(SOCKET s, struct sockaddr *name, int *namelen)
{
    NEED_INIT(SOCKET_ERROR);
    if (!name || !namelen || *namelen < 0) return fail_code(WSAEFAULT);
    { NTSTATUS st = NtShzSockName(s, 1, name, (PULONG)namelen); return st ? fail(st) : 0; }
}

DLLAPI int WSAAPI setsockopt(SOCKET s, int level, int optname, const char *optval, int optlen)
{
    ULONG widened = 0;
    NTSTATUS st;
    NEED_INIT(SOCKET_ERROR);
    if (level == SOL_SOCKET && optname == 0x7010 && optlen == 0) {
        st = NtShzSockSetOpt(s, SOL_SOCKET, 0x7010, NULL, 0);
        return st ? fail(st) : 0;
    }
    if (!optval || optlen < 1) return fail_code(WSAEFAULT);
    if (optlen < 4) {                                       /* char / short BOOLEAN-style options */
        memcpy(&widened, optval, (size_t)optlen);
        optval = (const char *)&widened;
        optlen = 4;
    }
    st = NtShzSockSetOpt(s, (ULONG_PTR)(ULONG)level, (ULONG_PTR)(ULONG)optname, optval, (ULONG_PTR)(ULONG)optlen);
    return st ? fail(st) : 0;
}

DLLAPI int WSAAPI getsockopt(SOCKET s, int level, int optname, char *optval, int *optlen)
{
    NTSTATUS st;
    NEED_INIT(SOCKET_ERROR);
    if (!optval || !optlen || *optlen < 0) return fail_code(WSAEFAULT);
    st = NtShzSockGetOpt(s, (ULONG_PTR)(ULONG)level, (ULONG_PTR)(ULONG)optname, optval, (PULONG)optlen);
    return st ? fail(st) : 0;
}

DLLAPI int WSAAPI ioctlsocket(SOCKET s, long cmd, u_long *argp)
{
    ULONG v, ret = 0;
    NTSTATUS st;
    NEED_INIT(SOCKET_ERROR);
    if (!argp) return fail_code(WSAEFAULT);
    switch ((ULONG)cmd) {
    case 0x8004667e:                                        /* FIONBIO */
        v = (ULONG)*argp;
        st = NtShzSockIoctl(s, (ULONG)cmd, &v, 4, 0, 0, &ret);
        break;
    case 0x4004667f:                                        /* FIONREAD */
    case 0x40047307:                                        /* SIOCATMARK */
        v = 0;
        st = NtShzSockIoctl(s, (ULONG)cmd, 0, 0, &v, 4, &ret);
        if (!st) *argp = v;
        break;
    default:
        return fail_code(WSAEINVAL);
    }
    return st ? fail(st) : 0;
}

DLLAPI int WSAAPI WSAIoctl(SOCKET s, DWORD code, LPVOID in, DWORD inlen, LPVOID out, DWORD outlen, LPDWORD ret, LPWSAOVERLAPPED ov,
                           LPWSAOVERLAPPED_COMPLETION_ROUTINE cr)
{
    ULONG r = 0;
    NTSTATUS st;
    NEED_INIT(SOCKET_ERROR);
    ws2_trace_request("WSAIoctl", code, ov != NULL, cr != NULL);
    if (code == 0xc8000006 && in && inlen >= 16) ws2_trace_guid(in);
    if (ov || cr) return fail_code(WSAEOPNOTSUPP);          /* synchronous only */
    switch (code) {
    case 0xc8000006:                                      /* SIO_GET_EXTENSION_FUNCTION_POINTER */
        return shz_ws2_extension_pointer(s, in, inlen, out, outlen, ret);
    case 0x8004667e:                                        /* FIONBIO */
        if (!in || inlen < 4) return fail_code(WSAEFAULT);
        st = NtShzSockIoctl(s, code, in, 4, 0, 0, &r);
        break;
    case 0x4004667f:                                        /* FIONREAD */
    case 0x40047307:                                        /* SIOCATMARK */
        if (!out || outlen < 4) return fail_code(WSAEFAULT);
        st = NtShzSockIoctl(s, code, 0, 0, out, 4, &r);
        break;
    case 0x9800000c:                                        /* SIO_UDP_CONNRESET */
        if (!in || inlen < 1) return fail_code(WSAEFAULT);
        { ULONG v = *(const unsigned char *)in; st = NtShzSockIoctl(s, code, &v, 4, 0, 0, &r); }
        break;
    case 0x98000004: {                                      /* SIO_KEEPALIVE_VALS: {onoff, idle ms, interval ms} */
        const ULONG *k = in;
        ULONG on;
        if (!in || inlen < 12) return fail_code(WSAEFAULT);
        on = k[0] != 0;
        st = NtShzSockSetOpt(s, SOL_SOCKET, SO_KEEPALIVE, &on, 4);
        if (!st && on) {
            ULONG idle = (k[1] + 999) / 1000, intvl = (k[2] + 999) / 1000;
            st = NtShzSockSetOpt(s, IPPROTO_TCP, 3, &idle, 4);
            if (!st) st = NtShzSockSetOpt(s, IPPROTO_TCP, 17, &intvl, 4);
        }
        break;
    }
    default:
        return fail_code(WSAEOPNOTSUPP);
    }
    if (st) return fail(st);
    if (ret) *ret = r;
    return 0;
}

/* ---------------------------------------------------------------- select / poll */
DLLAPI int WSAAPI __WSAFDIsSet(SOCKET s, fd_set *set)
{
    u_int i;
    for (i = 0; i < set->fd_count; ++i)
        if (set->fd_array[i] == s)
            return 1;
    return 0;
}

static ULONG ms_from_timeval(const struct timeval *tv)
{
    unsigned long long ms;
    if (!tv) return 0xffffffffu;                            /* infinite */
    ms = (unsigned long long)(tv->tv_sec < 0 ? 0 : tv->tv_sec) * 1000ull + (unsigned long long)((tv->tv_usec < 0 ? 0 : tv->tv_usec) + 999) / 1000;
    return ms > 0x7ffffffeull ? 0x7ffffffeu : (ULONG)ms;
}

DLLAPI int WSAAPI select(int nfds, fd_set *rd, fd_set *wr, fd_set *ex, const struct timeval *tv)
{
    WSAPOLLFD e[3 * FD_SETSIZE];
    unsigned char role[3 * FD_SETSIZE];
    u_int n = 0, i, total = 0, nr = rd ? rd->fd_count : 0, nw = wr ? wr->fd_count : 0, nx = ex ? ex->fd_count : 0;
    ULONG ready = 0;
    NTSTATUS st;
    (void)nfds;
    NEED_INIT(SOCKET_ERROR);
    if (!nr && !nw && !nx)
        return fail_code(WSAEINVAL);                        /* Winsock: at least one socket is required */
    for (i = 0; i < nr; ++i) { e[n].fd = rd->fd_array[i]; e[n].events = POLLRDNORM; e[n].revents = 0; role[n++] = 0; }
    for (i = 0; i < nw; ++i) { e[n].fd = wr->fd_array[i]; e[n].events = POLLWRNORM; e[n].revents = 0; role[n++] = 1; }
    for (i = 0; i < nx; ++i) { e[n].fd = ex->fd_array[i]; e[n].events = 0; e[n].revents = 0; role[n++] = 2; }
    st = NtShzSockPoll(e, n, ms_from_timeval(tv), &ready);
    if (st) return fail(st);
    for (i = 0; i < n; ++i)
        if (e[i].revents & POLLNVAL)
            return fail_code(WSAENOTSOCK);
    if (rd) rd->fd_count = 0;
    if (wr) wr->fd_count = 0;
    if (ex) ex->fd_count = 0;
    for (i = 0; i < n; ++i) {
        const SHORT r = e[i].revents;
        if (role[i] == 0 && (r & POLLRDNORM)) { rd->fd_array[rd->fd_count++] = e[i].fd; ++total; }
        else if (role[i] == 1 && (r & POLLWRNORM)) { wr->fd_array[wr->fd_count++] = e[i].fd; ++total; }
        else if (role[i] == 2 && (r & POLLERR)) { ex->fd_array[ex->fd_count++] = e[i].fd; ++total; }
    }
    return (int)total;
}

DLLAPI int WSAAPI WSAPoll(LPWSAPOLLFD fdArray, ULONG fds, INT timeout)
{
    ULONG ready = 0;
    NTSTATUS st;
    NEED_INIT(SOCKET_ERROR);
    if (!fdArray || !fds) return fail_code(WSAEINVAL);
    st = NtShzSockPoll(fdArray, fds, (ULONG_PTR)(ULONG)timeout, &ready);
    if (st) return fail(st);
    return (int)ready;
}

/* ---------------------------------------------------------------- events */
DLLAPI WSAEVENT WSAAPI WSACreateEvent(void)
{
    return (WSAEVENT)CreateEventW(0, TRUE, FALSE, 0);
}
DLLAPI BOOL WSAAPI WSACloseEvent(WSAEVENT h) { return CloseHandle(h) ? TRUE : (SetLastError(WSA_INVALID_HANDLE), FALSE); }
DLLAPI BOOL WSAAPI WSASetEvent(WSAEVENT h) { return SetEvent(h) ? TRUE : (SetLastError(WSA_INVALID_HANDLE), FALSE); }
DLLAPI BOOL WSAAPI WSAResetEvent(WSAEVENT h) { return ResetEvent(h) ? TRUE : (SetLastError(WSA_INVALID_HANDLE), FALSE); }

DLLAPI DWORD WSAAPI WSAWaitForMultipleEvents(DWORD cEvents, const WSAEVENT *lphEvents, BOOL fWaitAll, DWORD dwTimeout, BOOL fAlertable)
{
    DWORD r;
    NEED_INIT(WSA_WAIT_FAILED);
    if (!cEvents || !lphEvents || cEvents > WSA_MAXIMUM_WAIT_EVENTS) { SetLastError(WSA_INVALID_PARAMETER); return WSA_WAIT_FAILED; }
    r = WaitForMultipleObjectsEx(cEvents, lphEvents, fWaitAll, dwTimeout, fAlertable);
    if (r == WAIT_FAILED) { SetLastError(WSA_INVALID_HANDLE); return WSA_WAIT_FAILED; }
    return r;
}

DLLAPI int WSAAPI WSAEventSelect(SOCKET s, WSAEVENT hEventObject, long lNetworkEvents)
{
    struct { ULONG64 ev; ULONG mask, pad; } a;
    ULONG ret = 0;
    NTSTATUS st;
    NEED_INIT(SOCKET_ERROR);
    a.ev = (ULONG64)(ULONG_PTR)hEventObject;
    a.mask = (ULONG)lNetworkEvents & 0x3f;                  /* FD_READ..FD_CLOSE; FD_QOS etc. are not implemented */
    a.pad = 0;
    if (lNetworkEvents && !hEventObject) return fail_code(WSAEINVAL);
    st = NtShzSockIoctl(s, 0x53480001, &a, 12, 0, 0, &ret);
    return st ? fail(st) : 0;
}

DLLAPI int WSAAPI WSAEnumNetworkEvents(SOCKET s, WSAEVENT hEventObject, LPWSANETWORKEVENTS lpNetworkEvents)
{
    ULONG ret = 0;
    NTSTATUS st;
    NEED_INIT(SOCKET_ERROR);
    if (!lpNetworkEvents) return fail_code(WSAEINVAL);
    st = NtShzSockIoctl(s, 0x53480002, 0, 0, lpNetworkEvents, sizeof *lpNetworkEvents, &ret);
    if (st) return fail(st);
    if (hEventObject)
        ResetEvent(hEventObject);
    return 0;
}

/* ---------------------------------------------------------------- names */
/* A/W read the same computer-name state and retain the existing fallback token.
 * GetHostNameW's capacity is in WCHARs, including the NUL (Microsoft Learn).
 * Contract references: Wine df15af3652511150490934682202d45af892f887,
 * dlls/ws2_32/protocol.c; ReactOS 9dc3ca87209fd8ebabd96c8ea95d439c13e7fdf8,
 * dll/win32/ws2_32/src/getxbyxx.c. Original Shizuku implementation, no upstream code copied. */
static DWORD local_hostname(WCHAR name[MAX_COMPUTERNAME_LENGTH + 1])
{
    static const WCHAR fallback[] = L"SHIZUKU";
    DWORD n = MAX_COMPUTERNAME_LENGTH + 1;
    if (!GetComputerNameW(name, &n)) {
        memcpy(name, fallback, sizeof fallback);
        n = sizeof fallback / sizeof fallback[0] - 1;
    }
    return n;
}

DLLAPI int WSAAPI gethostname(char *name, int namelen)
{
    WCHAR w[MAX_COMPUTERNAME_LENGTH + 1];
    DWORD n, i;
    NEED_INIT(SOCKET_ERROR);
    if (!name || namelen <= 0) return fail_code(WSAEFAULT);
    n = local_hostname(w);
    if ((DWORD)namelen <= n) return fail_code(WSAEFAULT);
    for (i = 0; i < n; ++i) name[i] = (char)(w[i] > 0x7f ? '?' : w[i]);
    name[n] = 0;
    return 0;
}

DLLAPI int WSAAPI GetHostNameW(PWSTR name, int namelen)
{
    WCHAR w[MAX_COMPUTERNAME_LENGTH + 1];
    DWORD n;
    NEED_INIT(SOCKET_ERROR);
    if (!name || namelen <= 0) return fail_code(WSAEFAULT);
    n = local_hostname(w);
    if ((DWORD)namelen <= n) return fail_code(WSAEFAULT);
    memcpy(name, w, (n + 1) * sizeof *name);
    return 0;
}

struct svc { const char *name; unsigned short port; };
static const struct svc services[] = {
    {"echo", 7}, {"discard", 9}, {"daytime", 13}, {"ftp-data", 20}, {"ftp", 21}, {"ssh", 22}, {"telnet", 23}, {"smtp", 25},
    {"time", 37}, {"domain", 53}, {"tftp", 69}, {"http", 80}, {"pop3", 110}, {"ntp", 123}, {"imap", 143}, {"snmp", 161},
    {"ldap", 389}, {"https", 443}, {"submission", 587}, {"imaps", 993}, {"pop3s", 995}, {0, 0}
};

static int ieq(const char *a, const char *b)
{
    for (; *a && *b; ++a, ++b)
        if ((*a | 32) != (*b | 32)) return 0;
    return !*a && !*b;
}

/* ---- service database: original implementation of the documented Winsock contract.
 * Primary references: Microsoft getservbyname/SERVENT; Wine db11d0fe6a169c457e23d007e20404643d067aa8
 * dlls/ws2_32/{ws2_32.spec,protocol.c}. No Wine body copied. The existing numeric/name helper below is not a
 * protocol/alias database: this API reads the real OS services file instead of inventing records from that table. */
struct svc_span { const char *p; size_t n; };
struct svc_row { struct svc_span name, proto; const char *aliases, *end; size_t alias_count; unsigned port; };
struct svc_thread {
    struct svc_thread *next;
    DWORD tid;
    struct servent entry;
    void *payload;
    struct protoent protocol;
    void *protocol_payload;
    struct hostent host;
    void *host_payload;
};
static SRWLOCK g_svc_lock = SRWLOCK_INIT;
static DWORD g_svc_tls = TLS_OUT_OF_INDEXES;
static struct svc_thread *g_svc_threads;

static int svc_space(char c) { return c == ' ' || c == '\t' || c == '\r' || c == '\v' || c == '\f'; }
static int svc_token(const char **cursor, const char *end, struct svc_span *token)
{
    const char *p = *cursor, *start;
    while (p < end && svc_space(*p)) ++p;
    start = p;
    while (p < end && !svc_space(*p)) ++p;
    token->p = start; token->n = (size_t)(p - start); *cursor = p;
    return p != start;
}
static int svc_ascii(const struct svc_span *token)
{
    size_t i;
    for (i = 0; i < token->n; ++i)
        if ((unsigned char)token->p[i] < 0x21 || (unsigned char)token->p[i] > 0x7e) return 0;
    return token->n != 0;
}
static unsigned char svc_lower(unsigned char c) { return c >= 'A' && c <= 'Z' ? (unsigned char)(c + 32) : c; }
static int svc_equal(const struct svc_span *token, const char *name)
{
    size_t i;
    for (i = 0; i < token->n; ++i)
        if (!name[i] || svc_lower((unsigned char)token->p[i]) != svc_lower((unsigned char)name[i])) return 0;
    return !name[token->n];
}
static int svc_parse_line(const char *line, const char *end, const char *name, const char *proto, struct svc_row *row, int *known_name)
{
    const char *p = line, *comment;
    struct svc_span port, alias;
    unsigned value = 0;
    size_t i;
    int matched;
    for (comment = line; comment < end; ++comment) if (*comment == '#') { end = comment; break; }
    if (!svc_token(&p, end, &row->name) || !svc_ascii(&row->name) || !svc_token(&p, end, &port)) return 0;
    for (i = 0; i < port.n && port.p[i] >= '0' && port.p[i] <= '9'; ++i) {
        const unsigned digit = (unsigned)(port.p[i] - '0');
        if (value > (65535u - digit) / 10u) return 0;
        value = value * 10u + digit;
    }
    if (!i || i >= port.n || port.p[i] != '/' || i + 1 == port.n) return 0;
    row->proto.p = port.p + i + 1; row->proto.n = port.n - i - 1;
    if (!svc_ascii(&row->proto)) return 0;
    for (i = 0; i < row->proto.n; ++i) if (row->proto.p[i] == '/') return 0;
    row->port = value; row->aliases = p; row->end = end; row->alias_count = 0;
    matched = name ? svc_equal(&row->name, name) : 0;
    while (svc_token(&p, end, &alias)) {
        if (!svc_ascii(&alias)) return 0;
        ++row->alias_count;
        if (name && svc_equal(&alias, name)) matched = 1;
    }
    if (matched) *known_name = 1;
    return (!name || matched) && (!proto || svc_equal(&row->proto, proto));
}
static char *svc_read_catalog(const WCHAR *suffix, size_t suffix_chars, DWORD *length, int *error)
{
    WCHAR path[MAX_PATH];
    LARGE_INTEGER size;
    HANDLE file;
    UINT n;
    DWORD done = 0;
    char *data;
    *error = WSANO_RECOVERY;
    n = GetSystemDirectoryW(path, MAX_PATH);
    if (!n || n >= MAX_PATH || n + suffix_chars > MAX_PATH) return 0;
    memcpy(path + n, suffix, suffix_chars * sizeof *suffix);
    file = CreateFileW(path, GENERIC_READ, FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
                       0, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, 0);
    if (file == INVALID_HANDLE_VALUE) return 0;
    if (!GetFileSizeEx(file, &size) || size.QuadPart < 0) { CloseHandle(file); return 0; }
    if ((ULONGLONG)size.QuadPart > 16u * 1024u * 1024u) { CloseHandle(file); *error = WSAENOBUFS; return 0; }
    *length = (DWORD)size.QuadPart;
    data = HeapAlloc(GetProcessHeap(), 0, (size_t)*length + 1);
    if (!data) { CloseHandle(file); *error = WSAENOBUFS; return 0; }
    while (done < *length) {
        DWORD got = 0, request = *length - done;
        if (request > 1024u * 1024u) request = 1024u * 1024u;
        if (!ReadFile(file, data + done, request, &got, 0) || !got || got > request) {
            CloseHandle(file); HeapFree(GetProcessHeap(), 0, data); return 0;
        }
        done += got;
    }
    CloseHandle(file); data[*length] = 0;
    return data;
}
static char *svc_read_database(DWORD *length, int *error)
{
    static const WCHAR suffix[] = L"\\drivers\\etc\\services";
    return svc_read_catalog(suffix, sizeof suffix / sizeof *suffix, length, error);
}
static struct svc_thread *svc_storage(int *error)
{
    struct svc_thread *state, *candidate;
    const DWORD tid = GetCurrentThreadId();
    AcquireSRWLockExclusive(&g_svc_lock);
    if (g_svc_tls == TLS_OUT_OF_INDEXES) g_svc_tls = TlsAlloc();
    if (g_svc_tls == TLS_OUT_OF_INDEXES) { ReleaseSRWLockExclusive(&g_svc_lock); *error = WSAENOBUFS; return 0; }
    candidate = TlsGetValue(g_svc_tls);
    /* Some runtime TLS-slot reuse paths retain old values in other threads. Never dereference a TLS value until
     * membership and the actual calling thread identity are checked against this loaded DLL's owned records. */
    for (state = g_svc_threads; state; state = state->next)
        if (state == candidate && state->tid == tid) break;
    if (!state) {
        state = HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, sizeof *state);
        if (!state || !TlsSetValue(g_svc_tls, state)) {
            if (state) HeapFree(GetProcessHeap(), 0, state);
            ReleaseSRWLockExclusive(&g_svc_lock); *error = WSAENOBUFS; return 0;
        }
        state->tid = tid; state->next = g_svc_threads; g_svc_threads = state;
    }
    ReleaseSRWLockExclusive(&g_svc_lock);
    return state;
}
static char *svc_copy(char **where, const struct svc_span *token)
{
    char *result = *where;
    memcpy(result, token->p, token->n); result[token->n] = 0; *where += token->n + 1;
    return result;
}
static struct servent *svc_result(const struct svc_row *row, int *error)
{
    struct svc_thread *state;
    struct servent entry;
    struct svc_span alias;
    const char *cursor = row->aliases;
    const size_t text = (size_t)(row->end - row->name.p) + 2;
    size_t i = 0, bytes;
    char **aliases, *strings;
    void *payload, *previous;
    if (row->alias_count == (size_t)-1 || row->alias_count + 1 > ((size_t)-1 - text) / sizeof(char *)) {
        *error = WSAENOBUFS; return 0;
    }
    bytes = (row->alias_count + 1) * sizeof(char *) + text;
    payload = HeapAlloc(GetProcessHeap(), 0, bytes);
    if (!payload) { *error = WSAENOBUFS; return 0; }
    state = svc_storage(error);
    if (!state) { HeapFree(GetProcessHeap(), 0, payload); return 0; }
    aliases = payload; strings = (char *)(aliases + row->alias_count + 1);
    entry.s_name = svc_copy(&strings, &row->name);
    entry.s_proto = svc_copy(&strings, &row->proto);
    entry.s_port = (short)htons((u_short)row->port); entry.s_aliases = aliases;
    while (svc_token(&cursor, row->end, &alias)) aliases[i++] = svc_copy(&strings, &alias);
    aliases[i] = 0;
    previous = state->payload; state->payload = payload; state->entry = entry;
    if (previous) HeapFree(GetProcessHeap(), 0, previous);
    return &state->entry;
}
DLLAPI struct servent *WSAAPI getservbyname(const char *name, const char *proto)
{
    const DWORD saved_error = GetLastError();
    DWORD length, offset = 0;
    int error = WSAHOST_NOT_FOUND, known_name = 0;
    char *data;
    struct servent *result = 0;
    NEED_INIT(0);
    if (!name) { SetLastError(WSAEFAULT); return 0; }
    data = svc_read_database(&length, &error);
    if (!data) { SetLastError((DWORD)error); return 0; }
    error = WSAHOST_NOT_FOUND;
    while (offset < length) {
        DWORD end = offset;
        struct svc_row row;
        while (end < length && data[end] != '\n') ++end;
        if (svc_parse_line(data + offset, data + end, name, proto, &row, &known_name)) { result = svc_result(&row, &error); break; }
        offset = end < length ? end + 1 : length;
    }
    HeapFree(GetProcessHeap(), 0, data);
    if (!result && error == WSAHOST_NOT_FOUND && known_name) error = WSANO_DATA;
    SetLastError(result ? saved_error : (DWORD)error);
    return result;
}
/* ---- legacy database lookups: genuine system catalog records, no fallback ---- */
DLLAPI struct servent *WSAAPI getservbyport(int port, const char *proto)
{
    const DWORD saved = GetLastError();
    const unsigned wanted = htons((u_short)port);
    DWORD length, offset = 0;
    int error = WSAHOST_NOT_FOUND, known = 0;
    char *data;
    struct servent *result = 0;
    NEED_INIT(0);
    data = svc_read_database(&length, &error);
    if (!data) { SetLastError((DWORD)error); return 0; }
    error = WSAHOST_NOT_FOUND;
    while (offset < length) {
        DWORD end = offset;
        struct svc_row row;
        while (end < length && data[end] != '\n') ++end;
        if (svc_parse_line(data + offset, data + end, 0, 0, &row, &known) && row.port == wanted) {
            known = 1;
            if (!proto || svc_equal(&row.proto, proto)) { result = svc_result(&row, &error); break; }
        }
        offset = end < length ? end + 1 : length;
    }
    HeapFree(GetProcessHeap(), 0, data);
    if (!result && error == WSAHOST_NOT_FOUND && known) error = WSANO_DATA;
    SetLastError(result ? saved : (DWORD)error);
    return result;
}

struct legacy_row {
    struct svc_span name;
    const char *aliases, *end;
    size_t alias_count;
    unsigned number;
};
static int legacy_row_start(const char *line, const char **end, const char **cursor)
{
    const char *p;
    for (p = line; p < *end; ++p) if (*p == '#') { *end = p; break; }
    *cursor = line;
    return line != *end;
}
static int legacy_aliases(const char *cursor, const char *end, struct legacy_row *row)
{
    struct svc_span alias;
    row->aliases = cursor; row->end = end; row->alias_count = 0;
    while (svc_token(&cursor, end, &alias)) {
        if (!svc_ascii(&alias)) return 0;
        ++row->alias_count;
    }
    return 1;
}
static int legacy_number(const struct svc_span *token, unsigned maximum, unsigned *number)
{
    size_t i;
    unsigned n = 0;
    if (!token->n) return 0;
    for (i = 0; i < token->n; ++i) {
        const unsigned digit = (unsigned char)token->p[i] - (unsigned)'0';
        if (digit > 9 || n > (maximum - digit) / 10u) return 0;
        n = n * 10u + digit;
    }
    *number = n;
    return 1;
}
static int legacy_proto_row(const char *line, const char *end, struct legacy_row *row)
{
    const char *cursor;
    struct svc_span number;
    if (!legacy_row_start(line, &end, &cursor) || !svc_token(&cursor, end, &row->name)
        || !svc_ascii(&row->name) || !svc_token(&cursor, end, &number)
        || !legacy_number(&number, 65535u, &row->number)) return 0;
    return legacy_aliases(cursor, end, row);
}
static int legacy_name_matches(const struct legacy_row *row, const char *name)
{
    const char *cursor = row->aliases;
    struct svc_span alias;
    if (svc_equal(&row->name, name)) return 1;
    while (svc_token(&cursor, row->end, &alias)) if (svc_equal(&alias, name)) return 1;
    return 0;
}
static struct protoent *legacy_proto_result(const struct legacy_row *row, int *error)
{
    struct svc_thread *state;
    struct protoent result;
    const size_t text = (size_t)(row->end - row->name.p) + 1;
    size_t bytes, i = 0;
    const char *cursor = row->aliases;
    struct svc_span alias;
    char **aliases, *strings;
    void *payload, *previous;
    if (row->alias_count == (size_t)-1 || row->alias_count + 1 > ((size_t)-1 - text) / sizeof(char *)) {
        *error = WSAENOBUFS; return 0;
    }
    bytes = (row->alias_count + 1) * sizeof(char *) + text;
    payload = HeapAlloc(GetProcessHeap(), 0, bytes);
    if (!payload) { *error = WSAENOBUFS; return 0; }
    state = svc_storage(error);
    if (!state) { HeapFree(GetProcessHeap(), 0, payload); return 0; }
    aliases = payload; strings = (char *)(aliases + row->alias_count + 1);
    result.p_name = svc_copy(&strings, &row->name);
    result.p_proto = (short)row->number; result.p_aliases = aliases;
    while (svc_token(&cursor, row->end, &alias)) aliases[i++] = svc_copy(&strings, &alias);
    aliases[i] = 0;
    previous = state->protocol_payload; state->protocol_payload = payload; state->protocol = result;
    if (previous) HeapFree(GetProcessHeap(), 0, previous);
    return &state->protocol;
}
static struct protoent *legacy_proto_lookup(const char *name, int number)
{
    static const WCHAR suffix[] = L"\\drivers\\etc\\protocols";
    const DWORD saved = GetLastError();
    DWORD length, offset = 0;
    int error = WSAHOST_NOT_FOUND;
    char *data;
    struct protoent *result = 0;
    data = svc_read_catalog(suffix, sizeof suffix / sizeof *suffix, &length, &error);
    if (!data) { SetLastError((DWORD)error); return 0; }
    error = WSAHOST_NOT_FOUND;
    while (offset < length) {
        DWORD end = offset;
        struct legacy_row row;
        while (end < length && data[end] != '\n') ++end;
        if (legacy_proto_row(data + offset, data + end, &row)
            && (name ? legacy_name_matches(&row, name) : number >= 0 && (unsigned)number == row.number)) {
            result = legacy_proto_result(&row, &error); break;
        }
        offset = end < length ? end + 1 : length;
    }
    HeapFree(GetProcessHeap(), 0, data);
    SetLastError(result ? saved : (DWORD)error);
    return result;
}
DLLAPI struct protoent *WSAAPI getprotobyname(const char *name)
{
    NEED_INIT(0);
    if (!name) { SetLastError(WSAEFAULT); return 0; }
    return legacy_proto_lookup(name, 0);
}
DLLAPI struct protoent *WSAAPI getprotobynumber(int number)
{
    NEED_INIT(0);
    return legacy_proto_lookup(0, number);
}

static struct hostent *legacy_host_result(const struct svc_span *name, const char *alias_start,
                                         const char *alias_end, size_t alias_count, const ULONG *addresses,
                                         unsigned count, int *error)
{
    struct svc_thread *state;
    struct hostent result;
    struct svc_span alias;
    const char *cursor = alias_start;
    size_t i, text = name->n + 1, pointers, bytes;
    char **aliases, **list, *strings, *raw_addresses;
    void *payload, *previous;
    if (!count || count > 8 || alias_count > 16u * 1024u * 1024u) { *error = WSANO_RECOVERY; return 0; }
    for (i = 0; i < alias_count; ++i) {
        if (!svc_token(&cursor, alias_end, &alias) || text > (size_t)-1 - alias.n - 1) { *error = WSAENOBUFS; return 0; }
        text += alias.n + 1;
    }
    pointers = alias_count + count + 2;
    if (text > (size_t)-1 - count * 4u || pointers > ((size_t)-1 - text - count * 4u) / sizeof(char *)) {
        *error = WSAENOBUFS; return 0;
    }
    bytes = pointers * sizeof(char *) + count * 4u + text;
    payload = HeapAlloc(GetProcessHeap(), 0, bytes);
    if (!payload) { *error = WSAENOBUFS; return 0; }
    state = svc_storage(error);
    if (!state) { HeapFree(GetProcessHeap(), 0, payload); return 0; }
    aliases = payload; list = aliases + alias_count + 1; raw_addresses = (char *)(list + count + 1);
    strings = raw_addresses + count * 4u;
    result.h_name = svc_copy(&strings, name); result.h_aliases = aliases;
    cursor = alias_start;
    for (i = 0; i < alias_count; ++i) { svc_token(&cursor, alias_end, &alias); aliases[i] = svc_copy(&strings, &alias); }
    aliases[alias_count] = 0;
    memcpy(raw_addresses, addresses, count * 4u);
    for (i = 0; i < count; ++i) list[i] = raw_addresses + i * 4u;
    list[count] = 0;
    result.h_addrtype = AF_INET; result.h_length = 4; result.h_addr_list = list;
    previous = state->host_payload; state->host_payload = payload; state->host = result;
    if (previous) HeapFree(GetProcessHeap(), 0, previous);
    return &state->host;
}
static int legacy_ipv4(const struct svc_span *token, ULONG *address)
{
    size_t start = 0, end;
    unsigned part, value;
    unsigned char octets[4];
    for (part = 0; part < 4; ++part) {
        struct svc_span number;
        end = start;
        while (end < token->n && token->p[end] != '.') ++end;
        number.p = token->p + start; number.n = end - start;
        if (!legacy_number(&number, 255, &value) || (part < 3 ? end == token->n : end != token->n)) return 0;
        octets[part] = (unsigned char)value; start = end + 1;
    }
    memcpy(address, octets, 4);
    return 1;
}
DLLAPI struct hostent *WSAAPI gethostbyaddr(const char *address, int length, int type)
{
    static const WCHAR suffix[] = L"\\drivers\\etc\\hosts";
    const DWORD saved = GetLastError();
    DWORD bytes, offset = 0;
    ULONG wanted;
    int error = WSAHOST_NOT_FOUND;
    char *data;
    struct hostent *result = 0;
    NEED_INIT(0);
    if (!address || length < 4) { SetLastError(WSAEFAULT); return 0; }
    if (type != AF_INET) { SetLastError(WSAEAFNOSUPPORT); return 0; }
    memcpy(&wanted, address, 4);
    data = svc_read_catalog(suffix, sizeof suffix / sizeof *suffix, &bytes, &error);
    if (!data) { SetLastError((DWORD)error); return 0; }
    error = WSAHOST_NOT_FOUND;
    while (offset < bytes) {
        DWORD end = offset;
        const char *cursor, *line_end;
        struct svc_span ip;
        struct legacy_row row;
        ULONG candidate;
        while (end < bytes && data[end] != '\n') ++end;
        line_end = data + end;
        if (legacy_row_start(data + offset, &line_end, &cursor) && svc_token(&cursor, line_end, &ip)
            && legacy_ipv4(&ip, &candidate) && candidate == wanted && svc_token(&cursor, line_end, &row.name)
            && svc_ascii(&row.name) && legacy_aliases(cursor, line_end, &row)) {
            result = legacy_host_result(&row.name, row.aliases, row.end, row.alias_count, &candidate, 1, &error); break;
        }
        offset = end < bytes ? end + 1 : bytes;
    }
    HeapFree(GetProcessHeap(), 0, data);
    SetLastError(result ? saved : (DWORD)error);
    return result;
}
/* ---- end legacy database lookups ---- */
BOOL WINAPI DllMain(HINSTANCE module, DWORD reason, LPVOID reserved)
{
    struct svc_thread *state = 0;
    DWORD slot;
    const DWORD saved_error = GetLastError();
    (void)module;
    /* At process termination, killed threads can own locks; the OS reclaims their heap/TLS without a wait here. */
    if (reason == DLL_PROCESS_DETACH && reserved) return TRUE;
    if (reason == DLL_THREAD_DETACH) {
        struct svc_thread **link;
        const DWORD tid = GetCurrentThreadId();
        AcquireSRWLockExclusive(&g_svc_lock);
        if (g_svc_tls != TLS_OUT_OF_INDEXES) {
            struct svc_thread *candidate = TlsGetValue(g_svc_tls);
            for (link = &g_svc_threads; *link; link = &(*link)->next)
                if (*link == candidate && (*link)->tid == tid) { state = *link; *link = state->next; break; }
            TlsSetValue(g_svc_tls, 0);
        }
        ReleaseSRWLockExclusive(&g_svc_lock);
        if (state) { if (state->payload) HeapFree(GetProcessHeap(), 0, state->payload); if (state->protocol_payload) HeapFree(GetProcessHeap(), 0, state->protocol_payload); if (state->host_payload) HeapFree(GetProcessHeap(), 0, state->host_payload); HeapFree(GetProcessHeap(), 0, state); }
    } else if (reason == DLL_PROCESS_DETACH) {
        AcquireSRWLockExclusive(&g_svc_lock);
        state = g_svc_threads; g_svc_threads = 0; slot = g_svc_tls; g_svc_tls = TLS_OUT_OF_INDEXES;
        ReleaseSRWLockExclusive(&g_svc_lock);
        if (slot != TLS_OUT_OF_INDEXES) TlsFree(slot);
        while (state) {
            struct svc_thread *next = state->next;
            if (state->payload) HeapFree(GetProcessHeap(), 0, state->payload);
            if (state->protocol_payload) HeapFree(GetProcessHeap(), 0, state->protocol_payload);
            if (state->host_payload) HeapFree(GetProcessHeap(), 0, state->host_payload);
            HeapFree(GetProcessHeap(), 0, state); state = next;
        }
    }
    SetLastError(saved_error);
    return TRUE;
}
/* ---- end service database ---- */

/* -> 0 and *port (host order), or a Winsock error code */
static int service_port(const char *service, int numeric_only, unsigned *port)
{
    unsigned v = 0, i;
    if (!service || !*service) { *port = 0; return 0; }
    for (i = 0; service[i] >= '0' && service[i] <= '9'; ++i) {
        v = v * 10 + (unsigned)(service[i] - '0');
        if (v > 65535) return WSATYPE_NOT_FOUND;
    }
    if (i && !service[i]) { *port = v; return 0; }
    if (numeric_only) return WSATYPE_NOT_FOUND;
    for (i = 0; services[i].name; ++i)
        if (ieq(service, services[i].name)) { *port = services[i].port; return 0; }
    return WSATYPE_NOT_FOUND;
}

/* Resolves `node` to up to 8 IPv4 addresses (network byte order). Returns 0 or a Winsock error code. */
static int resolve_node(const char *node, int flags, ULONG *addrs, unsigned *n)
{
    ULONG host;
    ULONG count = 0;
    NTSTATUS st;
    size_t len = strlen(node);
    if (parse_ipv4_loose(node, &host)) { addrs[0] = htonl((u_long)host); *n = 1; return 0; }
    if (flags & AI_NUMERICHOST) return WSAHOST_NOT_FOUND;
    st = NtShzNetResolve(node, len, addrs, 8, &count, 0, 0);
    if (st) return map_status(st);
    *n = count;
    return count ? 0 : WSAHOST_NOT_FOUND;
}

struct ai_plan {
    int family, socktype, protocol;
    unsigned nsock;
    struct { int type, proto; } socks[2];
    ULONG addrs[8];
    unsigned naddr, port;
    const char *canon;
};

static int plan_addrinfo(const char *node, const char *service, int flags, int family, int socktype, int protocol, struct ai_plan *p)
{
    int rc;
    unsigned i;
    memset(p, 0, sizeof *p);
    if (family != AF_UNSPEC && family != AF_INET) return family == AF_INET6 ? WSAHOST_NOT_FOUND : WSAEAFNOSUPPORT;
    if (!node && !service) return WSAHOST_NOT_FOUND;
    if (socktype == 0) {
        if (protocol == 0 || protocol == IPPROTO_TCP) { p->socks[p->nsock].type = SOCK_STREAM; p->socks[p->nsock++].proto = IPPROTO_TCP; }
        if (protocol == 0 || protocol == IPPROTO_UDP) { p->socks[p->nsock].type = SOCK_DGRAM; p->socks[p->nsock++].proto = IPPROTO_UDP; }
        if (!p->nsock) return WSAEINVAL;
    } else if (socktype == SOCK_STREAM && (protocol == 0 || protocol == IPPROTO_TCP)) {
        p->socks[0].type = SOCK_STREAM; p->socks[0].proto = IPPROTO_TCP; p->nsock = 1;
    } else if (socktype == SOCK_DGRAM && (protocol == 0 || protocol == IPPROTO_UDP)) {
        p->socks[0].type = SOCK_DGRAM; p->socks[0].proto = IPPROTO_UDP; p->nsock = 1;
    } else {
        return (socktype == SOCK_STREAM || socktype == SOCK_DGRAM) ? WSAEINVAL : WSAESOCKTNOSUPPORT;
    }
    rc = service_port(service, (flags & AI_NUMERICSERV) != 0, &p->port);
    if (rc) return rc;
    if (!node) {
        p->addrs[0] = (flags & AI_PASSIVE) ? htonl(INADDR_ANY) : htonl(INADDR_LOOPBACK);
        p->naddr = 1;
    } else {
        rc = resolve_node(node, flags, p->addrs, &p->naddr);
        if (rc) return rc;
    }
    p->canon = (flags & AI_CANONNAME) && node ? node : 0;
    (void)i;
    return 0;
}

static void fill_sockaddr(struct sockaddr_in *sa, ULONG addr_be, unsigned port)
{
    memset(sa, 0, sizeof *sa);
    sa->sin_family = AF_INET;
    sa->sin_port = htons((u_short)port);
    sa->sin_addr.s_addr = addr_be;
}

DLLAPI int WSAAPI getaddrinfo(const char *node, const char *service, const struct addrinfo *hints, struct addrinfo **res)
{
    struct ai_plan p;
    struct addrinfo *head = 0, **tail = &head;
    unsigned a, k;
    int rc, flags = hints ? hints->ai_flags : 0;
    NEED_INIT(WSANOTINITIALISED);
    if (!res) { SetLastError(WSAEINVAL); return WSAEINVAL; }
    *res = 0;
    if (node && !*node) node = 0;
    rc = plan_addrinfo(node, service, flags, hints ? hints->ai_family : 0, hints ? hints->ai_socktype : 0, hints ? hints->ai_protocol : 0, &p);
    if (rc) { SetLastError((DWORD)rc); return rc; }
    for (a = 0; a < p.naddr; ++a)
        for (k = 0; k < p.nsock; ++k) {
            const size_t canon_len = p.canon && !head ? strlen(p.canon) + 1 : 0;
            struct addrinfo *ai = HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, sizeof *ai + sizeof(struct sockaddr_in) + canon_len);
            if (!ai) { freeaddrinfo(head); SetLastError(WSA_NOT_ENOUGH_MEMORY); return WSA_NOT_ENOUGH_MEMORY; }
            ai->ai_family = AF_INET;
            ai->ai_socktype = p.socks[k].type;
            ai->ai_protocol = p.socks[k].proto;
            ai->ai_addrlen = sizeof(struct sockaddr_in);
            ai->ai_addr = (struct sockaddr *)(ai + 1);
            fill_sockaddr((struct sockaddr_in *)ai->ai_addr, p.addrs[a], p.port);
            if (canon_len) {
                ai->ai_canonname = (char *)(ai->ai_addr) + sizeof(struct sockaddr_in);
                memcpy(ai->ai_canonname, p.canon, canon_len);
            }
            *tail = ai;
            tail = &ai->ai_next;
        }
    *res = head;
    return 0;
}

DLLAPI void WSAAPI freeaddrinfo(LPADDRINFO pAddrInfo)
{
    while (pAddrInfo) {
        struct addrinfo *next = pAddrInfo->ai_next;
        HeapFree(GetProcessHeap(), 0, pAddrInfo);
        pAddrInfo = next;
    }
}

static int narrow(PCWSTR w, char *out, size_t cap)
{
    size_t i;
    if (!w) return 0;
    for (i = 0; w[i]; ++i) {
        if (i + 1 >= cap || w[i] > 0x7e) return -1;
        out[i] = (char)w[i];
    }
    out[i] = 0;
    return 1;
}

/* Original implementation of the Microsoft Learn GetNameInfoW contract, strengthened from E1 proposal 0001.
 * References reviewed: Wine df15af3652511150490934682202d45af892f887 dlls/ws2_32/protocol.c;
 * ReactOS 9dc3ca87209fd8ebabd96c8ea95d439c13e7fdf8 dll/win32/ws2_32/src/addrinfo.c. No code copied.
 * Numeric IPv4/IPv6 conversion needs no IPv6 transport. There is no PTR resolver: a requested name fails with
 * NI_NAMEREQD, otherwise the numeric address is returned. NI_NUMERICHOST bypasses name lookup, even with NI_NAMEREQD.
 * Service lookup uses the existing small table, plus the transport-specific names for ports 512..514; unknown ports
 * fall back to decimal as on Vista+. Both capacities are WCHAR counts including the NUL. Preflight both outputs. */
static INT nameinfo_error(INT code) { SetLastError((DWORD)code); return code; }

static unsigned nameinfo_decimal(ULONG value, char *out)
{
    char reverse[10];
    unsigned n = 0, i;
    do { reverse[n++] = (char)('0' + value % 10); value /= 10; } while (value);
    for (i = 0; i < n; ++i) out[i] = reverse[n - i - 1];
    out[n] = 0;
    return n;
}

DLLAPI INT WSAAPI GetNameInfoW(const SOCKADDR *sa, socklen_t salen, PWCHAR host, DWORD hostlen,
                              PWCHAR serv, DWORD servlen, INT flags)
{
    char address[64], port_text[6];
    const void *addr;
    const char *service = port_text;
    ULONG scope = 0;
    unsigned port, hn = 0, sn = 0, i;
    NEED_INIT(WSANOTINITIALISED);
    if (!sa || salen < (socklen_t)sizeof sa->sa_family) return nameinfo_error(WSAEFAULT);
    if (sa->sa_family == AF_INET) {
        const struct sockaddr_in *in4 = (const struct sockaddr_in *)sa;
        if (salen < (socklen_t)sizeof *in4) return nameinfo_error(WSAEFAULT);
        addr = &in4->sin_addr;
        port = ntohs(in4->sin_port);
    } else if (sa->sa_family == AF_INET6) {
        const struct sockaddr_in6 *in6 = (const struct sockaddr_in6 *)sa;
        if (salen < (socklen_t)sizeof *in6) return nameinfo_error(WSAEFAULT);
        addr = &in6->sin6_addr;
        port = ntohs(in6->sin6_port);
        scope = in6->sin6_scope_id;
    } else {
        return nameinfo_error(WSAEAFNOSUPPORT);
    }
    if (flags & ~(NI_NOFQDN | NI_NUMERICHOST | NI_NAMEREQD | NI_NUMERICSERV | NI_DGRAM))
        return nameinfo_error(WSAEINVAL);
    if ((host && !hostlen) || (serv && !servlen)) return nameinfo_error(WSAEINVAL);
    if (!host && !serv) return nameinfo_error(WSAHOST_NOT_FOUND);
    if (host) {
        if ((flags & NI_NAMEREQD) && !(flags & NI_NUMERICHOST)) return nameinfo_error(WSAHOST_NOT_FOUND);
        if (!inet_ntop(sa->sa_family, addr, address, sizeof address)) return nameinfo_error(WSAGetLastError());
        hn = (unsigned)strlen(address);
        if (scope) { address[hn++] = '%'; hn += nameinfo_decimal(scope, address + hn); }
        if (hn + 1 > hostlen) return nameinfo_error(WSAEFAULT);
    }
    if (serv) {
        nameinfo_decimal(port, port_text);
        if (!(flags & NI_NUMERICSERV)) {
            if (port == 512) service = flags & NI_DGRAM ? "biff" : "exec";
            else if (port == 513) service = flags & NI_DGRAM ? "who" : "login";
            else if (port == 514) service = flags & NI_DGRAM ? "syslog" : "shell";
            else for (i = 0; services[i].name; ++i)
                if (services[i].port == port) { service = services[i].name; break; }
        }
        sn = (unsigned)strlen(service);
        if (sn + 1 > servlen) return nameinfo_error(WSAEFAULT);
    }
    if (host) { for (i = 0; i <= hn; ++i) host[i] = (WCHAR)(unsigned char)address[i]; }
    if (serv) { for (i = 0; i <= sn; ++i) serv[i] = (WCHAR)(unsigned char)service[i]; }
    return 0;
}

DLLAPI int WSAAPI GetAddrInfoW(PCWSTR pNodeName, PCWSTR pServiceName, const ADDRINFOW *pHints, PADDRINFOW *ppResult)
{
    char node[260], service[64];
    struct ai_plan p;
    ADDRINFOW *head = 0, **tail = &head;
    unsigned a, k;
    int rc, nn, sn, flags = pHints ? pHints->ai_flags : 0;
    NEED_INIT(WSANOTINITIALISED);
    if (!ppResult) { SetLastError(WSAEINVAL); return WSAEINVAL; }
    *ppResult = 0;
    nn = narrow(pNodeName, node, sizeof node);
    sn = narrow(pServiceName, service, sizeof service);
    if (nn < 0 || sn < 0) { SetLastError(WSAHOST_NOT_FOUND); return WSAHOST_NOT_FOUND; }   /* non-ASCII names need IDNA, which is not implemented */
    rc = plan_addrinfo(nn && node[0] ? node : 0, sn ? service : 0, flags, pHints ? pHints->ai_family : 0, pHints ? pHints->ai_socktype : 0,
                       pHints ? pHints->ai_protocol : 0, &p);
    if (rc) { SetLastError((DWORD)rc); return rc; }
    for (a = 0; a < p.naddr; ++a)
        for (k = 0; k < p.nsock; ++k) {
            size_t canon_len = 0, i;
            ADDRINFOW *ai;
            if (p.canon && !head) canon_len = strlen(p.canon) + 1;
            ai = HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, sizeof *ai + sizeof(struct sockaddr_in) + canon_len * sizeof(WCHAR));
            if (!ai) { FreeAddrInfoW(head); SetLastError(WSA_NOT_ENOUGH_MEMORY); return WSA_NOT_ENOUGH_MEMORY; }
            ai->ai_family = AF_INET;
            ai->ai_socktype = p.socks[k].type;
            ai->ai_protocol = p.socks[k].proto;
            ai->ai_addrlen = sizeof(struct sockaddr_in);
            ai->ai_addr = (struct sockaddr *)(ai + 1);
            fill_sockaddr((struct sockaddr_in *)ai->ai_addr, p.addrs[a], p.port);
            if (canon_len) {
                ai->ai_canonname = (PWSTR)((char *)ai->ai_addr + sizeof(struct sockaddr_in));
                for (i = 0; i < canon_len; ++i) ai->ai_canonname[i] = (WCHAR)(unsigned char)p.canon[i];
            }
            *tail = ai;
            tail = &ai->ai_next;
        }
    *ppResult = head;
    return 0;
}

DLLAPI void WSAAPI FreeAddrInfoW(PADDRINFOW pAddrInfo)
{
    while (pAddrInfo) {
        ADDRINFOW *next = pAddrInfo->ai_next;
        HeapFree(GetProcessHeap(), 0, pAddrInfo);
        pAddrInfo = next;
    }
}

DLLAPI struct hostent *WSAAPI gethostbyname(const char *name)
{
    struct svc_span host_name;
    struct hostent *result;
    const DWORD saved = GetLastError();
    ULONG a[8];
    unsigned n = 0;
    int rc;
    char local[MAX_COMPUTERNAME_LENGTH + 2];
    if (!g_started) { SetLastError(WSANOTINITIALISED); return 0; }
    if (!name || !*name) {                                  /* NULL / "": the local host, answered with our own address */
        struct { ULONG flags, ip, mask, gw, d0, d1, srv; unsigned char mac[6]; unsigned short pad; ULONG a, b, c; } info;
        ULONG ret = 0;
        if (gethostname(local, sizeof local)) return 0;
        name = local;
        if (NtShzNetQuery(0, &info, sizeof info, &ret) == 0 && info.ip) { a[0] = info.ip; n = 1; }
        else { a[0] = htonl(INADDR_LOOPBACK); n = 1; }
        rc = 0;
    } else {
        rc = resolve_node(name, 0, a, &n);
    }
    if (rc) { SetLastError((DWORD)rc); return 0; }
    host_name.p = name; host_name.n = strlen(name);
    result = legacy_host_result(&host_name, 0, 0, 0, a, n, &rc);
    SetLastError(result ? saved : (DWORD)rc);
    return result;
}

/* ---------------------------------------------------------------- catalog: transport and namespace providers */
/* {53485A31-5443-5049-8000-5443502F4950} "SHZ1" "TCPIP": the transport provider built into this ws2_32 */
static const GUID g_provider = { 0x53485a31, 0x5443, 0x5049, { 0x80, 0x00, 0x54, 0x43, 0x50, 0x2f, 0x49, 0x50 } };
/* {53485A31-4E53-4453-8000-444E53000001} "SHZ1" "NS DNS": the namespace provider (Kernel64 resolver) */
static const GUID g_ns_provider = { 0x53485a31, 0x4e53, 0x4453, { 0x80, 0x00, 0x44, 0x4e, 0x53, 0x00, 0x00, 0x01 } };

static void wcopy(WCHAR *d, const char *s, size_t cap) { size_t i; for (i = 0; s[i] && i + 1 < cap; ++i) d[i] = (WCHAR)(unsigned char)s[i]; d[i] = 0; }

static void protocol_info(WSAPROTOCOL_INFOW *p, int tcp)
{
    memset(p, 0, sizeof *p);
    p->dwServiceFlags1 = tcp ? XP1_GUARANTEED_DELIVERY | XP1_GUARANTEED_ORDER | XP1_GRACEFUL_CLOSE
                             : XP1_CONNECTIONLESS | XP1_MESSAGE_ORIENTED | XP1_SUPPORT_BROADCAST;
    p->dwProviderFlags = PFL_MATCHES_PROTOCOL_ZERO;
    p->ProviderId = g_provider;
    p->dwCatalogEntryId = tcp ? 1001 : 1002;
    p->ProtocolChain.ChainLen = BASE_PROTOCOL;
    p->iVersion = 2;
    p->iAddressFamily = AF_INET;
    p->iMaxSockAddr = sizeof(struct sockaddr_in);
    p->iMinSockAddr = sizeof(struct sockaddr_in);
    p->iSocketType = tcp ? SOCK_STREAM : SOCK_DGRAM;
    p->iProtocol = tcp ? IPPROTO_TCP : IPPROTO_UDP;
    p->iNetworkByteOrder = BIGENDIAN;
    p->iSecurityScheme = SECURITY_PROTOCOL_NONE;
    p->dwMessageSize = tcp ? 0 : 65507;                     /* the largest datagram the kernel stack sends (IPv4 limit) */
    wcopy(p->szProtocol, tcp ? "Shizuku Tcpip [TCP/IP]" : "Shizuku Tcpip [UDP/IP]", WSAPROTOCOL_LEN + 1);
}

/* -> number of entries (0 or more), or -1 with *err set */
static int enum_protocols(const INT *filter, WSAPROTOCOL_INFOW *buf, DWORD *len, int *err)
{
    static const int protos[2] = { IPPROTO_TCP, IPPROTO_UDP };
    int pick[2], n = 0, i;
    if (!len) { *err = WSAEFAULT; return -1; }
    for (i = 0; i < 2; ++i) {
        int want = !filter, k;
        for (k = 0; filter && filter[k]; ++k) if (filter[k] == protos[i]) want = 1;
        if (want) pick[n++] = i;
    }
    if (!buf || *len < n * sizeof *buf) { *len = (DWORD)(n * sizeof *buf); *err = WSAENOBUFS; return -1; }
    for (i = 0; i < n; ++i) protocol_info(&buf[i], pick[i] == 0);
    *len = (DWORD)(n * sizeof *buf);
    return n;
}

DLLAPI int WSAAPI WSAEnumProtocolsW(LPINT lpiProtocols, LPWSAPROTOCOL_INFOW lpProtocolBuffer, LPDWORD lpdwBufferLength)
{
    int err = 0, n;
    NEED_INIT(SOCKET_ERROR);
    n = enum_protocols(lpiProtocols, lpProtocolBuffer, lpdwBufferLength, &err);
    return n < 0 ? fail_code(err) : n;
}

/* ---- ANSI provider enumeration: same real transport metadata as W ---- */
_Static_assert(sizeof(WSAPROTOCOL_INFOA) == 372 && sizeof(WSAPROTOCOL_INFOW) == 628
               && offsetof(WSAPROTOCOL_INFOA, szProtocol) == 116
               && offsetof(WSAPROTOCOL_INFOW, szProtocol) == 116, "Windows protocol-info A/W ABI");
DLLAPI int WSAAPI WSAEnumProtocolsA(LPINT protocols, LPWSAPROTOCOL_INFOA buffer, LPDWORD length)
{
    WSAPROTOCOL_INFOW wide[2];
    DWORD wide_bytes = sizeof wide, need;
    int error = 0, count, i;
    NEED_INIT(SOCKET_ERROR);
    if (!length) return fail_code(WSAEFAULT);
    count = enum_protocols(protocols, wide, &wide_bytes, &error);
    if (count < 0) return fail_code(error);
    need = (DWORD)count * sizeof *buffer;
    if (count && (!buffer || *length < need)) { *length = need; return fail_code(WSAENOBUFS); }
    for (i = 0; i < count; ++i) {
        unsigned j;
        memset(&buffer[i], 0, sizeof buffer[i]);
        memcpy(&buffer[i], &wide[i], offsetof(WSAPROTOCOL_INFOA, szProtocol));
        /* The built-in provider labels above are ASCII, so their A conversion
         * is exact and independent of the current ANSI code page. */
        for (j = 0; j < WSAPROTOCOL_LEN && wide[i].szProtocol[j]; ++j)
            buffer[i].szProtocol[j] = (char)wide[i].szProtocol[j];
    }
    *length = need;
    return count;
}
/* ---- end ANSI provider enumeration ---- */

DLLAPI int WSAAPI WSCEnumProtocols(LPINT lpiProtocols, LPWSAPROTOCOL_INFOW lpProtocolBuffer, LPDWORD lpdwBufferLength, LPINT lpErrno)
{
    int err = 0, n = enum_protocols(lpiProtocols, lpProtocolBuffer, lpdwBufferLength, &err);
    if (n < 0) { if (lpErrno) *lpErrno = err; return SOCKET_ERROR; }
    return n;
}

/* The provider's DLL is this module itself. */
DLLAPI int WSAAPI WSCGetProviderPath(LPGUID lpProviderId, WCHAR *lpszProviderDllPath, LPINT lpProviderDllPathLen, LPINT lpErrno)
{
    WCHAR path[MAX_PATH];
    HMODULE self = 0;
    DWORD n;
    if (!lpErrno) return SOCKET_ERROR;
    if (!lpProviderId || !lpProviderDllPathLen) { *lpErrno = WSAEFAULT; return SOCKET_ERROR; }
    if (memcmp(lpProviderId, &g_provider, sizeof(GUID))) { *lpErrno = WSAEINVAL; return SOCKET_ERROR; }
    if (!GetModuleHandleExW(GET_MODULE_HANDLE_EX_FLAG_FROM_ADDRESS | GET_MODULE_HANDLE_EX_FLAG_UNCHANGED_REFCOUNT, (LPCWSTR)(void *)WSCGetProviderPath, &self) ||
        !(n = GetModuleFileNameW(self, path, MAX_PATH))) { *lpErrno = WSAEINVAL; return SOCKET_ERROR; }
    if (!lpszProviderDllPath || *lpProviderDllPathLen < (int)n + 1) { *lpProviderDllPathLen = (int)n + 1; *lpErrno = WSAEFAULT; return SOCKET_ERROR; }
    memcpy(lpszProviderDllPath, path, (n + 1) * sizeof(WCHAR));
    *lpProviderDllPathLen = (int)n + 1;
    return 0;
}

DLLAPI INT WSAAPI WSAEnumNameSpaceProvidersW(LPDWORD lpdwBufferLength, LPWSANAMESPACE_INFOW lpnspBuffer)
{
    static const char ident[] = "Shizuku DNS (Kernel64 resolver)";
    const DWORD need = sizeof(WSANAMESPACE_INFOW) + sizeof ident * sizeof(WCHAR);
    NEED_INIT(SOCKET_ERROR);
    if (!lpdwBufferLength) return fail_code(WSAEFAULT);
    if (!lpnspBuffer || *lpdwBufferLength < need) { *lpdwBufferLength = need; return fail_code(WSAEFAULT); }
    memset(lpnspBuffer, 0, sizeof *lpnspBuffer);
    lpnspBuffer->NSProviderId = g_ns_provider;
    lpnspBuffer->dwNameSpace = NS_DNS;
    lpnspBuffer->fActive = TRUE;
    lpnspBuffer->dwVersion = 1;
    lpnspBuffer->lpszIdentifier = (LPWSTR)(lpnspBuffer + 1);
    wcopy(lpnspBuffer->lpszIdentifier, ident, sizeof ident);
    return 1;
}

/* ---------------------------------------------------------------- socket duplication and overlapped results */
DLLAPI int WSAAPI WSADuplicateSocketW(SOCKET s, DWORD dwProcessId, LPWSAPROTOCOL_INFOW lpProtocolInfo)
{
    ULONG type = 0, n = 4;
    HANDLE dup = 0;
    NTSTATUS st;
    NEED_INIT(SOCKET_ERROR);
    if (!lpProtocolInfo) return fail_code(WSAEFAULT);
    st = NtShzSockGetOpt(s, SOL_SOCKET, SO_TYPE, &type, &n);
    if (st) return fail(st);
    if (dwProcessId != GetCurrentProcessId()) return fail_code(WSAEINVAL);      /* no handle duplication into other processes */
    if (!DuplicateHandle(GetCurrentProcess(), (HANDLE)s, GetCurrentProcess(), &dup, 0, FALSE, DUPLICATE_SAME_ACCESS)) return fail_code(WSAENOBUFS);
    protocol_info(lpProtocolInfo, type == SOCK_STREAM);
    lpProtocolInfo->dwProviderReserved = (DWORD)(ULONG_PTR)dup;         /* WSASocketW(FROM_PROTOCOL_INFO) picks it up */
    return 0;
}

DLLAPI BOOL WSAAPI WSAGetOverlappedResult(SOCKET s, LPWSAOVERLAPPED ov, LPDWORD transferred, BOOL wait, LPDWORD flags)
{
    ULONG type = 0, n = 4;
    NTSTATUS st;
    if (!g_started) { SetLastError(WSANOTINITIALISED); return FALSE; }
    if (!ov || !transferred || !flags) { SetLastError(WSAEFAULT); return FALSE; }
    st = NtShzSockGetOpt(s, SOL_SOCKET, SO_TYPE, &type, &n);
    if (st) { SetLastError((DWORD)map_status(st)); return FALSE; }
    while ((NTSTATUS)ov->Internal == (NTSTATUS)0x103) {     /* STATUS_PENDING */
        if (!wait) { SetLastError(WSA_IO_INCOMPLETE); return FALSE; }
        { HANDLE event = (HANDLE)((ULONG_PTR)ov->hEvent & ~(ULONG_PTR)1);
          if (WaitForSingleObject(event ? event : (HANDLE)s, INFINITE) == WAIT_FAILED) { SetLastError(WSA_INVALID_HANDLE); return FALSE; } }
    }
    *transferred = (DWORD)ov->InternalHigh;
    *flags = 0;
    if ((NTSTATUS)ov->Internal) { SetLastError((DWORD)map_status((NTSTATUS)ov->Internal)); return FALSE; }
    return TRUE;
}

/* ---------------------------------------------------------------- GetAddrInfoExW */
static PADDRINFOEXW build_addrinfoex(const struct ai_plan *p, int *err)
{
    PADDRINFOEXW head = 0, *tail = &head;
    unsigned a, k;
    for (a = 0; a < p->naddr; ++a)
        for (k = 0; k < p->nsock; ++k) {
            size_t canon_len = p->canon && !head ? strlen(p->canon) + 1 : 0, i;
            PADDRINFOEXW ai = HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, sizeof *ai + sizeof(struct sockaddr_in) + sizeof(GUID) + canon_len * sizeof(WCHAR));
            if (!ai) { FreeAddrInfoExW(head); *err = WSA_NOT_ENOUGH_MEMORY; return 0; }
            ai->ai_family = AF_INET;
            ai->ai_socktype = p->socks[k].type;
            ai->ai_protocol = p->socks[k].proto;
            ai->ai_addrlen = sizeof(struct sockaddr_in);
            ai->ai_addr = (struct sockaddr *)(ai + 1);
            fill_sockaddr((struct sockaddr_in *)ai->ai_addr, p->addrs[a], p->port);
            ai->ai_provider = (LPGUID)((char *)ai->ai_addr + sizeof(struct sockaddr_in));
            *ai->ai_provider = g_ns_provider;
            if (canon_len) {
                WCHAR *cn = (WCHAR *)((char *)ai->ai_provider + sizeof(GUID));
                for (i = 0; i < canon_len; ++i) cn[i] = (WCHAR)(unsigned char)p->canon[i];
                ai->ai_canonname = cn;
            }
            *tail = ai;
            tail = &ai->ai_next;
        }
    *err = 0;
    return head;
}

DLLAPI void WSAAPI FreeAddrInfoExW(PADDRINFOEXW pAddrInfo)
{
    while (pAddrInfo) {
        PADDRINFOEXW next = pAddrInfo->ai_next;
        HeapFree(GetProcessHeap(), 0, pAddrInfo);
        pAddrInfo = next;
    }
}

typedef struct aix {                                        /* one asynchronous GetAddrInfoExW request */
    struct aix *next;
    WCHAR name[260], service[64];
    int have_name, have_service, flags, family, socktype, protocol;
    PADDRINFOEXW *result;
    LPOVERLAPPED ov;
    volatile LONG cancelled, done;
} aix_t;
static aix_t *g_aix;
static SRWLOCK g_aix_lock = SRWLOCK_INIT;

static int resolve_ex(const WCHAR *name, const WCHAR *service, int flags, int family, int socktype, int protocol, PADDRINFOEXW *out)
{
    char node[260], serv[64];
    struct ai_plan p;
    int nn = narrow(name, node, sizeof node), sn = narrow(service, serv, sizeof serv), rc;
    if (nn < 0 || sn < 0) return WSAHOST_NOT_FOUND;         /* non-ASCII names would need IDNA */
    rc = plan_addrinfo(nn && node[0] ? node : 0, sn ? serv : 0, flags, family, socktype, protocol, &p);
    if (rc) return rc;
    *out = build_addrinfoex(&p, &rc);
    return rc;
}

static DWORD WINAPI aix_worker(LPVOID arg)
{
    aix_t *r = arg;
    PADDRINFOEXW res = 0;
    const int rc = resolve_ex(r->have_name ? r->name : 0, r->have_service ? r->service : 0, r->flags, r->family, r->socktype, r->protocol, &res);
    HANDLE ev;
    AcquireSRWLockExclusive(&g_aix_lock);
    if (r->cancelled) { FreeAddrInfoExW(res); res = 0; }
    *r->result = res;
    r->ov->InternalHigh = 0;
    r->ov->Internal = (ULONG_PTR)(r->cancelled ? WSA_E_CANCELLED : rc);   /* GetAddrInfoExOverlappedResult reads it */
    ev = r->ov->hEvent;
    r->done = 1;
    {                                                       /* the request is finished: drop it from the list */
        aix_t **pp;
        for (pp = &g_aix; *pp; pp = &(*pp)->next) if (*pp == r) { *pp = r->next; break; }
    }
    ReleaseSRWLockExclusive(&g_aix_lock);
    if (ev) SetEvent(ev);
    HeapFree(GetProcessHeap(), 0, r);
    return 0;
}

static void wcopyw(WCHAR *d, const WCHAR *s, size_t cap) { size_t i; for (i = 0; s[i] && i + 1 < cap; ++i) d[i] = s[i]; d[i] = 0; }

DLLAPI int WSAAPI GetAddrInfoExW(PCWSTR pName, PCWSTR pServiceName, DWORD dwNameSpace, LPGUID lpNspId, const ADDRINFOEXW *hints,
                                 PADDRINFOEXW *ppResult, PTIMEVAL timeout, LPOVERLAPPED lpOverlapped,
                                 LPLOOKUPSERVICE_COMPLETION_ROUTINE lpCompletionRoutine, LPHANDLE lpNameHandle)
{
    const int flags = hints ? hints->ai_flags : 0, family = hints ? hints->ai_family : 0;
    const int socktype = hints ? hints->ai_socktype : 0, protocol = hints ? hints->ai_protocol : 0;
    int rc;
    if (!g_started) { SetLastError(WSANOTINITIALISED); return WSANOTINITIALISED; }
    if (!ppResult) { SetLastError(WSAEINVAL); return WSAEINVAL; }
    *ppResult = 0;
    if (dwNameSpace != NS_ALL && dwNameSpace != NS_DNS) { SetLastError(WSAEINVAL); return WSAEINVAL; }    /* no provider for it */
    if (lpNspId && memcmp(lpNspId, &g_ns_provider, sizeof(GUID))) { SetLastError(WSAEINVAL); return WSAEINVAL; }
    if (hints && (hints->ai_addrlen || hints->ai_canonname || hints->ai_addr || hints->ai_blob || hints->ai_bloblen || hints->ai_provider ||
                  hints->ai_next)) { SetLastError(WSAEINVAL); return WSAEINVAL; }
    if (lpCompletionRoutine) { SetLastError(WSAEOPNOTSUPP); return WSAEOPNOTSUPP; }    /* would need an APC to the caller */
    if (!lpOverlapped) {
        if (timeout || lpNameHandle) { SetLastError(WSAEINVAL); return WSAEINVAL; }     /* both only apply to asynchronous calls */
        rc = resolve_ex(pName, pServiceName, flags, family, socktype, protocol, ppResult);
        if (rc) SetLastError((DWORD)rc);
        return rc;
    }
    {
        aix_t *r = HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, sizeof *r);
        HANDLE th;
        if (!r) { SetLastError(WSA_NOT_ENOUGH_MEMORY); return WSA_NOT_ENOUGH_MEMORY; }
        if (pName) { wcopyw(r->name, pName, 260); r->have_name = 1; }
        if (pServiceName) { wcopyw(r->service, pServiceName, 64); r->have_service = 1; }
        r->flags = flags; r->family = family; r->socktype = socktype; r->protocol = protocol;
        r->result = ppResult;
        r->ov = lpOverlapped;
        lpOverlapped->Internal = (ULONG_PTR)WSA_IO_PENDING;
        AcquireSRWLockExclusive(&g_aix_lock);
        r->next = g_aix;
        g_aix = r;
        ReleaseSRWLockExclusive(&g_aix_lock);
        if (lpNameHandle) *lpNameHandle = (HANDLE)r;
        th = CreateThread(0, 0, aix_worker, r, 0, 0);
        if (!th) {
            AcquireSRWLockExclusive(&g_aix_lock);
            { aix_t **pp; for (pp = &g_aix; *pp; pp = &(*pp)->next) if (*pp == r) { *pp = r->next; break; } }
            ReleaseSRWLockExclusive(&g_aix_lock);
            HeapFree(GetProcessHeap(), 0, r);
            if (lpNameHandle) *lpNameHandle = 0;
            SetLastError(WSA_NOT_ENOUGH_MEMORY);
            return WSA_NOT_ENOUGH_MEMORY;
        }
        CloseHandle(th);
        SetLastError(WSA_IO_PENDING);
        return WSA_IO_PENDING;
    }
}

DLLAPI int WSAAPI GetAddrInfoExCancel(LPHANDLE lpHandle)
{
    aix_t *r;
    if (!lpHandle) return WSA_INVALID_HANDLE;
    AcquireSRWLockExclusive(&g_aix_lock);
    for (r = g_aix; r && (HANDLE)r != *lpHandle; r = r->next) { }
    if (r) InterlockedExchange(&r->cancelled, 1);           /* the worker frees the result and reports WSA_E_CANCELLED */
    ReleaseSRWLockExclusive(&g_aix_lock);
    return r ? NO_ERROR : WSA_INVALID_HANDLE;               /* unknown or already completed */
}

DLLAPI INT WSAAPI GetAddrInfoExOverlappedResult(LPOVERLAPPED lpOverlapped)
{
    if (!lpOverlapped) return WSAEINVAL;
    return (INT)lpOverlapped->Internal;                     /* WSA_IO_PENDING while running, then the result code */
}

/* ---------------------------------------------------------------- RnR: WSALookupService* and WSASetService */
/* SVCID_HOSTNAME {0002a800-...}, SVCID_INET_HOSTADDRBYNAME {0002a803-...}, SVCID_INET_HOSTADDRBYINETSTRING {0002a801-...} */
static int svcid_is(const GUID *g, unsigned short low)
{
    static const BYTE tail[8] = { 0xC0, 0, 0, 0, 0, 0, 0, 0x46 };
    return g->Data1 == 0x0002a800u + (low - 0xa800) && g->Data2 == 0 && g->Data3 == 0 && !memcmp(g->Data4, tail, 8);
}

typedef struct lookup {
    struct lookup *next;
    DWORD flags;
    GUID cls;
    char name[256];
    ULONG addrs[8];
    unsigned naddr;
    int delivered;
} lookup_t;
static lookup_t *g_lookups;
static SRWLOCK g_lookup_lock = SRWLOCK_INIT;

DLLAPI INT WSAAPI WSALookupServiceBeginW(LPWSAQUERYSETW q, DWORD flags, LPHANDLE lphLookup)
{
    lookup_t *l;
    char name[256];
    int rc;
    NEED_INIT(SOCKET_ERROR);
    if (!q || !lphLookup || q->dwSize < sizeof *q) return fail_code(WSAEFAULT);
    if (!q->lpServiceClassId) return fail_code(WSAEINVAL);
    if (q->dwNameSpace != NS_ALL && q->dwNameSpace != NS_DNS) return fail_code(WSASERVICE_NOT_FOUND);   /* no provider for it */
    if (q->lpNSProviderId && memcmp(q->lpNSProviderId, &g_ns_provider, sizeof(GUID))) return fail_code(WSASERVICE_NOT_FOUND);
    if (!svcid_is(q->lpServiceClassId, 0xa800) && !svcid_is(q->lpServiceClassId, 0xa803) && !svcid_is(q->lpServiceClassId, 0xa801))
        return fail_code(WSASERVICE_NOT_FOUND);             /* the DNS namespace knows host names only */
    if (q->lpszServiceInstanceName) {
        if (narrow(q->lpszServiceInstanceName, name, sizeof name) < 0) return fail_code(WSAHOST_NOT_FOUND);
    } else if (gethostname(name, sizeof name)) {
        return SOCKET_ERROR;
    }
    l = HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, sizeof *l);
    if (!l) return fail_code(WSA_NOT_ENOUGH_MEMORY);
    rc = resolve_node(name, svcid_is(q->lpServiceClassId, 0xa801) ? AI_NUMERICHOST : 0, l->addrs, &l->naddr);
    if (rc) { HeapFree(GetProcessHeap(), 0, l); return fail_code(rc); }
    l->flags = flags;
    l->cls = *q->lpServiceClassId;
    memcpy(l->name, name, strlen(name) + 1);
    AcquireSRWLockExclusive(&g_lookup_lock);
    l->next = g_lookups;
    g_lookups = l;
    ReleaseSRWLockExclusive(&g_lookup_lock);
    *lphLookup = (HANDLE)l;
    return 0;
}

static lookup_t *lookup_find(HANDLE h)
{
    lookup_t *l;
    for (l = g_lookups; l && (HANDLE)l != h; l = l->next) { }
    return l;
}

DLLAPI INT WSAAPI WSALookupServiceNextW(HANDLE hLookup, DWORD dwControlFlags, LPDWORD lpdwBufferLength, LPWSAQUERYSETW r)
{
    lookup_t *l;
    DWORD need, flags, off;
    size_t nlen;
    unsigned i;
    NEED_INIT(SOCKET_ERROR);
    if (!lpdwBufferLength) return fail_code(WSAEFAULT);
    AcquireSRWLockExclusive(&g_lookup_lock);
    l = lookup_find(hLookup);
    if (!l) { ReleaseSRWLockExclusive(&g_lookup_lock); return fail_code(WSA_INVALID_HANDLE); }
    if (l->delivered) { ReleaseSRWLockExclusive(&g_lookup_lock); return fail_code(WSA_E_NO_MORE); }
    flags = l->flags | dwControlFlags;
    nlen = strlen(l->name) + 1;
    need = sizeof *r;
    if (flags & LUP_RETURN_NAME) need += (DWORD)(nlen * sizeof(WCHAR));
    if (flags & LUP_RETURN_TYPE) need += sizeof(GUID);
    if (flags & LUP_RETURN_ADDR) need += l->naddr * (DWORD)(sizeof(CSADDR_INFO) + 2 * sizeof(struct sockaddr_in));
    if (flags & LUP_RETURN_BLOB) need += sizeof(BLOB) + 32 + 8 + (l->naddr + 1) * 8 + l->naddr * 4 + (DWORD)nlen + 8;
    need = (need + 7) & ~7u;
    if (!r || *lpdwBufferLength < need) { ReleaseSRWLockExclusive(&g_lookup_lock); *lpdwBufferLength = need; return fail_code(WSAEFAULT); }
    memset(r, 0, need);
    r->dwSize = sizeof *r;
    r->dwNameSpace = NS_DNS;
    off = sizeof *r;
    if (flags & LUP_RETURN_NAME) {
        r->lpszServiceInstanceName = (LPWSTR)((char *)r + off);
        for (i = 0; i < nlen; ++i) r->lpszServiceInstanceName[i] = (WCHAR)(unsigned char)l->name[i];
        off += (DWORD)(nlen * sizeof(WCHAR));
    }
    off = (off + 7) & ~7u;
    if (flags & LUP_RETURN_TYPE) {
        r->lpServiceClassId = (LPGUID)((char *)r + off);
        *r->lpServiceClassId = l->cls;
        off += sizeof(GUID);
    }
    if ((flags & LUP_RETURN_ADDR) && l->naddr) {
        CSADDR_INFO *cs = (CSADDR_INFO *)((char *)r + off);
        struct sockaddr_in *sa = (struct sockaddr_in *)(cs + l->naddr);
        r->lpcsaBuffer = cs;
        r->dwNumberOfCsAddrs = l->naddr;
        for (i = 0; i < l->naddr; ++i) {
            fill_sockaddr(&sa[2 * i], INADDR_ANY, 0);       /* local address: any */
            fill_sockaddr(&sa[2 * i + 1], l->addrs[i], 0);  /* remote address: the host's */
            cs[i].LocalAddr.lpSockaddr = (LPSOCKADDR)&sa[2 * i];
            cs[i].LocalAddr.iSockaddrLength = sizeof(struct sockaddr_in);
            cs[i].RemoteAddr.lpSockaddr = (LPSOCKADDR)&sa[2 * i + 1];
            cs[i].RemoteAddr.iSockaddrLength = sizeof(struct sockaddr_in);
            cs[i].iSocketType = SOCK_STREAM;
            cs[i].iProtocol = IPPROTO_TCP;
        }
        off += l->naddr * (DWORD)(sizeof(CSADDR_INFO) + 2 * sizeof(struct sockaddr_in));
    }
    if (flags & LUP_RETURN_BLOB) {                          /* a hostent with offsets relative to the blob, as RnR returns it */
        BLOB *b = (BLOB *)((char *)r + off);
        BYTE *h;
        ULONG_PTR *list;
        DWORD boff;
        off += sizeof(BLOB);
        off = (off + 7) & ~7u;
        h = (BYTE *)r + off;
        r->lpBlob = b;
        b->pBlobData = h;
        boff = 32;                                          /* struct hostent (x64): name, aliases, type, length, addr list */
        *(ULONG_PTR *)(h + 8) = boff;                       /* h_aliases -> empty list */
        *(ULONG_PTR *)(h + boff) = 0;
        boff += 8;
        *(short *)(h + 16) = AF_INET;
        *(short *)(h + 18) = 4;
        *(ULONG_PTR *)(h + 24) = boff;                      /* h_addr_list */
        list = (ULONG_PTR *)(h + boff);
        boff += (l->naddr + 1) * 8;
        for (i = 0; i < l->naddr; ++i) { list[i] = boff; memcpy(h + boff, &l->addrs[i], 4); boff += 4; }
        list[l->naddr] = 0;
        *(ULONG_PTR *)h = boff;                             /* h_name */
        memcpy(h + boff, l->name, nlen);
        boff += (DWORD)nlen;
        b->cbSize = boff;
    }
    l->delivered = 1;
    ReleaseSRWLockExclusive(&g_lookup_lock);
    *lpdwBufferLength = need;
    return 0;
}

DLLAPI INT WSAAPI WSALookupServiceEnd(HANDLE hLookup)
{
    lookup_t **pp, *l = 0;
    NEED_INIT(SOCKET_ERROR);
    AcquireSRWLockExclusive(&g_lookup_lock);
    for (pp = &g_lookups; *pp; pp = &(*pp)->next)
        if ((HANDLE)*pp == hLookup) { l = *pp; *pp = l->next; break; }
    ReleaseSRWLockExclusive(&g_lookup_lock);
    if (!l) return fail_code(WSA_INVALID_HANDLE);
    HeapFree(GetProcessHeap(), 0, l);
    return 0;
}

DLLAPI INT WSAAPI WSASetServiceW(LPWSAQUERYSETW lpqsRegInfo, WSAESETSERVICEOP essoperation, DWORD dwControlFlags)
{
    (void)dwControlFlags;
    NEED_INIT(SOCKET_ERROR);
    if (!lpqsRegInfo || lpqsRegInfo->dwSize < sizeof *lpqsRegInfo) return fail_code(WSAEFAULT);
    if (essoperation != RNRSERVICE_REGISTER && essoperation != RNRSERVICE_DEREGISTER && essoperation != RNRSERVICE_DELETE)
        return fail_code(WSAEINVAL);
    if (lpqsRegInfo->dwNameSpace != NS_ALL && lpqsRegInfo->dwNameSpace != NS_DNS) return fail_code(WSAEINVAL);   /* no provider */
    return fail_code(WSAEOPNOTSUPP);                        /* the DNS namespace answers queries; it cannot register services */
}
