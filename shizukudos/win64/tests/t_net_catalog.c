/* SPDX-License-Identifier: GPL-2.0-only
 * ws2_32 catalog and name-service functions over the loopback stack (no NIC needed): WSAEnumProtocolsW / WSCEnumProtocols /
 * WSCGetProviderPath, WSAEnumNameSpaceProvidersW, WSALookupServiceBeginW/NextW/End, WSASetServiceW, GetAddrInfoExW (synchronous
 * and with an OVERLAPPED event), GetAddrInfoExCancel, WSADuplicateSocketW + WSASocketW(FROM_PROTOCOL_INFO), WSAGetOverlappedResult.
 * Expected values follow the documented Winsock behaviour; "localhost" and 127.0.0.1 are answered without any server.
 */
#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include "nettest.h"

INT WSAAPI WSCEnumProtocols(LPINT, LPWSAPROTOCOL_INFOW, LPDWORD, LPINT);
INT WSAAPI WSCGetProviderPath(LPGUID, WCHAR *, LPINT, LPINT);
INT WSAAPI GetAddrInfoExCancel(LPHANDLE);
INT WSAAPI GetAddrInfoExOverlappedResult(LPOVERLAPPED);

#define LO ((u_long)0x0100007f)
static const GUID svcid_hostname = { 0x0002a800, 0, 0, { 0xC0, 0, 0, 0, 0, 0, 0, 0x46 } };
static const GUID svcid_nla = { 0x37e515, 0xb5c9, 0x4a43, { 0xba, 0xda, 0x8b, 0x48, 0xa8, 0x7a, 0xd2, 0x39 } };

static WCHAR *W(const char *s) { static WCHAR b[4][64]; static int k; WCHAR *w = b[k++ & 3]; int i = 0; while ((w[i] = (WCHAR)(unsigned char)s[i])) ++i; return w; }
static int wtail(const WCHAR *s, const char *t)
{
    size_t n = 0, m = strlen(t), i;
    while (s[n]) ++n;
    if (n < m) return 0;
    for (i = 0; i < m; ++i) if ((s[n - m + i] | 32) != (t[i] | 32)) return 0;
    return 1;
}

static void test_catalog(void)
{
    WSAPROTOCOL_INFOW p[4];
    WSANAMESPACE_INFOW ns[4];
    DWORD len = 0;
    INT err = 0, filt[2] = { IPPROTO_UDP, 0 }, plen = 0;
    WCHAR path[MAX_PATH];
    int n;
    GUID bogus = { 1, 2, 3, { 4, 5, 6, 7, 8, 9, 10, 11 } };
    n = WSAEnumProtocolsW(0, 0, &len);
    CHECK(n == SOCKET_ERROR && WSAGetLastError() == WSAENOBUFS && len == 2 * sizeof p[0], "WSAEnumProtocolsW sizes two entries (TCP and UDP over IPv4)");
    n = WSAEnumProtocolsW(0, p, &len);
    CHECK(n == 2, "WSAEnumProtocolsW returns 2 protocols");
    CHECK(n == 2 && p[0].iAddressFamily == AF_INET && p[0].iSocketType == SOCK_STREAM && p[0].iProtocol == IPPROTO_TCP &&
          (p[0].dwServiceFlags1 & XP1_GUARANTEED_DELIVERY) && (p[0].dwServiceFlags1 & XP1_GUARANTEED_ORDER) && p[0].ProtocolChain.ChainLen == BASE_PROTOCOL &&
          p[0].iMaxSockAddr == sizeof(struct sockaddr_in), "entry 1: a reliable, ordered TCP base protocol");
    CHECK(n == 2 && p[1].iSocketType == SOCK_DGRAM && p[1].iProtocol == IPPROTO_UDP && (p[1].dwServiceFlags1 & XP1_CONNECTIONLESS) &&
          (p[1].dwServiceFlags1 & XP1_MESSAGE_ORIENTED) && p[1].dwMessageSize == 65507, "entry 2: connectionless, message-oriented UDP (65507-byte datagrams)");
    len = sizeof p;
    CHECK(WSAEnumProtocolsW(filt, p, &len) == 1 && p[0].iProtocol == IPPROTO_UDP, "the protocol filter selects UDP only");
    len = sizeof p;
    CHECK(WSCEnumProtocols(0, p, &len, &err) == 2, "WSCEnumProtocols");
    CHECK(WSCGetProviderPath(&p[0].ProviderId, 0, &plen, &err) == SOCKET_ERROR && err == WSAEFAULT && plen > 0, "WSCGetProviderPath sizes the path");
    CHECK(WSCGetProviderPath(&p[0].ProviderId, path, &plen, &err) == 0 && wtail(path, "\\ws2_32.dll"), "the provider is implemented by ws2_32.dll");
    CHECK(WSCGetProviderPath(&bogus, path, &plen, &err) == SOCKET_ERROR && err == WSAEINVAL, "an unknown provider id is WSAEINVAL");
    len = 0;
    CHECK(WSAEnumNameSpaceProvidersW(&len, 0) == SOCKET_ERROR && WSAGetLastError() == WSAEFAULT && len > sizeof ns[0], "WSAEnumNameSpaceProvidersW sizes its answer");
    len = sizeof ns;
    CHECK(WSAEnumNameSpaceProvidersW(&len, ns) == 1 && ns[0].dwNameSpace == NS_DNS && ns[0].fActive && ns[0].lpszIdentifier && ns[0].lpszIdentifier[0],
          "one active namespace provider: DNS");
}

static void test_rnr(void)
{
    WSAQUERYSETW q, *r;
    HANDLE h = 0;
    BYTE buf[1024];
    DWORD len = 0;
    GUID cls = svcid_hostname;
    memset(&q, 0, sizeof q);
    q.dwSize = sizeof q;
    q.dwNameSpace = NS_ALL;
    q.lpServiceClassId = &cls;
    q.lpszServiceInstanceName = W("localhost");
    CHECK(WSALookupServiceBeginW(&q, LUP_RETURN_NAME | LUP_RETURN_ADDR | LUP_RETURN_BLOB, &h) == 0 && h, "WSALookupServiceBeginW(SVCID_HOSTNAME, localhost)");
    CHECK(WSALookupServiceNextW(h, 0, &len, 0) == SOCKET_ERROR && WSAGetLastError() == WSAEFAULT && len > sizeof q, "WSALookupServiceNextW sizes the result");
    r = (WSAQUERYSETW *)buf;
    len = sizeof buf;
    CHECK(WSALookupServiceNextW(h, 0, &len, r) == 0, "WSALookupServiceNextW");
    CHECK(r->lpszServiceInstanceName && !memcmp(r->lpszServiceInstanceName, W("localhost"), 20), "the result names the host");
    CHECK(r->dwNumberOfCsAddrs == 1 && ((struct sockaddr_in *)r->lpcsaBuffer[0].RemoteAddr.lpSockaddr)->sin_addr.s_addr == LO,
          "CSADDR_INFO: localhost is 127.0.0.1");
    if (r->lpBlob && r->lpBlob->pBlobData) {
        const BYTE *hb = r->lpBlob->pBlobData;
        const ULONG_PTR list = *(const ULONG_PTR *)(hb + 24), first = *(const ULONG_PTR *)(hb + list);
        CHECK(*(const short *)(hb + 16) == AF_INET && *(const short *)(hb + 18) == 4 && *(const u_long *)(hb + first) == LO &&
              !strcmp((const char *)hb + *(const ULONG_PTR *)hb, "localhost"), "the hostent blob (offsets relative to the blob)");
    } else {
        CHECK(0, "LUP_RETURN_BLOB returned a hostent blob");
    }
    len = sizeof buf;
    CHECK(WSALookupServiceNextW(h, 0, &len, r) == SOCKET_ERROR && WSAGetLastError() == WSA_E_NO_MORE, "the next call is WSA_E_NO_MORE");
    CHECK(WSALookupServiceEnd(h) == 0, "WSALookupServiceEnd");
    CHECK(WSALookupServiceEnd(h) == SOCKET_ERROR && WSAGetLastError() == WSA_INVALID_HANDLE, "ending twice is WSA_INVALID_HANDLE");
    q.dwNameSpace = NS_NLA;
    cls = svcid_nla;
    CHECK(WSALookupServiceBeginW(&q, LUP_RETURN_ALL, &h) == SOCKET_ERROR && WSAGetLastError() == WSASERVICE_NOT_FOUND, "the NLA namespace has no provider");
    q.dwNameSpace = NS_DNS;
    cls = svcid_hostname;
    cls.Data1 = 0x0002a801;                               /* SVCID_INET_HOSTADDRBYINETSTRING: numeric addresses only */
    q.lpszServiceInstanceName = W("not.an.address");
    CHECK(WSALookupServiceBeginW(&q, LUP_RETURN_ADDR, &h) == SOCKET_ERROR && WSAGetLastError() == WSAHOST_NOT_FOUND,
          "HOSTADDRBYINETSTRING with a name that is no address is WSAHOST_NOT_FOUND");
    cls = svcid_hostname;
    q.lpszServiceInstanceName = W("myservice");
    CHECK(WSASetServiceW(&q, RNRSERVICE_REGISTER, 0) == SOCKET_ERROR && WSAGetLastError() == WSAEOPNOTSUPP, "the DNS namespace cannot register services");
    CHECK(WSASetServiceW(&q, (WSAESETSERVICEOP)9, 0) == SOCKET_ERROR && WSAGetLastError() == WSAEINVAL, "an unknown operation is WSAEINVAL");
}

static void test_getaddrinfoex(void)
{
    ADDRINFOEXW hints, *res = 0;
    OVERLAPPED ov;
    HANDLE cancel = 0;
    int rc;
    memset(&hints, 0, sizeof hints);
    hints.ai_family = AF_INET;
    hints.ai_socktype = SOCK_STREAM;
    rc = GetAddrInfoExW(W("127.0.0.1"), W("80"), NS_ALL, 0, &hints, &res, 0, 0, 0, 0);
    CHECK(rc == 0 && res && res->ai_family == AF_INET && res->ai_protocol == IPPROTO_TCP && res->ai_addrlen == sizeof(struct sockaddr_in) &&
          ((struct sockaddr_in *)res->ai_addr)->sin_addr.s_addr == LO && ntohs(((struct sockaddr_in *)res->ai_addr)->sin_port) == 80 && !res->ai_next,
          "GetAddrInfoExW(127.0.0.1, 80): one TCP address");
    CHECK(res && res->ai_provider != 0, "the answer names its namespace provider");
    FreeAddrInfoExW(res);
    res = 0;
    CHECK(GetAddrInfoExW(W("localhost"), 0, NS_DNS, 0, 0, &res, 0, 0, 0, 0) == 0 && res && ((struct sockaddr_in *)res->ai_addr)->sin_addr.s_addr == LO,
          "GetAddrInfoExW(localhost) in the DNS namespace");
    FreeAddrInfoExW(res);
    res = 0;
    CHECK(GetAddrInfoExW(W("localhost"), 0, NS_NLA, 0, 0, &res, 0, 0, 0, 0) == WSAEINVAL, "a namespace without a provider is WSAEINVAL");
    hints.ai_next = &hints;
    CHECK(GetAddrInfoExW(W("localhost"), 0, NS_ALL, 0, &hints, &res, 0, 0, 0, 0) == WSAEINVAL, "hints with ai_next set are WSAEINVAL");
    hints.ai_next = 0;

    memset(&ov, 0, sizeof ov);
    ov.hEvent = CreateEventW(0, TRUE, FALSE, 0);
    rc = GetAddrInfoExW(W("localhost"), W("443"), NS_ALL, 0, &hints, &res, 0, &ov, 0, &cancel);
    CHECK(rc == WSA_IO_PENDING && cancel, "an OVERLAPPED request is pending and has a cancel handle");
    CHECK(WaitForSingleObject(ov.hEvent, 10000) == WAIT_OBJECT_0, "its event is signalled on completion");
    CHECK(GetAddrInfoExOverlappedResult(&ov) == 0 && res && ntohs(((struct sockaddr_in *)res->ai_addr)->sin_port) == 443, "... with the result stored");
    CHECK(GetAddrInfoExCancel(&cancel) == WSA_INVALID_HANDLE, "a completed request can no longer be cancelled");
    FreeAddrInfoExW(res);
    res = 0;
    CHECK(GetAddrInfoExW(W("localhost"), 0, NS_ALL, 0, 0, &res, 0, &ov, (LPLOOKUPSERVICE_COMPLETION_ROUTINE)test_getaddrinfoex, 0) == WSAEOPNOTSUPP,
          "a completion routine (an APC) is WSAEOPNOTSUPP");
    CloseHandle(ov.hEvent);
}

static void test_duplicate_overlapped(void)
{
    SOCKET s = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP), d;
    struct sockaddr_in a, b;
    int la = sizeof a, lb = sizeof b;
    WSAPROTOCOL_INFOW pi;
    WSAOVERLAPPED ov;
    DWORD got = 0, fl = 9;
    memset(&a, 0, sizeof a);
    a.sin_family = AF_INET;
    a.sin_addr.s_addr = LO;
    CHECK(s != INVALID_SOCKET && bind(s, (struct sockaddr *)&a, sizeof a) == 0 && getsockname(s, (struct sockaddr *)&a, &la) == 0, "a bound UDP socket");
    CHECK(WSADuplicateSocketW(s, GetCurrentProcessId(), &pi) == 0 && pi.iSocketType == SOCK_DGRAM && pi.iProtocol == IPPROTO_UDP,
          "WSADuplicateSocketW describes the socket");
    d = WSASocketW(FROM_PROTOCOL_INFO, FROM_PROTOCOL_INFO, FROM_PROTOCOL_INFO, &pi, 0, 0);
    CHECK(d != INVALID_SOCKET && d != s && getsockname(d, (struct sockaddr *)&b, &lb) == 0 && b.sin_port == a.sin_port,
          "WSASocketW(FROM_PROTOCOL_INFO) opens the same socket (same bound port)");
    CHECK(WSADuplicateSocketW(s, 0x7ffffff0, &pi) == SOCKET_ERROR && WSAGetLastError() == WSAEINVAL, "duplicating into another process is WSAEINVAL here");
    memset(&ov, 0, sizeof ov);
    ov.InternalHigh = 5;
    CHECK(WSAGetOverlappedResult(s, &ov, &got, FALSE, &fl) && got == 5, "WSAGetOverlappedResult of a completed request reports its byte count");
    ov.Internal = 0x103;                                  /* STATUS_PENDING */
    CHECK(!WSAGetOverlappedResult(s, &ov, &got, FALSE, &fl) && WSAGetLastError() == WSA_IO_INCOMPLETE, "a pending request is WSA_IO_INCOMPLETE");
    ov.Internal = 0;
    CHECK(!WSAGetOverlappedResult((SOCKET)GetCurrentProcess(), &ov, &got, FALSE, &fl), "a handle that is no socket fails");
    closesocket(d);
    closesocket(s);
}

int main(void)
{
    WSADATA wd;
    if (WSAStartup(MAKEWORD(2, 2), &wd)) { printf("FAIL: WSAStartup\n"); return 1; }
    test_catalog();
    test_rnr();
    test_getaddrinfoex();
    test_duplicate_overlapped();
    WSACleanup();
    printf("t_net_catalog: %s\n", g_bad ? "FAILED" : "all checks passed");
    return g_bad ? 1 : 0;
}
