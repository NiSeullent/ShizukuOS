/* SPDX-License-Identifier: GPL-2.0-only
 * Dedicated E1 name-info/hostname/RNG/profile contract test; no NIC or reverse-DNS service needed.
 * Expected values are literal addresses/ports and Microsoft Learn contracts, not the DLL's own formatting output.
 * E1_NETAPI_HOST is an isolated host harness: real function bodies, simulated OS dependencies, no guest claim.
 */
#ifdef E1_NETAPI_HOST
#include "e1_host.h"
#else
#define WIN32_LEAN_AND_MEAN
#include <winsock2.h>
#include <ws2tcpip.h>
#include <userenv.h>
#include <string.h>
#endif
#include "u_check.h"

#define COUNT(a) (sizeof(a) / sizeof((a)[0]))
typedef BOOLEAN (WINAPI *rng_fn)(PVOID, ULONG);

static void fill_w(WCHAR *p, unsigned n)
{
    unsigned i;
    for (i = 0; i < n; ++i) p[i] = 0x5a5a;
}
static int untouched_w(const WCHAR *p, unsigned n)
{
    unsigned i;
    for (i = 0; i < n; ++i) if (p[i] != 0x5a5a) return 0;
    return 1;
}
static unsigned wide_len(const WCHAR *p) { unsigned n = 0; while (p[n]) ++n; return n; }

static void nameinfo_error_case(const char *name, const SOCKADDR *sa, socklen_t len,
                                 WCHAR *host, DWORD hn, WCHAR *serv, DWORD sn, INT flags, INT want)
{
    INT rc;
    SetLastError(0);
    rc = GetNameInfoW(sa, len, host, hn, serv, sn, flags);
    U_CHECKF(name, rc == want && WSAGetLastError() == want, "return=%d error=%d expected=%d", rc, WSAGetLastError(), want);
}

static void nameinfo_tests(void)
{
    struct sockaddr_in v4;
    struct sockaddr_in6 v6;
    SOCKADDR unsupported;
    WCHAR host[80], serv[20];
    unsigned i;
    static const struct { const char *address, *expected; ULONG scope; } ips[] = {
        { "::", "::", 0 }, { "::1", "::1", 0 }, { "2001:db8::1234", "2001:db8::1234", 0 },
        { "::ffff:192.0.2.128", "::ffff:192.0.2.128", 0 }, { "fe80::1", "fe80::1%7", 7 },
        { "fe80::abcd", "fe80::abcd%4294967295", 0xffffffffu },
        { "1234:5678:9abc:def0:1234:5678:9abc:def0", "1234:5678:9abc:def0:1234:5678:9abc:def0", 0 }
    };
    memset(&v4, 0, sizeof v4);
    v4.sin_family = AF_INET;
    v4.sin_port = htons(443);
    /* Network-order bytes, independently of inet_pton/inet_addr in the DLL. */
    ((BYTE *)&v4.sin_addr)[0] = 192; ((BYTE *)&v4.sin_addr)[1] = 0;
    ((BYTE *)&v4.sin_addr)[2] = 2; ((BYTE *)&v4.sin_addr)[3] = 9;
    fill_w(host, COUNT(host)); fill_w(serv, COUNT(serv));
    U_CHECK("IPv4 numeric host and port", !GetNameInfoW((SOCKADDR *)&v4, sizeof v4, host, COUNT(host), serv, COUNT(serv),
              NI_NUMERICHOST | NI_NUMERICSERV) && u_wide_eq(host, L"192.0.2.9") && u_wide_eq(serv, L"443"));
    U_CHECK("numeric outputs terminate without overwriting guard", host[9] == 0 && host[10] == 0x5a5a && serv[3] == 0 && serv[4] == 0x5a5a);
    U_CHECK("IPv4 exact WCHAR capacities", !GetNameInfoW((SOCKADDR *)&v4, sizeof v4, host, 10, serv, 4, NI_NUMERICHOST | NI_NUMERICSERV));
    U_CHECK("default host is numeric fallback, service from table", !GetNameInfoW((SOCKADDR *)&v4, sizeof v4,
              host, COUNT(host), serv, COUNT(serv), 0) && u_wide_eq(host, L"192.0.2.9") && u_wide_eq(serv, L"https"));
    U_CHECK("NOFQDN does not invent reverse DNS", !GetNameInfoW((SOCKADDR *)&v4, sizeof v4, host, COUNT(host), 0, 0, NI_NOFQDN)
              && u_wide_eq(host, L"192.0.2.9"));
    nameinfo_error_case("no PTR backend with NAMEREQD", (SOCKADDR *)&v4, sizeof v4, host, COUNT(host), 0, 0, NI_NAMEREQD, WSAHOST_NOT_FOUND);
    U_CHECK("NUMERICHOST bypasses NAMEREQD lookup", !GetNameInfoW((SOCKADDR *)&v4, sizeof v4, host, COUNT(host), 0, 0,
              NI_NUMERICHOST | NI_NAMEREQD) && u_wide_eq(host, L"192.0.2.9"));
    U_CHECK("service-only ignores NAMEREQD", !GetNameInfoW((SOCKADDR *)&v4, sizeof v4, 0, 999, serv, COUNT(serv), NI_NAMEREQD)
              && u_wide_eq(serv, L"https"));
    U_CHECK("host-only ignores unused service size", !GetNameInfoW((SOCKADDR *)&v4, sizeof v4, host, COUNT(host), 0, 999, NI_NUMERICHOST));
    v4.sin_port = htons(513);
    U_CHECK("TCP service 513 is login", !GetNameInfoW((SOCKADDR *)&v4, sizeof v4, 0, 0, serv, COUNT(serv), 0) && u_wide_eq(serv, L"login"));
    U_CHECK("UDP service 513 is who", !GetNameInfoW((SOCKADDR *)&v4, sizeof v4, 0, 0, serv, COUNT(serv), NI_DGRAM) && u_wide_eq(serv, L"who"));
    U_CHECK("NUMERICSERV overrides UDP service name", !GetNameInfoW((SOCKADDR *)&v4, sizeof v4, 0, 0, serv, COUNT(serv), NI_DGRAM | NI_NUMERICSERV)
              && u_wide_eq(serv, L"513"));
    v4.sin_port = htons(65535);
    U_CHECK("unknown service falls back to maximum port", !GetNameInfoW((SOCKADDR *)&v4, sizeof v4, 0, 0, serv, COUNT(serv), 0)
              && u_wide_eq(serv, L"65535"));
    v4.sin_port = 0;
    U_CHECK("zero port is numeric zero", !GetNameInfoW((SOCKADDR *)&v4, sizeof v4, 0, 0, serv, 2, NI_NUMERICSERV) && u_wide_eq(serv, L"0"));
    v4.sin_port = htons(443);
    nameinfo_error_case("null sockaddr", 0, sizeof v4, host, COUNT(host), 0, 0, 0, WSAEFAULT);
    nameinfo_error_case("sockaddr length zero", (SOCKADDR *)&v4, 0, host, COUNT(host), 0, 0, 0, WSAEFAULT);
    nameinfo_error_case("sockaddr length negative", (SOCKADDR *)&v4, -1, host, COUNT(host), 0, 0, 0, WSAEFAULT);
    nameinfo_error_case("truncated IPv4 sockaddr", (SOCKADDR *)&v4, sizeof v4 - 1, host, COUNT(host), 0, 0, 0, WSAEFAULT);
    memset(&unsupported, 0, sizeof unsupported); unsupported.sa_family = AF_UNSPEC;
    nameinfo_error_case("unsupported family", &unsupported, sizeof unsupported, host, COUNT(host), 0, 0, 0, WSAEAFNOSUPPORT);
    nameinfo_error_case("unknown flags", (SOCKADDR *)&v4, sizeof v4, host, COUNT(host), 0, 0, 0x40000000, WSAEINVAL);
    nameinfo_error_case("no output requested", (SOCKADDR *)&v4, sizeof v4, 0, 0, 0, 0, 0, WSAHOST_NOT_FOUND);
    nameinfo_error_case("requested host has zero capacity", (SOCKADDR *)&v4, sizeof v4, host, 0, serv, COUNT(serv), 0, WSAEINVAL);
    nameinfo_error_case("requested service has zero capacity", (SOCKADDR *)&v4, sizeof v4, host, COUNT(host), serv, 0, 0, WSAEINVAL);
    fill_w(host, COUNT(host)); fill_w(serv, COUNT(serv));
    nameinfo_error_case("host one WCHAR short", (SOCKADDR *)&v4, sizeof v4, host, 9, serv, COUNT(serv), NI_NUMERICSERV, WSAEFAULT);
    U_CHECK("short host leaves both buffers intact", untouched_w(host, COUNT(host)) && untouched_w(serv, COUNT(serv)));
    nameinfo_error_case("service one WCHAR short", (SOCKADDR *)&v4, sizeof v4, host, COUNT(host), serv, 3, NI_NUMERICSERV, WSAEFAULT);
    U_CHECK("short service leaves both buffers intact", untouched_w(host, COUNT(host)) && untouched_w(serv, COUNT(serv)));
    for (i = 0; i < COUNT(ips); ++i) {
        memset(&v6, 0, sizeof v6); v6.sin6_family = AF_INET6; v6.sin6_port = htons(65535); v6.sin6_scope_id = ips[i].scope;
        U_CHECKF("IPv6 test input parses", InetPtonW(AF_INET6, u_wide(ips[i].address, host, COUNT(host)), &v6.sin6_addr) == 1, "case=%u", i);
        fill_w(host, COUNT(host)); fill_w(serv, COUNT(serv));
        U_CHECKF("IPv6 numeric host, scope and service", !GetNameInfoW((SOCKADDR *)&v6, sizeof v6, host, COUNT(host), serv, COUNT(serv),
                  NI_NUMERICHOST | NI_NUMERICSERV) && u_ascii_eq_w(host, ips[i].expected) && u_wide_eq(serv, L"65535"), "case=%u", i);
        U_CHECK("IPv6 exact host capacity", !GetNameInfoW((SOCKADDR *)&v6, sizeof v6, host, (DWORD)strlen(ips[i].expected) + 1, 0, 0, NI_NUMERICHOST));
        fill_w(host, COUNT(host));
        nameinfo_error_case("IPv6 one WCHAR short", (SOCKADDR *)&v6, sizeof v6, host, (DWORD)strlen(ips[i].expected), 0, 0, NI_NUMERICHOST, WSAEFAULT);
        U_CHECK("IPv6 short buffer remains intact", untouched_w(host, COUNT(host)));
    }
    nameinfo_error_case("truncated IPv6 sockaddr", (SOCKADDR *)&v6, sizeof v6 - 1, host, COUNT(host), 0, 0, 0, WSAEFAULT);
    nameinfo_error_case("IPv6 NAMEREQD fails honestly", (SOCKADDR *)&v6, sizeof v6, host, COUNT(host), 0, 0, NI_NAMEREQD, WSAHOST_NOT_FOUND);
}

static void hostname_tests(void)
{
    char a[64];
    WCHAR w[64], computer[MAX_COMPUTERNAME_LENGTH + 1];
    DWORD n = COUNT(computer);
    unsigned len;
    fill_w(w, COUNT(w));
    U_CHECK("hostname A succeeds", !gethostname(a, COUNT(a)));
    U_CHECK("hostname W succeeds", !GetHostNameW(w, COUNT(w)));
    U_CHECK("hostname A/W share state", u_ascii_eq_w(w, a));
    U_CHECK("hostname matches computer name", GetComputerNameW(computer, &n) && u_wide_eq(w, computer));
    len = wide_len(w);
    U_CHECK("hostname exact capacity", !GetHostNameW(w, (int)len + 1));
    fill_w(w, COUNT(w));
    SetLastError(0);
    U_CHECK("hostname one WCHAR short", GetHostNameW(w, (int)len) == SOCKET_ERROR && WSAGetLastError() == WSAEFAULT);
    U_CHECK("hostname short buffer intact", untouched_w(w, COUNT(w)));
    SetLastError(0); U_CHECK("hostname null buffer", GetHostNameW(0, 64) == SOCKET_ERROR && WSAGetLastError() == WSAEFAULT);
    SetLastError(0); U_CHECK("hostname zero capacity", GetHostNameW(w, 0) == SOCKET_ERROR && WSAGetLastError() == WSAEFAULT);
    SetLastError(0); U_CHECK("hostname negative capacity", GetHostNameW(w, -1) == SOCKET_ERROR && WSAGetLastError() == WSAEFAULT);
}

static void profile_tests(void)
{
    static const WCHAR path[] = L"D:\\e1home\\profile";
    static const WCHAR unicode_path[] = L"D:\\e1home\\\x03a9\x00e9\x4e2d";
    WCHAR w[80], *saved = 0;
    char a[240], expected[240];
    HANDLE token = 0, no_query = 0, event;
    DWORD n, old_size;
    int bytes;
    BOOL ok;
    old_size = GetEnvironmentVariableW(L"USERPROFILE", 0, 0);
    if (old_size) {
        saved = malloc(old_size * sizeof *saved);
        U_CHECK("allocate original USERPROFILE", saved != 0);
        if (!saved) return;
        if (!GetEnvironmentVariableW(L"USERPROFILE", saved, old_size)) { free(saved); U_CHECK("snapshot original USERPROFILE", 0); return; }
    }
    ok = OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &token);
    U_CHECK("open query token", ok);
    if (!ok) { free(saved); return; }
    U_CHECK("set profile fixture", SetEnvironmentVariableW(L"USERPROFILE", path));
    n = 0; SetLastError(0);
    U_CHECK("profile W size query", !GetUserProfileDirectoryW(token, 0, &n) && GetLastError() == ERROR_INSUFFICIENT_BUFFER && n == COUNT(path));
    fill_w(w, COUNT(w)); n = COUNT(path) - 1; SetLastError(0);
    U_CHECK("profile W one WCHAR short", !GetUserProfileDirectoryW(token, w, &n) && GetLastError() == ERROR_INSUFFICIENT_BUFFER && n == COUNT(path));
    U_CHECK("profile W short output intact", untouched_w(w, COUNT(w)));
    n = COUNT(path); U_CHECK("profile W exact capacity and returned size", GetUserProfileDirectoryW(token, w, &n)
              && n == COUNT(path) && u_wide_eq(w, path) && w[COUNT(path)] == 0x5a5a);
    n = COUNT(w); U_CHECK("profile W oversized capacity reports written size", GetUserProfileDirectoryW(token, w, &n) && n == COUNT(path));
    n = 0; SetLastError(0);
    U_CHECK("profile A size query", !GetUserProfileDirectoryA(token, 0, &n) && GetLastError() == ERROR_INSUFFICIENT_BUFFER && n == COUNT(path));
    memset(a, 0x5a, sizeof a); n = COUNT(path) - 1; SetLastError(0);
    U_CHECK("profile A short capacity", !GetUserProfileDirectoryA(token, a, &n) && GetLastError() == ERROR_INSUFFICIENT_BUFFER && n == COUNT(path));
    U_CHECK("profile A short output intact", a[0] == 0x5a && a[COUNT(path) - 1] == 0x5a);
    n = COUNT(path); U_CHECK("profile A exact capacity", GetUserProfileDirectoryA(token, a, &n) && n == COUNT(path)
              && u_ascii_eq_w(path, a) && a[COUNT(path)] == 0x5a);
    SetLastError(0); U_CHECK("profile W missing size pointer", !GetUserProfileDirectoryW(token, w, 0) && GetLastError() == ERROR_INVALID_PARAMETER);
    SetLastError(0); U_CHECK("profile A missing size pointer", !GetUserProfileDirectoryA(token, a, 0) && GetLastError() == ERROR_INVALID_PARAMETER);
    n = COUNT(w); SetLastError(0); U_CHECK("profile rejects null token", !GetUserProfileDirectoryW(0, w, &n) && GetLastError() == ERROR_INVALID_HANDLE);
    n = COUNT(a); SetLastError(0); U_CHECK("profile A rejects invalid token", !GetUserProfileDirectoryA(INVALID_HANDLE_VALUE, a, &n) && GetLastError() == ERROR_INVALID_HANDLE);
    event = CreateEventW(0, TRUE, FALSE, 0);
    U_CHECK("allocate wrong-type handle", event != 0);
    if (event) { n = COUNT(w); U_CHECK("profile rejects event handle", !GetUserProfileDirectoryW(event, w, &n)); CloseHandle(event); }
    ok = OpenProcessToken(GetCurrentProcess(), TOKEN_DUPLICATE, &no_query);
    U_CHECK("open token without TOKEN_QUERY", ok);
    if (ok) {
        n = COUNT(w); SetLastError(0);
        U_CHECK("profile enforces TOKEN_QUERY", !GetUserProfileDirectoryW(no_query, w, &n) && GetLastError() == ERROR_ACCESS_DENIED);
        CloseHandle(no_query);
    }
    U_CHECK("set Unicode profile fixture", SetEnvironmentVariableW(L"USERPROFILE", unicode_path));
    n = COUNT(w); U_CHECK("profile W preserves UTF-16", GetUserProfileDirectoryW(token, w, &n) && n == COUNT(unicode_path) && u_wide_eq(w, unicode_path));
    bytes = WideCharToMultiByte(CP_ACP, 0, unicode_path, -1, expected, sizeof expected, 0, 0);
    U_CHECK("independent ACP expected buffer", bytes > 0);
    n = COUNT(a); U_CHECK("profile A uses ACP conversion and byte count", bytes > 0 && GetUserProfileDirectoryA(token, a, &n)
              && n == (DWORD)bytes && !memcmp(a, expected, (size_t)bytes));
    U_CHECK("remove profile fixture", SetEnvironmentVariableW(L"USERPROFILE", 0));
    fill_w(w, COUNT(w)); n = COUNT(w); SetLastError(0);
    U_CHECK("missing profile W fails honestly", !GetUserProfileDirectoryW(token, w, &n) && GetLastError() == ERROR_FILE_NOT_FOUND
              && n == COUNT(w) && untouched_w(w, COUNT(w)));
    n = COUNT(a); SetLastError(0); U_CHECK("missing profile A fails honestly", !GetUserProfileDirectoryA(token, a, &n) && GetLastError() == ERROR_FILE_NOT_FOUND);
    n = 0; SetLastError(0); U_CHECK("missing profile size query does not invent path", !GetUserProfileDirectoryW(token, 0, &n) && GetLastError() == ERROR_FILE_NOT_FOUND && !n);
    U_CHECK("set empty profile fixture", SetEnvironmentVariableW(L"USERPROFILE", L""));
    n = COUNT(w); SetLastError(0); U_CHECK("empty profile fails honestly", !GetUserProfileDirectoryW(token, w, &n) && GetLastError() == ERROR_FILE_NOT_FOUND);
    U_CHECK("restore USERPROFILE", SetEnvironmentVariableW(L"USERPROFILE", saved));
    free(saved); CloseHandle(token);
}

static void rng_tests(void)
{
    HMODULE module = LoadLibraryW(L"advapi32.dll");
    rng_fn rng = module ? (rng_fn)GetProcAddress(module, "SystemFunction036") : 0;
    BYTE a[66], b[64], *large;
    BOOL ok;
    unsigned i;
    const ULONG big = (1u << 20) + 17; /* exercises shz_rand's 1 MiB call boundary */
    U_CHECK("advapi32 named SystemFunction036 export", rng != 0);
    if (!rng) { if (module) FreeLibrary(module); return; }
    memset(a, 0x5a, sizeof a);
    U_CHECK("RNG zero-length null succeeds", rng(0, 0));
    U_CHECK("RNG zero-length buffer untouched", rng(a, 0) && a[0] == 0x5a);
    SetLastError(0); U_CHECK("RNG null nonzero buffer fails", !rng(0, 1) && GetLastError() == ERROR_INVALID_PARAMETER);
    U_CHECK("RNG fills actual buffer", rng(a + 1, 64));
    U_CHECK("RNG writes only requested byte span", a[0] == 0x5a && a[65] == 0x5a);
    ok = rng(b, sizeof b);
    U_CHECK("RNG second call succeeds", ok);
    U_CHECK("RNG not constant/repeating output (smoke only)", ok && memcmp(a + 1, b, sizeof b) != 0);
    large = malloc(big + 2);
    U_CHECK("allocate RNG chunk boundary buffer", large != 0);
    if (large) {
        memset(large, 0x5a, big + 2);
        U_CHECK("RNG handles more than 1 MiB", rng(large + 1, big));
        U_CHECK("large RNG preserves guards", large[0] == 0x5a && large[big + 1] == 0x5a);
        for (i = 1; i <= big && large[i] == 0x5a; ++i) { }
        U_CHECK("large RNG is not a success-shaped no-op", i <= big);
        free(large);
    }
    /* Kernel64 validates user pages; this checks error propagation, not a write through an invalid pointer. */
    U_CHECK("RNG inaccessible buffer fails", !rng((PVOID)(ULONG_PTR)1, 1));
    FreeLibrary(module);
}

int main(void)
{
    WSADATA data;
    struct sockaddr_in sa;
    WCHAR w[80];
    memset(&sa, 0, sizeof sa); sa.sin_family = AF_INET;
    nameinfo_error_case("GetNameInfoW requires WSAStartup", (SOCKADDR *)&sa, sizeof sa, w, COUNT(w), 0, 0, NI_NUMERICHOST, WSANOTINITIALISED);
    SetLastError(0); U_CHECK("GetHostNameW requires WSAStartup", GetHostNameW(w, COUNT(w)) == SOCKET_ERROR && WSAGetLastError() == WSANOTINITIALISED);
    U_CHECK("WSAStartup", WSAStartup(MAKEWORD(2, 2), &data) == 0);
    nameinfo_tests(); hostname_tests(); profile_tests(); rng_tests();
    U_CHECK("WSACleanup", !WSACleanup());
    SetLastError(0); U_CHECK("GetHostNameW after cleanup fails", GetHostNameW(w, COUNT(w)) == SOCKET_ERROR && WSAGetLastError() == WSANOTINITIALISED);
    nameinfo_error_case("GetNameInfoW after cleanup fails", (SOCKADDR *)&sa, sizeof sa, w, COUNT(w), 0, 0, NI_NUMERICHOST, WSANOTINITIALISED);
    return u_finish("T_E1_NETAPI");
}
