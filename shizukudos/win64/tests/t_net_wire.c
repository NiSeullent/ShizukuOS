/* SPDX-License-Identifier: GPL-2.0-only
 * Winsock over the real (emulated) wire: RTL8139 -> QEMU user-mode networking (SLIRP) -> servers that
 * tests/run_k64_net.py runs on the host, reached as 10.0.2.2:
 *     17000 mode banner   17001 TCP echo   17002 TCP sink (CRC + count reply)   17003 TCP source (seeded byte stream)
 *     17004 TCP control (CLOSE / RESET / HOLD / HALF)   17005 UDP echo   17006 blackholed by the lossy proxy
 *     17053 DNS test server   17999 nothing listens
 * The guest prints machine-readable "WIRE ..." lines; the runner recomputes the same data on the host and compares byte
 * counts and digests, and cross-checks TCP/IP checksums and retransmissions in QEMU's own packet capture.
 * Exits 0 with "SKIP: no NIC" when no RTL8139 is present (plain standalone runner). */
#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include "nettest.h"

#define HOST_BE ((u_long)0x0202000a)                    /* 10.0.2.2 */
static int g_lossy;

static void addr_of(struct sockaddr_in *a, u_long ip_be, unsigned short port)
{
    memset(a, 0, sizeof *a);
    a->sin_family = AF_INET;
    a->sin_port = htons(port);
    a->sin_addr.s_addr = ip_be;
}
static SOCKET tcp_to(unsigned short port, int *err)
{
    struct sockaddr_in a;
    SOCKET s = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    addr_of(&a, HOST_BE, port);
    if (s == INVALID_SOCKET) { *err = WSAGetLastError(); return s; }
    if (connect(s, (struct sockaddr *)&a, sizeof a)) { *err = WSAGetLastError(); closesocket(s); return INVALID_SOCKET; }
    *err = 0;
    return s;
}
static int read_line(SOCKET s, char *buf, int cap)
{
    int n = 0;
    while (n + 1 < cap) {
        char c;
        int r = recv(s, &c, 1, 0);
        if (r <= 0) break;
        buf[n++] = c;
        if (c == '\n') break;
    }
    buf[n] = 0;
    return n;
}

static void test_mode(void)
{
    int err;
    char line[64];
    SOCKET s = tcp_to(17000, &err);
    CHECK(s != INVALID_SOCKET, "connected to the host mode server 10.0.2.2:17000 (SLIRP host alias) err=%d", err);
    if (s == INVALID_SOCKET) { printf("FAIL: cannot reach the host servers; is the runner active?\n"); ExitProcess(1); }
    read_line(s, line, sizeof line);
    closesocket(s);
    g_lossy = strlen(line) >= 10 && !memcmp(line, "MODE lossy", 10);
    printf("WIRE mode=%s\n", g_lossy ? "lossy" : "direct");
}

static void test_ping(const struct shz_net_info *in)
{
    ULONG rtt = 0;
    NTSTATUS st = NtShzNetPing(in->gw_be, (0x5150ull << 16) | 1, 56, 3000, &rtt);
    CHECK(st == 0, "ICMP echo to the gateway 10.0.2.2 (rtt %u ms)", (unsigned)rtt);
    st = NtShzNetPing(in->dns0_be, (0x5150ull << 16) | 2, 56, 3000, &rtt);
    CHECK(st == 0, "ICMP echo to the DNS server (ARP + echo, rtt %u ms)", (unsigned)rtt);
}

static void test_echo(void)
{
    static const int sizes[] = {1, 100, 1459, 1460, 1461, 2920, 5000, 65535, 70000};
    int err, i, ok = 1;
    SOCKET s = tcp_to(17001, &err);
    unsigned char *out = xmalloc(70000), *in = xmalloc(70000);
    CHECK(s != INVALID_SOCKET, "TCP connect to the host echo server (err %d)", err);
    for (i = 0; s != INVALID_SOCKET && i < (int)(sizeof sizes / sizeof sizes[0]); ++i) {
        fill_pat(out, (size_t)sizes[i], (unsigned long long)i * 1000);
        if (send_all(s, out, sizes[i]) != sizes[i] || recv_all(s, in, sizes[i]) != sizes[i] || memcmp(in, out, (size_t)sizes[i])) {
            printf("FAIL: echo of %d bytes\n", sizes[i]);
            ok = 0;
            ++g_bad;
        }
    }
    CHECK(ok, "echo round trips of 1..70000 bytes (MSS boundaries 1459/1460/1461, window sized) all intact");
    closesocket(s);
    free(out); free(in);
}

static void test_upload(void)
{
    const int n = 1536 * 1024;
    int err;
    SOCKET s = tcp_to(17002, &err);
    unsigned char *data = xmalloc((size_t)n);
    unsigned resp[2] = {0, 0}, crc;
    DWORD t0 = GetTickCount();
    fill_pat(data, (size_t)n, 5000000);
    crc = shz_crc32(data, (size_t)n);
    CHECK(s != INVALID_SOCKET, "TCP connect to the host sink server");
    CHECK(send_all(s, data, n) == n, "uploaded %d bytes (1.5 MiB)", n);
    shutdown(s, SD_SEND);
    CHECK(recv_all(s, resp, 8) == 8, "sink replied with its CRC32 and byte count");
    printf("WIRE upload n=%d start=5000000 crc=%08x server_crc=%08x server_n=%u ms=%u\n", n, crc, resp[0], resp[1], (unsigned)(GetTickCount() - t0));
    CHECK(resp[0] == crc && resp[1] == (unsigned)n, "host CRC32 %08x and count %u match ours (%08x, %d)", resp[0], resp[1], crc, n);
    closesocket(s);
    free(data);
}

static void test_download(void)
{
    const unsigned n = 1536 * 1024, seed = 4242;
    int err;
    SOCKET s = tcp_to(17003, &err);
    unsigned char *buf = xmalloc(65536);
    unsigned req[3] = {n, seed, 0}, got = 0, crc = 0xffffffffu, i, b;
    DWORD t0 = GetTickCount();
    CHECK(s != INVALID_SOCKET, "TCP connect to the host source server");
    CHECK(send_all(s, req, 12) == 12, "sent the request (%u bytes, seed %u)", n, seed);
    for (;;) {
        int r = recv(s, (char *)buf, 65536, 0);
        if (r <= 0) break;
        for (i = 0; i < (unsigned)r; ++i) {                 /* streaming CRC32 (same polynomial as shz_crc32) */
            crc ^= buf[i];
            for (b = 0; b < 8; ++b) crc = (crc >> 1) ^ (0xedb88320u & (0u - (crc & 1u)));
        }
        got += (unsigned)r;
    }
    crc = ~crc;
    printf("WIRE download n=%u seed=%u got=%u crc=%08x ms=%u\n", n, seed, got, crc, (unsigned)(GetTickCount() - t0));
    CHECK(got == n, "downloaded %u of %u bytes and saw the server's FIN", got, n);
    closesocket(s);
    free(buf);
}

static void test_errors(void)
{
    int err, r;
    char b[32];
    DWORD to = 600, t0;
    SOCKET s;
    t0 = GetTickCount();
    s = tcp_to(17999, &err);
    CHECK(s == INVALID_SOCKET && err == WSAECONNREFUSED, "connect to a closed port on the host fails with WSAECONNREFUSED (10061), got %d after %u ms", err, (unsigned)(GetTickCount() - t0));
    s = tcp_to(17004, &err);
    send(s, "CLOSE\n", 6, 0);
    r = recv(s, b, sizeof b, 0);
    CHECK(r == 0, "server-side close is seen as an orderly EOF (recv == 0), got %d", r);
    r = send(s, "late", 4, 0);
    if (r == 4) r = send(s, "later", 5, 0);                  /* the first send after the peer's FIN may still be accepted; the RST it draws fails the next */
    Sleep(200);
    r = send(s, "latest", 6, 0);
    CHECK(r == SOCKET_ERROR || r == 6, "send after the peer closed does not hang (result %d, err %d)", r, WSAGetLastError());
    closesocket(s);
    s = tcp_to(17004, &err);
    send(s, "RESET\n", 6, 0);
    r = recv(s, b, sizeof b, 0);
    CHECK(r == SOCKET_ERROR && WSAGetLastError() == WSAECONNRESET, "server-side RST is reported as WSAECONNRESET (10054), got r=%d err=%d", r, WSAGetLastError());
    closesocket(s);
    s = tcp_to(17004, &err);
    send(s, "HOLD\n", 5, 0);
    setsockopt(s, SOL_SOCKET, SO_RCVTIMEO, (const char *)&to, sizeof to);
    t0 = GetTickCount();
    r = recv(s, b, sizeof b, 0);
    CHECK(r == SOCKET_ERROR && WSAGetLastError() == WSAETIMEDOUT && GetTickCount() - t0 >= 550 && GetTickCount() - t0 < 3000,
          "recv on a silent server times out with WSAETIMEDOUT after %u ms (SO_RCVTIMEO 600)", (unsigned)(GetTickCount() - t0));
    closesocket(s);
}

static void test_half_close(void)
{
    int err, r;
    char reply[64];
    unsigned char data[1000];
    SOCKET s = tcp_to(17004, &err);
    fill_pat(data, sizeof data, 0);
    send(s, "HALF\n", 5, 0);
    CHECK(send_all(s, data, 1000) == 1000, "half-close: 1000 bytes sent to the server");
    CHECK(shutdown(s, SD_SEND) == 0, "half-close: shutdown(SD_SEND) sends our FIN through SLIRP");
    r = read_line(s, reply, sizeof reply);
    CHECK(r > 0 && !memcmp(reply, "HALF-OK 1000", 12), "half-close: the server saw EOF after exactly 1000 bytes and its reply still arrives ('%.*s')", r > 0 ? r - 1 : 0, reply);
    CHECK(recv(s, reply, 1, 0) == 0, "half-close: then the server's FIN (recv == 0)");
    closesocket(s);
}

static void test_many(void)
{
    enum { N = 64 };
    SOCKET s[N];
    int i, err, up = 0, good = 0;
    for (i = 0; i < N; ++i) { s[i] = tcp_to(17001, &err); if (s[i] != INVALID_SOCKET) ++up; }
    CHECK(up == N, "%d simultaneous TCP connections through SLIRP established", up);
    for (i = 0; i < N; ++i) {
        char out[100], in[100];
        int k;
        if (s[i] == INVALID_SOCKET) continue;
        for (k = 0; k < 100; ++k) out[k] = (char)pat((unsigned)(i * 100 + k));
        if (send_all(s[i], out, 100) == 100) { if (recv_all(s[i], in, 100) == 100 && !memcmp(in, out, 100)) ++good; }
    }
    CHECK(good == N, "each of the %d connections echoed its own 100 bytes", good);
    for (i = 0; i < N; ++i) if (s[i] != INVALID_SOCKET) closesocket(s[i]);
}

/* 512 KiB upload to a port on which the lossy proxy imposes a total outage in the middle of the transfer (all frames dropped for
 * 2.5 s): the sender must back off exponentially, then resume and deliver every byte. In the direct boot there is no outage. */
static void test_outage(void)
{
    const int n = 512 * 1024;
    int err;
    SOCKET s = tcp_to(17007, &err);
    unsigned char *data = xmalloc((size_t)n);
    unsigned resp[2] = {0, 0}, crc;
    DWORD t0 = GetTickCount();
    ULONG r0 = net_stat(NST_TCP_RETRANS);
    fill_pat(data, (size_t)n, 9000000);
    crc = shz_crc32(data, (size_t)n);
    CHECK(s != INVALID_SOCKET, "connect to the outage port");
    CHECK(send_all(s, data, n) == n, "uploaded %d bytes across the outage", n);
    shutdown(s, SD_SEND);
    CHECK(recv_all(s, resp, 8) == 8, "sink replied after the outage");
    printf("WIRE outage_upload n=%d start=9000000 crc=%08x server_crc=%08x server_n=%u ms=%u retrans=%u\n", n, crc, resp[0], resp[1],
           (unsigned)(GetTickCount() - t0), (unsigned)(net_stat(NST_TCP_RETRANS) - r0));
    CHECK(resp[0] == crc && resp[1] == (unsigned)n, "all %d bytes arrived intact (CRC %08x)", n, crc);
    closesocket(s);
    free(data);
}

static void test_keepalive(void)
{
    int err, on = 1, idle = 1, intvl = 1;
    SOCKET s = tcp_to(17001, &err);
    struct sockaddr_in la;
    int ll = sizeof la;
    char b[16];
    ULONG k0 = net_stat(NST_TCP_KEEPALIVE_TX);
    CHECK(s != INVALID_SOCKET, "keepalive test connection");
    getsockname(s, (struct sockaddr *)&la, &ll);
    CHECK(setsockopt(s, SOL_SOCKET, SO_KEEPALIVE, (const char *)&on, sizeof on) == 0 && setsockopt(s, IPPROTO_TCP, 3, (const char *)&idle, sizeof idle) == 0 &&
          setsockopt(s, IPPROTO_TCP, 17, (const char *)&intvl, sizeof intvl) == 0, "SO_KEEPALIVE with TCP_KEEPIDLE=1 s and TCP_KEEPINTVL=1 s");
    send_all(s, "0123456789", 10);
    recv_all(s, b, 10);
    Sleep(3600);
    printf("WIRE keepalive sport=%u probes=%u\n", ntohs(la.sin_port), (unsigned)(net_stat(NST_TCP_KEEPALIVE_TX) - k0));
    CHECK(net_stat(NST_TCP_KEEPALIVE_TX) - k0 >= 2, "an idle connection sent %u keep-alive probes in 3.6 s", (unsigned)(net_stat(NST_TCP_KEEPALIVE_TX) - k0));
    CHECK(send_all(s, "after", 5) == 5 && recv_all(s, b, 5) == 5 && !memcmp(b, "after", 5), "the connection is still usable after the probes were answered");
    closesocket(s);
}

static void test_udp(void)
{
    static const int sizes[] = {1, 100, 1472, 1473, 4000, 9000};
    struct sockaddr_in to, from;
    SOCKET u = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP), u2 = socket(AF_INET, SOCK_DGRAM, 0);
    unsigned char *out = xmalloc(10000), *in = xmalloc(10000);
    int i, ok = 1, fl;
    DWORD tmo = 2000;
    ULONG frag_before = net_stat(NST_IP_FRAG_TX), reasm_before = net_stat(NST_IP_REASM);
    setsockopt(u, SOL_SOCKET, SO_RCVTIMEO, (const char *)&tmo, sizeof tmo);
    setsockopt(u2, SOL_SOCKET, SO_RCVTIMEO, (const char *)&tmo, sizeof tmo);
    addr_of(&to, HOST_BE, 17005);
    for (i = 0; i < (int)(sizeof sizes / sizeof sizes[0]); ++i) {
        int r;
        fill_pat(out, (size_t)sizes[i], (unsigned long long)i * 77);
        fl = sizeof from;
        if (sendto(u, (const char *)out, sizes[i], 0, (struct sockaddr *)&to, sizeof to) != sizes[i]) { ok = 0; printf("FAIL: sendto %d\n", sizes[i]); continue; }
        r = recvfrom(u, (char *)in, 10000, 0, (struct sockaddr *)&from, &fl);
        if (r != sizes[i] || memcmp(in, out, (size_t)sizes[i]) || from.sin_addr.s_addr != HOST_BE || ntohs(from.sin_port) != 17005) {
            ok = 0;
            printf("FAIL: udp echo of %d bytes returned %d (err %d)\n", sizes[i], r, WSAGetLastError());
        }
    }
    CHECK(ok, "UDP echo of 1..9000 bytes through SLIRP, sender address 10.0.2.2:17005 verified");
    CHECK(net_stat(NST_IP_FRAG_TX) > frag_before && net_stat(NST_IP_REASM) > reasm_before,
          "datagrams above the 1500-byte MTU were fragmented (%u fragments sent) and reassembled (%u datagrams) on the wire",
          (unsigned)(net_stat(NST_IP_FRAG_TX) - frag_before), (unsigned)(net_stat(NST_IP_REASM) - reasm_before));
    for (i = 0; i < 3; ++i) {                              /* interleaved traffic on two sockets */
        char a[8] = "A0", b[8] = "B0";
        char ra[16], rb[16];
        a[1] = (char)('0' + i); b[1] = (char)('0' + i);
        sendto(u, a, 2, 0, (struct sockaddr *)&to, sizeof to);
        sendto(u2, b, 2, 0, (struct sockaddr *)&to, sizeof to);
        if (recvfrom(u2, rb, sizeof rb, 0, 0, 0) != 2 || rb[0] != 'B' || recvfrom(u, ra, sizeof ra, 0, 0, 0) != 2 || ra[0] != 'A') ok = 0;
    }
    CHECK(ok, "two UDP sockets interleaved: each receives only its own echoes");
    closesocket(u); closesocket(u2);
    free(out); free(in);
}

static void test_nonblocking(void)
{
    struct sockaddr_in a;
    SOCKET s = socket(AF_INET, SOCK_STREAM, 0);
    u_long nb = 1;
    fd_set rd, wr;
    struct timeval tv;
    char buf[64];
    int r;
    DWORD t0 = GetTickCount();
    ioctlsocket(s, FIONBIO, &nb);
    addr_of(&a, HOST_BE, 17001);
    r = connect(s, (struct sockaddr *)&a, sizeof a);
    CHECK(r == SOCKET_ERROR && WSAGetLastError() == WSAEWOULDBLOCK, "non-blocking connect over the wire returns WSAEWOULDBLOCK");
    FD_ZERO(&wr); FD_SET(s, &wr); tv.tv_sec = 5; tv.tv_usec = 0;
    r = select(0, 0, &wr, 0, &tv);
    CHECK(r == 1 && FD_ISSET(s, &wr), "select() reports the connecting socket writable after the SYN/SYN-ACK/ACK exchange (%u ms)", (unsigned)(GetTickCount() - t0));
    send(s, "nonblocking-echo", 16, 0);
    FD_ZERO(&rd); FD_SET(s, &rd);
    r = select(0, &rd, 0, 0, &tv);
    CHECK(r == 1 && recv(s, buf, sizeof buf, 0) == 16 && !memcmp(buf, "nonblocking-echo", 16), "select() readable, recv returns the echoed 16 bytes");
    closesocket(s);
    /* non-blocking connect to a port nothing listens on: the RST arrives as an exceptional condition with WSAECONNREFUSED */
    s = socket(AF_INET, SOCK_STREAM, 0);
    ioctlsocket(s, FIONBIO, &nb);
    addr_of(&a, HOST_BE, 17999);
    connect(s, (struct sockaddr *)&a, sizeof a);
    { fd_set ex; int soerr = 0, sl = sizeof soerr;
      FD_ZERO(&wr); FD_ZERO(&ex); FD_SET(s, &wr); FD_SET(s, &ex);
      r = select(0, 0, &wr, &ex, &tv);
      getsockopt(s, SOL_SOCKET, SO_ERROR, (char *)&soerr, &sl);
      CHECK(r >= 1 && FD_ISSET(s, &ex) && !FD_ISSET(s, &wr) && soerr == WSAECONNREFUSED, "refused non-blocking connect lands in exceptfds with SO_ERROR == WSAECONNREFUSED (%d)", soerr); }
    closesocket(s);
}

static void print_addrs(const char *tag, const ULONG *a, unsigned n)
{
    unsigned i;
    printf("WIRE dns %s n=%u", tag, n);
    for (i = 0; i < n; ++i) {
        const unsigned char *b = (const unsigned char *)&a[i];
        printf(" %u.%u.%u.%u", b[0], b[1], b[2], b[3]);
    }
    printf("\n");
}

static void test_dns(const struct shz_net_info *in)
{
    ULONG a[8], count, q0;
    NTSTATUS st;
    const ULONG srv = HOST_BE;
    (void)in;
    st = NtShzNetResolve("a.shizuku.test", 14, a, 8, &count, srv, 17053);
    CHECK(st == 0 && count == 1 && a[0] == inet_addr("192.0.2.10"), "A query for a.shizuku.test -> 192.0.2.10 from the host DNS server (status %08x)", (unsigned)st);
    print_addrs("a", a, count);
    st = NtShzNetResolve("alias.shizuku.test", 18, a, 8, &count, srv, 17053);
    CHECK(st == 0 && count == 1 && a[0] == inet_addr("192.0.2.10"), "CNAME chain alias -> a.shizuku.test is followed inside one response");
    print_addrs("alias", a, count);
    st = NtShzNetResolve("multi.shizuku.test", 18, a, 8, &count, srv, 17053);
    CHECK(st == 0 && count == 3 && a[0] == inet_addr("192.0.2.21") && a[1] == inet_addr("192.0.2.22") && a[2] == inet_addr("192.0.2.23"), "three A records returned in order");
    print_addrs("multi", a, count);
    st = NtShzNetResolve("MiXeD.Shizuku.TEST", 18, a, 8, &count, srv, 17053);
    CHECK(st == 0 && count == 1 && a[0] == inet_addr("192.0.2.40"), "a mixed-case query name is sent lower-cased and resolves (192.0.2.40)");
    count = 0;
    st = NtShzNetResolve("nx.shizuku.test", 15, a, 8, &count, srv, 17053);
    CHECK((st & 0xffff) == WSAHOST_NOT_FOUND && count == 0, "NXDOMAIN -> WSAHOST_NOT_FOUND (11001), status %08x", (unsigned)st);
    st = NtShzNetResolve("nodata.shizuku.test", 19, a, 8, &count, srv, 17053);
    CHECK((st & 0xffff) == WSANO_DATA, "NOERROR without answers -> WSANO_DATA (11004), status %08x", (unsigned)st);
    q0 = net_stat(NST_DNS_QUERY);
    st = NtShzNetResolve("drop-first.shizuku.test", 23, a, 8, &count, srv, 17053);
    CHECK(st == 0 && count == 1 && a[0] == inet_addr("192.0.2.30") && net_stat(NST_DNS_QUERY) - q0 == 2, "first query unanswered: the resolver retransmits after 1 s and succeeds (%u queries sent)", (unsigned)(net_stat(NST_DNS_QUERY) - q0));
    st = NtShzNetResolve("servfail.shizuku.test", 21, a, 8, &count, srv, 17053);
    CHECK((st & 0xffff) == WSATRY_AGAIN, "SERVFAIL is retried and finally reported as WSATRY_AGAIN (11002), status %08x", (unsigned)st);
    q0 = net_stat(NST_DNS_CACHE_HIT);
    st = NtShzNetResolve("a.shizuku.test", 14, a, 8, &count, srv, 17053);
    CHECK(st == 0 && count == 1 && net_stat(NST_DNS_CACHE_HIT) == q0 + 1, "a second lookup of a.shizuku.test is answered from the cache (no packet)");
    st = NtShzNetResolve("nx.shizuku.test", 15, a, 8, &count, srv, 17053);
    CHECK((st & 0xffff) == WSAHOST_NOT_FOUND && net_stat(NST_DNS_CACHE_HIT) == q0 + 2, "NXDOMAIN is cached negatively");
    {   /* SLIRP answers a datagram to a closed host port with ICMP port unreachable: the resolver must give up at once */
        DWORD t0 = GetTickCount();
        st = NtShzNetResolve("nobody-answers.shizuku.test", 27, a, 8, &count, HOST_BE, 17054);   /* nothing listens on 17054 */
        CHECK((st & 0xffff) == WSATRY_AGAIN && GetTickCount() - t0 < 900, "ICMP port unreachable from the DNS server ends the lookup at once with WSATRY_AGAIN (%u ms), status %08x",
              (unsigned)(GetTickCount() - t0), (unsigned)st);
    }
}

static void test_dns_slirp(const struct shz_net_info *in)
{
    ULONG a[8], count = 0;
    NTSTATUS st;
    DWORD t0 = GetTickCount();
    (void)in;
    st = NtShzNetResolve("example.com", 11, a, 8, &count, 0, 0);
    if (st == 0 && count) {
        print_addrs("slirp-example.com", a, count);
        CHECK(1, "the DHCP-provided resolver (SLIRP 10.0.2.3) answered example.com with %u address(es) after %u ms", (unsigned)count, (unsigned)(GetTickCount() - t0));
    } else {
        printf("WIRE dns slirp-example.com BLOCKED status=%08x after %u ms\n", (unsigned)st, (unsigned)(GetTickCount() - t0));
        printf("INFO: SLIRP's DNS forwarder returned no answer for example.com: name resolution through SLIRP is BLOCKED in this environment\n");
    }
}

static void test_addrinfo_wire(void)
{
    struct addrinfo hints, *res = 0;
    int r;
    memset(&hints, 0, sizeof hints);
    hints.ai_family = AF_INET; hints.ai_socktype = SOCK_STREAM;
    r = getaddrinfo("10.0.2.2", "17001", &hints, &res);
    if (r == 0 && res) {                                    /* the resulting sockaddr is directly usable: connect through it */
        SOCKET s = socket(res->ai_family, res->ai_socktype, res->ai_protocol);
        int c = connect(s, res->ai_addr, (int)res->ai_addrlen);
        char b[4];
        CHECK(c == 0 && send(s, "ping", 4, 0) == 4 && recv_all(s, b, 4) == 4 && !memcmp(b, "ping", 4), "getaddrinfo(10.0.2.2, 17001) result connects and echoes");
        closesocket(s);
        freeaddrinfo(res);
    } else {
        CHECK(0, "getaddrinfo(10.0.2.2, 17001) returned %d", r);
    }
}

static void test_connect_timeout(void)
{
    struct sockaddr_in a;
    SOCKET s = socket(AF_INET, SOCK_STREAM, 0);
    DWORD t0 = GetTickCount(), dt;
    ULONG retr0 = net_stat(NST_TCP_RETRANS);
    int r;
    addr_of(&a, HOST_BE, 17006);
    r = connect(s, (struct sockaddr *)&a, sizeof a);
    dt = GetTickCount() - t0;
    CHECK(r == SOCKET_ERROR && WSAGetLastError() == WSAETIMEDOUT && dt >= 12000 && dt < 30000,
          "connect to a blackholed port gives up with WSAETIMEDOUT (10060) after %u ms (SYN retransmissions at 1, 3, 7 s)", (unsigned)dt);
    CHECK(net_stat(NST_TCP_RETRANS) - retr0 == 3, "exactly 3 SYN retransmissions (%u)", (unsigned)(net_stat(NST_TCP_RETRANS) - retr0));
    printf("WIRE connect_timeout ms=%u syn_retrans=%u\n", (unsigned)dt, (unsigned)(net_stat(NST_TCP_RETRANS) - retr0));
    closesocket(s);
}

int main(void)
{
    struct shz_net_info in;
    WSADATA wsa;
    unsigned long long m0[4], m1[4];
    ULONG retrans0, fast0, ooo0, badcs0;
    if (!net_require_nic(&in))
        return g_bad;
    WSAStartup(MAKEWORD(2, 2), &wsa);
    net_census(m0);
    test_mode();
    retrans0 = net_stat(NST_TCP_RETRANS); fast0 = net_stat(NST_TCP_FAST_RETRANS); ooo0 = net_stat(NST_TCP_OOO); badcs0 = net_stat(NST_TCP_BAD_CSUM);
    test_ping(&in);
    test_echo();
    test_upload();
    test_download();
    test_errors();
    test_half_close();
    test_many();
    test_outage();
    test_keepalive();
    test_udp();
    test_nonblocking();
    test_addrinfo_wire();
    test_dns(&in);
    test_dns_slirp(&in);
    if (g_lossy)
        test_connect_timeout();
    printf("WIRE stats retrans=%u fast_retrans=%u ooo=%u dupack_tx=%u bad_csum=%u tcp_tx=%u tcp_rx=%u\n",
           (unsigned)(net_stat(NST_TCP_RETRANS) - retrans0), (unsigned)(net_stat(NST_TCP_FAST_RETRANS) - fast0),
           (unsigned)(net_stat(NST_TCP_OOO) - ooo0), (unsigned)net_stat(NST_TCP_DUPACK_TX), (unsigned)(net_stat(NST_TCP_BAD_CSUM) - badcs0),
           (unsigned)net_stat(NST_TCP_TX), (unsigned)net_stat(NST_TCP_RX));
    printf("WIRE stats_abs ip_bad=%u udp_bad=%u tcp_bad=%u echo_rx=%u echo_tx=%u arp_rep_tx=%u arp_req_rx=%u unreach_tx=%u rst_tx=%u reasm=%u frag_tx=%u\n",
           (unsigned)net_stat(NST_IP_BAD_CSUM), (unsigned)net_stat(NST_UDP_BAD_CSUM), (unsigned)net_stat(NST_TCP_BAD_CSUM), (unsigned)net_stat(NST_ICMP_ECHO_RX),
           (unsigned)net_stat(NST_ICMP_ECHO_TX), (unsigned)net_stat(NST_ARP_REP_TX), (unsigned)net_stat(NST_ARP_REQ_RX), (unsigned)net_stat(NST_ICMP_UNREACH_TX),
           (unsigned)net_stat(NST_TCP_RST_TX), (unsigned)net_stat(NST_IP_REASM), (unsigned)net_stat(NST_IP_FRAG_TX));
    if (g_lossy)
        CHECK(net_stat(NST_TCP_RETRANS) - retrans0 > 0, "the lossy path forced TCP retransmissions (%u) and every transfer still verified", (unsigned)(net_stat(NST_TCP_RETRANS) - retrans0));
    if (g_lossy)
        Sleep(2500);                                        /* let the proxy's injected frames (ARP/ICMP/fragments/RST probes) arrive and be answered */
    Sleep(100);
    net_census(m1);
    CHECK(m1[3] <= m0[3] + 2, "no socket objects leaked by the wire tests (%llu live before, %llu after)", m0[3], m1[3]);
    WSACleanup();
    return g_bad ? 1 : 0;
}
