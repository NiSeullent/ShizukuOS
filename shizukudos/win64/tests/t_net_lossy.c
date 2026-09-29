/* SPDX-License-Identifier: GPL-2.0-only
 * Fault-injection half of the wire tests: only meaningful in the runner's "lossy" boot, where the frame-level proxy sits between
 * the guest NIC and SLIRP. It is a separate program so that each stays inside the kernel's 60 s per-app watchdog.
 *   - connect() to a port whose SYNs the proxy blackholes must give up with WSAETIMEDOUT after the SYN backoff 1, 2, 4, 8 s
 *   - a 512 KiB upload across a 2.5 s total outage in the middle of the transfer must survive (exponential RTO backoff, then
 *     recovery) and arrive byte-identical
 * In the direct boot (or without NIC) it prints SKIP and exits 0. */
#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include "nettest.h"

#define HOST_BE ((u_long)0x0202000a)                    /* 10.0.2.2 */

static SOCKET tcp_to(unsigned short port, int *err)
{
    struct sockaddr_in a;
    SOCKET s = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    memset(&a, 0, sizeof a);
    a.sin_family = AF_INET;
    a.sin_port = htons(port);
    a.sin_addr.s_addr = HOST_BE;
    if (s == INVALID_SOCKET) { *err = WSAGetLastError(); return s; }
    if (connect(s, (struct sockaddr *)&a, sizeof a)) { *err = WSAGetLastError(); closesocket(s); return INVALID_SOCKET; }
    *err = 0;
    return s;
}

static int lossy_mode(void)
{
    int err;
    char line[64];
    int n;
    SOCKET s = tcp_to(17008, &err);                     /* mode banner (same server as 17000, separate port so the proxy's trigger stays with t_net_wire) */
    if (s == INVALID_SOCKET) { printf("FAIL: cannot reach the host mode server (err %d)\n", err); ++g_bad; return 0; }
    n = recv(s, line, sizeof line - 1, 0);
    closesocket(s);
    line[n > 0 ? n : 0] = 0;
    return n >= 10 && !memcmp(line, "MODE lossy", 10);
}

static void test_connect_timeout(void)
{
    struct sockaddr_in a;
    SOCKET s = socket(AF_INET, SOCK_STREAM, 0);
    DWORD t0 = GetTickCount(), dt;
    ULONG retr0 = net_stat(NST_TCP_RETRANS);
    int r;
    memset(&a, 0, sizeof a);
    a.sin_family = AF_INET; a.sin_port = htons(17006); a.sin_addr.s_addr = HOST_BE;
    r = connect(s, (struct sockaddr *)&a, sizeof a);
    dt = GetTickCount() - t0;
    CHECK(r == SOCKET_ERROR && WSAGetLastError() == WSAETIMEDOUT && dt >= 12000 && dt < 30000,
          "connect to a blackholed port gives up with WSAETIMEDOUT (10060) after %u ms (SYN retransmissions at 1, 3, 7 s)", (unsigned)dt);
    CHECK(net_stat(NST_TCP_RETRANS) - retr0 == 3, "exactly 3 SYN retransmissions (%u)", (unsigned)(net_stat(NST_TCP_RETRANS) - retr0));
    printf("WIRE connect_timeout ms=%u syn_retrans=%u\n", (unsigned)dt, (unsigned)(net_stat(NST_TCP_RETRANS) - retr0));
    closesocket(s);
}

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

int main(void)
{
    struct shz_net_info in;
    WSADATA wsa;
    if (!net_require_nic(&in))
        return g_bad;
    WSAStartup(MAKEWORD(2, 2), &wsa);
    if (!lossy_mode()) {
        printf("SKIP: not the lossy boot (no fault-injecting proxy on the wire)\n");
        WSACleanup();
        return g_bad ? 1 : 0;
    }
    test_outage();
    test_connect_timeout();
    WSACleanup();
    return g_bad ? 1 : 0;
}
