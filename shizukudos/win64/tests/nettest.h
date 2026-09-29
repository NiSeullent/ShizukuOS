/* SPDX-License-Identifier: GPL-2.0-only
 * Shared helpers of the t_net_*.c self-checking programs: native network syscall prototypes (ntdll stubs generated from
 * SYSCALL_LIST_NET), the query structures, and PASS:/FAIL: reporting. Exit code 0 = every check passed (or SKIP: no NIC). */
#ifndef SHZ_NETTEST_H
#define SHZ_NETTEST_H
#include <winsock2.h>
#include <ws2tcpip.h>
#include "shzcrt.h"

#ifndef NT_SUCCESS
typedef LONG NTSTATUS;
#endif

struct shz_net_info {
    unsigned flags;                             /* bit0 NIC present, bit1 link up, bit2 configured, bit3 DHCP bound */
    unsigned ip_be, mask_be, gw_be, dns0_be, dns1_be, dhcp_server_be;
    unsigned char mac[6];
    unsigned short pad;
    unsigned lease_secs, lease_remaining_secs, dhcp_state;
};
struct shz_tcp_row { unsigned lip_be, rip_be; unsigned short lport, rport; unsigned state; unsigned snd_una, snd_nxt, rcv_nxt, cwnd, rto; };
/* stack counters returned by NtShzNetQuery(1): keep in step with net.h NS_* (only the ones the tests read are named) */
enum { NST_ETH_RX, NST_ETH_TX, NST_ETH_RX_DROP, NST_ARP_REQ_TX, NST_ARP_REP_RX, NST_ARP_REQ_RX, NST_ARP_REP_TX, NST_IP_RX,
       NST_IP_TX, NST_IP_BAD_CSUM, NST_IP_REASM, NST_IP_FRAG_TX, NST_ICMP_ECHO_RX, NST_ICMP_ECHO_TX, NST_ICMP_REPLY_RX,
       NST_ICMP_UNREACH_TX, NST_UDP_RX, NST_UDP_TX, NST_UDP_BAD_CSUM, NST_TCP_RX, NST_TCP_TX, NST_TCP_BAD_CSUM, NST_TCP_RETRANS,
       NST_TCP_FAST_RETRANS, NST_TCP_RST_TX, NST_TCP_RST_RX, NST_TCP_OOO, NST_TCP_DUPACK_TX, NST_TCP_PERSIST,
       NST_TCP_KEEPALIVE_TX, NST_DNS_QUERY, NST_DNS_CACHE_HIT, NST_DHCP_TX, NST_DHCP_RX, NST_LO_PKTS, NST_COUNT };
enum { TCPS_CLOSED_T, TCPS_LISTEN_T, TCPS_SYN_SENT_T, TCPS_SYN_RCVD_T, TCPS_ESTABLISHED_T, TCPS_FIN_WAIT_1_T, TCPS_FIN_WAIT_2_T,
       TCPS_CLOSE_WAIT_T, TCPS_CLOSING_T, TCPS_LAST_ACK_T, TCPS_TIME_WAIT_T };

NTSTATUS __stdcall NtShzNetQuery(ULONG cls, PVOID buf, ULONG len, PULONG ret);
NTSTATUS __stdcall NtShzNetPing(ULONG64 dst_be, ULONG64 idseq, ULONG64 payload, ULONG64 timeout_ms, PULONG rtt);
NTSTATUS __stdcall NtShzNetResolve(const char *name, ULONG64 namelen, ULONG *results, ULONG64 max, PULONG count, ULONG64 server_be,
                                   ULONG64 server_port);

static int g_bad;
#define CHECK(cond, ...) do { if (cond) { printf("PASS: " __VA_ARGS__); printf("\n"); } else { printf("FAIL: " __VA_ARGS__); printf("\n"); ++g_bad; } } while (0)

static int net_query_info(struct shz_net_info *in)
{
    ULONG ret = 0;
    return NtShzNetQuery(0, in, sizeof *in, &ret) == 0 && ret == sizeof *in;
}
/* Returns 1 when a NIC is present; otherwise prints the explicit skip line the plain runner relies on. */
static int net_require_nic(struct shz_net_info *in)
{
    if (!net_query_info(in)) { printf("FAIL: NtShzNetQuery(info)\n"); ++g_bad; return 0; }
    if (!(in->flags & 1)) { printf("SKIP: no NIC\n"); return 0; }
    return 1;
}
static ULONG net_stat(unsigned idx)
{
    ULONG s[NST_COUNT + 6], ret = 0;
    if (NtShzNetQuery(1, s, sizeof s, &ret)) return 0;
    return s[idx];
}
static ULONG net_state_count(unsigned state)
{
    ULONG c[11], ret = 0;
    if (NtShzNetQuery(4, c, sizeof c, &ret) || state > 10) return 0;
    return c[state];
}
static void *xmalloc(size_t n) { void *p = malloc(n); if (!p) { printf("FAIL: out of memory\n"); ExitProcess(3); } return p; }
/* deterministic byte stream: the host runner recomputes the same function to verify what the guest sent */
static unsigned char pat(unsigned long long i) { return (unsigned char)((i * 131u) ^ (i >> 8) ^ (i >> 17)); }
static void fill_pat(unsigned char *b, size_t n, unsigned long long start) { size_t i; for (i = 0; i < n; ++i) b[i] = pat(start + i); }
static int send_all(SOCKET s, const void *p, int n)
{
    const char *c = p;
    int sent = 0;
    while (sent < n) {
        int r = send(s, c + sent, n - sent, 0);
        if (r == SOCKET_ERROR) return -1;
        sent += r;
    }
    return sent;
}
static int recv_all(SOCKET s, void *p, int n)
{
    char *c = p;
    int got = 0;
    while (got < n) {
        int r = recv(s, c + got, n - got, 0);
        if (r <= 0) return got ? got : r;
        got += r;
    }
    return got;
}

/* NtShzNetQuery(3) control: 1 = DHCP renew now, 2 = flush DNS cache, 3 = flush ARP cache */
static int net_control(unsigned op)
{
    ULONG v = op, ret = 0;
    return NtShzNetQuery(3, &v, 4, &ret) == 0;
}
/* NtShzNetQuery(5): {free physical pages, kernel heap bytes in use, live TCBs, live sockets} for leak checks */
static int net_census(unsigned long long m[4])
{
    ULONG ret = 0;
    return NtShzNetQuery(5, m, 32, &ret) == 0 && ret == 32;
}
#endif
