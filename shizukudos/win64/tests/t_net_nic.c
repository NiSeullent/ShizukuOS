/* SPDX-License-Identifier: GPL-2.0-only
 * NIC + DHCP + ARP + ICMP check: the RTL8139 must be up, DHCP must have configured the interface, the gateway must be
 * reachable (ARP resolves it, an ICMP echo comes back) and the loopback interface must answer a ping to 127.0.0.1.
 * Prints machine-readable "NETINFO ..." / "PING ..." lines that tests/run_k64_net.py cross-checks against QEMU's own
 * packet capture. Exits 0 with "SKIP: no NIC" when the machine has no RTL8139 (the plain standalone runner). */
#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include "nettest.h"

static void ip_text(unsigned be, char *out)
{
    const unsigned char *b = (const unsigned char *)&be;
    shz_snprintf(out, 16, "%u.%u.%u.%u", b[0], b[1], b[2], b[3]);
}

int main(void)
{
    struct shz_net_info in;
    char ip[16], mask[16], gw[16], dns[16], srv[16];
    ULONG rtt = 0, before_req, before_rep, before_echo;
    NTSTATUS st;
    if (!net_require_nic(&in))
        return g_bad;
    ip_text(in.ip_be, ip); ip_text(in.mask_be, mask); ip_text(in.gw_be, gw); ip_text(in.dns0_be, dns); ip_text(in.dhcp_server_be, srv);
    printf("NETINFO ip=%s mask=%s gw=%s dns=%s dhcp_server=%s lease=%u mac=%02x:%02x:%02x:%02x:%02x:%02x state=%u\n", ip, mask, gw, dns,
           srv, in.lease_secs, in.mac[0], in.mac[1], in.mac[2], in.mac[3], in.mac[4], in.mac[5], in.dhcp_state);
    CHECK(in.flags & 2, "RTL8139 link is up");
    CHECK((in.flags & 4) && in.ip_be != 0, "interface configured (%s)", ip);
    CHECK((in.flags & 8) && in.dhcp_state == 4, "DHCP lease is BOUND (server %s, %u s)", srv, in.lease_secs);
    {   /* the lease was obtained during this boot: no more of it can have elapsed than the uptime (other test programs may
         * have run for a minute or more before this one) */
        const ULONG up = (ULONG)(GetTickCount64() / 1000);
        CHECK(in.lease_secs != 0 && in.lease_remaining_secs <= in.lease_secs && in.lease_remaining_secs + up + 2 >= in.lease_secs,
              "lease time %u s, %u s remaining after %u s of uptime", in.lease_secs, in.lease_remaining_secs, (unsigned)up);
    }
    CHECK(in.mask_be != 0 && in.gw_be != 0 && ((in.ip_be ^ in.gw_be) & in.mask_be) == 0, "gateway %s is on-link for %s/%s", gw, ip, mask);
    CHECK(in.dns0_be != 0, "DHCP supplied a DNS server (%s)", dns);

    before_req = net_stat(NST_ARP_REQ_TX);
    before_rep = net_stat(NST_ARP_REP_RX);
    before_echo = net_stat(NST_ICMP_REPLY_RX);
    st = NtShzNetPing(in.gw_be, (0x4242ull << 16) | 1, 32, 2000, &rtt);
    printf("PING %s status=%08x rtt=%u ms\n", gw, (unsigned)st, (unsigned)rtt);
    CHECK(st == 0, "ICMP echo to the gateway %s answered", gw);
    CHECK(net_stat(NST_ICMP_REPLY_RX) == before_echo + 1, "exactly one echo reply was received");
    CHECK(net_stat(NST_ARP_REQ_TX) >= before_req && net_stat(NST_ARP_REP_RX) >= before_rep && net_stat(NST_ARP_REP_RX) >= 1,
          "the gateway MAC was learned through ARP (%u requests sent, %u replies received)", (unsigned)net_stat(NST_ARP_REQ_TX),
          (unsigned)net_stat(NST_ARP_REP_RX));
    st = NtShzNetPing(in.gw_be, (0x4242ull << 16) | 2, 1400, 2000, &rtt);
    CHECK(st == 0, "1400-byte echo (fills a frame) to the gateway answered");
    st = NtShzNetPing(0x0100007f, (0x4243ull << 16) | 1, 64, 1000, &rtt);
    CHECK(st == 0, "loopback ping 127.0.0.1 answered by our own stack");
    st = NtShzNetPing(in.ip_be, (0x4244ull << 16) | 1, 64, 1000, &rtt);
    CHECK(st == 0, "ping to our own address answered over loopback");
    /* ARP cache expiry / re-resolution: drop every neighbour, the next packet must trigger a new request and still get through */
    before_req = net_stat(NST_ARP_REQ_TX);
    CHECK(net_control(3), "ARP cache flushed");
    st = NtShzNetPing(in.gw_be, (0x4245ull << 16) | 1, 32, 2000, &rtt);
    CHECK(st == 0 && net_stat(NST_ARP_REQ_TX) == before_req + 1, "after the flush the packet waits for a fresh ARP resolution and is delivered when the reply arrives (%u new request)",
          (unsigned)(net_stat(NST_ARP_REQ_TX) - before_req));
    /* ARP for a host that does not exist: 3 requests one second apart, then the queued packet is dropped */
    {
        const ULONG ghost = (in.ip_be & in.mask_be) | 0x4d000000u;    /* x.y.z.77 */
        DWORD t0 = GetTickCount();
        before_req = net_stat(NST_ARP_REQ_TX);
        st = NtShzNetPing(ghost, (0x4246ull << 16) | 1, 32, 4500, &rtt);
        printf("ARP-FAIL ghost=%u.%u.%u.%u requests=%u ms=%u\n", ghost & 255, (ghost >> 8) & 255, (ghost >> 16) & 255, ghost >> 24,
               (unsigned)(net_stat(NST_ARP_REQ_TX) - before_req), (unsigned)(GetTickCount() - t0));
        CHECK(st != 0 && net_stat(NST_ARP_REQ_TX) - before_req == 3, "ping to an unresolvable neighbour sends exactly 3 ARP requests and times out (status %08x)", (unsigned)st);
        {
            struct sockaddr_in a;
            WSADATA w;
            SOCKET s;
            int r;
            WSAStartup(MAKEWORD(2, 2), &w);
            s = socket(AF_INET, SOCK_STREAM, 0);
            memset(&a, 0, sizeof a); a.sin_family = AF_INET; a.sin_port = htons(80); a.sin_addr.s_addr = ghost;
            t0 = GetTickCount();
            r = connect(s, (struct sockaddr *)&a, sizeof a);
            CHECK(r == SOCKET_ERROR && WSAGetLastError() == WSAEHOSTUNREACH && GetTickCount() - t0 < 6000, "TCP connect to the unresolvable neighbour fails with WSAEHOSTUNREACH (10065) after %u ms, got %d",
                  (unsigned)(GetTickCount() - t0), WSAGetLastError());
            closesocket(s);
            WSACleanup();
        }
    }
    /* DHCP renewal (RFC 2131 4.4.5): forced RENEWING -> unicast REQUEST to the server -> ACK -> BOUND again with the same address */
    {
        struct shz_net_info after;
        ULONG tx0 = net_stat(NST_DHCP_TX), rx0 = net_stat(NST_DHCP_RX);
        DWORD t0 = GetTickCount();
        CHECK(net_control(1), "DHCP renewal forced");
        do { Sleep(20); net_query_info(&after); } while (after.dhcp_state != 4 && GetTickCount() - t0 < 3000);
        printf("DHCP-RENEW state=%u ip=%08x tx=%u rx=%u\n", after.dhcp_state, after.ip_be, (unsigned)(net_stat(NST_DHCP_TX) - tx0), (unsigned)(net_stat(NST_DHCP_RX) - rx0));
        CHECK(after.dhcp_state == 4 && after.ip_be == in.ip_be && net_stat(NST_DHCP_TX) == tx0 + 1 && net_stat(NST_DHCP_RX) == rx0 + 1,
              "renewal completed: one unicast REQUEST sent, one ACK received, still BOUND to %s", ip);
    }
    CHECK(net_stat(NST_ETH_TX) > 0 && net_stat(NST_ETH_RX) > 0 && net_stat(NST_IP_BAD_CSUM) == 0,
          "frames flowed both ways (tx %u, rx %u) and no IP header checksum failed", (unsigned)net_stat(NST_ETH_TX), (unsigned)net_stat(NST_ETH_RX));
    return g_bad ? 1 : 0;
}
