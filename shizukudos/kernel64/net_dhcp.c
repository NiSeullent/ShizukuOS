/* SPDX-License-Identifier: GPL-2.0-only
 * DHCP client (RFC 2131 / 2132). INIT -> SELECTING (DISCOVER, wait for OFFER) -> REQUESTING (REQUEST with server id +
 * requested address) -> BOUND, then RENEWING at T1 (unicast REQUEST to the server), REBINDING at T2 (broadcast) and
 * deconfiguration at lease expiry; a NAK restarts discovery. Retransmission uses exponential backoff (2, 4, 8, ... 64 s).
 * Options used: subnet mask, router, DNS servers (first two), lease time, server id, T1/T2. Not implemented: option overload
 * (sname/file carrying options), ARP conflict probing of the offered address, INFORM, RELEASE on shutdown.
 * The renewal/rebinding/expiry timers are implemented but a real lease (24 h from SLIRP) never reaches them in a test run;
 * dhcp_renew_now() forces the RENEWING exchange so that path can be exercised.
 */
#include "net.h"

static uint32_t xid;
static uint64_t next_tx, discover_start;
static unsigned tries;
static ip4_t off_ip, off_server;

#define DHCP_DISCOVER 1
#define DHCP_OFFER 2
#define DHCP_REQUEST 3
#define DHCP_ACK 5
#define DHCP_NAK 6

static uint32_t build(uint8_t *b, uint8_t type, ip4_t ciaddr, ip4_t req_ip, ip4_t server_id)
{
    uint32_t o = 240;
    static const uint8_t params[] = {1, 3, 6, 15, 51, 54, 58, 59};
    memset(b, 0, 300);
    b[0] = 1; b[1] = 1; b[2] = 6;
    wr32(b + 4, xid);
    wr16(b + 8, (uint16_t)((net_now() - discover_start) / 1000));      /* secs since the client began acquisition */
    wr16(b + 10, ciaddr ? 0 : 0x8000);                                  /* BROADCAST flag while we have no address */
    wr32(b + 12, ciaddr);
    memcpy(b + 28, g_net.mac, 6);
    b[236] = 0x63; b[237] = 0x82; b[238] = 0x53; b[239] = 0x63;
    b[o++] = 53; b[o++] = 1; b[o++] = type;
    b[o++] = 61; b[o++] = 7; b[o++] = 1; memcpy(b + o, g_net.mac, 6); o += 6;
    b[o++] = 12; b[o++] = 7; memcpy(b + o, "SHZ-K64", 7); o += 7;               /* same name as COMPUTERNAME in the process environment */
    if (req_ip) { b[o++] = 50; b[o++] = 4; wr32(b + o, req_ip); o += 4; }
    if (server_id) { b[o++] = 54; b[o++] = 4; wr32(b + o, server_id); o += 4; }
    b[o++] = 55; b[o++] = sizeof params; memcpy(b + o, params, sizeof params); o += sizeof params;
    b[o++] = 255;
    return o < 300 ? 300 : o;                                           /* BOOTP minimum packet size */
}

static void send_msg(uint8_t type, ip4_t ciaddr, ip4_t req_ip, ip4_t server_id, int unicast_to_server)
{
    uint8_t pkt[320];
    const uint32_t n = build(pkt, type, ciaddr, req_ip, server_id);
    NSTAT(NS_DHCP_TX);
    if (unicast_to_server)
        udp_send_raw(g_net.ip, g_net.dhcp_server, 68, 67, pkt, n, 0);
    else
        udp_send_raw(ciaddr, 0xffffffffu, 68, 67, pkt, n, 1);
}

static uint64_t backoff_ms(unsigned n)
{
    uint64_t ms = 2000ull << (n > 5 ? 5 : n);                          /* 2, 4, 8, 16, 32, 64 s */
    return ms + (net_rand32() % 500);                                  /* small jitter, RFC 2131 4.1 */
}

void dhcp_start(void)
{
    xid = net_rand32();
    tries = 0;
    discover_start = net_now();
    g_net.dhcp_state = DHCP_SELECTING;
    send_msg(DHCP_DISCOVER, 0, 0, 0, 0);
    next_tx = net_now() + backoff_ms(0);
}

void dhcp_renew_now(void)
{
    if (g_net.dhcp_state != DHCP_BOUND)
        return;
    g_net.dhcp_state = DHCP_RENEWING;
    xid = net_rand32();
    tries = 0;
    send_msg(DHCP_REQUEST, g_net.ip, 0, 0, 1);
    next_tx = net_now() + 10000;
}

void dhcp_timer(uint64_t now)
{
    if (g_net.dhcp_state == DHCP_OFF)
        return;
    switch (g_net.dhcp_state) {
    case DHCP_SELECTING:
        if (now >= next_tx) {
            ++tries;
            send_msg(DHCP_DISCOVER, 0, 0, 0, 0);
            next_tx = now + backoff_ms(tries);
        }
        break;
    case DHCP_REQUESTING:
        if (now >= next_tx) {
            if (++tries >= 4) {
                dhcp_start();                                          /* no ACK: begin again from DISCOVER */
            } else {
                send_msg(DHCP_REQUEST, 0, off_ip, off_server, 0);
                next_tx = now + backoff_ms(tries);
            }
        }
        break;
    case DHCP_BOUND:
        if (now >= g_net.t1_ms)
            dhcp_renew_now();
        break;
    case DHCP_RENEWING:
        if (now >= g_net.t2_ms) {
            g_net.dhcp_state = DHCP_REBINDING;
            xid = net_rand32();
            send_msg(DHCP_REQUEST, g_net.ip, 0, 0, 0);
            next_tx = now + 10000;
        } else if (now >= next_tx) {
            send_msg(DHCP_REQUEST, g_net.ip, 0, 0, 1);
            next_tx = now + 10000;
        }
        break;
    case DHCP_REBINDING:
        if (now >= g_net.lease_start_ms + (uint64_t)g_net.lease_secs * 1000) {
            kprintf("K64 net: DHCP lease expired\n");
            net_deconfigure();
            dhcp_start();
        } else if (now >= next_tx) {
            send_msg(DHCP_REQUEST, g_net.ip, 0, 0, 0);
            next_tx = now + 10000;
        }
        break;
    default:
        break;
    }
}

static uint32_t class_mask(ip4_t ip)
{
    if ((ip >> 31) == 0) return 0xff000000u;
    if ((ip >> 30) == 2) return 0xffff0000u;
    return 0xffffff00u;
}

int dhcp_input(ip4_t src, const uint8_t *d, uint32_t len)
{
    uint32_t i, mask = 0, gw = 0, dns0 = 0, dns1 = 0, lease = 0, t1 = 0, t2 = 0, server = 0;
    uint8_t type = 0;
    const ip4_t yiaddr = len >= 240 ? rd32(d + 16) : 0;
    if (g_net.dhcp_state == DHCP_OFF || g_net.dhcp_state == DHCP_BOUND || len < 240 || d[0] != 2 || rd32(d + 4) != xid ||
        memcmp(d + 28, g_net.mac, 6) || d[236] != 0x63 || d[237] != 0x82 || d[238] != 0x53 || d[239] != 0x63)
        return 0;
    for (i = 240; i < len && d[i] != 255; ) {
        const uint8_t code = d[i];
        uint32_t l;
        if (code == 0) { ++i; continue; }
        if (i + 1 >= len) break;
        l = d[i + 1];
        if (i + 2 + l > len) break;
        switch (code) {
        case 53: if (l == 1) type = d[i + 2]; break;
        case 1: if (l == 4) mask = rd32(d + i + 2); break;
        case 3: if (l >= 4) gw = rd32(d + i + 2); break;
        case 6: if (l >= 4) dns0 = rd32(d + i + 2); if (l >= 8) dns1 = rd32(d + i + 6); break;
        case 51: if (l == 4) lease = rd32(d + i + 2); break;
        case 54: if (l == 4) server = rd32(d + i + 2); break;
        case 58: if (l == 4) t1 = rd32(d + i + 2); break;
        case 59: if (l == 4) t2 = rd32(d + i + 2); break;
        default: break;
        }
        i += 2 + l;
    }
    NSTAT(NS_DHCP_RX);
    if (g_net.dhcp_state == DHCP_SELECTING && type == DHCP_OFFER && yiaddr) {
        off_ip = yiaddr;
        off_server = server ? server : src;
        g_net.dhcp_state = DHCP_REQUESTING;
        tries = 0;
        send_msg(DHCP_REQUEST, 0, off_ip, off_server, 0);
        next_tx = net_now() + backoff_ms(0);
        return 1;
    }
    if ((g_net.dhcp_state == DHCP_REQUESTING || g_net.dhcp_state == DHCP_RENEWING || g_net.dhcp_state == DHCP_REBINDING) &&
        type == DHCP_ACK && yiaddr) {
        const uint64_t now = net_now();
        if (!lease) lease = 3600;
        if (!mask) mask = class_mask(yiaddr);
        off_ip = yiaddr;
        net_dhcp_apply(yiaddr, mask, gw, dns0, dns1, server ? server : src, lease);
        g_net.t1_ms = now + (uint64_t)(t1 ? t1 : lease / 2) * 1000;
        g_net.t2_ms = now + (uint64_t)(t2 ? t2 : lease - lease / 8) * 1000;
        g_net.dhcp_state = DHCP_BOUND;
        net_wake_all();
        return 1;
    }
    if (type == DHCP_NAK && (g_net.dhcp_state == DHCP_REQUESTING || g_net.dhcp_state == DHCP_RENEWING ||
                             g_net.dhcp_state == DHCP_REBINDING)) {
        net_deconfigure();
        dhcp_start();
        return 1;
    }
    return 0;
}
