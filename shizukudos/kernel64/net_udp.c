/* SPDX-License-Identifier: GPL-2.0-only
 * UDP (RFC 768): checksum generation/verification, demultiplexing to datagram sockets, ICMP port-unreachable for closed
 * ports (RFC 1122 4.1.3.5), and asynchronous ICMP errors delivered to the sending socket (reported on Windows as
 * WSAECONNRESET on the next receive). Limits: no multicast, one delivery per datagram (the first matching socket).
 */
#include "net.h"

void udp_input(ip4_t src, ip4_t dst, const uint8_t *seg, uint32_t len, const uint8_t *ip_pkt, uint32_t ip_len)
{
    uint16_t sport, dport, ulen, csum;
    const int bcast = ip_is_broadcast(dst);
    sock_t *s, *best = 0;
    int best_score = -1;
    NSTAT(NS_UDP_RX);
    if (len < 8)
        return;
    sport = rd16(seg);
    dport = rd16(seg + 2);
    ulen = rd16(seg + 4);
    csum = rd16(seg + 6);
    if (ulen < 8 || ulen > len)
        return;
    len = ulen;
    if (csum && csum_fold(csum_pseudo(src, dst, IPPROTO_UDP_, len) + csum_add(0, seg, len)) != 0) {
        NSTAT(NS_UDP_BAD_CSUM);
        return;
    }
    if (dport == 68 && dhcp_input(src, seg + 8, len - 8))
        return;
    for (s = g_socks; s; s = s->next) {
        int score;
        if (s->type != SK_DGRAM || s->dead || !s->bound || s->lport != dport)
            continue;
        if (s->lip && s->lip != dst)
            continue;                                       /* bound to a specific address (also excludes broadcast) */
        if (s->connected && (s->rip != src || s->rport != sport))
            continue;
        score = (s->connected ? 2 : 0) + (s->lip ? 1 : 0);
        if (score > best_score) { best = s; best_score = score; }
    }
    if (!best) {
        if (!bcast && ip_pkt)
            icmp_send_unreach(src, 3, ip_pkt, ip_len);      /* port unreachable */
        return;
    }
    if (best->dq_bytes + (len - 8) > best->rcvbuf || best->dq_count >= 256)
        return;                                             /* receive buffer full: datagram dropped, like a real stack */
    {
        dgram_t *d = kmalloc(sizeof *d + (len - 8));
        if (!d)
            return;
        d->next = 0;
        d->src = src;
        d->sport = sport;
        d->len = (uint16_t)(len - 8);
        memcpy(d->data, seg + 8, len - 8);
        if (best->dq_tail) best->dq_tail->next = d; else best->dq_head = d;
        best->dq_tail = d;
        best->dq_bytes += len - 8;
        ++best->dq_count;
    }
    sock_notify(best);
}

static int32_t udp_emit(ip4_t src, ip4_t dst, uint16_t sport, uint16_t dport, const uint8_t *data, uint32_t len, int limited_bc)
{
    uint8_t *u = g_l4;
    uint16_t sum;
    if (len > 65507)
        return NET_ERR(WSAEMSGSIZE);
    wr16(u, sport); wr16(u + 2, dport); wr16(u + 4, (uint16_t)(len + 8)); wr16(u + 6, 0);
    memcpy(u + 8, data, len);
    sum = csum_fold(csum_pseudo(src, limited_bc ? 0xffffffffu : dst, IPPROTO_UDP_, len + 8) + csum_add(0, u, len + 8));
    wr16(u + 6, sum ? sum : 0xffff);
    NSTAT(NS_UDP_TX);
    return limited_bc ? ip_output_broadcast(IPPROTO_UDP_, src, u, len + 8) : ip_output(IPPROTO_UDP_, src, dst, u, len + 8, 0);
}

int32_t udp_send_raw(ip4_t src, ip4_t dst, uint16_t sport, uint16_t dport, const uint8_t *data, uint32_t len, int limited_broadcast)
{
    return udp_emit(src, dst, sport, dport, data, len, limited_broadcast);
}

int32_t udp_send(sock_t *s, ip4_t dip, uint16_t dport, const uint8_t *data, uint32_t len, ip4_t src_override)
{
    ip4_t src = src_override ? src_override : s->lip;
    int32_t st;
    if (!dip || !dport)
        return NET_ERR(WSAEADDRNOTAVAIL);
    if (ip_is_broadcast(dip) && !s->broadcast)
        return NET_ERR(WSAEACCES);
    if (!src) {
        st = ip_route_src(dip, &src, 0);
        if (st)
            return st;
    }
    return udp_emit(src, dip, s->lport, dport, data, len, 0);
}

/* orig = the IP header + first 8 payload bytes of a datagram we sent that provoked an ICMP error. */
void udp_icmp_error(const uint8_t *orig, uint32_t len, int32_t err)
{
    const uint32_t ihl = (uint32_t)(orig[0] & 15) * 4;
    sock_t *s;
    uint16_t sport, dport;
    ip4_t dst;
    if (len < ihl + 8)
        return;
    sport = rd16(orig + ihl);
    dport = rd16(orig + ihl + 2);
    dst = rd32(orig + 16);
    for (s = g_socks; s; s = s->next)
        if (s->type == SK_DGRAM && !s->dead && s->bound && s->lport == sport && (!s->connected || (s->rip == dst && s->rport == dport))) {
            s->err = err;
            sock_notify(s);
            return;
        }
}
