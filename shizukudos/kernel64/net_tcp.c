/* SPDX-License-Identifier: GPL-2.0-only
 * TCP (RFC 793, with RFC 1122 / 5681 / 5961 / 6298 / 6528 behaviour). See net.h for the list of what is NOT implemented
 * (window scaling, SACK, timestamps, out-of-order reassembly).
 *
 * Data model: a connection is a tcb_t on g_tcbs. The application's socket points at it (sock->tcb / tcb->sock). When the
 * application closes the socket the tcb is orphaned (tcb->sock == NULL) and finishes the close handshake on its own, then
 * TIME_WAIT (2*MSL, MSL = 30 s) and is freed by the timer. Listeners are sockets, not tcbs; each incoming SYN creates a
 * child tcb in SYN_RCVD with tcb->parent = listener until accept() takes it.
 * Sequence bookkeeping: sndq holds the bytes from snd_una on (unacknowledged + not yet sent); a SYN/FIN occupies one
 * sequence number but no queue byte. snd_max is the highest sequence sent; after a timeout snd_nxt is pulled back to
 * snd_una (go-back-N over the old data) while snd_max still bounds which ACKs are acceptable.
 */
#include "net.h"

tcb_t *g_tcbs;

enum { F_FIN = 0x01, F_SYN = 0x02, F_RST = 0x04, F_PSH = 0x08, F_ACK = 0x10 };
#define SEQ_LT(a, b) ((int32_t)((a) - (b)) < 0)
#define SEQ_LEQ(a, b) ((int32_t)((a) - (b)) <= 0)
#define SEQ_GT(a, b) ((int32_t)((a) - (b)) > 0)
#define SEQ_GEQ(a, b) ((int32_t)((a) - (b)) >= 0)
#define MSL_MS 30000u
#define RTO_INIT 1000u
#define RTO_MIN 200u                                    /* RFC 6298 recommends 1 s; 200 ms as Linux, timers tick at 5-10 ms */
#define RTO_MAX 60000u
#define MAX_DATA_RTX 9                                  /* give up after 9 retransmissions of one segment (~4 minutes) */
#define MAX_SYN_TRIES 4                                 /* SYN sent 4 times over 1+2+4+8 = 15 s */
#define DELACK_MS 40u
#define FIN_WAIT2_MS 60000u
#define KA_IDLE_MS 7200000u
#define KA_INTVL_MS 1000u
#define KA_PROBES 10
#define DEF_MSS 536u

static int ack_dirty;
static uint32_t isn_secret;

static uint32_t ka_idle_ms(const tcb_t *t) { return t->sock && t->sock->ka_idle_s ? t->sock->ka_idle_s * 1000u : KA_IDLE_MS; }
static uint32_t ka_intvl_ms(const tcb_t *t) { return t->sock && t->sock->ka_intvl_s ? t->sock->ka_intvl_s * 1000u : KA_INTVL_MS; }
static uint32_t ka_cnt(const tcb_t *t) { return t->sock && t->sock->ka_cnt ? t->sock->ka_cnt : KA_PROBES; }

/* SO_KEEPALIVE / TCP_KEEPIDLE changed on a live connection. */
void tcp_keepalive_changed(tcb_t *t)
{
    if (t->sock && t->sock->keepalive && (t->state == TCPS_ESTABLISHED || t->state == TCPS_CLOSE_WAIT))
        t->ka_deadline = net_now() + ka_idle_ms(t);
    else
        t->ka_deadline = 0;
}

static uint32_t min32(uint32_t a, uint32_t b) { return a < b ? a : b; }
static uint32_t max32(uint32_t a, uint32_t b) { return a > b ? a : b; }

/* RFC 6528: ISN = M (4 microsecond clock) + F(4-tuple, secret), F an FNV-1a hash here. */
static uint32_t make_isn(ip4_t lip, uint16_t lport, ip4_t rip, uint16_t rport)
{
    uint32_t h = 2166136261u;
    const uint32_t v[5] = {lip, rip, ((uint32_t)lport << 16) | rport, isn_secret, isn_secret ^ 0x5bd1e995u};
    unsigned i, b;
    if (!isn_secret) {
        isn_secret = net_rand32() | 1;
        return make_isn(lip, lport, rip, rport);
    }
    for (i = 0; i < 5; ++i)
        for (b = 0; b < 32; b += 8) {
            h ^= (v[i] >> b) & 255;
            h *= 16777619u;
        }
    return h + (uint32_t)net_now() * 250u;
}

/* ---------------------------------------------------------------- list, notification helpers */
static void tcb_notify(tcb_t *t)
{
    if (t->sock) sock_notify(t->sock);
    else if (t->parent) sock_notify(t->parent);
    else net_wake_all();
}

static void tcb_unlink(tcb_t *t)
{
    tcb_t **pp;
    for (pp = &g_tcbs; *pp; pp = &(*pp)->next)
        if (*pp == t) { *pp = t->next; break; }
}

static void acceptq_remove(tcb_t *t)
{
    sock_t *l = t->parent;
    tcb_t *p, *prev = 0;
    if (!l)
        return;
    if (t->queued)
        for (p = l->acc_head; p; prev = p, p = p->acc_next)
            if (p == t) {
                if (prev) prev->acc_next = p->acc_next; else l->acc_head = p->acc_next;
                if (l->acc_tail == p) l->acc_tail = prev;
                --l->acc_count;
                break;
            }
    t->queued = 0;
    t->parent = 0;
}

static void tcb_free(tcb_t *t)
{
    acceptq_remove(t);
    tcb_unlink(t);
    if (t->sock)
        t->sock->tcb = 0;
    bq_free(&t->sndq);
    bq_free(&t->rcvq);
    kfree(t);
}

static tcb_t *tcb_alloc(sock_t *for_sock, uint32_t sndlim, uint32_t rcvlim)
{
    tcb_t *t = kzalloc(sizeof *t);
    (void)for_sock;
    if (!t)
        return 0;
    t->sndq.limit = sndlim;
    t->rcvq.limit = rcvlim;
    t->rto = RTO_INIT;
    t->next = g_tcbs;
    g_tcbs = t;
    return t;
}

static tcb_t *tcb_lookup(ip4_t lip, uint16_t lport, ip4_t rip, uint16_t rport)
{
    tcb_t *t;
    for (t = g_tcbs; t; t = t->next)
        if (t->lport == lport && t->rport == rport && t->rip == rip && t->lip == lip && t->state != TCPS_CLOSED)
            return t;
    return 0;
}

static sock_t *find_listener(ip4_t dst, uint16_t dport)
{
    sock_t *s, *any = 0;
    for (s = g_socks; s; s = s->next)
        if (s->type == SK_STREAM && s->listening && !s->dead && s->lport == dport) {
            if (s->lip == dst) return s;
            if (!s->lip) any = s;
        }
    return any;
}

/* ---------------------------------------------------------------- segment transmission */
static uint32_t rcv_window(tcb_t *t)
{
    const uint32_t avail = bq_space(&t->rcvq);
    const uint32_t cur = SEQ_GT(t->rcv_adv, t->rcv_nxt) ? t->rcv_adv - t->rcv_nxt : 0;
    const uint32_t thresh = min32(t->mss ? t->mss : DEF_MSS, t->rcvq.limit / 2);
    uint32_t win = cur;
    if (avail < cur) win = avail;
    else if (avail - cur >= thresh) win = avail;            /* receiver-side silly window avoidance (RFC 1122 4.2.3.3) */
    return win > 65535 ? 65535 : win;
}

static void xmit(tcb_t *t, uint32_t seq, uint8_t flags, uint32_t data_off, uint32_t data_len, int with_mss, uint32_t mss_opt)
{
    uint8_t *s = g_l4;
    const uint32_t hlen = with_mss ? 24 : 20;
    uint32_t win;
    if (with_mss) {
        win = min32(t->rcvq.limit, 65535);
    } else {
        win = rcv_window(t);
        if (SEQ_GT(t->rcv_nxt + win, t->rcv_adv))
            t->rcv_adv = t->rcv_nxt + win;
    }
    wr16(s, t->lport); wr16(s + 2, t->rport);
    wr32(s + 4, seq);
    wr32(s + 8, (flags & F_ACK) ? t->rcv_nxt : 0);
    s[12] = (uint8_t)((hlen / 4) << 4);
    s[13] = flags;
    wr16(s + 14, (uint16_t)win);
    wr16(s + 16, 0); wr16(s + 18, 0);
    if (with_mss) { s[20] = 2; s[21] = 4; wr16(s + 22, (uint16_t)mss_opt); }
    if (data_len)
        bq_peek(&t->sndq, data_off, s + hlen, data_len);
    wr16(s + 16, csum_fold(csum_pseudo(t->lip, t->rip, IPPROTO_TCP_, hlen + data_len) + csum_add(0, s, hlen + data_len)));
    NSTAT(NS_TCP_TX);
    ip_output(IPPROTO_TCP_, t->lip, t->rip, s, hlen + data_len, 0);
    if (flags & F_ACK) {
        t->ack_pending = 0; t->ack_now = 0; t->ack_deadline = 0; t->rx_unacked = 0;
    }
}

static uint32_t local_mss(tcb_t *t)
{
    uint32_t mtu = NET_MTU;
    ip_route_src(t->rip, 0, &mtu);
    return mtu - 40;
}

static void send_ack(tcb_t *t) { xmit(t, t->snd_nxt, F_ACK, 0, 0, 0, 0); }

static void send_syn(tcb_t *t, int with_ack)
{
    xmit(t, t->iss, (uint8_t)(F_SYN | (with_ack ? F_ACK : 0)), 0, 0, 1, local_mss(t));
}

/* RST for a segment that matches no connection (RFC 793 p.65). */
static void reply_rst(ip4_t lip, ip4_t rip, uint16_t lport, uint16_t rport, uint32_t seq, uint32_t ack, uint8_t flags, uint32_t slen)
{
    uint8_t *s = g_l4;
    uint32_t rseq, rack;
    uint8_t rf;
    if (flags & F_ACK) { rseq = ack; rack = 0; rf = F_RST; }
    else { rseq = 0; rack = seq + slen; rf = F_RST | F_ACK; }
    wr16(s, lport); wr16(s + 2, rport); wr32(s + 4, rseq); wr32(s + 8, rack);
    s[12] = 5 << 4; s[13] = rf; wr16(s + 14, 0); wr16(s + 16, 0); wr16(s + 18, 0);
    wr16(s + 16, csum_fold(csum_pseudo(lip, rip, IPPROTO_TCP_, 20) + csum_add(0, s, 20)));
    NSTAT(NS_TCP_RST_TX); NSTAT(NS_TCP_TX);
    ip_output(IPPROTO_TCP_, lip, rip, s, 20, 0);
}

static void send_rst_conn(tcb_t *t)
{
    uint8_t *s = g_l4;
    wr16(s, t->lport); wr16(s + 2, t->rport); wr32(s + 4, t->snd_nxt); wr32(s + 8, t->rcv_nxt);
    s[12] = 5 << 4; s[13] = F_RST | F_ACK; wr16(s + 14, 0); wr16(s + 16, 0); wr16(s + 18, 0);
    wr16(s + 16, csum_fold(csum_pseudo(t->lip, t->rip, IPPROTO_TCP_, 20) + csum_add(0, s, 20)));
    NSTAT(NS_TCP_RST_TX); NSTAT(NS_TCP_TX);
    ip_output(IPPROTO_TCP_, t->lip, t->rip, s, 20, 0);
}

/* ---------------------------------------------------------------- output engine */
static void arm_rtx(tcb_t *t) { t->rtx_deadline = net_now() + t->rto; }

static void tcp_output_ex(tcb_t *t, int force_probe)
{
    if (t->state != TCPS_ESTABLISHED && t->state != TCPS_CLOSE_WAIT && t->state != TCPS_FIN_WAIT_1 &&
        t->state != TCPS_CLOSING && t->state != TCPS_LAST_ACK)
        return;
    for (;;) {
        const uint32_t data_end = t->snd_una + t->sndq.len;
        uint32_t unsent, wnd, flight, avail, len, off;
        int fin = 0, nodelay, forced = 0;
        if (SEQ_GT(t->snd_nxt, data_end))
            break;                                          /* the FIN is already out in this pass */
        unsent = data_end - t->snd_nxt;
        off = t->snd_nxt - t->snd_una;
        wnd = min32(t->snd_wnd, t->cwnd);
        flight = t->snd_nxt - t->snd_una;
        avail = wnd > flight ? wnd - flight : 0;
        len = min32(min32(unsent, avail), t->mss);
        if (force_probe && len == 0 && unsent > 0) {
            len = 1;                                        /* zero-window probe: one byte beyond the window (BSD t_force) */
            forced = 1;
            force_probe = 0;
            NSTAT(NS_TCP_PERSIST);
        }
        nodelay = t->sock ? t->sock->nodelay : 1;
        if (!forced && len > 0 && len < t->mss && flight > 0 && !nodelay && !(t->fin_queued && len == unsent))
            len = 0;                                        /* Nagle: hold a small segment while data is unacknowledged */
        if (!forced && len > 0 && len < t->mss && len < unsent && flight > 0)
            len = 0;                                        /* sender-side SWS avoidance: do not chase a small window */
        if (len == 0) {
            if (t->fin_queued && unsent == 0 && t->snd_nxt == data_end && !t->fin_acked) {
                fin = 1;
            } else {
                break;
            }
        } else if (!forced && t->fin_queued && len == unsent && len < avail) {
            fin = 1;                                        /* piggyback the FIN on the last data segment */
        }
        {
            const uint8_t flags = (uint8_t)(F_ACK | (len && len == unsent ? F_PSH : 0) | (fin ? F_FIN : 0));
            const uint32_t seq = t->snd_nxt;
            xmit(t, seq, flags, off, len, 0, 0);
            if (forced) {                                   /* a probe is not part of the flow: no snd_nxt advance, no RTO, no RTT */
                if (SEQ_GT(seq + len, t->snd_max)) t->snd_max = seq + len;
                break;
            }
            if (!t->rtt_timing && SEQ_GEQ(seq, t->snd_max) && (len || fin)) {
                t->rtt_timing = 1;
                t->rtt_seq = seq + len + fin;
                t->rtt_start = net_now();
            }
            t->snd_nxt += len + (uint32_t)fin;
            if (SEQ_GT(t->snd_nxt, t->snd_max))
                t->snd_max = t->snd_nxt;
            if (!t->rtx_deadline)
                arm_rtx(t);
            t->persist_deadline = 0;
            if (fin) {
                t->fin_sent = 1;
                if (t->state == TCPS_ESTABLISHED) t->state = TCPS_FIN_WAIT_1;
                else if (t->state == TCPS_CLOSE_WAIT) t->state = TCPS_LAST_ACK;
                break;
            }
        }
    }
    {   /* persist timer: data waiting, peer window closed, nothing in flight to provoke an ACK */
        const uint32_t data_end = t->snd_una + t->sndq.len;
        if (SEQ_GT(data_end, t->snd_nxt) && t->snd_wnd == 0 && t->snd_una == t->snd_nxt && !t->persist_deadline) {
            t->persist_shift = 0;
            t->persist_deadline = net_now() + t->rto;
        }
    }
}

void tcp_output(tcb_t *t) { tcp_output_ex(t, 0); }

/* Retransmits the segment at snd_una (SYN, SYN-ACK, data or FIN). Returns how much sequence space it covers. */
static uint32_t retransmit_one(tcb_t *t)
{
    const uint32_t data_end = t->snd_una + t->sndq.len;
    NSTAT(NS_TCP_RETRANS);
    t->rtt_timing = 0;                                      /* Karn: never time a retransmitted segment */
    if (t->state == TCPS_SYN_SENT) { send_syn(t, 0); return 0; }
    if (t->state == TCPS_SYN_RCVD) { send_syn(t, 1); return 0; }
    if (SEQ_LT(t->snd_una, data_end)) {
        const uint32_t queued = data_end - t->snd_una;
        const uint32_t was_sent = SEQ_GT(t->snd_max, data_end) ? queued : t->snd_max - t->snd_una;
        const uint32_t n = min32(t->mss, was_sent ? was_sent : queued);
        const int last = n == queued;
        const int fin = last && t->fin_queued && SEQ_GT(t->snd_max, data_end);
        xmit(t, t->snd_una, (uint8_t)(F_ACK | (last ? F_PSH : 0) | (fin ? F_FIN : 0)), 0, n, 0, 0);
        return n + (uint32_t)fin;
    }
    if (t->fin_sent && !t->fin_acked) {
        xmit(t, data_end, F_ACK | F_FIN, 0, 0, 0, 0);
        return 1;
    }
    return 0;
}

/* ---------------------------------------------------------------- connection setup */
tcb_t *tcp_connect(sock_t *s, ip4_t dst, uint16_t dport, int32_t *err)
{
    ip4_t src;
    uint32_t mtu;
    tcb_t *t;
    int32_t st = ip_route_src(dst, &src, &mtu);
    if (st) { *err = st; return 0; }
    if (s->lip) src = s->lip;
    if (!s->lport) {
        s->lport = sock_alloc_port(SK_STREAM);
        if (!s->lport) { *err = NET_ERR(WSAEADDRINUSE); return 0; }
        s->bound = 1;
    }
    if (tcb_lookup(src, s->lport, dst, dport)) { *err = NET_ERR(WSAEADDRINUSE); return 0; }
    t = tcb_alloc(s, s->sndbuf, s->rcvbuf);
    if (!t) { *err = STATUS_NO_MEMORY; return 0; }
    t->sock = s;
    t->lip = src; t->lport = s->lport; t->rip = dst; t->rport = dport;
    t->iss = make_isn(src, s->lport, dst, dport);
    t->snd_una = t->snd_nxt = t->snd_max = t->iss;
    t->mss = min32(mtu - 40, 65535);
    t->state = TCPS_SYN_SENT;
    t->last_rx = net_now();
    t->rcv_adv = 0;
    send_syn(t, 0);
    t->snd_nxt = t->snd_max = t->iss + 1;
    t->rtt_timing = 1; t->rtt_seq = t->iss + 1; t->rtt_start = net_now();
    arm_rtx(t);
    s->tcb = t;
    s->lip = s->lip ? s->lip : src;
    s->rip = dst; s->rport = dport;
    return t;
}

int32_t tcp_listen(sock_t *s, uint32_t backlog)
{
    if (backlog < 1) backlog = 1;
    if (backlog > 128) backlog = 128;
    s->backlog = backlog;
    s->listening = 1;
    return 0;
}

tcb_t *tcp_accept_dequeue(sock_t *l)
{
    tcb_t *t = l->acc_head;
    if (!t)
        return 0;
    l->acc_head = t->acc_next;
    if (!l->acc_head) l->acc_tail = 0;
    t->acc_next = 0;
    t->parent = 0;
    t->queued = 0;
    --l->acc_count;
    return t;
}

static void passive_open(sock_t *l, ip4_t src, ip4_t dst, uint16_t sport, uint16_t dport, uint32_t seq, uint32_t wnd, uint32_t peer_mss)
{
    tcb_t *c, *t;
    uint32_t pending = l->acc_count, mtu = NET_MTU;
    for (c = g_tcbs; c; c = c->next)
        if (c->parent == l && c->state == TCPS_SYN_RCVD)
            ++pending;
    if (pending >= l->backlog)
        return;                                             /* queue full: drop the SYN, the peer retries */
    ip_route_src(src, 0, &mtu);
    t = tcb_alloc(0, l->sndbuf, l->rcvbuf);
    if (!t)
        return;
    t->parent = l;
    t->passive = 1;
    t->lip = dst; t->lport = dport; t->rip = src; t->rport = sport;
    t->irs = seq;
    t->rcv_nxt = seq + 1;
    t->iss = make_isn(dst, dport, src, sport);
    t->snd_una = t->iss;
    t->mss = min32(peer_mss ? peer_mss : DEF_MSS, mtu - 40);
    if (t->mss < 64) t->mss = 64;
    t->snd_wnd = wnd; t->snd_wl1 = seq; t->snd_wl2 = 0;
    t->state = TCPS_SYN_RCVD;
    t->last_rx = net_now();
    send_syn(t, 1);
    t->snd_nxt = t->snd_max = t->iss + 1;
    t->rcv_adv = t->rcv_nxt + min32(t->rcvq.limit, 65535);
    t->rtt_timing = 1; t->rtt_seq = t->iss + 1; t->rtt_start = net_now();
    arm_rtx(t);
}

/* ---------------------------------------------------------------- close / abort / reset */
/* Error termination (RST, timeout, abort): both queues are discarded. */
static void tcb_die(tcb_t *t, int32_t err)
{
    t->state = TCPS_CLOSED;
    if (err && !t->err) t->err = err;
    t->rtx_deadline = t->persist_deadline = t->tw_deadline = t->ack_deadline = t->ka_deadline = 0;
    bq_free(&t->sndq);
    bq_free(&t->rcvq);
    tcb_notify(t);
}

/* Graceful completion (LAST_ACK acked, TIME_WAIT over): data the application has not read yet stays readable. */
static void tcb_closed(tcb_t *t)
{
    t->state = TCPS_CLOSED;
    t->rtx_deadline = t->persist_deadline = t->tw_deadline = t->ack_deadline = t->ka_deadline = 0;
    bq_free(&t->sndq);
    tcb_notify(t);
}

void tcp_abort(tcb_t *t, int send_rst)
{
    if (send_rst && t->state != TCPS_CLOSED && t->state != TCPS_SYN_SENT && t->state != TCPS_TIME_WAIT)
        send_rst_conn(t);
    tcb_die(t, NET_ERR(WSAECONNABORTED));
}

void tcp_shutdown_write(tcb_t *t)
{
    if (t->fin_queued)
        return;
    if (t->state == TCPS_ESTABLISHED || t->state == TCPS_CLOSE_WAIT || t->state == TCPS_SYN_RCVD) {
        t->fin_queued = 1;
        tcp_output(t);
    }
}

void tcp_sock_closed(sock_t *s)
{
    tcb_t *t;
    if (s->listening) {                                     /* listener: reset every unaccepted / half-open child */
        tcb_t *c, *n;
        s->listening = 0;
        for (c = g_tcbs; c; c = n) {
            n = c->next;
            if (c->parent == s) {
                if (c->state != TCPS_CLOSED && c->state != TCPS_TIME_WAIT)
                    send_rst_conn(c);
                tcb_free(c);
            }
        }
        return;
    }
    t = s->tcb;
    if (!t)
        return;
    t->sock = 0;
    s->tcb = 0;
    if (t->state == TCPS_CLOSED || t->state == TCPS_SYN_SENT || t->state == TCPS_TIME_WAIT) {
        if (t->state != TCPS_TIME_WAIT)
            tcb_closed(t);                                  /* reaped by the timer sweep; TIME_WAIT keeps running as an orphan */
        bq_free(&t->rcvq);
        t->rcvq.limit = 0;
        return;
    }
    if ((s->linger_on && s->linger_secs == 0) || t->rcvq.len > 0) {
        send_rst_conn(t);                                   /* abortive close, or unread data (RFC 2525 2.17) */
        tcb_die(t, NET_ERR(WSAECONNRESET));
        return;
    }
    t->rcvq.limit = 0;                                      /* nothing can be delivered any more: later data draws a RST */
    if (t->state == TCPS_ESTABLISHED || t->state == TCPS_CLOSE_WAIT || t->state == TCPS_SYN_RCVD)
        tcp_shutdown_write(t);
    if (t->state == TCPS_FIN_WAIT_2)
        t->tw_deadline = net_now() + FIN_WAIT2_MS;
}

/* ARP for `nexthop` failed: connections still in SYN_SENT towards it cannot ever complete. */
void tcp_host_unreachable(ip4_t nexthop)
{
    tcb_t *t;
    for (t = g_tcbs; t; t = t->next)
        if (t->state == TCPS_SYN_SENT && net_nexthop(t->rip) == nexthop)
            tcb_die(t, NET_ERR(WSAEHOSTUNREACH));
}

static void enter_time_wait(tcb_t *t)
{
    t->state = TCPS_TIME_WAIT;
    t->rtx_deadline = t->persist_deadline = t->ka_deadline = 0;
    t->tw_deadline = net_now() + 2 * MSL_MS;
    bq_free(&t->sndq);
    tcb_notify(t);
}

/* ---------------------------------------------------------------- RTT / congestion */
static void rtt_sample(tcb_t *t, uint32_t r)
{
    int32_t delta;
    if (r < 1) r = 1;
    if (!t->srtt) {
        t->srtt = r << 3;
        t->rttvar = r << 1;
    } else {
        delta = (int32_t)r - (int32_t)(t->srtt >> 3);
        t->srtt = (uint32_t)((int32_t)t->srtt + delta);
        if (delta < 0) delta = -delta;
        t->rttvar = (uint32_t)((int32_t)t->rttvar + delta - (int32_t)(t->rttvar >> 2));
    }
    t->rto = (t->srtt >> 3) + t->rttvar;
    if (t->rto < RTO_MIN) t->rto = RTO_MIN;
    if (t->rto > RTO_MAX) t->rto = RTO_MAX;
}

static void init_cwnd(tcb_t *t)
{
    t->cwnd = min32(4 * t->mss, max32(2 * t->mss, 4380));   /* RFC 3390 initial window */
    t->ssthresh = 0x7fffffffu;
}

/* ---------------------------------------------------------------- input */
static void established(tcb_t *t, uint32_t seq, uint32_t ack, uint32_t wnd)
{
    t->state = TCPS_ESTABLISHED;
    t->was_est = 1;
    t->snd_una = ack;
    t->snd_wnd = wnd; t->snd_wl1 = seq; t->snd_wl2 = ack;
    if (wnd > t->snd_max_wnd) t->snd_max_wnd = wnd;
    t->rtx_deadline = 0;
    t->rtx_count = 0;
    init_cwnd(t);
    if (t->parent) {                                        /* passive: hand the connection to accept() */
        sock_t *l = t->parent;
        t->acc_next = 0;
        if (l->acc_tail) l->acc_tail->acc_next = t; else l->acc_head = t;
        l->acc_tail = t;
        ++l->acc_count;
        t->queued = 1;
    }
    tcp_keepalive_changed(t);
    tcb_notify(t);
}

static void got_reset(tcb_t *t)
{
    NSTAT(NS_TCP_RST_RX);
    if (t->state == TCPS_SYN_RCVD && t->passive) {          /* half-open connection from a listener: forget it silently */
        tcb_free(t);
        return;
    }
    tcb_die(t, t->state == TCPS_SYN_RCVD ? NET_ERR(WSAECONNREFUSED) : NET_ERR(WSAECONNRESET));
}

/* Processes the ACK field. Returns 0 if the segment must be dropped. */
static int process_ack(tcb_t *t, uint32_t seq, uint32_t ack, uint32_t wnd, uint32_t dlen, uint8_t flags)
{
    const uint64_t now = net_now();
    if (SEQ_GT(ack, t->snd_max)) {                          /* acknowledges something we never sent */
        send_ack(t);
        return 0;
    }
    if (SEQ_LEQ(ack, t->snd_una)) {
        if (ack == t->snd_una && dlen == 0 && !(flags & F_FIN) && wnd == t->snd_wnd && t->snd_una != t->snd_max) {
            ++t->dupacks;
            if (t->dupacks == 3 && !t->in_recovery) {       /* fast retransmit (RFC 5681 3.2) */
                const uint32_t flight = t->snd_max - t->snd_una;
                const uint32_t save = t->snd_nxt;
                t->ssthresh = max32(flight / 2, 2 * t->mss);
                t->recover = t->snd_max;
                t->in_recovery = 1;
                NSTAT(NS_TCP_FAST_RETRANS);
                t->snd_nxt = t->snd_una;
                retransmit_one(t);
                t->snd_nxt = save;
                t->cwnd = t->ssthresh + 3 * t->mss;
            } else if (t->dupacks > 3 && t->in_recovery) {
                t->cwnd += t->mss;                          /* window inflation */
                tcp_output(t);
            }
        }
    } else {
        const uint32_t acked = ack - t->snd_una, data_end = t->snd_una + t->sndq.len;
        uint32_t data_acked = acked;
        if (t->fin_sent && SEQ_GT(ack, data_end)) {
            t->fin_acked = 1;
            data_acked = data_end - t->snd_una;
        }
        if (data_acked > t->sndq.len) data_acked = t->sndq.len;
        bq_drop(&t->sndq, data_acked);
        t->snd_una = ack;
        if (SEQ_LT(t->snd_nxt, t->snd_una)) t->snd_nxt = t->snd_una;
        if (t->rtt_timing && SEQ_GEQ(ack, t->rtt_seq)) {
            rtt_sample(t, (uint32_t)(now - t->rtt_start));
            t->rtt_timing = 0;
        }
        if (t->in_recovery) {
            if (SEQ_GEQ(ack, t->recover)) {                 /* full ACK: leave recovery (NewReno, RFC 6582) */
                t->cwnd = min32(t->ssthresh, max32(t->snd_max - t->snd_una, t->mss) + t->mss);
                t->in_recovery = 0;
                t->dupacks = 0;
            } else {                                        /* partial ACK: the next hole is lost too */
                const uint32_t save = t->snd_nxt;
                t->snd_nxt = t->snd_una;
                retransmit_one(t);
                t->snd_nxt = save;
                t->cwnd = t->cwnd > data_acked ? t->cwnd - data_acked : t->mss;
                if (data_acked >= t->mss) t->cwnd += t->mss;
            }
        } else {
            t->dupacks = 0;
            if (t->cwnd < t->ssthresh) t->cwnd += min32(acked, t->mss);
            else t->cwnd += max32(1, t->mss * t->mss / t->cwnd);
        }
        t->rtx_count = 0;
        if (t->srtt) {
            t->rto = (t->srtt >> 3) + t->rttvar;
            if (t->rto < RTO_MIN) t->rto = RTO_MIN;
            if (t->rto > RTO_MAX) t->rto = RTO_MAX;
        } else {
            t->rto = RTO_INIT;
        }
        t->rtx_deadline = t->snd_una == t->snd_max ? 0 : now + t->rto;
        tcb_notify(t);                                      /* send buffer space opened */
    }
    if (SEQ_LT(t->snd_wl1, seq) || (t->snd_wl1 == seq && SEQ_LEQ(t->snd_wl2, ack))) {
        t->snd_wnd = wnd; t->snd_wl1 = seq; t->snd_wl2 = ack;
        if (wnd > t->snd_max_wnd) t->snd_max_wnd = wnd;
        if (wnd) t->persist_deadline = 0;
    }
    return 1;
}

static void segment_for_tcb(tcb_t *t, uint32_t seq, uint32_t ack, uint8_t flags, uint32_t wnd, const uint8_t *data, uint32_t dlen,
                            uint32_t peer_mss)
{
    const uint64_t now = net_now();
    uint32_t slen = dlen + ((flags & F_SYN) ? 1 : 0) + ((flags & F_FIN) ? 1 : 0);
    uint32_t rwin, right;
    int has_fin;
    t->last_rx = now;
    t->ka_probes = 0;
    if (t->ka_deadline && t->sock && t->sock->keepalive && (t->state == TCPS_ESTABLISHED || t->state == TCPS_CLOSE_WAIT))
        t->ka_deadline = now + ka_idle_ms(t);

    if (t->state == TCPS_SYN_SENT) {
        const int ack_ok = (flags & F_ACK) && SEQ_GT(ack, t->iss) && SEQ_LEQ(ack, t->snd_nxt);
        if ((flags & F_ACK) && !ack_ok) {
            if (!(flags & F_RST))
                reply_rst(t->lip, t->rip, t->lport, t->rport, seq, ack, flags, slen);
            return;
        }
        if (flags & F_RST) {
            if (ack_ok) { NSTAT(NS_TCP_RST_RX); tcb_die(t, NET_ERR(WSAECONNREFUSED)); }
            return;
        }
        if (!(flags & F_SYN))
            return;
        t->irs = seq;
        t->rcv_nxt = seq + 1;
        if (peer_mss) t->mss = min32(t->mss, peer_mss);
        else t->mss = min32(t->mss, DEF_MSS);
        if (t->mss < 64) t->mss = 64;
        t->rcv_adv = t->rcv_nxt + min32(t->rcvq.limit, 65535);
        if (ack_ok) {
            if (t->rtt_timing && SEQ_GEQ(ack, t->rtt_seq) && t->rtx_count == 0)
                rtt_sample(t, (uint32_t)(now - t->rtt_start));
            t->rtt_timing = 0;
            established(t, seq, ack, wnd);
            send_ack(t);
        } else {                                            /* simultaneous open */
            t->state = TCPS_SYN_RCVD;
            send_syn(t, 1);
            arm_rtx(t);
        }
        return;
    }

    if (t->state == TCPS_SYN_RCVD && (flags & F_SYN) && seq == t->irs) {   /* our SYN-ACK was lost: send it again */
        send_syn(t, 1);
        return;
    }

    /* 1. sequence number acceptability (RFC 793 p.69) */
    rwin = SEQ_GT(t->rcv_adv, t->rcv_nxt) ? t->rcv_adv - t->rcv_nxt : 0;
    right = t->rcv_nxt + rwin;
    {
        int ok;
        if (slen == 0) ok = rwin == 0 ? seq == t->rcv_nxt : (SEQ_GEQ(seq, t->rcv_nxt) && SEQ_LT(seq, right));
        else if (rwin == 0) ok = 0;
        else ok = (SEQ_GEQ(seq, t->rcv_nxt) && SEQ_LT(seq, right)) ||
                  (SEQ_GEQ(seq + slen - 1, t->rcv_nxt) && SEQ_LT(seq + slen - 1, right));
        if (t->state == TCPS_TIME_WAIT && (flags & F_FIN) && !(flags & F_RST)) {   /* retransmitted FIN: re-ACK, restart 2MSL */
            t->tw_deadline = now + 2 * MSL_MS;
            send_ack(t);
            return;
        }
        if (!ok) {
            if (!(flags & F_RST)) {
                NSTAT(NS_TCP_DUPACK_TX);
                send_ack(t);
            }
            return;
        }
    }
    /* 2. RST (RFC 5961: exact match resets, in-window gets a challenge ACK; RFC 1337: ignored in TIME_WAIT) */
    if (flags & F_RST) {
        if (t->state == TCPS_TIME_WAIT) return;
        if (seq == t->rcv_nxt) got_reset(t);
        else send_ack(t);
        return;
    }
    /* 3. SYN inside the window: challenge ACK, never accepted (RFC 5961 4.2) */
    if (flags & F_SYN) {
        send_ack(t);
        return;
    }
    if (!(flags & F_ACK))
        return;
    /* 4. ACK processing */
    if (t->state == TCPS_SYN_RCVD) {
        if (SEQ_LT(t->snd_una, ack) && SEQ_LEQ(ack, t->snd_nxt)) {
            if (t->rtt_timing && SEQ_GEQ(ack, t->rtt_seq) && t->rtx_count == 0)
                rtt_sample(t, (uint32_t)(now - t->rtt_start));
            t->rtt_timing = 0;
            established(t, seq, ack, wnd);
        } else {
            reply_rst(t->lip, t->rip, t->lport, t->rport, seq, ack, flags, slen);
            return;
        }
    }
    if (!process_ack(t, seq, ack, wnd, dlen, flags))
        return;
    if (t->fin_acked) {
        if (t->state == TCPS_FIN_WAIT_1) {
            t->state = TCPS_FIN_WAIT_2;
            t->rtx_deadline = 0;
            if (!t->sock) t->tw_deadline = now + FIN_WAIT2_MS;
            tcb_notify(t);
        } else if (t->state == TCPS_CLOSING) {
            enter_time_wait(t);
        } else if (t->state == TCPS_LAST_ACK) {
            tcb_closed(t);
            return;
        }
    }
    /* 5. data and FIN */
    has_fin = (flags & F_FIN) != 0;
    if (SEQ_LT(seq, t->rcv_nxt)) {                          /* trim what we already have */
        uint32_t cut = t->rcv_nxt - seq;
        if (cut > dlen) cut = dlen;
        data += cut; dlen -= cut; seq += cut;
        if (has_fin && SEQ_LT(seq + dlen, t->rcv_nxt)) has_fin = 0;
    }
    if (SEQ_GT(seq + dlen + (uint32_t)has_fin, right)) {    /* trim what does not fit the window */
        if (SEQ_GT(seq + dlen, right)) dlen = right - seq;
        has_fin = 0;
    }
    if (t->state == TCPS_ESTABLISHED || t->state == TCPS_FIN_WAIT_1 || t->state == TCPS_FIN_WAIT_2) {
        if (dlen > 0) {
            if (!t->sock && t->state != TCPS_ESTABLISHED && t->rcvq.limit == 0) {   /* orphan: nobody can read this (RFC 1122 4.2.2.13) */
                send_rst_conn(t);
                tcb_die(t, NET_ERR(WSAECONNRESET));
                return;
            }
            if (seq == t->rcv_nxt) {
                const uint32_t n = bq_write(&t->rcvq, data, dlen);
                t->rcv_nxt += n;
                if (n < dlen) has_fin = 0;                  /* could not take everything: leave the FIN for the retransmission */
                if (n) {
                    t->ack_pending = 1;
                    ack_dirty = 1;
                    if (!t->ack_deadline) t->ack_deadline = now + DELACK_MS;
                    t->rx_unacked += n;
                    if (t->rx_unacked >= 2 * t->mss) t->ack_now = 1;    /* RFC 1122 4.2.3.2: ACK at least every 2nd full segment */
                    tcb_notify(t);
                }
            } else {
                NSTAT(NS_TCP_OOO_DROP);                     /* out of order: drop, duplicate ACK triggers the peer's fast retransmit */
                NSTAT(NS_TCP_DUPACK_TX);
                send_ack(t);
                return;
            }
        }
        if (has_fin && seq + dlen == t->rcv_nxt) {
            t->rcv_nxt += 1;
            t->rcvd_fin = 1;
            t->ack_now = 1;
            if (t->state == TCPS_ESTABLISHED) t->state = TCPS_CLOSE_WAIT;
            else if (t->state == TCPS_FIN_WAIT_1) t->state = t->fin_acked ? TCPS_TIME_WAIT : TCPS_CLOSING;
            else if (t->state == TCPS_FIN_WAIT_2) t->state = TCPS_TIME_WAIT;
            if (t->state == TCPS_TIME_WAIT) enter_time_wait(t);
            tcb_notify(t);
        }
    } else if (dlen > 0 || has_fin) {
        /* CLOSE_WAIT / CLOSING / LAST_ACK: the peer already sent its FIN, so data here is a stray retransmission */
        t->ack_now = 1;
    }
    tcp_output(t);                                          /* new data may go out now, carrying the ACK */
    if (t->ack_now)
        send_ack(t);
}

void tcp_input(ip4_t src, ip4_t dst, const uint8_t *seg, uint32_t len)
{
    uint32_t hlen, seq, ack, wnd, dlen, slen, peer_mss = 0, i;
    uint16_t sport, dport;
    uint8_t flags;
    tcb_t *t;
    sock_t *l;
    NSTAT(NS_TCP_RX);
    if (len < 20)
        return;
    hlen = (uint32_t)(seg[12] >> 4) * 4;
    if (hlen < 20 || hlen > len)
        return;
    if (ip_is_broadcast(dst) || ip_is_broadcast(src))
        return;
    if (csum_fold(csum_pseudo(src, dst, IPPROTO_TCP_, len) + csum_add(0, seg, len)) != 0) {
        NSTAT(NS_TCP_BAD_CSUM);
        return;
    }
    sport = rd16(seg); dport = rd16(seg + 2);
    seq = rd32(seg + 4); ack = rd32(seg + 8);
    flags = seg[13];
    wnd = rd16(seg + 14);
    dlen = len - hlen;
    slen = dlen + ((flags & F_SYN) ? 1 : 0) + ((flags & F_FIN) ? 1 : 0);
    for (i = 20; i < hlen; ) {                              /* options: only MSS is used */
        const uint8_t kind = seg[i];
        if (kind == 0) break;
        if (kind == 1) { ++i; continue; }
        if (i + 1 >= hlen || seg[i + 1] < 2 || i + seg[i + 1] > hlen) break;
        if (kind == 2 && seg[i + 1] == 4) peer_mss = rd16(seg + i + 2);
        i += seg[i + 1];
    }
    t = tcb_lookup(dst, dport, src, sport);
    if (t && t->state == TCPS_TIME_WAIT && (flags & (F_SYN | F_ACK | F_RST)) == F_SYN && SEQ_GT(seq, t->rcv_nxt)) {
        tcb_free(t);                                        /* RFC 1122 4.2.2.13: a new incarnation may reuse the tuple */
        t = 0;
    }
    if (t) {
        segment_for_tcb(t, seq, ack, flags, wnd, seg + hlen, dlen, peer_mss);
        return;
    }
    if (flags & F_RST)
        return;
    l = find_listener(dst, dport);
    if (l) {
        if ((flags & (F_SYN | F_ACK)) == F_SYN)
            passive_open(l, src, dst, sport, dport, seq, wnd, peer_mss);
        else if (flags & F_ACK)
            reply_rst(dst, src, dport, sport, seq, ack, flags, slen);
        return;
    }
    reply_rst(dst, src, dport, sport, seq, ack, flags, slen);      /* closed port */
}

/* ---------------------------------------------------------------- application side */
int tcp_can_write(const tcb_t *t) { return t->state == TCPS_ESTABLISHED || t->state == TCPS_CLOSE_WAIT; }

void tcp_after_read(tcb_t *t)
{
    const uint32_t cur = SEQ_GT(t->rcv_adv, t->rcv_nxt) ? t->rcv_adv - t->rcv_nxt : 0;
    const uint32_t now_win = rcv_window(t);
    if (t->state != TCPS_ESTABLISHED && t->state != TCPS_FIN_WAIT_1 && t->state != TCPS_FIN_WAIT_2)
        return;
    if (now_win > cur && now_win - cur >= min32(t->mss, t->rcvq.limit / 2))
        send_ack(t);                                        /* window update */
}

/* ---------------------------------------------------------------- timers */
void tcp_flush_acks(void)
{
    tcb_t *t;
    if (!ack_dirty)
        return;
    ack_dirty = 0;
    for (t = g_tcbs; t; t = t->next)
        if (t->ack_pending && t->state != TCPS_CLOSED)
            send_ack(t);
}

void tcp_timers(uint64_t now)
{
    tcb_t **pp = &g_tcbs;
    while (*pp) {
        tcb_t *t = *pp;
        if (t->state == TCPS_CLOSED && !t->sock && !t->queued) {    /* finished orphan / dead half-open child: reap */
            *pp = t->next;
            bq_free(&t->sndq);
            bq_free(&t->rcvq);
            kfree(t);
            continue;
        }
        if (t->ack_pending && t->ack_deadline && now >= t->ack_deadline && t->state != TCPS_CLOSED)
            send_ack(t);
        if (t->state == TCPS_TIME_WAIT && now >= t->tw_deadline)
            tcb_closed(t);
        else if (t->state == TCPS_FIN_WAIT_2 && t->tw_deadline && now >= t->tw_deadline)
            tcb_closed(t);
        if (t->rtx_deadline && now >= t->rtx_deadline && t->state != TCPS_CLOSED) {
            const int syn = t->state == TCPS_SYN_SENT || t->state == TCPS_SYN_RCVD;
            ++t->rtx_count;
            if ((syn && t->rtx_count >= MAX_SYN_TRIES) || (!syn && t->rtx_count > MAX_DATA_RTX)) {
                t->timed_out = 1;
                if (!syn) send_rst_conn(t);
                tcb_die(t, NET_ERR(WSAETIMEDOUT));
            } else {
                uint32_t consumed = 0;
                if (!syn) {                                 /* RFC 5681 3.1: multiplicative decrease, loss window = 1 segment */
                    t->ssthresh = max32((t->snd_max - t->snd_una) / 2, 2 * t->mss);
                    t->cwnd = t->mss;
                    t->in_recovery = 0;
                    t->dupacks = 0;
                    t->snd_nxt = t->snd_una;                /* go back N: the rest is resent as ACKs open the window */
                }
                t->rto = t->rto * 2 > RTO_MAX ? RTO_MAX : t->rto * 2;
                consumed = retransmit_one(t);
                if (!syn)
                    t->snd_nxt = t->snd_una + consumed;
                arm_rtx(t);
            }
        }
        if (t->persist_deadline && now >= t->persist_deadline && t->state != TCPS_CLOSED) {
            if (t->snd_wnd == 0 && SEQ_GT(t->snd_una + t->sndq.len, t->snd_nxt)) {
                tcp_output_ex(t, 1);
                if (t->persist_shift < 6) ++t->persist_shift;
                t->persist_deadline = now + min32(t->rto << t->persist_shift, RTO_MAX);
            } else {
                t->persist_deadline = 0;
            }
        }
        if (t->ka_deadline && now >= t->ka_deadline && (t->state == TCPS_ESTABLISHED || t->state == TCPS_CLOSE_WAIT)) {
            if (!t->sock || !t->sock->keepalive) {
                t->ka_deadline = 0;
            } else if (t->ka_probes >= ka_cnt(t)) {
                tcb_die(t, NET_ERR(WSAETIMEDOUT));
            } else {
                xmit(t, t->snd_una - 1, F_ACK, 0, 0, 0, 0); /* seq = snd_una - 1 provokes an ACK from a live peer */
                NSTAT(NS_TCP_KEEPALIVE_TX);
                ++t->ka_probes;
                t->ka_deadline = now + ka_intvl_ms(t);
            }
        }
        pp = &(*pp)->next;
    }
}

uint32_t tcp_state_count(int state)
{
    uint32_t n = 0;
    tcb_t *t;
    for (t = g_tcbs; t; t = t->next)
        if (t->state == state)
            ++n;
    return n;
}

unsigned tcp_dump(uint8_t *out, unsigned max_entries)
{
    unsigned n = 0;
    tcb_t *t;
    struct shz_tcp_row *rows = (struct shz_tcp_row *)out;
    for (t = g_tcbs; t && n < max_entries; t = t->next) {
        rows[n].lip_be = bs32(t->lip); rows[n].rip_be = bs32(t->rip);
        rows[n].lport = t->lport; rows[n].rport = t->rport;
        rows[n].state = t->state;
        rows[n].snd_una = t->snd_una; rows[n].snd_nxt = t->snd_nxt; rows[n].rcv_nxt = t->rcv_nxt;
        rows[n].cwnd = t->cwnd; rows[n].rto = t->rto;
        ++n;
    }
    return n;
}
