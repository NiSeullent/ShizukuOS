/* SPDX-License-Identifier: GPL-2.0-only
 * Kernel64 network stack core: the net lock and sleep/wake primitive, paged socket buffers, ARP (RFC 826), IPv4 (RFC 791,
 * 1122: header checksum, fragment reassembly, fragmentation), ICMP echo/unreachable (RFC 792), the loopback interface,
 * the "net" kernel thread and the lazy start-up. See net.h for scope and limits.
 *
 * Concurrency: one mutex (net_mtx) protects every stack structure. Sleepers (blocking socket calls) park on a private
 * semaphore registered in `waiters`; anything that changes a socket calls net_wake_all() and the sleepers re-check their
 * condition (level triggered, so a lost wake-up cannot happen: the check and the registration happen under the lock).
 * Loopback packets are queued and delivered by net_unlock() before the lock is released, so a loopback exchange runs
 * synchronously in the thread that caused it instead of bouncing through the scheduler for every segment.
 */
#include "net.h"

net_cfg_t g_net;
uint32_t g_nstat[NS_COUNT];
uint8_t g_l4[NET_L4_MAX + 128];                     /* transport-header + payload composition buffer (under the lock) */

static kmutex_t net_mtx, init_mtx;

/* ---------------------------------------------------------------- lock / sleep */
typedef struct waiter { struct waiter *next; ksem_t sem; } waiter_t;
static waiter_t *waiters;

static void lo_drain(void);

void net_lock(void) { mutex_lock(&net_mtx); }
int net_lock_held(void) { return net_mtx.locked && net_mtx.owner == thread_current(); }
void net_unlock(void)
{
    KASSERT(net_lock_held());
    lo_drain();
    mutex_unlock(&net_mtx);
}

void net_wake_all(void)
{
    waiter_t *w;
    for (w = waiters; w; w = w->next)
        sem_post(&w->sem);
}

void net_sleep(uint32_t ms)
{
    waiter_t w, **pp;
    sem_init(&w.sem, 0);
    w.next = waiters;
    waiters = &w;
    net_unlock();
    sem_wait_timeout(&w.sem, ms ? ms : 1);
    mutex_lock(&net_mtx);
    for (pp = &waiters; *pp; pp = &(*pp)->next)
        if (*pp == &w) { *pp = w.next; break; }
}

int net_current_terminating(void)
{
    process_t *p = current_process();
    return p && p->terminated;
}

uint64_t net_now(void) { return ticks_now(); }

static uint64_t rng_state = 0x9e3779b97f4a7c15ull;
uint32_t net_rand32(void)
{
    uint64_t t;
    __asm__ volatile("rdtsc; shl $32, %%rdx; or %%rdx, %%rax" : "=a"(t) :: "rdx");
    rng_state ^= t + 0x9e3779b97f4a7c15ull + ticks_now();
    rng_state ^= rng_state << 13;
    rng_state ^= rng_state >> 7;
    rng_state ^= rng_state << 17;
    return (uint32_t)(rng_state >> 16);
}

/* ---------------------------------------------------------------- checksums */
uint32_t csum_add(uint32_t sum, const void *data, uint32_t len)
{
    const uint8_t *p = data;
    while (len > 1) {
        sum += (uint32_t)((p[0] << 8) | p[1]);
        p += 2;
        len -= 2;
    }
    if (len)
        sum += (uint32_t)p[0] << 8;
    return sum;
}
uint16_t csum_fold(uint32_t sum)
{
    while (sum >> 16)
        sum = (sum & 0xffff) + (sum >> 16);
    return (uint16_t)~sum;
}
uint32_t csum_pseudo(ip4_t src, ip4_t dst, uint8_t proto, uint32_t len)
{
    return (src >> 16) + (src & 0xffff) + (dst >> 16) + (dst & 0xffff) + proto + len;
}

/* ---------------------------------------------------------------- paged byte queue */
static bchunk_t *chunk_new(void)
{
    const uint64_t pa = pmm_alloc();
    bchunk_t *c;
    if (!pa)
        return 0;
    c = (bchunk_t *)p2v(pa);
    c->next = 0;
    return c;
}
static void chunk_free(bchunk_t *c) { pmm_free(v2p_direct((uint64_t)c)); }
static uint8_t *chunk_data(bchunk_t *c) { return (uint8_t *)c + sizeof(bchunk_t); }

uint32_t bq_space(const bq_t *q) { return q->len < q->limit ? q->limit - q->len : 0; }

/* Appends a chunk when the tail is full or absent; returns the tail or NULL on exhaustion. */
static bchunk_t *bq_room(bq_t *q)
{
    if (!q->tail || q->toff == BQ_DATA) {
        bchunk_t *c = chunk_new();
        if (!c)
            return 0;
        if (q->tail) q->tail->next = c;
        else { q->head = c; q->hoff = 0; }
        q->tail = c;
        q->toff = 0;
    }
    return q->tail;
}

uint32_t bq_write(bq_t *q, const void *src, uint32_t n)
{
    const uint8_t *s = src;
    uint32_t done = 0;
    if (n > bq_space(q))
        n = bq_space(q);
    while (done < n) {
        bchunk_t *c = bq_room(q);
        uint32_t k;
        if (!c)
            break;
        k = BQ_DATA - q->toff;
        if (k > n - done) k = n - done;
        memcpy(chunk_data(c) + q->toff, s + done, k);
        q->toff += k;
        q->len += k;
        done += k;
    }
    return done;
}

int32_t bq_write_user(bq_t *q, process_t *p, uint64_t uva, uint32_t n, uint32_t *done_out)
{
    uint32_t done = 0;
    int32_t st = STATUS_SUCCESS;
    if (n > bq_space(q))
        n = bq_space(q);
    while (done < n) {
        bchunk_t *c = bq_room(q);
        uint32_t k;
        if (!c) { st = STATUS_NO_MEMORY; break; }
        k = BQ_DATA - q->toff;
        if (k > n - done) k = n - done;
        if (copy_from_user(p, chunk_data(c) + q->toff, uva + done, k)) { st = STATUS_ACCESS_VIOLATION; break; }
        q->toff += k;
        q->len += k;
        done += k;
    }
    *done_out = done;
    return done ? STATUS_SUCCESS : st;
}

void bq_peek(const bq_t *q, uint32_t off, void *dst, uint32_t n)
{
    uint8_t *d = dst;
    bchunk_t *c = q->head;
    uint32_t pos = q->hoff + off;
    while (pos >= BQ_DATA) { c = c->next; pos -= BQ_DATA; }
    while (n) {
        uint32_t k = BQ_DATA - pos;
        if (k > n) k = n;
        memcpy(d, chunk_data(c) + pos, k);
        d += k; n -= k; pos = 0;
        c = c->next;
    }
}

int32_t bq_read_user(bq_t *q, process_t *p, uint64_t uva, uint32_t n, int consume)
{
    bchunk_t *c = q->head;
    uint32_t pos = q->hoff, done = 0;
    while (done < n) {
        uint32_t k = BQ_DATA - pos;
        if (k > n - done) k = n - done;
        if (copy_to_user(p, uva + done, chunk_data(c) + pos, k))
            return STATUS_ACCESS_VIOLATION;
        done += k; pos = 0;
        c = c->next;
    }
    if (consume)
        bq_drop(q, n);
    return STATUS_SUCCESS;
}

void bq_drop(bq_t *q, uint32_t n)
{
    while (n && q->head) {
        const uint32_t end = q->head == q->tail ? q->toff : BQ_DATA;
        uint32_t take = end - q->hoff;
        if (take > n) take = n;
        q->hoff += take;
        q->len -= take;
        n -= take;
        if (q->hoff == end) {
            bchunk_t *h = q->head;
            if (q->head == q->tail) { q->head = q->tail = 0; q->hoff = q->toff = 0; }
            else { q->head = h->next; q->hoff = 0; }
            chunk_free(h);
        }
    }
}

void bq_free(bq_t *q)
{
    bchunk_t *c = q->head;
    while (c) {
        bchunk_t *n = c->next;
        chunk_free(c);
        c = n;
    }
    q->head = q->tail = 0;
    q->hoff = q->toff = q->len = 0;
}

/* ---------------------------------------------------------------- addresses and routing */
int ip_is_local(ip4_t a) { return (a >> 24) == 127 || (g_net.ip && a == g_net.ip); }
int ip_is_broadcast(ip4_t a)
{
    if (a == 0xffffffffu)
        return 1;
    return g_net.ip && g_net.mask && (a & ~g_net.mask) == ~g_net.mask && (a & g_net.mask) == (g_net.ip & g_net.mask);
}

typedef struct { int lo, bcast; ip4_t nexthop, src; uint32_t mtu; } route_t;

static int32_t route_lookup(ip4_t dst, route_t *rt)
{
    memset(rt, 0, sizeof *rt);
    if (ip_is_local(dst)) {                                 /* loopback: replies go back to the address that was used */
        rt->lo = 1; rt->src = dst; rt->mtu = LO_MTU; rt->nexthop = dst;
        return 0;
    }
    if (!g_net.nic_present || dst == 0 || (dst >> 28) == 0xe)     /* no interface / 0.0.0.0 / multicast (not implemented) */
        return NET_ERR(WSAENETUNREACH);
    if (dst == 0xffffffffu || ip_is_broadcast(dst)) {
        rt->bcast = 1; rt->src = g_net.ip; rt->mtu = NET_MTU; rt->nexthop = dst;
        return 0;
    }
    if (!g_net.ip)
        return NET_ERR(WSAENETUNREACH);
    if ((dst & g_net.mask) == (g_net.ip & g_net.mask)) rt->nexthop = dst;
    else if (g_net.gw) rt->nexthop = g_net.gw;
    else return NET_ERR(WSAENETUNREACH);
    rt->src = g_net.ip;
    rt->mtu = NET_MTU;
    return 0;
}

int32_t ip_route_src(ip4_t dst, ip4_t *src, uint32_t *mtu)
{
    route_t rt;
    const int32_t st = route_lookup(dst, &rt);
    if (st)
        return st;
    if (src) *src = rt.src;
    if (mtu) *mtu = rt.mtu;
    return 0;
}

ip4_t net_nexthop(ip4_t dst)
{
    route_t rt;
    return route_lookup(dst, &rt) ? 0 : rt.nexthop;
}

/* ---------------------------------------------------------------- loopback */
typedef struct lo_pkt { struct lo_pkt *next; uint32_t len; uint8_t data[]; } lo_pkt_t;
static lo_pkt_t *lo_head, *lo_tail;
static int lo_busy;
static void ip_input(const uint8_t *p, uint32_t len, const uint8_t *smac);

static void lo_push(const uint8_t *pkt, uint32_t len)
{
    lo_pkt_t *q = kmalloc(sizeof *q + len);
    if (!q)
        return;                                             /* out of heap: dropped like a full queue; TCP retransmits */
    q->next = 0;
    q->len = len;
    memcpy(q->data, pkt, len);
    if (lo_tail) lo_tail->next = q; else lo_head = q;
    lo_tail = q;
    NSTAT(NS_LO_PKTS);
}

static void lo_drain(void)
{
    if (lo_busy)
        return;
    lo_busy = 1;
    while (lo_head) {
        lo_pkt_t *q = lo_head;
        lo_head = q->next;
        if (!lo_head) lo_tail = 0;
        ip_input(q->data, q->len, 0);
        kfree(q);
    }
    lo_busy = 0;
}

/* ---------------------------------------------------------------- ARP */
#define ARP_N 16
#define ARP_PEND 3
#define ARP_VALID_MS 60000u                      /* entries live 60 s and are refreshed by traffic from that neighbour */
#define ARP_RETRY_MS 1000u
#define ARP_TRIES 3
enum { A_FREE = 0, A_INCOMPLETE, A_VALID };
typedef struct {
    ip4_t ip;
    uint8_t mac[6];
    uint8_t state, tries;
    uint64_t expires, next_tx;
    uint8_t *pend[ARP_PEND];
    uint16_t pend_len[ARP_PEND];
} arp_ent_t;
static arp_ent_t arp_tab[ARP_N];
static uint8_t g_out[ETH_HLEN + LO_MTU + 64];            /* outgoing IPv4 packet under construction, ETH_HLEN of headroom */

static arp_ent_t *arp_find(ip4_t ip)
{
    unsigned i;
    for (i = 0; i < ARP_N; ++i)
        if (arp_tab[i].state != A_FREE && arp_tab[i].ip == ip)
            return &arp_tab[i];
    return 0;
}

static void arp_free_pending(arp_ent_t *e)
{
    unsigned i;
    for (i = 0; i < ARP_PEND; ++i)
        if (e->pend[i]) { kfree(e->pend[i]); e->pend[i] = 0; }
}

static arp_ent_t *arp_alloc(ip4_t ip)
{
    arp_ent_t *best = 0;
    unsigned i;
    for (i = 0; i < ARP_N; ++i) {
        if (arp_tab[i].state == A_FREE) { best = &arp_tab[i]; break; }
        if (!best || arp_tab[i].expires < best->expires) best = &arp_tab[i];
    }
    arp_free_pending(best);
    memset(best, 0, sizeof *best);
    best->ip = ip;
    return best;
}

static void eth_send_raw(const uint8_t *dst_mac, uint16_t type, const uint8_t *payload, uint32_t len)
{
    uint8_t f[ETH_HLEN + 64];
    if (len > 64) return;
    memcpy(f, dst_mac, 6);
    memcpy(f + 6, g_net.mac, 6);
    wr16(f + 12, type);
    memcpy(f + ETH_HLEN, payload, len);
    if (nic_send(f, ETH_HLEN + len) == 0)
        NSTAT(NS_ETH_TX);
}

static void arp_send(uint16_t op, const uint8_t *dst_mac, const uint8_t *tha, ip4_t tpa, ip4_t spa)
{
    uint8_t a[28];
    wr16(a, 1); wr16(a + 2, 0x0800); a[4] = 6; a[5] = 4; wr16(a + 6, op);
    memcpy(a + 8, g_net.mac, 6);
    wr32(a + 14, spa);
    if (tha) memcpy(a + 18, tha, 6); else memset(a + 18, 0, 6);
    wr32(a + 24, tpa);
    eth_send_raw(dst_mac, 0x0806, a, 28);
}

static void arp_request(ip4_t ip)
{
    static const uint8_t bc[6] = {0xff, 0xff, 0xff, 0xff, 0xff, 0xff};
    arp_send(1, bc, 0, ip, g_net.ip);
    NSTAT(NS_ARP_REQ_TX);
}

static void arp_announce(void)                             /* RFC 5227 announcement after configuration */
{
    static const uint8_t bc[6] = {0xff, 0xff, 0xff, 0xff, 0xff, 0xff};
    if (g_net.nic_present && g_net.ip)
        arp_send(1, bc, 0, g_net.ip, g_net.ip);
}

static uint8_t g_flush[ETH_HLEN + NET_MTU + 16];

/* Records ip -> mac and transmits whatever waited for the resolution. */
static void arp_set(arp_ent_t *e, const uint8_t mac[6])
{
    unsigned i;
    memcpy(e->mac, mac, 6);
    e->state = A_VALID;
    e->expires = net_now() + ARP_VALID_MS;
    for (i = 0; i < ARP_PEND; ++i) {
        if (!e->pend[i])
            continue;
        if (e->pend_len[i] <= NET_MTU) {
            memcpy(g_flush + ETH_HLEN, e->pend[i], e->pend_len[i]);
            memcpy(g_flush, e->mac, 6);
            memcpy(g_flush + 6, g_net.mac, 6);
            wr16(g_flush + 12, 0x0800);
            if (nic_send(g_flush, ETH_HLEN + e->pend_len[i]) == 0)
                NSTAT(NS_ETH_TX);
        }
        kfree(e->pend[i]);
        e->pend[i] = 0;
    }
}

void arp_learn(ip4_t ip, const uint8_t mac[6])
{
    arp_ent_t *e = arp_find(ip);
    if (e)
        arp_set(e, mac);
}

static void arp_rx(const uint8_t *p, uint32_t len)
{
    ip4_t spa, tpa;
    uint16_t op;
    arp_ent_t *e;
    if (len < 28 || rd16(p) != 1 || rd16(p + 2) != 0x0800 || p[4] != 6 || p[5] != 4)
        return;
    op = rd16(p + 6);
    spa = rd32(p + 14);
    tpa = rd32(p + 24);
    if (op == 2) {
        NSTAT(NS_ARP_REP_RX);
        if (spa)
            arp_learn(spa, p + 8);                          /* only entries we asked for (or already know) are updated */
        return;
    }
    if (op != 1)
        return;
    NSTAT(NS_ARP_REQ_RX);
    if (!g_net.ip || tpa != g_net.ip || !spa)
        return;
    e = arp_find(spa);
    if (!e) {
        e = arp_alloc(spa);
        e->state = A_INCOMPLETE;
    }
    arp_set(e, p + 8);                                      /* RFC 826: the target of a request learns the sender */
    arp_send(2, p + 8, p + 8, spa, g_net.ip);
    NSTAT(NS_ARP_REP_TX);
}

static void arp_timer(uint64_t now)
{
    unsigned i;
    for (i = 0; i < ARP_N; ++i) {
        arp_ent_t *e = &arp_tab[i];
        if (e->state == A_VALID && now >= e->expires) {
            e->state = A_FREE;
        } else if (e->state == A_INCOMPLETE && now >= e->next_tx) {
            if (e->tries >= ARP_TRIES) {
                const ip4_t ip = e->ip;
                arp_free_pending(e);
                e->state = A_FREE;
                tcp_host_unreachable(ip);
            } else {
                arp_request(e->ip);
                ++e->tries;
                e->next_tx = now + ARP_RETRY_MS;
            }
        }
    }
}

/* Puts the IPv4 packet at pkt (ETH_HLEN bytes of headroom in front of it) on the wire or the loopback queue. */
static int32_t send_ip_packet(const route_t *rt, uint8_t *pkt, uint32_t len)
{
    arp_ent_t *e;
    NSTAT(NS_IP_TX);
    if (rt->lo) {
        lo_push(pkt, len);
        return 0;
    }
    if (rt->bcast) {
        memset(pkt - ETH_HLEN, 0xff, 6);
    } else {
        e = arp_find(rt->nexthop);
        if (e && e->state == A_VALID) {
            memcpy(pkt - ETH_HLEN, e->mac, 6);
        } else {
            unsigned i;
            if (!e) {
                e = arp_alloc(rt->nexthop);
                e->state = A_INCOMPLETE;
                e->expires = net_now();
            }
            for (i = 0; i < ARP_PEND && e->pend[i]; ++i)
                ;
            if (i == ARP_PEND) {                            /* full: drop the oldest */
                kfree(e->pend[0]);
                for (i = 0; i + 1 < ARP_PEND; ++i) { e->pend[i] = e->pend[i + 1]; e->pend_len[i] = e->pend_len[i + 1]; }
                e->pend[ARP_PEND - 1] = 0;
                i = ARP_PEND - 1;
            }
            e->pend[i] = kmalloc(len);
            if (e->pend[i]) {
                memcpy(e->pend[i], pkt, len);
                e->pend_len[i] = (uint16_t)len;
            }
            if (e->tries == 0) {
                arp_request(rt->nexthop);
                e->tries = 1;
                e->next_tx = net_now() + ARP_RETRY_MS;
            }
            return 0;                                       /* sent when the reply arrives */
        }
    }
    memcpy(pkt - ETH_HLEN + 6, g_net.mac, 6);
    wr16(pkt - 2, 0x0800);
    if (nic_send(pkt - ETH_HLEN, len + ETH_HLEN))
        return NET_ERR(WSAENETDOWN);
    NSTAT(NS_ETH_TX);
    return 0;
}

/* ---------------------------------------------------------------- IPv4 transmit */
static uint16_t ip_ident;

static void build_ip_header(uint8_t *h, uint8_t proto, ip4_t src, ip4_t dst, uint32_t total, uint16_t id, uint16_t frag)
{
    h[0] = 0x45; h[1] = 0;
    wr16(h + 2, (uint16_t)total);
    wr16(h + 4, id);
    wr16(h + 6, frag);
    h[8] = 64; h[9] = proto;
    wr16(h + 10, 0);
    wr32(h + 12, src);
    wr32(h + 16, dst);
    wr16(h + 10, csum_fold(csum_add(0, h, IP_HLEN)));
}

int32_t ip_output(uint8_t proto, ip4_t src, ip4_t dst, const uint8_t *payload, uint32_t len, int df)
{
    route_t rt;
    int32_t st;
    uint8_t *pkt = g_out + ETH_HLEN;
    KASSERT(net_lock_held());
    st = route_lookup(dst, &rt);
    if (st)
        return st;
    if (!src)
        src = rt.src;
    if (len + IP_HLEN <= rt.mtu) {
        build_ip_header(pkt, proto, src, dst, IP_HLEN + len, ++ip_ident, df ? 0x4000 : 0);
        memcpy(pkt + IP_HLEN, payload, len);
        return send_ip_packet(&rt, pkt, IP_HLEN + len);
    }
    if (df || len + IP_HLEN > 65535)
        return NET_ERR(WSAEMSGSIZE);
    {   /* fragmentation: payload pieces are multiples of 8 bytes except the last */
        static uint8_t frag_buf[ETH_HLEN + NET_MTU + 16];
        const uint32_t per = ((rt.mtu - IP_HLEN) / 8) * 8;
        const uint16_t id = ++ip_ident;
        uint32_t off = 0;
        while (off < len) {
            uint32_t n = len - off > per ? per : len - off;
            const int more = off + n < len;
            build_ip_header(frag_buf + ETH_HLEN, proto, src, dst, IP_HLEN + n, id, (uint16_t)((off / 8) | (more ? 0x2000 : 0)));
            memcpy(frag_buf + ETH_HLEN + IP_HLEN, payload + off, n);
            st = send_ip_packet(&rt, frag_buf + ETH_HLEN, IP_HLEN + n);
            NSTAT(NS_IP_FRAG_TX);
            if (st)
                return st;
            off += n;
        }
    }
    return 0;
}

int32_t ip_output_broadcast(uint8_t proto, ip4_t src, const uint8_t *payload, uint32_t len)
{
    route_t rt;
    uint8_t *pkt = g_out + ETH_HLEN;
    KASSERT(net_lock_held());
    if (!g_net.nic_present || len + IP_HLEN > NET_MTU)
        return NET_ERR(WSAENETUNREACH);
    memset(&rt, 0, sizeof rt);
    rt.bcast = 1; rt.mtu = NET_MTU; rt.nexthop = 0xffffffffu;
    build_ip_header(pkt, proto, src, 0xffffffffu, IP_HLEN + len, ++ip_ident, 0);
    memcpy(pkt + IP_HLEN, payload, len);
    return send_ip_packet(&rt, pkt, IP_HLEN + len);
}

/* ---------------------------------------------------------------- ICMP */
typedef struct { int used, done; ip4_t dst; uint16_t id, seq; uint64_t sent; uint32_t rtt; int32_t err; } ping_t;
static ping_t pings[4];
static uint64_t unreach_window;
static unsigned unreach_count;

void icmp_send_unreach(ip4_t to, uint8_t code, const uint8_t *orig, uint32_t orig_len)
{
    uint8_t *m = g_l4;
    uint32_t n;
    const uint64_t now = net_now();
    if (!orig || orig_len < IP_HLEN || !to || to == 0xffffffffu || ip_is_broadcast(to) || (to >> 28) == 0xe)
        return;
    if (orig[9] == IPPROTO_ICMP_ && orig_len >= IP_HLEN + 1 && orig[IP_HLEN] != 8 && orig[IP_HLEN] != 0)
        return;                                            /* never answer an ICMP error with an ICMP error */
    if (rd16(orig + 6) & 0x1fff)
        return;                                            /* non-first fragment */
    if (now - unreach_window >= 1000) { unreach_window = now; unreach_count = 0; }
    if (unreach_count++ >= 50)
        return;                                            /* rate limit: 50 per second */
    n = (uint32_t)(orig[0] & 15) * 4 + 8;
    if (n > orig_len) n = orig_len;
    m[0] = 3; m[1] = code; wr16(m + 2, 0); wr32(m + 4, 0);
    memcpy(m + 8, orig, n);
    wr16(m + 2, csum_fold(csum_add(0, m, 8 + n)));
    ip_output(IPPROTO_ICMP_, 0, to, m, 8 + n, 0);
    NSTAT(NS_ICMP_UNREACH_TX);
}

static void icmp_input(ip4_t src, ip4_t dst, const uint8_t *p, uint32_t len, const uint8_t *ip_pkt, uint32_t ip_len)
{
    unsigned i;
    (void)ip_pkt; (void)ip_len;
    if (len < 8 || csum_fold(csum_add(0, p, len)) != 0)
        return;
    if (p[0] == 8 && p[1] == 0) {                           /* echo request */
        NSTAT(NS_ICMP_ECHO_RX);
        if (ip_is_broadcast(dst) || len > LO_MTU - 64)
            return;
        memcpy(g_l4, p, len);
        g_l4[0] = 0;
        wr16(g_l4 + 2, 0);
        wr16(g_l4 + 2, csum_fold(csum_add(0, g_l4, len)));
        ip_output(IPPROTO_ICMP_, dst, src, g_l4, len, 0);
        NSTAT(NS_ICMP_ECHO_TX);
    } else if (p[0] == 0 && p[1] == 0) {                    /* echo reply */
        NSTAT(NS_ICMP_REPLY_RX);
        for (i = 0; i < 4; ++i)
            if (pings[i].used && !pings[i].done && pings[i].dst == src && pings[i].id == rd16(p + 4) && pings[i].seq == rd16(p + 6)) {
                pings[i].rtt = (uint32_t)(net_now() - pings[i].sent);
                pings[i].done = 1;
                net_wake_all();
            }
    } else if (p[0] == 3 && len >= 8 + IP_HLEN) {           /* destination unreachable: the quoted datagram names the flow */
        const uint8_t *o = p + 8;
        const uint32_t ol = len - 8;
        if ((o[0] >> 4) != 4)
            return;
        if (o[9] == IPPROTO_UDP_) {                         /* port unreachable surfaces as WSAECONNRESET, as on Windows */
            udp_icmp_error(o, ol, p[1] == 3 ? NET_ERR(WSAECONNRESET) : p[1] == 0 ? NET_ERR(WSAENETUNREACH) : NET_ERR(WSAEHOSTUNREACH));
        } else if (o[9] == IPPROTO_ICMP_ && ol >= IP_HLEN + 8 && o[IP_HLEN] == 8) {
            const uint8_t *e = o + (o[0] & 15) * 4;
            for (i = 0; i < 4; ++i)
                if (pings[i].used && !pings[i].done && pings[i].id == rd16(e + 4) && pings[i].seq == rd16(e + 6)) {
                    pings[i].err = p[1] == 0 ? NET_ERR(WSAENETUNREACH) : NET_ERR(WSAEHOSTUNREACH);
                    pings[i].done = 1;
                    net_wake_all();
                }
        }
    }
}

int32_t net_ping(ip4_t dst, uint16_t id, uint16_t seq, uint32_t payload_len, uint32_t timeout_ms, uint32_t *rtt_ms)
{
    ping_t *pg = 0;
    uint64_t deadline;
    uint32_t i;
    int32_t st;
    KASSERT(net_lock_held());
    if (payload_len > 8192)
        return NET_ERR(WSAEMSGSIZE);
    for (i = 0; i < 4; ++i)
        if (!pings[i].used) { pg = &pings[i]; break; }
    if (!pg)
        return NET_ERR(WSAENOBUFS);
    memset(pg, 0, sizeof *pg);
    pg->used = 1; pg->dst = dst; pg->id = id; pg->seq = seq; pg->sent = net_now();
    g_l4[0] = 8; g_l4[1] = 0; wr16(g_l4 + 2, 0); wr16(g_l4 + 4, id); wr16(g_l4 + 6, seq);
    for (i = 0; i < payload_len; ++i)
        g_l4[8 + i] = (uint8_t)('a' + i % 23);
    wr16(g_l4 + 2, csum_fold(csum_add(0, g_l4, 8 + payload_len)));
    st = ip_output(IPPROTO_ICMP_, 0, dst, g_l4, 8 + payload_len, 0);
    if (st) { pg->used = 0; return st; }
    NSTAT(NS_ICMP_ECHO_TX);
    deadline = net_now() + timeout_ms;
    while (!pg->done) {
        const uint64_t now = net_now();
        if (net_current_terminating()) { pg->used = 0; return NET_ERR(WSAEINTR); }
        if (now >= deadline) { pg->used = 0; return NET_ERR(WSAETIMEDOUT); }
        net_sleep(deadline - now > 20 ? 20 : (uint32_t)(deadline - now));
    }
    st = pg->err;
    if (rtt_ms) *rtt_ms = pg->rtt;
    pg->used = 0;
    return st;
}

/* ---------------------------------------------------------------- IPv4 receive + reassembly */
#define REASM_N 3
#define REASM_MS 30000u
typedef struct {
    int used;
    ip4_t src, dst;
    uint16_t id;
    uint8_t proto;
    uint64_t deadline;
    uint8_t *buf;
    uint32_t total, got_units;
    uint8_t bitmap[1024];                                   /* one bit per 8-byte unit of a maximal 65528-byte payload */
} reasm_t;
static reasm_t reasm[REASM_N];

static void reasm_free(reasm_t *r)
{
    if (r->buf) kfree(r->buf);
    memset(r, 0, sizeof *r);
}

static void ip_deliver(uint8_t proto, ip4_t src, ip4_t dst, const uint8_t *pl, uint32_t len, const uint8_t *ip_pkt, uint32_t ip_len)
{
    switch (proto) {
    case IPPROTO_ICMP_: icmp_input(src, dst, pl, len, ip_pkt, ip_len); break;
    case IPPROTO_UDP_: udp_input(src, dst, pl, len, ip_pkt, ip_len); break;
    case IPPROTO_TCP_: tcp_input(src, dst, pl, len); break;
    default:
        if (ip_pkt && !ip_is_broadcast(dst))
            icmp_send_unreach(src, 2, ip_pkt, ip_len);      /* protocol unreachable */
        break;
    }
}

static void ip_fragment_in(const uint8_t *p, uint32_t hlen, uint32_t total)
{
    const uint16_t fo = rd16(p + 6);
    const uint32_t off = (uint32_t)(fo & 0x1fff) * 8, dl = total - hlen;
    const int more = (fo & 0x2000) != 0;
    const ip4_t src = rd32(p + 12), dst = rd32(p + 16);
    reasm_t *r = 0;
    uint32_t u, first, last;
    unsigned i;
    if ((more && (dl & 7)) || dl == 0 || off + dl > 65528)
        return;
    for (i = 0; i < REASM_N; ++i)
        if (reasm[i].used && reasm[i].src == src && reasm[i].dst == dst && reasm[i].id == rd16(p + 4) && reasm[i].proto == p[9]) {
            r = &reasm[i];
            break;
        }
    if (!r) {
        for (i = 0; i < REASM_N; ++i)
            if (!reasm[i].used) { r = &reasm[i]; break; }
        if (!r) {                                           /* table full: evict the oldest */
            r = &reasm[0];
            for (i = 1; i < REASM_N; ++i)
                if (reasm[i].deadline < r->deadline) r = &reasm[i];
            reasm_free(r);
        }
        r->buf = kmalloc(65536);
        if (!r->buf) { memset(r, 0, sizeof *r); return; }
        r->used = 1; r->src = src; r->dst = dst; r->id = rd16(p + 4); r->proto = p[9];
        r->deadline = net_now() + REASM_MS;
    }
    memcpy(r->buf + off, p + hlen, dl);
    first = off / 8;
    last = (off + dl + 7) / 8;
    for (u = first; u < last; ++u)
        if (!(r->bitmap[u >> 3] & (1u << (u & 7)))) {
            r->bitmap[u >> 3] |= (uint8_t)(1u << (u & 7));
            ++r->got_units;
        }
    if (!more)
        r->total = off + dl;
    if (r->total && r->got_units == (r->total + 7) / 8) {
        NSTAT(NS_IP_REASM);
        {
            const uint8_t proto = r->proto;
            const ip4_t s = r->src, d = r->dst;
            const uint32_t n = r->total;
            uint8_t *buf = r->buf;
            r->buf = 0;
            memset(r, 0, sizeof *r);
            ip_deliver(proto, s, d, buf, n, 0, 0);
            kfree(buf);
        }
    }
}

static void ip_input(const uint8_t *p, uint32_t len, const uint8_t *smac)
{
    uint32_t ihl, total;
    ip4_t src, dst;
    int local;
    NSTAT(NS_IP_RX);
    if (len < IP_HLEN || (p[0] >> 4) != 4)
        return;
    ihl = (uint32_t)(p[0] & 15) * 4;
    if (ihl < IP_HLEN || ihl > len)
        return;
    total = rd16(p + 2);
    if (total < ihl || total > len)
        return;                                             /* truncated */
    len = total;                                            /* strip Ethernet padding */
    if (csum_fold(csum_add(0, p, ihl)) != 0) {
        NSTAT(NS_IP_BAD_CSUM);
        return;
    }
    src = rd32(p + 12);
    dst = rd32(p + 16);
    if (src == 0xffffffffu || (src >> 28) == 0xe || p[8] == 0)
        return;
    local = ip_is_local(dst);
    if (!local && !ip_is_broadcast(dst)) {
        /* Unconfigured host accepting the DHCP server's unicast reply (RFC 2131 4.1: it may arrive before we own the address). */
        if (!(g_net.ip == 0 && p[9] == IPPROTO_UDP_ && len >= ihl + 8 && rd16(p + ihl + 2) == 68))
            return;
    }
    if (smac) {                                             /* refresh a known neighbour */
        arp_ent_t *e = arp_find(src);
        if (e && e->state == A_VALID && !memcmp(e->mac, smac, 6))
            e->expires = net_now() + ARP_VALID_MS;
    }
    if ((rd16(p + 6) & 0x3fff) != 0) {                      /* MF set or offset != 0 (DF is bit 14 and ignored here) */
        ip_fragment_in(p, ihl, len);
        return;
    }
    ip_deliver(p[9], src, dst, p + ihl, len - ihl, p, len);
}

/* ---------------------------------------------------------------- receive path glue, timers, thread */
static void net_rx_frame(const uint8_t *f, uint32_t len)
{
    static const uint8_t bc[6] = {0xff, 0xff, 0xff, 0xff, 0xff, 0xff};
    uint16_t type;
    NSTAT(NS_ETH_RX);
    if (len < ETH_HLEN) { NSTAT(NS_ETH_RX_DROP); return; }
    if (memcmp(f, g_net.mac, 6) && memcmp(f, bc, 6)) { NSTAT(NS_ETH_RX_DROP); return; }
    type = rd16(f + 12);
    if (type == 0x0806) arp_rx(f + ETH_HLEN, len - ETH_HLEN);
    else if (type == 0x0800) ip_input(f + ETH_HLEN, len - ETH_HLEN, f + 6);
    else NSTAT(NS_ETH_RX_DROP);                             /* IPv6 and everything else: not implemented */
}

void net_timers(uint64_t now)
{
    unsigned i;
    arp_timer(now);
    for (i = 0; i < REASM_N; ++i)
        if (reasm[i].used && now >= reasm[i].deadline)
            reasm_free(&reasm[i]);
    dhcp_timer(now);
    tcp_timers(now);
}

static void net_thread(void *arg)
{
    uint64_t last_timer = 0;
    (void)arg;
    for (;;) {
        sem_wait_timeout(&g_nic_kick, 10);
        net_lock();
        if (g_net.nic_present) {
            g_net.link_up = nic_link_up();
            nic_rx_drain(net_rx_frame);
        }
        tcp_flush_acks();
        if (net_now() - last_timer >= 5) {
            last_timer = net_now();
            net_timers(last_timer);
        }
        net_unlock();
    }
}

void net_dhcp_apply(ip4_t ip, ip4_t mask, ip4_t gw, ip4_t dns0, ip4_t dns1, ip4_t server, uint32_t lease)
{
    g_net.ip = ip; g_net.mask = mask; g_net.gw = gw; g_net.dns[0] = dns0; g_net.dns[1] = dns1;
    g_net.dhcp_server = server; g_net.lease_secs = lease;
    g_net.lease_start_ms = net_now();
    kprintf("K64 net: configured %u.%u.%u.%u/%u.%u.%u.%u gw %u.%u.%u.%u dns %u.%u.%u.%u lease %us\n", ip >> 24, (ip >> 16) & 255,
            (ip >> 8) & 255, ip & 255, mask >> 24, (mask >> 16) & 255, (mask >> 8) & 255, mask & 255, gw >> 24, (gw >> 16) & 255,
            (gw >> 8) & 255, gw & 255, dns0 >> 24, (dns0 >> 16) & 255, (dns0 >> 8) & 255, dns0 & 255, lease);
    arp_announce();
    net_wake_all();
}

void net_deconfigure(void)
{
    unsigned i;
    g_net.ip = 0; g_net.mask = 0; g_net.gw = 0; g_net.dns[0] = g_net.dns[1] = 0; g_net.dhcp_server = 0;
    for (i = 0; i < ARP_N; ++i) {
        arp_free_pending(&arp_tab[i]);
        arp_tab[i].state = A_FREE;
    }
    net_wake_all();
}

int net_ensure_init(void)
{
    mutex_lock(&init_mtx);
    if (!g_net.stack_up) {
        sem_init(&g_nic_kick, 0);
        if (nic_probe_init(g_net.mac) == 0) {
            g_net.nic_present = 1;
            g_net.link_up = nic_link_up();
        } else {
#ifdef SHZ_STANDALONE
            kprintf("K64 net: no rtl8139 NIC; loopback only\n");
#else
            kprintf("K64 net: Supervisor profile has no NIC; loopback only\n");
#endif
        }
        if (!thread_create("net", net_thread, 0)) {
            mutex_unlock(&init_mtx);
            return -1;
        }
        g_net.stack_up = 1;
        if (g_net.nic_present) {
            const uint64_t start = net_now();
            net_lock();
            dhcp_start();
            while (g_net.dhcp_state != DHCP_BOUND && net_now() - start < 8000)
                net_sleep(20);
            if (g_net.dhcp_state != DHCP_BOUND)
                kprintf("K64 net: DHCP did not complete within 8 s; retrying in the background\n");
            net_unlock();
        }
    }
    mutex_unlock(&init_mtx);
    return 0;
}
