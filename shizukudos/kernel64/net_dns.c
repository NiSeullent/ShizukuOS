/* SPDX-License-Identifier: GPL-2.0-only
 * Stub DNS resolver (RFC 1035): A-record queries over UDP to the DHCP-provided server, with retransmission (1 s, 2 s, 4 s),
 * CNAME chains inside one response, name compression, response validation (source address/port, transaction id, QR bit,
 * question echo), a 16-entry positive cache honouring the record TTL (capped at 1 h) and a 30 s negative cache for
 * NXDOMAIN. "localhost" and dotted-decimal literals are answered locally.
 * Not implemented: AAAA/IPv6, TCP fallback for truncated responses (the addresses that did fit are used), search lists,
 * EDNS, DNSSEC, /etc/hosts.
 */
#include "net.h"

#define DNS_CACHE_N 16
#define DNS_MAX_ADDR 8
typedef struct {
    char name[128];
    ip4_t addr[DNS_MAX_ADDR];
    uint8_t n;
    int32_t neg;                                    /* 0 = positive entry, else the cached error */
    ip4_t server;                                   /* the entry answers queries to this server:port only */
    uint16_t port;
    uint64_t expires;
    uint8_t used;
} dns_ent_t;
static dns_ent_t cache[DNS_CACHE_N];

void dns_flush_cache(void) { memset(cache, 0, sizeof cache); }

static char lc(char c) { return c >= 'A' && c <= 'Z' ? (char)(c + 32) : c; }

static int parse_dotted(const char *s, ip4_t *out)
{
    uint32_t v = 0, parts = 0, cur = 0, digits = 0;
    for (;; ++s) {
        if (*s >= '0' && *s <= '9') {
            cur = cur * 10 + (uint32_t)(*s - '0');
            if (++digits > 3 || cur > 255) return 0;
        } else if (*s == '.' || *s == 0) {
            if (!digits) return 0;
            v = (v << 8) | cur;
            ++parts; cur = 0; digits = 0;
            if (!*s) break;
        } else {
            return 0;
        }
    }
    if (parts != 4)
        return 0;
    *out = v;
    return 1;
}

/* Decodes the (possibly compressed) name at `off` into dotted lowercase text; *next is the offset after the name field. */
static int dns_name(const uint8_t *p, uint32_t len, uint32_t off, char *out, uint32_t cap, uint32_t *next)
{
    uint32_t o = 0, hops = 0;
    int jumped = 0;
    for (;;) {
        uint32_t l;
        if (off >= len) return -1;
        l = p[off];
        if ((l & 0xc0) == 0xc0) {
            if (off + 1 >= len) return -1;
            if (!jumped) *next = off + 2;
            jumped = 1;
            off = ((l & 0x3f) << 8) | p[off + 1];
            if (++hops > 16) return -1;
            continue;
        }
        if (l & 0xc0) return -1;
        ++off;
        if (l == 0) {
            if (!jumped) *next = off;
            if (o && out[o - 1] == '.') --o;
            if (o >= cap) return -1;
            out[o] = 0;
            return 0;
        }
        if (off + l > len || o + l + 1 >= cap) return -1;
        while (l--) out[o++] = lc((char)p[off++]);
        out[o++] = '.';
    }
}

static uint32_t encode_query(uint8_t *q, uint16_t id, const char *name)
{
    uint32_t o = 12, i = 0;
    memset(q, 0, 12);
    wr16(q, id);
    wr16(q + 2, 0x0100);                            /* RD */
    wr16(q + 4, 1);
    while (name[i]) {
        uint32_t st = o++, l = 0;
        while (name[i] && name[i] != '.') { q[o++] = (uint8_t)name[i++]; ++l; }
        q[st] = (uint8_t)l;
        if (name[i] == '.') ++i;
    }
    q[o++] = 0;
    wr16(q + o, 1); wr16(q + o + 2, 1);             /* QTYPE A, QCLASS IN */
    return o + 4;
}

/* Parses a response to `qname`. Returns 0 with the A records, or a NET_ERR(). */
static int32_t parse_response(const uint8_t *p, uint32_t len, uint16_t id, const char *qname, ip4_t *addr, unsigned *n_out,
                              uint32_t *ttl_out)
{
    uint16_t flags, qd, an;
    uint32_t off = 12, i, pass, ttl_min = 0xffffffffu;
    char cur[256], owner[256], target[256];
    uint32_t rr_off[48], rr_type[48], rr_rdlen[48], rr_rdoff[48], rr_ttl[48];
    unsigned nrr = 0, n = 0;
    if (len < 12 || rd16(p) != id)
        return NET_ERR(WSANO_RECOVERY);
    flags = rd16(p + 2);
    if (!(flags & 0x8000))
        return NET_ERR(WSANO_RECOVERY);             /* not a response */
    qd = rd16(p + 4);
    an = rd16(p + 6);
    switch (flags & 15) {
    case 0: break;
    case 3: return NET_ERR(WSAHOST_NOT_FOUND);      /* NXDOMAIN */
    case 2: return NET_ERR(WSATRY_AGAIN);           /* SERVFAIL */
    default: return NET_ERR(WSANO_RECOVERY);
    }
    if (qd != 1)
        return NET_ERR(WSANO_RECOVERY);
    if (dns_name(p, len, off, owner, sizeof owner, &off) || strcmp(owner, qname) || off + 4 > len ||
        rd16(p + off) != 1 || rd16(p + off + 2) != 1)
        return NET_ERR(WSANO_RECOVERY);              /* the question is not the one we asked */
    off += 4;
    for (i = 0; i < an && nrr < 48; ++i) {
        uint32_t next;
        if (dns_name(p, len, off, owner, sizeof owner, &next) || next + 10 > len)
            break;
        rr_off[nrr] = off;
        rr_type[nrr] = rd16(p + next);
        rr_ttl[nrr] = rd32(p + next + 4);
        rr_rdlen[nrr] = rd16(p + next + 8);
        rr_rdoff[nrr] = next + 10;
        if (rr_rdoff[nrr] + rr_rdlen[nrr] > len)
            break;
        off = rr_rdoff[nrr] + rr_rdlen[nrr];
        ++nrr;
    }
    {
        uint32_t k = 0;
        while (qname[k] && k < sizeof cur - 1) { cur[k] = qname[k]; ++k; }
        cur[k] = 0;
    }
    for (pass = 0; pass < 8; ++pass) {              /* follow CNAMEs: owner == cur -> cur = target */
        int changed = 0;
        for (i = 0; i < nrr; ++i) {
            uint32_t nx;
            if (rr_type[i] != 5 || dns_name(p, len, rr_off[i], owner, sizeof owner, &nx) || strcmp(owner, cur))
                continue;
            if (dns_name(p, len, rr_rdoff[i], target, sizeof target, &nx))
                continue;
            if (strcmp(target, cur)) {
                uint32_t k = 0;
                while (target[k] && k < sizeof cur - 1) { cur[k] = target[k]; ++k; }
                cur[k] = 0;
                changed = 1;
            }
            if (rr_ttl[i] < ttl_min) ttl_min = rr_ttl[i];
        }
        if (!changed)
            break;
    }
    for (i = 0; i < nrr && n < DNS_MAX_ADDR; ++i) {
        uint32_t nx;
        if (rr_type[i] != 1 || rr_rdlen[i] != 4 || dns_name(p, len, rr_off[i], owner, sizeof owner, &nx) || strcmp(owner, cur))
            continue;
        addr[n++] = rd32(p + rr_rdoff[i]);
        if (rr_ttl[i] < ttl_min) ttl_min = rr_ttl[i];
    }
    if (!n)
        return NET_ERR(WSANO_DATA);                 /* the name exists but has no A record */
    *n_out = n;
    *ttl_out = ttl_min == 0xffffffffu ? 60 : ttl_min;
    return 0;
}

static dns_ent_t *cache_find(const char *name, ip4_t server, uint16_t port)
{
    unsigned i;
    const uint64_t now = net_now();
    for (i = 0; i < DNS_CACHE_N; ++i)
        if (cache[i].used && now < cache[i].expires && cache[i].server == server && cache[i].port == port && !strcmp(cache[i].name, name))
            return &cache[i];
    return 0;
}

static void cache_put(const char *name, ip4_t server, uint16_t port, const ip4_t *addr, unsigned n, int32_t neg, uint32_t ttl_s)
{
    dns_ent_t *e = 0;
    unsigned i;
    const uint64_t now = net_now();
    for (i = 0; i < DNS_CACHE_N; ++i) {
        if (cache[i].used && cache[i].server == server && cache[i].port == port && !strcmp(cache[i].name, name)) { e = &cache[i]; break; }
        if (!e && (!cache[i].used || now >= cache[i].expires)) e = &cache[i];
    }
    if (!e) e = &cache[net_rand32() % DNS_CACHE_N];
    memset(e, 0, sizeof *e);
    for (i = 0; name[i] && i < sizeof e->name - 1; ++i) e->name[i] = name[i];
    e->n = (uint8_t)n;
    for (i = 0; i < n; ++i) e->addr[i] = addr[i];
    e->neg = neg;
    e->server = server;
    e->port = port;
    e->expires = now + (uint64_t)(ttl_s > 3600 ? 3600 : ttl_s) * 1000;
    e->used = 1;
}

int32_t dns_resolve(const char *name_in, ip4_t *out, unsigned max, unsigned *count, ip4_t server, uint16_t port)
{
    char name[256];
    uint32_t n = 0, i, labels_len = 0;
    ip4_t addr[DNS_MAX_ADDR], lit;
    unsigned got = 0, attempt;
    uint32_t ttl_s = 60;
    int final = 0;
    int32_t st = NET_ERR(WSATRY_AGAIN);
    static const uint32_t timeouts[3] = {1000, 2000, 4000};
    sock_t *s;
    *count = 0;
    for (i = 0; name_in[i]; ++i) {
        if (n >= 253) return NET_ERR(WSAHOST_NOT_FOUND);
        name[n++] = lc(name_in[i]);
    }
    if (n && name[n - 1] == '.') --n;
    name[n] = 0;
    if (!n)
        return NET_ERR(WSAHOST_NOT_FOUND);
    for (i = 0; i <= n; ++i) {                      /* labels must be 1..63 bytes */
        if (i == n || name[i] == '.') {
            if (!labels_len || labels_len > 63) return NET_ERR(WSAHOST_NOT_FOUND);
            labels_len = 0;
        } else {
            ++labels_len;
        }
    }
    if (!strcmp(name, "localhost")) { out[0] = IP4(127, 0, 0, 1); *count = 1; return 0; }
    if (parse_dotted(name, &lit)) { out[0] = lit; *count = 1; return 0; }
    if (net_ensure_init())
        return NET_ERR(WSAENETDOWN);
    net_lock();
    if (!server) {
        server = g_net.dns[0];
        port = 53;
    }
    if (!port) port = 53;
    {
        dns_ent_t *e = server ? cache_find(name, server, port) : 0;
        if (e) {
            NSTAT(NS_DNS_CACHE_HIT);
            if (e->neg) { st = e->neg; net_unlock(); return st; }
            for (i = 0; i < e->n && i < max; ++i) out[i] = e->addr[i];
            *count = i;
            net_unlock();
            return 0;
        }
    }
    if (!server) {
        net_unlock();
        return NET_ERR(WSATRY_AGAIN);               /* no DNS server configured */
    }
    s = sock_new(SK_DGRAM, 1);
    if (!s) { net_unlock(); return NET_ERR(WSAENOBUFS); }
    s->lport = sock_alloc_port(SK_DGRAM);
    s->bound = 1;
    for (attempt = 0; attempt < 3 && !got && !final; ++attempt) {
        uint8_t q[300], resp[1500];
        const uint16_t id = (uint16_t)net_rand32();
        const uint32_t qlen = encode_query(q, id, name);
        const uint64_t deadline = net_now() + timeouts[attempt];
        NSTAT(NS_DNS_QUERY);
        st = udp_send(s, server, port, q, qlen, 0);
        if (st)
            break;
        for (;;) {
            uint32_t rl = 0;
            ip4_t from = 0;
            uint16_t fport = 0;
            const uint64_t now = net_now();
            const int32_t rs = ksock_recvfrom(s, resp, sizeof resp, &rl, &from, &fport,
                                              deadline > now ? (uint32_t)(deadline - now) : 1);
            if (rs) {                               /* timeout: retry with the next, longer wait; anything else ends the lookup */
                const int unreachable = rs == NET_ERR(WSAECONNRESET) || rs == NET_ERR(WSAENETUNREACH) || rs == NET_ERR(WSAEHOSTUNREACH);
                st = (rs == NET_ERR(WSAETIMEDOUT) || unreachable) ? NET_ERR(WSATRY_AGAIN) : rs;   /* ICMP unreachable: no server there */
                if (rs != NET_ERR(WSAETIMEDOUT)) final = 1;
                break;
            }
            if (from != server || fport != port || rl < 12 || rd16(resp) != id)
                continue;                           /* not the answer to our query: ignore it, keep waiting */
            st = parse_response(resp, rl, id, name, addr, &got, &ttl_s);
            if (st != NET_ERR(WSATRY_AGAIN))
                final = 1;                          /* SERVFAIL is retried, every other verdict is final */
            break;
        }
    }
    sock_close_kernel(s);
    if (got) {
        cache_put(name, server, port, addr, got, 0, ttl_s);
        for (i = 0; i < got && i < max; ++i) out[i] = addr[i];
        *count = i;
        net_unlock();
        return 0;
    }
    if (st == NET_ERR(WSAHOST_NOT_FOUND) || st == NET_ERR(WSANO_DATA))
        cache_put(name, server, port, 0, 0, st, 30);  /* RFC 2308 negative caching (fixed 30 s: no SOA parsing) */
    net_unlock();
    return st;
}
