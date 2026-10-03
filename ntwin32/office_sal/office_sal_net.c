/* SPDX-License-Identifier: GPL-2.0-only
 * IPv4 resolver contracts on the legacy Winsock resolver; see office_sal_net.h. */
#include "office_sal_net.h"
/* freestanding image (no CRT): small local helpers, kept out of loop->libcall idiom recognition */
#define OFN_NOLIB __attribute__((noinline, optimize("no-tree-loop-distribute-patterns")))
static OFN_NOLIB void *ofn_mc(void *d, const void *s, size_t n) { uint8_t *a = d; const uint8_t *b = s; while (n--) *a++ = *b++; return d; }
static OFN_NOLIB void *ofn_ms(void *d, int v, size_t n) { uint8_t *a = d; while (n--) *a++ = (uint8_t)v; return d; }
static OFN_NOLIB size_t ofn_sl(const char *s) { size_t n = 0; while (s[n]) ++n; return n; }
static OFN_NOLIB char *ofn_scpy(char *d, const char *s) { size_t i = 0; do d[i] = s[i]; while (s[i++]); return d; }
static OFN_NOLIB char *ofn_sc(char *s, int c) { for (; *s; ++s) if (*s == (char)c) return s; return 0; }
#define memcpy ofn_mc
#define memset ofn_ms
#define strlen ofn_sl
#define strcpy ofn_scpy
#define strchr ofn_sc

int ofn_inet_pton(int family, const uint16_t *t, void *dst, uint32_t *wsa_err)
{
    uint8_t a[4];
    int part = 0, digits = 0, val = 0;
    size_t i;
    if (wsa_err) *wsa_err = 0;
    if (!t || !dst) { if (wsa_err) *wsa_err = OFN_WSAEFAULT; return -1; }
    if (family != OFN_AF_INET) { if (wsa_err) *wsa_err = OFN_WSAEAFNOSUPPORT; return -1; }
    for (i = 0;; ++i) {
        uint16_t c = t[i];
        if (c >= '0' && c <= '9') {
            if (digits && val == 0) return 0;              /* leading zero: not strict dotted decimal */
            val = val * 10 + (c - '0');
            if (++digits > 3 || val > 255) return 0;
        } else if (c == '.' || c == 0) {
            if (!digits || part > 3) return 0;
            a[part++] = (uint8_t)val; digits = 0; val = 0;
            if (c == 0) break;
        } else return 0;
    }
    if (part != 4) return 0;
    memcpy(dst, a, 4);
    return 1;
}

static size_t put_ip4(const uint8_t a[4], uint16_t *o)
{
    size_t n = 0; int i;
    for (i = 0; i < 4; ++i) {
        unsigned v = a[i];
        if (v >= 100) o[n++] = (uint16_t)('0' + v / 100);
        if (v >= 10) o[n++] = (uint16_t)('0' + v / 10 % 10);
        o[n++] = (uint16_t)('0' + v % 10);
        if (i < 3) o[n++] = '.';
    }
    o[n] = 0;
    return n;
}

uint32_t ofn_inet_ntop4(const uint8_t a[4], uint16_t *buf, size_t size)
{
    uint16_t tmp[16];
    size_t n;
    if (!a || !buf) return OFN_WSAEFAULT;
    n = put_ip4(a, tmp);
    if (size < n + 1) return OFN_WSAENOBUFS;
    memcpy(buf, tmp, (n + 1) * sizeof tmp[0]);
    return 0;
}

static int ascii_len(const uint16_t *w, size_t max, char *out)
{
    size_t n = 0;
    while (w[n]) { if (w[n] > 0x7F || n + 1 >= max) return -1; out[n] = (char)w[n]; ++n; }
    out[n] = 0;
    return (int)n;
}

static uint32_t put_w(const char *s, uint16_t *o, uint32_t cap)
{
    size_t n = strlen(s), i;
    if (n + 1 > cap) return OFN_WSAEFAULT;
    for (i = 0; i <= n; ++i) o[i] = (uint8_t)s[i];
    return 0;
}

static int dig_port(const uint16_t *w, uint16_t *port)
{
    unsigned v = 0; size_t i;
    if (!w[0]) return 0;
    for (i = 0; w[i]; ++i) { if (w[i] < '0' || w[i] > '9' || (v = v * 10 + (w[i] - '0')) > 65535 || i > 5) return 0; }
    *port = (uint16_t)v;
    return 1;
}

static void sockaddr4(uint8_t *sa, const uint8_t ip[4], uint16_t port)
{
    memset(sa, 0, 16);
    sa[0] = OFN_AF_INET; sa[2] = (uint8_t)(port >> 8); sa[3] = (uint8_t)port;
    memcpy(sa + 4, ip, 4);
}

void ofn_freeaddrinfo(const struct ofn_backend *b, struct ofn_addrinfow *ai)
{
    while (ai) { struct ofn_addrinfow *n = ai->ai_next; b->release(b->ctx, ai); ai = n; }
}

uint32_t ofn_getaddrinfo(const struct ofn_backend *b, const uint16_t *node, const uint16_t *service,
                         const struct ofn_addrinfow *h, struct ofn_addrinfow **res)
{
    int flags = 0, family = 0, stype = 0, proto = 0, naddr = 0, i, t, ntypes;
    uint8_t addrs[8][4];
    char host[256], canon[256], svc[64];
    uint16_t port = 0, ports[2] = {0, 0};
    struct ofn_addrinfow *head = 0, **tail = &head;
    int types[3], protos[3];
    if (!b || !b->resolve || !b->alloc || !b->release || !res) return OFN_WSAEFAULT;
    *res = 0;
    canon[0] = 0;
    if (h) {
        flags = h->ai_flags; family = h->ai_family; stype = h->ai_socktype; proto = h->ai_protocol;
        if (h->ai_addrlen || h->ai_canonname || h->ai_addr || h->ai_next) return OFN_WSAEINVAL;
        if (flags & ~(OFN_AI_PASSIVE | OFN_AI_CANONNAME | OFN_AI_NUMERICHOST | OFN_AI_NUMERICSERV | OFN_AI_ADDRCONFIG)) return OFN_WSAEINVAL;
        if (family != OFN_AF_UNSPEC && family != OFN_AF_INET) return OFN_WSAEAFNOSUPPORT;
        if (stype < 0 || stype > 3) return OFN_WSAESOCKTNOSUPPORT;
        if ((proto == 6 && stype != 0 && stype != 1) || (proto == 17 && stype != 0 && stype != 2) ||
            (proto != 0 && proto != 6 && proto != 17)) return OFN_WSAESOCKTNOSUPPORT;
        if (stype == 0 && proto == 6) stype = 1;
        if (stype == 0 && proto == 17) stype = 2;
    }
    if (!node && !service) return OFN_WSAHOST_NOT_FOUND;
    if ((flags & OFN_AI_CANONNAME) && !node) return OFN_WSAEINVAL;
    if (node) {
        uint32_t perr;
        if (ascii_len(node, sizeof host, host) <= 0) return OFN_WSAHOST_NOT_FOUND;
        if (ofn_inet_pton(OFN_AF_INET, node, addrs[0], &perr) == 1) { naddr = 1; strcpy(canon, host); }
        else if (flags & OFN_AI_NUMERICHOST) return OFN_WSAHOST_NOT_FOUND;
        else {
            naddr = b->resolve(b->ctx, host, addrs, 8, canon);
            if (naddr < 0) return (uint32_t)-naddr;
            if (naddr == 0) return OFN_WSAHOST_NOT_FOUND;
        }
    } else {
        static const uint8_t any[4] = {0, 0, 0, 0}, lo[4] = {127, 0, 0, 1};
        memcpy(addrs[0], (flags & OFN_AI_PASSIVE) ? any : lo, 4);
        naddr = 1;
    }
    if (stype == 0) { types[0] = 1; protos[0] = 6; types[1] = 2; protos[1] = 17; types[2] = 3; protos[2] = 0; ntypes = 3; }
    else { types[0] = stype; protos[0] = proto ? proto : stype == 1 ? 6 : stype == 2 ? 17 : 0; ntypes = 1; }
    if (service) {
        if (ascii_len(service, sizeof svc, svc) <= 0) return OFN_WSATYPE_NOT_FOUND;
        if (dig_port(service, &port)) { ports[0] = ports[1] = port; }
        else if (flags & OFN_AI_NUMERICSERV) return OFN_WSATYPE_NOT_FOUND;
        else {
            int found = 0;
            if (!b->service_by_name) return OFN_WSATYPE_NOT_FOUND;
            if (stype != 2 && b->service_by_name(b->ctx, svc, "tcp", &ports[0]) == 0) found |= 1;
            if (stype != 1 && b->service_by_name(b->ctx, svc, "udp", &ports[1]) == 0) found |= 2;
            if (!found) return OFN_WSATYPE_NOT_FOUND;
            if (!(found & 1)) ports[0] = ports[1];
            if (!(found & 2)) ports[1] = ports[0];
        }
    }
    for (i = 0; i < naddr; ++i) {
        for (t = 0; t < ntypes; ++t) {
            size_t clen = (i == 0 && t == 0 && (flags & OFN_AI_CANONNAME)) ? strlen(canon[0] ? canon : host) + 1 : 0;
            struct ofn_addrinfow *e = b->alloc(b->ctx, sizeof *e + 16 + clen * sizeof(uint16_t));
            if (!e) { ofn_freeaddrinfo(b, head); *res = 0; return OFN_WSA_NOT_ENOUGH_MEMORY; }
            memset(e, 0, sizeof *e);
            e->ai_flags = i == 0 && t == 0 ? flags : 0; e->ai_family = OFN_AF_INET; e->ai_socktype = types[t];
            e->ai_protocol = protos[t]; e->ai_addrlen = 16; e->ai_addr = (uint8_t *)(e + 1);
            sockaddr4((uint8_t *)e->ai_addr, addrs[i], types[t] == 2 ? ports[1] : ports[0]);
            if (clen) { e->ai_canonname = (uint16_t *)((uint8_t *)e->ai_addr + 16); put_w(canon[0] ? canon : host, e->ai_canonname, (uint32_t)clen); }
            *tail = e; tail = &e->ai_next;
        }
    }
    *res = head;
    return 0;
}

uint32_t ofn_getnameinfo(const struct ofn_backend *b, const void *sa, size_t salen, uint16_t *host, uint32_t hostlen,
                         uint16_t *serv, uint32_t servlen, int flags)
{
    const uint8_t *s = sa;
    uint16_t port;
    if (!b || !sa || salen < 16) return OFN_WSAEFAULT;
    if (flags & ~(OFN_NI_NOFQDN | OFN_NI_NUMERICHOST | OFN_NI_NAMEREQD | OFN_NI_NUMERICSERV | OFN_NI_DGRAM)) return OFN_WSAEINVAL;
    if (s[0] != OFN_AF_INET || s[1] != 0) return OFN_WSAEAFNOSUPPORT;
    if (!host && !serv) return OFN_WSAHOST_NOT_FOUND;
    port = (uint16_t)((s[2] << 8) | s[3]);
    if (host && hostlen) {
        char name[256];
        int named = 0;
        if (!(flags & OFN_NI_NUMERICHOST) && b->host_by_addr && b->host_by_addr(b->ctx, s + 4, name) == 0 && name[0]) {
            named = 1;
            if (flags & OFN_NI_NOFQDN) { char *d = strchr(name, '.'); if (d) *d = 0; }
        }
        if (!named && (flags & OFN_NI_NAMEREQD)) return OFN_WSAHOST_NOT_FOUND;
        if (named) { uint32_t e = put_w(name, host, hostlen); if (e) return e; }
        else if (ofn_inet_ntop4(s + 4, host, hostlen)) return OFN_WSAEFAULT;
    }
    if (serv && servlen) {
        char name[64];
        if (!(flags & OFN_NI_NUMERICSERV) && b->service_by_port &&
            b->service_by_port(b->ctx, port, (flags & OFN_NI_DGRAM) ? "udp" : "tcp", name) == 0 && name[0]) {
            uint32_t e = put_w(name, serv, servlen); if (e) return e;
        } else {
            char num[8]; int n = 0, d; unsigned v = port; char r[6];
            d = 0; do { r[d++] = (char)('0' + v % 10); v /= 10; } while (v);
            while (d) num[n++] = r[--d];
            num[n] = 0;
            { uint32_t e = put_w(num, serv, servlen); if (e) return e; }
        }
    }
    return 0;
}
