/* SPDX-License-Identifier: GPL-2.0-only
 * Windows 98 SE WS2_32 exports no InetPtonW/InetNtopW/GetAddrInfoW/FreeAddrInfoW/GetNameInfoW. This is a
 * contract-faithful IPv4-only implementation on the legacy resolver (gethostbyname/gethostbyaddr/
 * getservbyname/getservbyport), like Microsoft's wspiapi fallback. Truthful limits: IPv4 only (AF_INET6
 * -> WSAEAFNOSUPPORT), ASCII host names only (no IDN), AI_V4MAPPED/ALL/SECURE etc. refused (WSAEINVAL).
 */
#ifndef SHZ_OFFICE_SAL_NET_H
#define SHZ_OFFICE_SAL_NET_H
#include "office_sal.h"
#include <stddef.h>
#ifdef __cplusplus
extern "C" {
#endif

#define OFN_WSAEINVAL 10022u
#define OFN_WSAEFAULT 10014u
#define OFN_WSAEAFNOSUPPORT 10047u
#define OFN_WSAESOCKTNOSUPPORT 10044u
#define OFN_WSAENOBUFS 10055u
#define OFN_WSAHOST_NOT_FOUND 11001u
#define OFN_WSATYPE_NOT_FOUND 10109u
#define OFN_WSA_NOT_ENOUGH_MEMORY 8u
#define OFN_AF_UNSPEC 0
#define OFN_AF_INET 2
#define OFN_AI_PASSIVE 1
#define OFN_AI_CANONNAME 2
#define OFN_AI_NUMERICHOST 4
#define OFN_AI_NUMERICSERV 8
#define OFN_AI_ADDRCONFIG 0x400
#define OFN_NI_NOFQDN 1
#define OFN_NI_NUMERICHOST 2
#define OFN_NI_NAMEREQD 4
#define OFN_NI_NUMERICSERV 8
#define OFN_NI_DGRAM 16

struct ofn_addrinfow {            /* layout identical to ADDRINFOW */
    int ai_flags, ai_family, ai_socktype, ai_protocol;
    size_t ai_addrlen;
    uint16_t *ai_canonname;
    void *ai_addr;
    struct ofn_addrinfow *ai_next;
};

struct ofn_backend {
    void *ctx;
    /* returns number of IPv4 addresses (<= max) or -(WSA error); canon = official name (may be empty) */
    int (*resolve)(void *ctx, const char *name, uint8_t addrs[][4], int max, char canon[256]);
    int (*host_by_addr)(void *ctx, const uint8_t addr[4], char name[256]);     /* 0 ok, else WSA error */
    int (*service_by_name)(void *ctx, const char *name, const char *proto, uint16_t *port_host);
    int (*service_by_port)(void *ctx, uint16_t port_host, const char *proto, char name[64]);
    void *(*alloc)(void *ctx, size_t n);
    void (*release)(void *ctx, void *p);
};

/* InetPton/InetNtop return values: 1/0/-1 (pton) and ofn_inet_ntop4 -> 0 or WSA error */
int ofn_inet_pton(int family, const uint16_t *text, void *dst, uint32_t *wsa_err);
uint32_t ofn_inet_ntop4(const uint8_t addr[4], uint16_t *buf, size_t size);
/* return 0 or the WSA error to set (EAI_* values equal WSA codes on Windows) */
uint32_t ofn_getaddrinfo(const struct ofn_backend *b, const uint16_t *node, const uint16_t *service,
                         const struct ofn_addrinfow *hints, struct ofn_addrinfow **res);
void ofn_freeaddrinfo(const struct ofn_backend *b, struct ofn_addrinfow *ai);
uint32_t ofn_getnameinfo(const struct ofn_backend *b, const void *sa, size_t salen, uint16_t *host, uint32_t hostlen,
                         uint16_t *serv, uint32_t servlen, int flags);

#ifdef __cplusplus
}
#endif
#endif
