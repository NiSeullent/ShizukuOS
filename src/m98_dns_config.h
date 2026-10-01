/* SPDX-License-Identifier: GPL-2.0-only */
#ifndef M98_DNS_CONFIG_H
#define M98_DNS_CONFIG_H
#include <stdint.h>
#include <stddef.h>
#define M98_DNS_NAME_CAP 132u
#define M98_DNS_SERVER_CAP 64u
#define M98_DNS_FIXED4_SIZE 584u
#define M98_DNS_FIXED4_LIST 268u
#define M98_DNS_OK 0u
#define M98_DNS_INVALID_DATA 13u
#define M98_DNS_NOMEM 8u
#define M98_DNS_NOT_SUPPORTED 50u
#define M98_DNS_INVALID_PARAMETER 87u
#define M98_DNS_MORE_DATA 234u
#define M98_DNS_INSUFFICIENT_BUFFER 122u
/* Values from the public DNS_CONFIG_TYPE ABI. IPv4 bytes are wire order. */
enum { M98_DNS_DOMAIN_W=0, M98_DNS_DOMAIN_A=1, M98_DNS_DOMAIN_UTF8=2,
       M98_DNS_SERVERS=6, M98_DNS_HOST_W=12, M98_DNS_HOST_A=13,
       M98_DNS_HOST_UTF8=14, M98_DNS_FULL_W=15, M98_DNS_FULL_A=16,
       M98_DNS_FULL_UTF8=17 };
typedef struct {
    char host_a[M98_DNS_NAME_CAP], domain_a[M98_DNS_NAME_CAP];
    uint16_t host_w[M98_DNS_NAME_CAP], domain_w[M98_DNS_NAME_CAP];
    uint32_t server_count;
    uint8_t servers[M98_DNS_SERVER_CAP][4];
} m98_dns_snapshot;
/* Decode exactly n ACP bytes without substitution, writing a UTF16 NUL.
 * Return zero on success. No decoder or allocator may reenter the query. */
typedef uint32_t (*m98_dns_decode)(void *, const char *, uint32_t,
                                  uint16_t *, uint32_t);
typedef void *(*m98_dns_alloc)(void *, uint32_t);
/* Request-only validation, with no provider reads or output writes. */
uint32_t m98_dns_validate_request(uint32_t,uint32_t,const uint16_t *,
                                 const void *,void *,const uint32_t *,m98_dns_alloc);
/* Bounded parser for the original Win32 FIXED_INFO layout. base is the
 * provider's 32-bit virtual address, so host tests need no native pointer.
 * Only the embedded list or complete aligned appended nodes are admitted.
 * A failed parse leaves snapshot unchanged. Input must remain immutable. */
uint32_t m98_dns_parse_fixed4(const void *, uint32_t, uint32_t,
                             m98_dns_decode, void *, m98_dns_snapshot *);
/* flags 0: buffer contains bytes. flags 1: buffer points to a void* output,
 * allocated by allocator (native adapter uses LocalAlloc/LocalFree).
 * Server sizing with NULL succeeds; a short non-NULL buffer is MORE_DATA.
 * String sizing/short buffer is INSUFFICIENT_BUFFER. Length includes NUL.
 * All other failures leave length, buffer and allocation pointer unchanged.
 * adapter-scoped configuration is explicitly unsupported. */
uint32_t m98_dns_query(const m98_dns_snapshot *, uint32_t, uint32_t,
                       const uint16_t *, const void *, void *, uint32_t *,
                       m98_dns_alloc, void *);
#endif
