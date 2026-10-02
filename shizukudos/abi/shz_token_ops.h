/* SPDX-License-Identifier: GPL-2.0-only */
#ifndef SHZ_TOKEN_OPS_H
#define SHZ_TOKEN_OPS_H
#include <stdint.h>

/* New operation: old backends reject it instead of silently discarding access.
 * a2 = source handle; a3 = access32 | type8<<32 | level8<<40; a4 = output.
 * Upper16 bits are reserved and must be zero. Legacy op5 remains type8|level8<<8.
 * Both operations require TOKEN_DUPLICATE and can only retain/reduce grants. */
#define SHZ_TOKEN_OP_DUPLICATE_EX 0x100u
#define SHZ_TOKEN_ALL_ACCESS 0x000f01ffu
#define SHZ_TOKEN_QUERY 0x0008u
#define SHZ_TOKEN_DUPLICATE 0x0002u
#define SHZ_TOKEN_IMPERSONATE 0x0004u
#define SHZ_TOKEN_ADJUST_PRIVILEGES 0x0020u
#define SHZ_TOKEN_ADJUST_DEFAULT 0x0080u
#define SHZ_TOKEN_ADJUST_SESSIONID 0x0100u
#define SHZ_TOKEN_READ_CONTROL 0x00020000u
#define SHZ_TOKEN_WRITE_DAC 0x00040000u

/* Token generic mapping; maximum is a caller-supplied authorization ceiling.
 * This is handle admission, not an object DACL or account authority. */
static inline int shz_token_map_access(uint32_t desired, uint32_t maximum, uint32_t *out)
{
    uint32_t mapped = desired & ~0xf2000000u;
    if (desired & 0x80000000u) mapped |= 0x00020008u;
    if (desired & 0x40000000u) mapped |= 0x000200e0u;
    if (desired & 0x20000000u) mapped |= 0x00020000u;
    if (desired & 0x10000000u) mapped |= SHZ_TOKEN_ALL_ACCESS;
    if (desired & 0x02000000u) mapped |= maximum;
    if (mapped & ~SHZ_TOKEN_ALL_ACCESS || mapped & ~maximum) return 0;
    *out = mapped;
    return 1;
}

static inline uint64_t shz_token_duplicate_pack(uint32_t access, uint32_t type, uint32_t level)
{
    return (uint64_t)access | ((uint64_t)type << 32) | ((uint64_t)level << 40);
}
#endif
