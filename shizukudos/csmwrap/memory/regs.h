/* SPDX-License-Identifier: GPL-2.0-only
 * Host-callable register file for CSM BIOS services.
 * CF and ZF follow the real-mode flags the guest would see in EFLAGS.
 */
#ifndef CSMWRAP_REGS_H
#define CSMWRAP_REGS_H
#include <stdint.h>

#define CSM_CF 0x0001u
#define CSM_ZF 0x0040u

enum {
    CSM_OK = 0,
    CSM_INT_OK = 0,
    CSM_INT_BLOCK = 1,
    CSM_ERR_ARG = -1,
    CSM_ERR_MALFORMED = -2,
    CSM_ERR_NOSPACE = -3,
    CSM_ERR_RANGE = -4,
    CSM_ERR_NOTFOUND = -5
};

typedef struct csm_regs {
    uint32_t eax, ebx, ecx, edx;
    uint32_t esi, edi, ebp;
    uint16_t flags;
    uint8_t *buf;
    uint32_t buf_bytes;
} csm_regs;

static inline uint8_t csm_ah(const csm_regs *r) { return (uint8_t)(r->eax >> 8); }
static inline uint8_t csm_al(const csm_regs *r) { return (uint8_t)r->eax; }
static inline void csm_set_ah(csm_regs *r, uint8_t ah)
{
    r->eax = (r->eax & 0xffff00ffu) | ((uint32_t)ah << 8);
}
static inline void csm_set_al(csm_regs *r, uint8_t al)
{
    r->eax = (r->eax & 0xffffff00u) | al;
}
static inline void csm_cf(csm_regs *r, int set)
{
    if (set) r->flags |= CSM_CF;
    else r->flags &= (uint16_t)~CSM_CF;
}
static inline void csm_zf(csm_regs *r, int set)
{
    if (set) r->flags |= CSM_ZF;
    else r->flags &= (uint16_t)~CSM_ZF;
}
#endif
