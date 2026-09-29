/* SPDX-License-Identifier: GPL-2.0-only
 * Host-side view of the DOS domain: guest RAM access and register accessors.
 */
#ifndef SHZ_GUEST_H
#define SHZ_GUEST_H
#include <stdint.h>
#include "vmx.h"
#include "../include/shz_info.h"

typedef struct {
    vcpu_t *vc;
    uint64_t ram_base, ram_size;
    shz_info_t *info;
    uint64_t tsc_hz;
} guest_t;
extern guest_t G;

/* Guest-physical to host pointer; NULL when [gpa, gpa+len) leaves guest RAM. */
static inline uint8_t *gpa_ptr(uint64_t gpa, uint64_t len)
{
    if (gpa > G.ram_size || len > G.ram_size - gpa)
        return 0;
    return (uint8_t *)(uintptr_t)(G.ram_base + gpa);
}

#define REG16(r) ((uint16_t)G.vc->gpr[r])
static inline void set_reg16(int r, uint16_t v) { G.vc->gpr[r] = (G.vc->gpr[r] & ~0xffffull) | v; }
static inline uint8_t reg8l(int r) { return (uint8_t)G.vc->gpr[r]; }
static inline uint8_t reg8h(int r) { return (uint8_t)(G.vc->gpr[r] >> 8); }
static inline void set_reg8l(int r, uint8_t v) { G.vc->gpr[r] = (G.vc->gpr[r] & ~0xffull) | v; }
static inline void set_reg8h(int r, uint8_t v) { G.vc->gpr[r] = (G.vc->gpr[r] & ~0xff00ull) | ((uint64_t)v << 8); }

#define AX REG16(GPR_RAX)
#define BX REG16(GPR_RBX)
#define CX REG16(GPR_RCX)
#define DX REG16(GPR_RDX)
#define SI REG16(GPR_RSI)
#define DI REG16(GPR_RDI)
#define BP REG16(GPR_RBP)
#define AL reg8l(GPR_RAX)
#define AH reg8h(GPR_RAX)
#define BL reg8l(GPR_RBX)
#define BH reg8h(GPR_RBX)
#define CL reg8l(GPR_RCX)
#define CH reg8h(GPR_RCX)
#define DL reg8l(GPR_RDX)
#define DH reg8h(GPR_RDX)

#endif
