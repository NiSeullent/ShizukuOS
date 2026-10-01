/* SPDX-License-Identifier: GPL-2.0-only */
#include "int15.h"
#include <string.h>

static void fail(csm_regs *r, uint8_t ah)
{
    csm_set_ah(r, ah);
    csm_cf(r, 1);
}

static int service_a20(csm_regs *r, csm_a20 *gate)
{
    if (!gate) {
        fail(r, 0x86);
        return CSM_INT_ERROR;
    }
    switch (csm_al(r)) {
    case 0x00:
        csm_a20_set(gate, 0);
        csm_set_ah(r, 0);
        csm_cf(r, 0);
        return CSM_INT_OK;
    case 0x01:
        csm_a20_set(gate, 1);
        csm_set_ah(r, 0);
        csm_cf(r, 0);
        return CSM_INT_OK;
    case 0x02:
        csm_set_ah(r, 0);
        csm_set_al(r, (uint8_t)csm_a20_enabled(gate));
        csm_cf(r, 0);
        return CSM_INT_OK;
    case 0x03:
        csm_set_ah(r, 0);
        r->ebx = (r->ebx & 0xffff0000u) | csm_a20_support_bx(gate);
        csm_cf(r, 0);
        return CSM_INT_OK;
    default:
        fail(r, 0x86);
        return CSM_INT_ERROR;
    }
}

static int service_88(csm_regs *r, const csm_e820_entry *map, size_t count)
{
    int present = 0;
    uint16_t kb;
    if (!map) {
        fail(r, 0x86);
        return CSM_INT_ERROR;
    }
    kb = csm_e820_extended_kb(map, count, &present);
    r->eax = (r->eax & 0xffff0000u) | kb;
    csm_cf(r, 0);
    (void)present;
    return CSM_INT_OK;
}

static int service_e820(csm_regs *r, const csm_e820_entry *map, size_t count)
{
    uint32_t index = r->ebx;
    uint32_t bytes;
    csm_e820_entry entry;
    if (r->edx != 0x534D4150u || r->ecx < 20 || !map || !r->buf) {
        fail(r, 0x86);
        return CSM_INT_ERROR;
    }
    if (index >= count) {
        fail(r, 0x86);
        return CSM_INT_ERROR;
    }
    bytes = r->ecx >= 24 ? 24u : 20u;
    if (r->buf_bytes < bytes) {
        fail(r, 0x86);
        return CSM_INT_ERROR;
    }
    entry = map[index];
    entry.attributes = 1;
    memcpy(r->buf, &entry, bytes);
    r->eax = 0x534D4150u;
    r->ecx = bytes;
    r->ebx = (index + 1u >= count) ? 0u : index + 1u;
    csm_cf(r, 0);
    return CSM_INT_OK;
}

int csm_int15(csm_regs *r, csm_a20 *gate, const csm_e820_entry *map, size_t count)
{
    if (!r)
        return CSM_ERR_ARG;
    if ((r->eax & 0xffffu) == 0xE820u)
        return service_e820(r, map, count);
    if (csm_ah(r) == 0x88)
        return service_88(r, map, count);
    if (csm_ah(r) == 0x24)
        return service_a20(r, gate);
    fail(r, 0x86);
    return CSM_INT_ERROR;
}
