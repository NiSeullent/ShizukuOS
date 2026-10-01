/* SPDX-License-Identifier: GPL-2.0-only */
#include "int16.h"

int csm_int16(csm_regs *r, csm_keyq *queue)
{
    uint16_t key = 0;
    if (!r || !queue)
        return CSM_ERR_ARG;
    switch (csm_ah(r)) {
    case 0x00:
        if (csm_keyq_pop(queue, &key)) {
            csm_zf(r, 1);
            csm_cf(r, 0);
            return CSM_INT_BLOCK;
        }
        r->eax = (r->eax & 0xffff0000u) | key;
        csm_zf(r, 0);
        csm_cf(r, 0);
        return CSM_INT_OK;
    case 0x01:
        if (csm_keyq_peek(queue, &key)) {
            csm_zf(r, 1);
            csm_cf(r, 0);
            return CSM_INT_OK;
        }
        r->eax = (r->eax & 0xffff0000u) | key;
        csm_zf(r, 0);
        csm_cf(r, 0);
        return CSM_INT_OK;
    case 0x02:
        csm_set_al(r, csm_keyq_shift(queue));
        csm_zf(r, 0);
        csm_cf(r, 0);
        return CSM_INT_OK;
    default:
        csm_set_ah(r, 0x86);
        csm_cf(r, 1);
        return CSM_INT_ERROR;
    }
}
