/* SPDX-License-Identifier: GPL-2.0-only */
#include "int1a.h"
#include "pci_bios.h"

static int read_bcd_clock(csm_regs *r, csm_time_source source, void *clock_ctx, int date)
{
    csm_civil civil;
    int st = csm_read_clock(source, clock_ctx, &civil);
    uint8_t hi, lo, dhi, dlo;
    if (st) {
        csm_cf(r, 1);
        return CSM_INT_ERROR;
    }
    if (date) {
        hi = csm_to_bcd(civil.year / 100);
        lo = csm_to_bcd(civil.year % 100);
        dhi = csm_to_bcd(civil.month);
        dlo = csm_to_bcd(civil.day);
    } else {
        hi = csm_to_bcd(civil.hour);
        lo = csm_to_bcd(civil.minute);
        dhi = csm_to_bcd(civil.second);
        dlo = 0;
    }
    if (hi == 0xff || lo == 0xff || dhi == 0xff || dlo == 0xff) {
        csm_cf(r, 1);
        return CSM_INT_ERROR;
    }
    r->ecx = (r->ecx & 0xffff0000u) | ((uint32_t)hi << 8) | lo;
    r->edx = (r->edx & 0xffff0000u) | ((uint32_t)dhi << 8) | dlo;
    csm_set_ah(r, 0);
    csm_cf(r, 0);
    return CSM_INT_OK;
}

int csm_int1a(csm_regs *r, csm_ticks *ticks, csm_time_source source, void *clock_ctx, csm_pci *pci)
{
    uint32_t packed;
    uint8_t midnight = 0;
    if (!r)
        return CSM_ERR_ARG;
    if (csm_ah(r) == 0xb1)
        return csm_pci_bios(r, pci);
    switch (csm_ah(r)) {
    case 0x00:
        if (!ticks) {
            csm_cf(r, 1);
            return CSM_INT_ERROR;
        }
        packed = csm_ticks_read(ticks, &midnight);
        r->ecx = (r->ecx & 0xffff0000u) | (packed >> 16);
        r->edx = (r->edx & 0xffff0000u) | (packed & 0xffffu);
        csm_set_al(r, midnight);
        csm_cf(r, 0);
        return CSM_INT_OK;
    case 0x01:
        if (!ticks) {
            csm_cf(r, 1);
            return CSM_INT_ERROR;
        }
        packed = ((r->ecx & 0xffffu) << 16) | (r->edx & 0xffffu);
        if (csm_ticks_set(ticks, packed)) {
            csm_cf(r, 1);
            return CSM_INT_ERROR;
        }
        csm_cf(r, 0);
        return CSM_INT_OK;
    case 0x02:
        return read_bcd_clock(r, source, clock_ctx, 0);
    case 0x04:
        return read_bcd_clock(r, source, clock_ctx, 1);
    default:
        csm_cf(r, 1);
        csm_set_ah(r, 0x86);
        return CSM_INT_ERROR;
    }
}
