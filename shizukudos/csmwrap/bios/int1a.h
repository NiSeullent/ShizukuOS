/* SPDX-License-Identifier: GPL-2.0-only
 * INT 1Ah time-of-day, RTC read, and PCI BIOS entry (AH=B1h).
 */
#ifndef CSMWRAP_INT1A_H
#define CSMWRAP_INT1A_H
#include "clock.h"
#include "pcibus.h"
#include "regs.h"
int csm_int1a(csm_regs *r, csm_ticks *ticks, csm_time_source source, void *clock_ctx, csm_pci *pci);
#endif
