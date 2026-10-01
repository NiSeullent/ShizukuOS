/* SPDX-License-Identifier: GPL-2.0-only
 * A20 gate state. The stored bit is what INT 15h AH=24h reports.
 * Enabling it does not touch the keyboard controller or port 92h.
 */
#ifndef CSMWRAP_A20_H
#define CSMWRAP_A20_H
#include <stdint.h>

typedef struct csm_a20 {
    int enabled;
} csm_a20;

void csm_a20_init(csm_a20 *gate);
void csm_a20_set(csm_a20 *gate, int enabled);
int csm_a20_enabled(const csm_a20 *gate);
/* BX value for INT 15h AX=2403h: keyboard controller and port 92h. */
uint16_t csm_a20_support_bx(const csm_a20 *gate);
#endif
