/* SPDX-License-Identifier: GPL-2.0-only
 * BIOS timer tick (18.2065 Hz) and a caller-supplied civil clock.
 */
#ifndef CSMWRAP_CLOCK_H
#define CSMWRAP_CLOCK_H
#include <stdint.h>

#define CSM_TICKS_PER_DAY 0x1800B0u

typedef struct csm_ticks {
    uint32_t ticks;
    uint8_t midnight;
} csm_ticks;

typedef struct csm_civil {
    int year; /* full year, 0..9999 */
    int month, day, hour, minute, second;
} csm_civil;

typedef int (*csm_time_source)(void *context, csm_civil *out);

void csm_ticks_init(csm_ticks *t);
int csm_ticks_set(csm_ticks *t, uint32_t ticks);
void csm_ticks_advance(csm_ticks *t, uint32_t count);
uint32_t csm_ticks_read(csm_ticks *t, uint8_t *midnight);

int csm_civil_valid(const csm_civil *time);
uint8_t csm_to_bcd(int value);
int csm_read_clock(csm_time_source source, void *context, csm_civil *out);
#endif
