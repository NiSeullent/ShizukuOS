/* SPDX-License-Identifier: GPL-2.0-only */
#include "a20.h"

void csm_a20_init(csm_a20 *gate)
{
    if (gate)
        gate->enabled = 1;
}

void csm_a20_set(csm_a20 *gate, int enabled)
{
    if (gate)
        gate->enabled = enabled ? 1 : 0;
}

int csm_a20_enabled(const csm_a20 *gate)
{
    return gate && gate->enabled ? 1 : 0;
}

uint16_t csm_a20_support_bx(const csm_a20 *gate)
{
    (void)gate;
    return 0x0003;
}
