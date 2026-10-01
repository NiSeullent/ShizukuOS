/* SPDX-License-Identifier: GPL-2.0-only */
#include "../include/csmwrap_abi.h"

static uint8_t byte_sum(const csmwrap_handoff *handoff)
{
    const uint8_t *bytes = (const uint8_t *)handoff;
    unsigned i;
    uint8_t sum = 0;
    for (i = 0; i < sizeof(*handoff); ++i)
        sum = (uint8_t)(sum + bytes[i]);
    return sum;
}

void csmwrap_handoff_seal(csmwrap_handoff *handoff)
{
    uint8_t sum;
    if (!handoff)
        return;
    handoff->checksum = 0;
    sum = byte_sum(handoff);
    handoff->checksum = (uint8_t)(0u - sum);
}

int csmwrap_handoff_check(const csmwrap_handoff *handoff)
{
    uint32_t sig0, sig1;
    if (!handoff || handoff->size != sizeof(*handoff))
        return -1;
    if (handoff->abi_major != 1 || handoff->abi_minor != 0)
        return -1;
    sig0 = (uint32_t)handoff->signature[0] | ((uint32_t)handoff->signature[1] << 8) |
           ((uint32_t)handoff->signature[2] << 16) | ((uint32_t)handoff->signature[3] << 24);
    sig1 = (uint32_t)handoff->signature[4] | ((uint32_t)handoff->signature[5] << 8) |
           ((uint32_t)handoff->signature[6] << 16) | ((uint32_t)handoff->signature[7] << 24);
    if (sig0 != CSMWRAP_SIG0 || sig1 != CSMWRAP_SIG1)
        return -1;
    if (byte_sum(handoff) != 0)
        return -1;
    return 0;
}
