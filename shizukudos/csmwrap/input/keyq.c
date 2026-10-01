/* SPDX-License-Identifier: GPL-2.0-only */
#include "keyq.h"
#include "regs.h"

void csm_keyq_init(csm_keyq *q)
{
    unsigned i;
    if (!q)
        return;
    for (i = 0; i < CSM_KEYQ_SLOTS; ++i)
        q->slot[i] = 0;
    q->head = q->tail = 0;
    q->shift = 0;
}

int csm_keyq_push(csm_keyq *q, uint16_t key)
{
    unsigned next;
    if (!q)
        return CSM_ERR_ARG;
    next = (q->head + 1u) % CSM_KEYQ_SLOTS;
    if (next == q->tail)
        return CSM_ERR_NOSPACE;
    q->slot[q->head] = key;
    q->head = next;
    return 0;
}

int csm_keyq_peek(const csm_keyq *q, uint16_t *key)
{
    if (!q || !key)
        return CSM_ERR_ARG;
    if (q->head == q->tail)
        return CSM_ERR_NOTFOUND;
    *key = q->slot[q->tail];
    return 0;
}

int csm_keyq_pop(csm_keyq *q, uint16_t *key)
{
    int st = csm_keyq_peek(q, key);
    if (st)
        return st;
    q->tail = (q->tail + 1u) % CSM_KEYQ_SLOTS;
    return 0;
}

void csm_keyq_set_shift(csm_keyq *q, uint8_t shift)
{
    if (q)
        q->shift = shift;
}

uint8_t csm_keyq_shift(const csm_keyq *q)
{
    return q ? q->shift : 0;
}

uint16_t csm_key_from_ascii(uint8_t ascii)
{
    static const char rows[] = "qwertyuiop[]asdfghjkl;'`\\zxcvbnm,./";
    static const uint8_t scans[] = {
        0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b,
        0x1e, 0x1f, 0x20, 0x21, 0x22, 0x23, 0x24, 0x25, 0x26, 0x27, 0x28, 0x29, 0x2b,
        0x2c, 0x2d, 0x2e, 0x2f, 0x30, 0x31, 0x32, 0x33, 0x34, 0x35};
    unsigned i;
    uint8_t lower = ascii;
    _Static_assert(sizeof scans == sizeof rows - 1, "scan map");
    if (ascii == '\r' || ascii == '\n')
        return 0x1c0d;
    if (ascii == 8 || ascii == 0x7f)
        return 0x0e08;
    if (ascii == 0x1b)
        return 0x011b;
    if (ascii == '\t')
        return 0x0f09;
    if (ascii == ' ')
        return 0x3920;
    if (ascii >= '1' && ascii <= '9')
        return (uint16_t)(((ascii - '1' + 2) << 8) | ascii);
    if (ascii == '0')
        return (uint16_t)(0x0b00 | ascii);
    if (ascii >= 'A' && ascii <= 'Z')
        lower = (uint8_t)(ascii - 'A' + 'a');
    for (i = 0; rows[i]; ++i)
        if (rows[i] == (char)lower)
            return (uint16_t)((scans[i] << 8) | ascii);
    return ascii < 0x80 ? ascii : 0;
}
