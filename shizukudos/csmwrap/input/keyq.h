/* SPDX-License-Identifier: GPL-2.0-only
 * 16-slot BIOS keyboard buffer. One slot stays empty, so 15 keys fit.
 * AH=02h flags are stored beside the queue for the test backend.
 */
#ifndef CSMWRAP_KEYQ_H
#define CSMWRAP_KEYQ_H
#include <stdint.h>

#define CSM_KEYQ_SLOTS 16

typedef struct csm_keyq {
    uint16_t slot[CSM_KEYQ_SLOTS];
    unsigned head, tail;
    uint8_t shift;
} csm_keyq;

void csm_keyq_init(csm_keyq *q);
int csm_keyq_push(csm_keyq *q, uint16_t key);
int csm_keyq_peek(const csm_keyq *q, uint16_t *key);
int csm_keyq_pop(csm_keyq *q, uint16_t *key);
void csm_keyq_set_shift(csm_keyq *q, uint8_t shift);
uint8_t csm_keyq_shift(const csm_keyq *q);
/* AX value (scan in AH, ASCII in AL) for a host character. 0 if unknown. */
uint16_t csm_key_from_ascii(uint8_t ascii);
#endif
