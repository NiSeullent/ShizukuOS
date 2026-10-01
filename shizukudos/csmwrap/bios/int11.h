/* SPDX-License-Identifier: GPL-2.0-only
 * INT 11h equipment word. Matches the BDA word published by the
 * existing Shizuku supervisor: 80x25 colour, coprocessor, one COM port.
 */
#ifndef CSMWRAP_INT11_H
#define CSMWRAP_INT11_H
#include <stdint.h>
#define CSM_EQUIPMENT_WORD 0x0222u
uint16_t csm_int11(void);
#endif
