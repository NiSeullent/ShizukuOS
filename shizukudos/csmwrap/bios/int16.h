/* SPDX-License-Identifier: GPL-2.0-only
 * INT 16h AH=00h read, AH=01h status, AH=02h shift flags.
 * An empty AH=00h does not invent a keystroke: it sets ZF and returns
 * CSM_INT_BLOCK so the caller can wait.
 */
#ifndef CSMWRAP_INT16_H
#define CSMWRAP_INT16_H
#include "keyq.h"
#include "regs.h"
int csm_int16(csm_regs *r, csm_keyq *queue);
#endif
