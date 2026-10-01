/* SPDX-License-Identifier: GPL-2.0-only
 * INT 15h AH=88h, AX=E820h, and AH=24h A20 gate services.
 */
#ifndef CSMWRAP_INT15_H
#define CSMWRAP_INT15_H
#include "a20.h"
#include "e820.h"
#include "regs.h"
#include <stddef.h>
int csm_int15(csm_regs *r, csm_a20 *gate, const csm_e820_entry *map, size_t count);
#endif
