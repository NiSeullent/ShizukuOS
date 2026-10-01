/* SPDX-License-Identifier: GPL-2.0-only
 * INT 10h text services for CSMWrap.
 *
 * Direct writes to VGA memory at physical 0xB8000 are NOT supported.
 * Guests must use this BIOS entry. There is no hardware text plane; the
 * video module owns the 80x25 cell buffer and paints the GOP framebuffer.
 *
 * Implemented: AH=00h, 02h, 03h, 06h, 07h, 08h, 09h, 0Eh, 0Fh.
 * Page numbers in BH are ignored; only page 0 exists.
 * AH=01h (cursor shape), AH=0Ah, AH=13h, and graphics modes are not
 * implemented. AH=03h returns the default underline shape 0607h.
 *
 * csmwrap_int10 matches csmwrap_service_fn and can be registered as
 * CSMWRAP_SVC_INT10. Implemented services clear CF. Others leave flags.
 */
#ifndef CSMWRAP_INT10_H
#define CSMWRAP_INT10_H
#include "../include/csmwrap_abi.h"

void csmwrap_int10(csmwrap_regs *regs);
#endif
