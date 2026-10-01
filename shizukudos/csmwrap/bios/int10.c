/* SPDX-License-Identifier: GPL-2.0-only
 * BIOS entry for text INT 10h.
 *
 * Direct MMIO / the VGA window at physical 0xB8000 is not supported and is
 * not consulted. This translation unit only decodes registers and calls the
 * cell-buffer video module. Completing this call path comes before any
 * hardware text-plane emulation.
 */
#include "int10.h"
#include "../video/video.h"

static void put16(uint32_t *reg, uint16_t value)
{
    *reg = (*reg & 0xffff0000u) | value;
}

static void clear_cf(csmwrap_regs *regs)
{
    regs->eflags &= ~1u;
}

void csmwrap_int10(csmwrap_regs *regs)
{
    uint8_t ah, al;
    if (!regs)
        return;
    ah = (uint8_t)(regs->eax >> 8);
    al = (uint8_t)regs->eax;
    switch (ah) {
    case 0x00:
        csm_video_set_mode(al);
        break;
    case 0x02:
        csm_video_set_cursor((uint8_t)(regs->edx >> 8), (uint8_t)regs->edx);
        break;
    case 0x03: {
        uint8_t row = 0, col = 0;
        uint16_t shape = 0;
        csm_video_get_cursor(&row, &col, &shape);
        put16(&regs->ecx, shape);
        put16(&regs->edx, (uint16_t)((row << 8) | col));
        break;
    }
    case 0x06:
    case 0x07:
        csm_video_scroll(ah == 0x07, al, (uint8_t)(regs->ebx >> 8),
                         (uint8_t)(regs->ecx >> 8), (uint8_t)regs->ecx,
                         (uint8_t)(regs->edx >> 8), (uint8_t)regs->edx);
        break;
    case 0x08:
        put16(&regs->eax, csm_video_read_cell_at_cursor());
        break;
    case 0x09:
        /* BH page is ignored; only page 0 exists. */
        csm_video_write_char_attr(al, (uint8_t)regs->ebx, (uint16_t)regs->ecx);
        break;
    case 0x0e:
        csm_video_teletype(al);
        break;
    case 0x0f:
        put16(&regs->eax, (uint16_t)(((uint16_t)csm_video_columns() << 8) |
                                     csm_video_mode()));
        regs->ebx = (regs->ebx & 0xffff00ffu) | ((uint32_t)csm_video_page() << 8);
        break;
    default:
        return;
    }
    clear_cf(regs);
}
