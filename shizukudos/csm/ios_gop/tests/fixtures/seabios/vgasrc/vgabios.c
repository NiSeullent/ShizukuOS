// VGA bios implementation
//
// Copyright (C) 2009-2013  Kevin O'Connor <kevin@koconnor.net>
// Copyright (C) 2001-2008 the LGPL VGABios developers Team
//
// This file may be distributed under the terms of the GNU LGPLv3 license.

#include "biosvar.h" // GET_BDA
#include "bregs.h" // struct bregs
#include "config.h" // CONFIG_*
#include "output.h" // dprintf
#include "std/vbe.h" // VBE_RETURN_STATUS_FAILED
#include "std/vga.h" // struct video_func_static
#include "stdvga.h" // stdvga_set_cursor_shape
#include "string.h" // memset_far
#include "vgabios.h" // calc_page_size
#include "vgafb.h" // vgafb_write_char
#include "vgahw.h" // vgahw_set_mode
#include "vgautil.h" // swcursor_pre_handle10


/****************************************************************
 * Helper functions
 ****************************************************************/

u16
calc_page_size(u8 memmodel, u16 width, u16 height)
{
    switch (memmodel) {
    case MM_TEXT:
        return ALIGN(width * height * 2, 2*1024);
    case MM_CGA:
        return 16*1024;
    default:
        return ALIGN(width * height / 8, 8*1024);
    }
}

int
vga_set_mode(int mode, int flags)
{
    dprintf(1, "set VGA mode %x\n", mode);
    struct vgamode_s *vmode_g = vgahw_find_mode(mode);
    if (!vmode_g)
        return VBE_RETURN_STATUS_FAILED;

    int ret = vgahw_set_mode(vmode_g, flags);
    if (ret)
        return ret;

    // Set the BIOS mem
    int width = GET_GLOBAL(vmode_g->width);
    int height = GET_GLOBAL(vmode_g->height);
    u8 memmodel = GET_GLOBAL(vmode_g->memmodel);
    int cheight = GET_GLOBAL(vmode_g->cheight);
    if (mode < 0x100)
        SET_BDA(video_mode, mode);
    else
        SET_BDA(video_mode, 0xff);
    SET_BDA_EXT(vbe_mode, mode | (flags & MF_VBEFLAGS));
    SET_BDA_EXT(vgamode_offset, (u32)vmode_g);
    if (CONFIG_VGA_ALLOCATE_EXTRA_STACK)
        // Disable extra stack if it appears a modern OS is in use.
        // This works around bugs in some versions of Windows (Vista
        // and possibly later) when the stack is in the e-segment.
        MASK_BDA_EXT(flags, BF_EXTRA_STACK
                     , (flags & MF_LEGACY) ? BF_EXTRA_STACK : 0);
    if (memmodel == MM_TEXT) {
        SET_BDA(video_cols, width);
        SET_BDA(video_rows, height-1);
        SET_BDA(cursor_type, 0x0607);
    } else {
        int cwidth = GET_GLOBAL(vmode_g->cwidth);
        SET_BDA(video_cols, width / cwidth);
        SET_BDA(video_rows, (height / cheight) - 1);
        SET_BDA(cursor_type, vga_emulate_text() ? 0x0607 : 0x0000);
    }
    SET_BDA(video_pagesize, calc_page_size(memmodel, width, height));
    SET_BDA(crtc_address, CONFIG_VGA_STDVGA_PORTS ? stdvga_get_crtc() : 0);
    SET_BDA(char_height, cheight);
    SET_BDA(video_ctl, 0x60 | (flags & MF_NOCLEARMEM ? 0x80 : 0x00));
    SET_BDA(video_switches, 0xF9);
    SET_BDA(modeset_ctl, GET_BDA(modeset_ctl) & 0x7f);
    int i;
    for (i=0; i<8; i++)
        SET_BDA(cursor_pos[i], 0x0000);
    SET_BDA(video_pagestart, 0x0000);
    SET_BDA(video_page, 0x00);

    // Set the ints 0x1F and 0x43
    SET_IVT(0x1f, SEGOFF(get_global_seg(), (u32)&vgafont8[128 * 8]));

    switch (cheight) {
    case 8:
        SET_IVT(0x43, SEGOFF(get_global_seg(), (u32)vgafont8));
        break;
    case 14:
        SET_IVT(0x43, SEGOFF(get_global_seg(), (u32)vgafont14));
        break;
    case 16:
        SET_IVT(0x43, SEGOFF(get_global_seg(), (u32)vgafont16));
        break;
    }

    return 0;
}

static void
handle_100f(struct bregs *regs)
{
    regs->bh = GET_BDA(video_page);
    regs->al = GET_BDA(video_mode) | (GET_BDA(video_ctl) & 0x80);
    regs->ah = GET_BDA(video_cols);
}
