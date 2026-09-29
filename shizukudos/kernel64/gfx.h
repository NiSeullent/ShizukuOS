/* SPDX-License-Identifier: GPL-2.0-only
 * Kernel64 graphics: internal interfaces shared by gfx_fb.c (display), gfx_wm.c (windows, compositor, syscalls) and
 * gfx_msg.c (message queues). Only the SHZ_STANDALONE profile has a display device; see gfx_fb.c.
 */
#ifndef K64_GFX_H
#define K64_GFX_H
#include "proc_internal.h"
#include "../win64/include/shzgfx.h"

#define STATUS_NO_SUCH_DEVICE ((int32_t)0xC000000E)

/* ---- gfx_fb.c ---- */
typedef struct {
    int ready;
    uint32_t width, height, bpp, pitch;             /* pitch in bytes */
    uint16_t bga_version;
    uint64_t lfb_pa;
    volatile uint32_t *lfb;                         /* uncached mapping of the linear framebuffer */
    uint32_t *back;                                 /* kernel back buffer, width*height dwords, 0x00RRGGBB */
} gfx_fb_t;
extern gfx_fb_t g_fb;

int gfx_fb_init(void);                              /* idempotent; 0 = display ready, else an NTSTATUS */
void gfx_fb_present(int x, int y, int w, int h);    /* copy a back-buffer rectangle to the framebuffer (clipped) */
void gfx_fb_test_pattern(void);
/* Page-granular kernel allocator for large pixel buffers (the 4 MiB kernel heap is too small): physical pages from the
 * PMM mapped contiguously at a reserved kernel address range. Zeroed. */
void *gfx_pages_alloc(uint64_t bytes);
void gfx_pages_free(void *p, uint64_t bytes);
/* 8x16 text (the only font): draws `n` UTF-16 code units, glyphs >= 0x80 as '?', clipped to [cx0,cx1)x[cy0,cy1). */
#define GFX_FONT_W 8
#define GFX_FONT_H 16
void gfx_text(uint32_t *buf, int stride, int bufw, int bufh, int x, int y, const uint16_t *s, unsigned n, uint32_t rgb,
              int cx0, int cy0, int cx1, int cy1);

int32_t gfx_syscall_display(process_t *cur, uint64_t out, uint64_t op);
#endif
