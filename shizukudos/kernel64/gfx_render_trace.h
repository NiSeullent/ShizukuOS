/* SPDX-License-Identifier: GPL-2.0-only
 * Called with gfx_lock held, and only after caller pixel staging succeeds.
 * Existing shz.systrace enables bounded actual samples; no framebuffer writes.
 */
#ifndef SHZ_GFX_RENDER_TRACE_H
#define SHZ_GFX_RENDER_TRACE_H
#include "../abi/shz_pixel_sample.h"

/* At most 16 live visible windows for each of the first four submissions.
 * This reads only kernel-owned state while gfx_lock is held, including the
 * retained surface's first pixel. A row describes ownership/occlusion, not
 * a successful page render. Hidden/message-only windows consume no budget. */
static void gfx_render_trace_tree(unsigned frame)
{
    unsigned i, rows = 0;
    if (frame > 4) return;
    for (i = 1; i < GFX_MAX_WINDOWS && rows < 16; ++i) {
        gwin_t *node = &g_win[i];
        char name[32]; unsigned j, limit;
        uint32_t first = 0;
        if (!node->used || node->destroying || !wm_is_visible(node)) continue;
        limit = node->cls ? node->cls->name_len : 0;
        if (limit > 31) limit = 31;
        for (j = 0; j < limit; ++j) {
            uint16_t c = node->cls->name[j];
            name[j] = c >= 32 && c < 127 ? (char)c : '?';
        }
        name[j] = 0;
        if (node->surf && node->sw > 0 && node->sh > 0) first = node->surf[0];
        kprintf("K64 raster: tree frame=%u row=%u hwnd=%llx parent=%llx next=%llx pid=%u tid=%u atom=%x class=%s style=%x exstyle=%x rect=%d,%d,%d,%d surface=%d,%d first=%x\n",
            frame,++rows,node->handle,node->parent ? node->parent->handle : 0,
            node->next ? node->next->handle : 0,node->pid,node->tid,node->cls ? node->cls->atom : 0,name,
            node->style,node->exstyle,node->x,node->y,node->w,node->h,node->sw,node->sh,first);
    }
}

static void gfx_render_trace_present(process_t *cur, const shz_present_t *p,
    gwin_t *w, int32_t status, const uint32_t *staged,
    const shz_present_layout_t *layout, const shz_rect_t *damage,
    uint64_t framebuffers_before)
{
    static unsigned count;
    static int enabled = -1;
    shz_pixel_samples_t source = {0,0,0,0,0,0,0}, stored = {0,0,0,0,0,0,0}, screen = {0,0,0,0,0,0,0};
    unsigned n;
    if (enabled < 0) enabled = k64_cmdline_has("shz.systrace");
    if (!enabled || count >= 4096) return;
    n = ++count;
    if (n > 32 && (n & 63)) return;
    if (staged) {
        const int32_t width = layout->rect.right-layout->rect.left;
        const int32_t height = layout->rect.bottom-layout->rect.top;
        source = shz_pixel_samples(staged,width,height,(uint32_t)width,1,0,0,width,height);
        if (!status && w && w->surf)
            stored = shz_pixel_samples(w->surf,w->sw,w->sh,(uint32_t)w->sw,1,
                layout->rect.left,layout->rect.top,layout->rect.right,layout->rect.bottom);
    }
    if (damage && g_fb.back)
        screen = shz_pixel_samples(g_fb.back,(int32_t)g_fb.width,(int32_t)g_fb.height,g_fb.width,1,
                                  damage->left,damage->top,damage->right,damage->bottom);
    kprintf("K64 raster: present seq=%u pid=%u hwnd=%llx owner=%u status=%x rect=%d,%d,%d,%d size=%u,%u style=%x exstyle=%x visible=%d fb_updates=%llu source_samples=%u source_first=%x source_hash=%x source_nonface=%u source_differing=%u stored_samples=%u stored_first=%x stored_hash=%x screen_samples=%u screen_first=%x screen_hash=%x screen_nonface=%u screen_differing=%u\n",
            n,(uint32_t)cur->pid,p->hwnd,w ? w->pid : 0,(uint32_t)status,p->x,p->y,p->w,p->h,p->surf_w,p->surf_h,
            w ? w->style : 0,w ? w->exstyle : 0,w ? wm_is_visible(w) : 0,g_fb.stat_presents-framebuffers_before,
            source.count,source.first,source.hash,source.nonface,source.differing,
            stored.count,stored.first,stored.hash,
            screen.count,screen.first,screen.hash,screen.nonface,screen.differing);
    gfx_render_trace_tree(n);
}
#endif
