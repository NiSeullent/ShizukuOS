/* SPDX-License-Identifier: GPL-2.0-only
 * Single-desktop subject gates. Caller holds gfx_lock; kernel queue/thread
 * identity, never window user data or a username, identifies the authority.
 * This does not implement separate desktops or the native Windows98 boundary.
 */
#ifndef SHZ_GFX_AUTH_H
#define SHZ_GFX_AUTH_H
#include "gfx.h"
#include "auth_policy.h"
void gin_auth_transition(void); /* gfx_input.c; caller holds gfx_lock. */
static inline int gfx_auth_queue(process_t *cur,const gqueue_t *q)
{
    if(!cur || !cur->used || cur->terminated || !q || !q->used || !q->proc || !q->thread ||
       !q->proc->used || q->proc->terminated || q->thread->id!=q->thread_id ||
       q->thread->state==TS_FREE || q->thread->state==TS_ZOMBIE || q->thread->proc!=q->proc ||
       q->pid!=(uint32_t)q->proc->pid)return 0;
    return shz_auth_process_access(cur,q->proc);
}
/* No foreground permits desktop metadata only. Mutating the shared desktop
 * or accessing global input requires a live authorized foreground recipient. */
static inline int gfx_auth_desktop(process_t *cur,int mutate)
{
    if(g_fg_q)return gfx_auth_queue(cur,g_fg_q);
    return !mutate && cur && cur->used && !cur->terminated;
}
static inline int gfx_auth_window(process_t *cur,const gwin_t *w)
{
    if(!w || !w->used || w->destroying)return 0;
    if(w==wm_desktop())return gfx_auth_desktop(cur,0);
    return w->q && w->pid==w->q->pid && w->q->thread &&
        w->tid==(uint32_t)w->q->thread->tid && gfx_auth_queue(cur,w->q);
}
static inline uint64_t gfx_auth_handle(process_t *cur,uint64_t handle)
{
    gwin_t *w=wm_lookup(handle);return gfx_auth_window(cur,w)?handle:0;
}
/* Rendering/input target inclusion is mutual: an authorized higher-integrity
 * viewer must not display an untrusted lower-integrity window as its prompt. */
static inline int gfx_auth_screen_window(const gwin_t *w)
{
    return g_fg_q && gfx_auth_queue(g_fg_q->proc,g_fg_q) && gfx_auth_window(g_fg_q->proc,w) &&
        w && w->q && gfx_auth_queue(w->q->proc,g_fg_q);
}
static inline int gfx_auth_activate(process_t *cur,const gwin_t *w)
{
    if(!gfx_auth_window(cur,w))return 0;
    if(!g_fg_q || gfx_auth_queue(cur,g_fg_q))return 1;
    /* Only an actual caller-owned activation consumes a kernel launch grant. */
    return w->pid==(uint32_t)cur->pid && shz_auth_gui_take_entry(cur);
}
#endif
