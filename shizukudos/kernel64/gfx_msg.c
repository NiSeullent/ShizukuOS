/* SPDX-License-Identifier: GPL-2.0-only
 * Kernel64 GUI message queues (see the design notes at the top of gfx_wm.c): per-thread queues, PostMessage, cross-thread
 * SendMessage with user-mode callbacks, GetMessage/PeekMessage, timers, update regions and the synthesised WM_PAINT,
 * WM_TIMER and WM_QUIT messages, plus the reaper that cleans up after threads that no longer exist.
 *
 * Message priority inside one retrieval, as on Windows: (1) messages sent by other threads, (2) posted messages in
 * order, (3) WM_QUIT, (4) WM_PAINT for the first window of the thread with a non-empty update region, (5) WM_TIMER for
 * the first due timer. A retrieved WM_PAINT does not clear the update region (BeginPaint/validation does), so a window
 * procedure that ignores WM_PAINT is asked again, exactly like the real thing.
 */
#include "gfx.h"

#define WM_QUIT 0x0012u
#define WM_PAINT 0x000fu
#define WM_TIMER 0x0113u
#define PM_REMOVE 1u
#define QS_POSTMESSAGE 0x0008u
#define QS_TIMER 0x0010u
#define QS_PAINT 0x0020u
#define QS_SENDMESSAGE 0x0040u
#define QS_HOTKEY 0x0080u
#define QS_ALLPOSTMESSAGE 0x0100u
#define USER_TIMER_MINIMUM 10u
#define USER_TIMER_MAXIMUM 0x7fffffffu
#define WAIT_POLL_TICKS 50u                     /* re-check process termination at least this often (1 tick = 1 ms) */

gqueue_t g_queues[GFX_MAX_QUEUES];
static gmsg_t g_msgs[GFX_MAX_MSGS];
static gmsg_t *msg_free;
static int msg_pool_ready;
static gsend_t g_sends[GFX_MAX_SENDS];
static uint64_t next_send_id = 1;

uint32_t gq_time(void) { return (uint32_t)ticks_now(); }

/* ---------------------------------------------------------------- queues */
int gq_thread_dead(gqueue_t *q)
{
    return q->thread->id != q->thread_id || q->thread->state == TS_ZOMBIE || q->thread->state == TS_FREE;
}

gqueue_t *gq_current(int create)
{
    thread_t *t = thread_current();
    unsigned i;
    gqueue_t *q;
    for (i = 0; i < GFX_MAX_QUEUES; ++i)
        if (g_queues[i].used && g_queues[i].thread == t && g_queues[i].thread_id == t->id) return &g_queues[i];
    if (!create || !t->proc) return 0;
    for (i = 0; i < GFX_MAX_QUEUES && g_queues[i].used; ++i) { }
    if (i == GFX_MAX_QUEUES) return 0;
    q = &g_queues[i];
    memset(q, 0, sizeof *q);
    q->used = 1;
    q->thread = t;
    q->thread_id = t->id;
    q->proc = t->proc;
    q->pid = (uint32_t)t->proc->pid;
    q->next_timer_id = 1;
    return q;
}

static gqueue_t *queue_by_thread_id(uint32_t id)
{
    unsigned i;
    for (i = 0; i < GFX_MAX_QUEUES; ++i)
        if (g_queues[i].used && g_queues[i].thread_id == id) return &g_queues[i];
    return 0;
}

void gq_wake(gqueue_t *q)
{
    const uint64_t f = irq_save();
    if (q->in_wait && q->thread->state == TS_BLOCKED) thread_wake(q->thread);
    irq_restore(f);
}

/* Called with gfx_lock held. Releases it, sleeps until woken or `wake_tick` (absolute, 0 = poll interval only), and
 * returns WITHOUT the lock. Interrupts are off between the unlock and the sleep: on a uniprocessor nothing can queue a
 * message and try to wake us in that window, so no wake-up is lost. */
static void gq_block(gqueue_t *q, uint64_t wake_tick)
{
    thread_t *t = q->thread;
    const uint64_t f = irq_save();
    const uint64_t now = ticks_now(), cap = now + WAIT_POLL_TICKS;
    uint64_t wake = wake_tick && wake_tick < cap ? wake_tick : cap;
    if (wake <= now) wake = now + 1;
    q->in_wait = 1;
    mutex_unlock(&gfx_lock);
    t->wake_tick = wake;
    thread_block_current();
    t->wake_tick = 0;
    q->in_wait = 0;
    irq_restore(f);
}

/* ---------------------------------------------------------------- posted message pool */
static gmsg_t *msg_alloc(void)
{
    gmsg_t *m;
    if (!msg_pool_ready) {
        unsigned i;
        for (i = 0; i < GFX_MAX_MSGS; ++i) { g_msgs[i].next = msg_free; msg_free = &g_msgs[i]; }
        msg_pool_ready = 1;
    }
    m = msg_free;
    if (m) { msg_free = m->next; memset(m, 0, sizeof *m); }
    return m;
}
static void msg_release(gmsg_t *m) { m->next = msg_free; msg_free = m; }

static int32_t post_to(gqueue_t *q, uint64_t hwnd, uint32_t message, uint64_t wparam, int64_t lparam)
{
    gmsg_t *m;
    if (q->nposted >= GFX_MSG_QUOTA) return STATUS_NO_QUOTA;
    m = msg_alloc();
    if (!m) return STATUS_NO_QUOTA;
    m->m.hwnd = hwnd;
    m->m.message = message;
    m->m.wparam = wparam;
    m->m.lparam = lparam;
    m->m.time = gq_time();
    if (q->tail) q->tail->next = m; else q->head = m;
    q->tail = m;
    ++q->nposted;
    gq_wake(q);
    return STATUS_SUCCESS;
}

/* ---------------------------------------------------------------- sent messages */
static gsend_t *send_alloc(void)
{
    unsigned i;
    for (i = 0; i < GFX_MAX_SENDS; ++i)
        if (!g_sends[i].id) {
            memset(&g_sends[i], 0, sizeof g_sends[i]);
            g_sends[i].id = next_send_id++;
            return &g_sends[i];
        }
    return 0;
}
static void send_release(gsend_t *s) { s->id = 0; }
static gsend_t *send_find(uint64_t id)
{
    unsigned i;
    if (!id) return 0;
    for (i = 0; i < GFX_MAX_SENDS; ++i)
        if (g_sends[i].id == id) return &g_sends[i];
    return 0;
}

static void send_list_remove(gsend_t **head, gsend_t **tail, gsend_t *s)
{
    gsend_t *p = 0, *c;
    for (c = *head; c; p = c, c = c->next)
        if (c == s) {
            if (p) p->next = c->next; else *head = c->next;
            if (*tail == c) *tail = p;
            c->next = 0;
            return;
        }
}
static void servicing_remove(gqueue_t *q, gsend_t *s)
{
    gsend_t **pp;
    for (pp = &q->servicing; *pp; pp = &(*pp)->next)
        if (*pp == s) { *pp = s->next; s->next = 0; return; }
}

static void send_finish(gsend_t *s, int state, int64_t result)
{
    gqueue_t *sq;
    if (s->state == GS_ABANDONED) { send_release(s); return; }
    s->state = state;
    s->result = result;
    sq = queue_by_thread_id(s->sender_tid);
    if (sq) gq_wake(sq);
}

/* Pops the first queued sent message of `q` into the servicing list and describes it as a callback. A message whose
 * window vanished is completed as failed and skipped. Returns 1 if `cb` was filled. */
static int take_sent(gqueue_t *q, shz_callback_t *cb)
{
    while (q->sent_head) {
        gsend_t *s = q->sent_head;
        gwin_t *w;
        q->sent_head = s->next;
        if (!q->sent_head) q->sent_tail = 0;
        s->next = 0;
        w = wm_lookup(s->hwnd);
        if (!w || w->q != q) { send_finish(s, GS_FAILED, 0); continue; }
        s->state = GS_SERVICING;
        s->next = q->servicing;
        q->servicing = s;
        memset(cb, 0, sizeof *cb);
        cb->id = s->id;
        cb->hwnd = s->hwnd;
        cb->message = s->message;
        cb->wparam = s->wparam;
        cb->lparam = s->lparam;
        cb->wndproc = w->wndproc;
        return 1;
    }
    return 0;
}

static int32_t sys_sendmessage(process_t *cur, uint64_t arg)
{
    shz_send_t s;
    gqueue_t *q;
    gsend_t *r = 0;
    gwin_t *w;
    int32_t st = STATUS_SUCCESS;
    uint64_t deadline;
    if (copy_from_user(cur, &s, arg, sizeof s)) return STATUS_ACCESS_VIOLATION;
    deadline = s.timeout_ms ? ticks_now() + s.timeout_ms : 0;
    mutex_lock(&gfx_lock);
    q = gq_current(1);
    if (!q) { st = STATUS_NO_MEMORY; goto out; }
    if (s.id == 0) {
        w = wm_lookup(s.hwnd);
        if (!w) { st = STATUS_INVALID_HANDLE; goto out; }
        if (w->q == q) { s.result_kind = SHZ_SEND_SAME_THREAD; s.wndproc = w->wndproc; goto out; }
        if (w->pid != (uint32_t)cur->pid) { st = STATUS_NOT_SUPPORTED; goto out; }      /* no cross-process marshalling */
        if (gq_thread_dead(w->q)) { s.result_kind = SHZ_SEND_FAILED; s.result = 0; goto out; }
        r = send_alloc();
        if (!r) { st = STATUS_NO_QUOTA; goto out; }
        r->hwnd = s.hwnd;
        r->message = s.message;
        r->wparam = s.wparam;
        r->lparam = s.lparam;
        r->target = w->q;
        r->sender_tid = q->thread_id;
        r->state = GS_QUEUED;
        if (w->q->sent_tail) w->q->sent_tail->next = r; else w->q->sent_head = r;
        w->q->sent_tail = r;
        s.id = r->id;
        gq_wake(w->q);
    } else {
        r = send_find(s.id);
        if (!r || r->sender_tid != q->thread_id) { st = STATUS_INVALID_PARAMETER; goto out; }
    }
    for (;;) {
        if (r->state == GS_DONE || r->state == GS_FAILED) {
            s.result_kind = r->state == GS_DONE ? SHZ_SEND_DONE : SHZ_SEND_FAILED;
            s.result = r->state == GS_DONE ? r->result : 0;
            send_release(r);
            goto out;
        }
        if (take_sent(q, &s.cb)) { s.result_kind = SHZ_SEND_CALLBACK; goto out; }       /* keep the wait alive while we serve */
        if (gq_thread_dead(r->target)) {
            if (r->state == GS_QUEUED) send_list_remove(&r->target->sent_head, &r->target->sent_tail, r);
            send_release(r);
            s.result_kind = SHZ_SEND_FAILED;
            s.result = 0;
            goto out;
        }
        if ((deadline && ticks_now() >= deadline) || cur->terminated) {
            if (r->state == GS_QUEUED) { send_list_remove(&r->target->sent_head, &r->target->sent_tail, r); send_release(r); }
            else r->state = GS_ABANDONED;                   /* being serviced: the receiver frees it when it replies */
            if (cur->terminated) { st = STATUS_PROCESS_IS_TERMINATING; goto out; }
            s.result_kind = SHZ_SEND_TIMEOUT;
            s.result = 0;
            goto out;
        }
        gq_block(q, deadline);
        mutex_lock(&gfx_lock);
        q = gq_current(1);
        r = send_find(s.id);
        if (!q || !r) { st = STATUS_INVALID_PARAMETER; goto out; }
    }
out:
    mutex_unlock(&gfx_lock);
    if (!st && copy_to_user(cur, arg, &s, sizeof s)) return STATUS_ACCESS_VIOLATION;
    return st;
}

static int32_t sys_replymessage(process_t *cur, uint64_t id, uint64_t result)
{
    gqueue_t *q;
    gsend_t *s;
    int32_t st = STATUS_INVALID_PARAMETER;
    (void)cur;
    mutex_lock(&gfx_lock);
    q = gq_current(0);
    s = q ? send_find(id) : 0;
    if (s && s->target == q && (s->state == GS_SERVICING || s->state == GS_ABANDONED)) {
        servicing_remove(q, s);
        send_finish(s, GS_DONE, (int64_t)result);
        st = STATUS_SUCCESS;
    }
    mutex_unlock(&gfx_lock);
    return st;
}

/* ---------------------------------------------------------------- update regions */
/* Region = up to SHZ_UPD_RECTS disjoint rectangles (client coordinates); when it would need more it collapses to its
 * bounding box (over-invalidation is always safe, never the other way round). */
static int rc_subtract(const shz_rect_t *a, const shz_rect_t *b, shz_rect_t out[4])
{
    shz_rect_t i;
    int n = 0;
    if (!rc_isect(a, b, &i)) { out[0] = *a; return 1; }
    if (i.top > a->top) { out[n].left = a->left; out[n].top = a->top; out[n].right = a->right; out[n].bottom = i.top; ++n; }
    if (i.bottom < a->bottom) { out[n].left = a->left; out[n].top = i.bottom; out[n].right = a->right; out[n].bottom = a->bottom; ++n; }
    if (i.left > a->left) { out[n].left = a->left; out[n].top = i.top; out[n].right = i.left; out[n].bottom = i.bottom; ++n; }
    if (i.right < a->right) { out[n].left = i.right; out[n].top = i.top; out[n].right = a->right; out[n].bottom = i.bottom; ++n; }
    return n;
}

#define PIECES 32
static void region_collapse(gwin_t *w, const shz_rect_t *extra)
{
    shz_rect_t bb = { 0, 0, 0, 0 };
    uint32_t i;
    for (i = 0; i < w->nupd; ++i) rc_union(&bb, &w->upd[i]);
    if (extra) rc_union(&bb, extra);
    w->nupd = rc_empty(&bb) ? 0 : 1;
    if (w->nupd) w->upd[0] = bb;
}

static void region_add(gwin_t *w, const shz_rect_t *r)
{
    shz_rect_t pieces[PIECES], next[PIECES];
    uint32_t np = 1, i, j;
    pieces[0] = *r;
    for (i = 0; i < w->nupd && np; ++i) {                    /* r minus what is already invalid */
        uint32_t nn = 0;
        for (j = 0; j < np; ++j) {
            shz_rect_t sub[4];
            int k, c = rc_subtract(&pieces[j], &w->upd[i], sub);
            for (k = 0; k < c; ++k) {
                if (nn == PIECES) { region_collapse(w, r); return; }
                next[nn++] = sub[k];
            }
        }
        memcpy(pieces, next, nn * sizeof pieces[0]);
        np = nn;
    }
    if (w->nupd + np > SHZ_UPD_RECTS) { region_collapse(w, r); return; }
    for (j = 0; j < np; ++j) w->upd[w->nupd++] = pieces[j];
}

static void region_subtract(gwin_t *w, const shz_rect_t *v)
{
    shz_rect_t keep[PIECES], bb = { 0, 0, 0, 0 };
    uint32_t nk = 0, i;
    int overflow = 0;
    for (i = 0; i < w->nupd && !overflow; ++i) {
        shz_rect_t sub[4];
        int k;
        const int c = rc_subtract(&w->upd[i], v, sub);
        for (k = 0; k < c; ++k) {
            if (nk == PIECES) { overflow = 1; break; }
            keep[nk++] = sub[k];
        }
    }
    if (overflow) { region_collapse(w, 0); return; }         /* cannot represent the difference: stay conservatively invalid */
    if (nk > SHZ_UPD_RECTS) {
        for (i = 0; i < nk; ++i) rc_union(&bb, &keep[i]);
        w->nupd = rc_empty(&bb) ? 0 : 1;
        if (w->nupd) w->upd[0] = bb;
        return;
    }
    memcpy(w->upd, keep, nk * sizeof keep[0]);
    w->nupd = nk;
}

int32_t gq_invalidate(gwin_t *w, const shz_rect_t *rects, uint32_t n, uint32_t flags)
{
    shz_rect_t cli, full;
    uint32_t i;
    const int32_t cw = w->w - w->ncl - w->ncr, ch = w->h - w->nct - w->ncb;
    cli.left = 0; cli.top = 0; cli.right = cw > 0 ? cw : 0; cli.bottom = ch > 0 ? ch : 0;
    full = cli;
    if (!n) { rects = &full; n = 1; }
    for (i = 0; i < n; ++i) {
        shz_rect_t r;
        if (!rc_isect(&rects[i], &cli, &r)) continue;
        if (flags & SHZ_INV_VALIDATE) region_subtract(w, &r);
        else region_add(w, &r);
    }
    if (flags & SHZ_INV_CHILDREN) {
        gwin_t *c;
        for (c = w->child; c; c = c->next) {
            shz_rect_t moved[SHZ_UPD_RECTS * 2 + 8];
            uint32_t m = 0;
            for (i = 0; i < n && m < sizeof moved / sizeof moved[0]; ++i) {
                shz_rect_t r, t;
                r.left = rects[i].left - (c->x); r.top = rects[i].top - (c->y);
                r.right = rects[i].right - (c->x); r.bottom = rects[i].bottom - (c->y);
                t.left = 0; t.top = 0; t.right = c->w; t.bottom = c->h;
                if (rc_isect(&r, &t, &r)) {
                    r.left -= c->ncl; r.right -= c->ncl; r.top -= c->nct; r.bottom -= c->nct;
                    moved[m++] = r;
                }
            }
            if (m) gq_invalidate(c, moved, m, flags);
        }
    }
    if (flags & SHZ_INV_VALIDATE) { if (!w->nupd) w->erase = 0; }
    else {
        if (flags & SHZ_INV_ERASE) w->erase = 1;
        if (w->nupd && w->q) gq_wake(w->q);
    }
    return STATUS_SUCCESS;
}

static int32_t sys_invalidate(process_t *cur, uint64_t arg)
{
    shz_inval_t iv;
    shz_rect_t rects[64];
    gwin_t *w;
    int32_t st = STATUS_SUCCESS;
    if (copy_from_user(cur, &iv, arg, sizeof iv)) return STATUS_ACCESS_VIOLATION;
    if (iv.nrects > 64) return STATUS_INVALID_PARAMETER;
    if (iv.nrects && copy_from_user(cur, rects, iv.rects, iv.nrects * sizeof rects[0])) return STATUS_ACCESS_VIOLATION;
    mutex_lock(&gfx_lock);
    w = wm_lookup(iv.hwnd);
    if (!w) st = STATUS_INVALID_HANDLE;
    else if (w->pid != (uint32_t)cur->pid) st = STATUS_ACCESS_DENIED;
    else st = gq_invalidate(w, rects, iv.nrects, iv.flags);
    mutex_unlock(&gfx_lock);
    return st;
}

static int32_t sys_paint(process_t *cur, uint64_t arg)
{
    shz_paint_t p;
    gwin_t *w;
    int32_t st = STATUS_SUCCESS;
    uint32_t i;
    if (copy_from_user(cur, &p, arg, sizeof p)) return STATUS_ACCESS_VIOLATION;
    mutex_lock(&gfx_lock);
    w = wm_lookup(p.hwnd);
    if (!w) { st = STATUS_INVALID_HANDLE; goto out; }
    if (w->pid != (uint32_t)cur->pid) { st = STATUS_ACCESS_DENIED; goto out; }
    if (p.op != SHZ_PAINT_BEGIN && p.op != SHZ_PAINT_GETUPDATE) { st = STATUS_INVALID_PARAMETER; goto out; }
    p.nrects = w->nupd;
    p.erase = w->erase;
    memset(&p.bbox, 0, sizeof p.bbox);
    for (i = 0; i < w->nupd; ++i) { p.rects[i] = w->upd[i]; rc_union(&p.bbox, &w->upd[i]); }
    if (p.op == SHZ_PAINT_BEGIN) { w->nupd = 0; w->erase = 0; }
out:
    mutex_unlock(&gfx_lock);
    if (!st && copy_to_user(cur, arg, &p, sizeof p)) return STATUS_ACCESS_VIOLATION;
    return st;
}

/* ---------------------------------------------------------------- timers */
static int32_t sys_timer(process_t *cur, uint64_t arg)
{
    shz_timer_t t;
    gqueue_t *q;
    gwin_t *w = 0;
    unsigned i;
    int32_t st = STATUS_SUCCESS;
    gtimer_t *slot = 0;
    if (copy_from_user(cur, &t, arg, sizeof t)) return STATUS_ACCESS_VIOLATION;
    mutex_lock(&gfx_lock);
    q = gq_current(1);
    if (!q) { st = STATUS_NO_MEMORY; goto out; }
    if (t.hwnd) {
        w = wm_lookup(t.hwnd);
        if (!w) { st = STATUS_INVALID_HANDLE; goto out; }
        if (w->q != q) { st = STATUS_ACCESS_DENIED; goto out; }
    }
    for (i = 0; i < GFX_MAX_TIMERS; ++i)
        if (q->timers[i].used && q->timers[i].hwnd == t.hwnd && q->timers[i].id == t.id && (t.hwnd || t.op == SHZ_TIMER_KILL)) {
            slot = &q->timers[i];
            break;
        }
    if (t.op == SHZ_TIMER_KILL) {
        if (!slot) st = STATUS_INVALID_PARAMETER;
        else slot->used = 0;
        goto out;
    }
    if (t.op != SHZ_TIMER_SET) { st = STATUS_INVALID_PARAMETER; goto out; }
    if (!slot) {
        for (i = 0; i < GFX_MAX_TIMERS && q->timers[i].used; ++i) { }
        if (i == GFX_MAX_TIMERS) { st = STATUS_NO_QUOTA; goto out; }
        slot = &q->timers[i];
    }
    if (t.elapse < USER_TIMER_MINIMUM) t.elapse = USER_TIMER_MINIMUM;
    if (t.elapse > USER_TIMER_MAXIMUM) t.elapse = USER_TIMER_MAXIMUM;
    slot->used = 1;
    slot->hwnd = t.hwnd;
    if (!t.hwnd) {                                           /* thread timer: the system picks an id */
        unsigned k;
        uint64_t id = q->next_timer_id;
        for (;;) {
            int clash = 0;
            for (k = 0; k < GFX_MAX_TIMERS; ++k)
                if (&q->timers[k] != slot && q->timers[k].used && !q->timers[k].hwnd && q->timers[k].id == id) clash = 1;
            if (!clash) break;
            ++id;
        }
        q->next_timer_id = id + 1;
        t.id = id;
    }
    slot->id = t.id;
    slot->proc = t.proc;
    slot->elapse = t.elapse;
    slot->due = ticks_now() + t.elapse;
    t.out_id = t.id;
out:
    mutex_unlock(&gfx_lock);
    if (!st && copy_to_user(cur, arg, &t, sizeof t)) return STATUS_ACCESS_VIOLATION;
    return st;
}

/* ---------------------------------------------------------------- retrieval */
static int filter_ok(uint64_t hf, uint32_t mn, uint32_t mx, uint64_t hwnd, uint32_t message)
{
    if (hf == (uint64_t)-1) { if (hwnd) return 0; }                          /* thread messages only */
    else if (hf && hwnd != hf) {
        gwin_t *fw = wm_lookup(hf), *mw = hwnd ? wm_lookup(hwnd) : 0;
        if (!fw || !mw || !wm_is_descendant(fw, mw)) return 0;
    }
    if ((mn || mx) && (message < mn || message > mx)) return 0;
    return 1;
}

static uint32_t qs_pending(gqueue_t *q)
{
    uint32_t f = 0, i;
    const uint64_t now = ticks_now();
    if (q->sent_head) f |= QS_SENDMESSAGE;
    if (q->head || q->quit) f |= QS_POSTMESSAGE;
    for (i = 0; i < GFX_MAX_TIMERS; ++i)
        if (q->timers[i].used && q->timers[i].due <= now) f |= QS_TIMER;
    for (i = 1; i < GFX_MAX_WINDOWS; ++i)
        if (g_win[i].used && g_win[i].q == q && g_win[i].nupd && wm_is_visible(&g_win[i])) { f |= QS_PAINT; break; }
    return f;
}

/* Fills g->result: MESSAGE/CALLBACK, or NONE when nothing is available. */
static void try_get(gqueue_t *q, shz_getmsg_t *g)
{
    uint32_t qs = (g->flags >> 16) & 0x7ffu;
    const int remove = (g->flags & PM_REMOVE) != 0;
    const uint64_t now = ticks_now();
    gmsg_t *m, *prev = 0;
    unsigned i;
    if (!qs) qs = 0x7ffu;
    g->result = SHZ_GM_RES_NONE;
    if ((qs & QS_SENDMESSAGE) && take_sent(q, &g->cb)) { g->result = SHZ_GM_RES_CALLBACK; return; }
    if (qs & (QS_POSTMESSAGE | QS_ALLPOSTMESSAGE | QS_HOTKEY)) {
        for (m = q->head; m; prev = m, m = m->next) {
            if (m->m.hwnd && !wm_lookup(m->m.hwnd)) continue;            /* window vanished: skipped, purged on destroy */
            if (!filter_ok(g->hwnd, g->min, g->max, m->m.hwnd, m->m.message)) continue;
            g->msg = m->m;
            if (remove) {
                if (prev) prev->next = m->next; else q->head = m->next;
                if (q->tail == m) q->tail = prev;
                --q->nposted;
                msg_release(m);
            }
            g->result = SHZ_GM_RES_MESSAGE;
            return;
        }
        if (q->quit && filter_ok(g->hwnd, g->min, g->max, 0, WM_QUIT)) {
            memset(&g->msg, 0, sizeof g->msg);
            g->msg.message = WM_QUIT;
            g->msg.wparam = (uint64_t)q->quit_code;
            g->msg.time = (uint32_t)now;
            if (remove) q->quit = 0;
            g->result = SHZ_GM_RES_MESSAGE;
            return;
        }
    }
    if (qs & QS_PAINT) {
        for (i = 1; i < GFX_MAX_WINDOWS; ++i) {
            gwin_t *w = &g_win[i];
            if (!w->used || w->q != q || !w->nupd || !wm_is_visible(w)) continue;
            if (!filter_ok(g->hwnd, g->min, g->max, w->handle, WM_PAINT)) continue;
            memset(&g->msg, 0, sizeof g->msg);
            g->msg.hwnd = w->handle;
            g->msg.message = WM_PAINT;
            g->msg.time = (uint32_t)now;
            g->result = SHZ_GM_RES_MESSAGE;
            return;
        }
    }
    if (qs & QS_TIMER) {
        for (i = 0; i < GFX_MAX_TIMERS; ++i) {
            gtimer_t *t = &q->timers[i];
            if (!t->used || t->due > now) continue;
            if (!filter_ok(g->hwnd, g->min, g->max, t->hwnd, WM_TIMER)) continue;
            memset(&g->msg, 0, sizeof g->msg);
            g->msg.hwnd = t->hwnd;
            g->msg.message = WM_TIMER;
            g->msg.wparam = t->id;
            g->msg.lparam = (int64_t)t->proc;
            g->msg.time = (uint32_t)now;
            if (remove) t->due = now + t->elapse;
            g->result = SHZ_GM_RES_MESSAGE;
            return;
        }
    }
}

static int32_t sys_getmessage(process_t *cur, uint64_t arg)
{
    shz_getmsg_t g;
    gqueue_t *q;
    int32_t st = STATUS_SUCCESS;
    if (copy_from_user(cur, &g, arg, sizeof g)) return STATUS_ACCESS_VIOLATION;
    for (;;) {
        uint64_t wake = 0;
        unsigned i;
        mutex_lock(&gfx_lock);
        q = gq_current(1);
        if (!q) { st = STATUS_NO_MEMORY; break; }
        try_get(q, &g);
        if (g.result != SHZ_GM_RES_NONE || !(g.flags & SHZ_GM_WAIT)) break;
        if (cur->terminated) { st = STATUS_PROCESS_IS_TERMINATING; break; }
        for (i = 0; i < GFX_MAX_TIMERS; ++i)
            if (q->timers[i].used && (!wake || q->timers[i].due < wake)) wake = q->timers[i].due;
        gq_block(q, wake);                                   /* drops the lock */
    }
    mutex_unlock(&gfx_lock);
    if (!st && copy_to_user(cur, arg, &g, sizeof g)) return STATUS_ACCESS_VIOLATION;
    return st;
}

/* ---------------------------------------------------------------- post / thread operations */
static int32_t sys_postmessage(process_t *cur, uint64_t hwnd, uint64_t msg, uint64_t wparam, uint64_t lparam)
{
    gqueue_t *q;
    gwin_t *w;
    int32_t st;
    (void)cur;
    mutex_lock(&gfx_lock);
    if (!hwnd) {
        q = gq_current(1);
        st = q ? post_to(q, 0, (uint32_t)msg, wparam, (int64_t)lparam) : STATUS_NO_MEMORY;
    } else if (hwnd == 0xffff) {
        st = STATUS_NOT_SUPPORTED;                                   /* HWND_BROADCAST */
    } else {
        w = wm_lookup(hwnd);
        if (!w || !w->q) st = STATUS_INVALID_HANDLE;
        else if (gq_thread_dead(w->q)) st = STATUS_INVALID_HANDLE;
        else st = post_to(w->q, hwnd, (uint32_t)msg, wparam, (int64_t)lparam);
    }
    mutex_unlock(&gfx_lock);
    return st;
}

static int32_t sys_threadop(process_t *cur, uint64_t arg)
{
    shz_threadop_t t;
    gqueue_t *q;
    int32_t st = STATUS_SUCCESS;
    unsigned i;
    if (copy_from_user(cur, &t, arg, sizeof t)) return STATUS_ACCESS_VIOLATION;
    mutex_lock(&gfx_lock);
    switch (t.op) {
    case SHZ_TOP_POSTQUIT:
        q = gq_current(1);
        if (!q) { st = STATUS_NO_MEMORY; break; }
        q->quit = 1;
        q->quit_code = (int32_t)t.a;
        gq_wake(q);
        break;
    case SHZ_TOP_POSTTHREAD:                                         /* a = tid, b = message, c = wparam, d = lparam */
        q = 0;
        for (i = 0; i < GFX_MAX_QUEUES; ++i)
            if (g_queues[i].used && g_queues[i].thread->tid == t.a && !gq_thread_dead(&g_queues[i])) q = &g_queues[i];
        if (!q) { st = STATUS_INVALID_CID; break; }
        st = post_to(q, 0, (uint32_t)t.b, t.c, (int64_t)t.d);
        break;
    case SHZ_TOP_QUEUESTATUS:
        q = gq_current(1);
        if (!q) { st = STATUS_NO_MEMORY; break; }
        t.out0 = qs_pending(q) & (uint32_t)t.a;
        break;
    case SHZ_TOP_INSEND:
        q = gq_current(0);
        t.out0 = q && q->servicing != 0;
        break;
    default: st = STATUS_INVALID_PARAMETER;
    }
    mutex_unlock(&gfx_lock);
    if (!st && copy_to_user(cur, arg, &t, sizeof t)) return STATUS_ACCESS_VIOLATION;
    return st;
}

int32_t gfx_syscall_msg(process_t *cur, uint32_t num, uint64_t a1, uint64_t a2, uint64_t a3, uint64_t a4)
{
    switch (num) {
    case SYS_NtUserPostMessage: return sys_postmessage(cur, a1, a2, a3, a4);
    case SYS_NtUserSendMessage: return sys_sendmessage(cur, a1);
    case SYS_NtUserGetMessage: return sys_getmessage(cur, a1);
    case SYS_NtUserReplyMessage: return sys_replymessage(cur, a1, a2);
    case SYS_NtUserThreadOp: return sys_threadop(cur, a1);
    case SYS_NtUserTimer: return sys_timer(cur, a1);
    case SYS_NtUserInvalidate: return sys_invalidate(cur, a1);
    case SYS_NtUserPaint: return sys_paint(cur, a1);
    default: return STATUS_INVALID_SYSTEM_SERVICE;
    }
}

/* ---------------------------------------------------------------- cleanup */
void gq_purge_window(gwin_t *w)
{
    gqueue_t *q = w->q;
    gmsg_t *m, *prev = 0, *next;
    unsigned i;
    if (!q) return;
    for (m = q->head; m; m = next) {
        next = m->next;
        if (m->m.hwnd == w->handle) {
            if (prev) prev->next = next; else q->head = next;
            if (q->tail == m) q->tail = prev;
            --q->nposted;
            msg_release(m);
        } else {
            prev = m;
        }
    }
    for (i = 0; i < GFX_MAX_TIMERS; ++i)
        if (q->timers[i].used && q->timers[i].hwnd == w->handle) q->timers[i].used = 0;
    {
        gsend_t *s, *sp = 0, *sn;
        for (s = q->sent_head; s; s = sn) {                          /* not yet serviced: fail them, the window is going away */
            sn = s->next;
            if (s->hwnd == w->handle) {
                if (sp) sp->next = sn; else q->sent_head = sn;
                if (q->sent_tail == s) q->sent_tail = sp;
                s->next = 0;
                send_finish(s, GS_FAILED, 0);
            } else {
                sp = s;
            }
        }
    }
    if (q->focus == w->handle) q->focus = 0;
    if (q->capture == w->handle) q->capture = 0;
    if (q->active == w->handle) q->active = 0;
}

void gq_reap_dead(void)
{
    unsigned i, k;
    for (i = 0; i < GFX_MAX_QUEUES; ++i) {
        gqueue_t *q = &g_queues[i];
        gsend_t *s, *n;
        gmsg_t *m, *mn;
        if (!q->used || !gq_thread_dead(q)) continue;
        for (k = 1; k < GFX_MAX_WINDOWS; ++k)
            if (g_win[k].used && g_win[k].q == q && !g_win[k].destroying) wm_destroy_tree(&g_win[k]);
        for (s = q->sent_head; s; s = n) { n = s->next; s->next = 0; send_finish(s, GS_FAILED, 0); }
        for (s = q->servicing; s; s = n) { n = s->next; s->next = 0; send_finish(s, GS_FAILED, 0); }
        for (m = q->head; m; m = mn) { mn = m->next; msg_release(m); }
        for (k = 0; k < GFX_MAX_SENDS; ++k) {                        /* sends made BY the dead thread */
            gsend_t *x = &g_sends[k];
            if (!x->id || x->sender_tid != q->thread_id) continue;
            if (x->state == GS_QUEUED) { send_list_remove(&x->target->sent_head, &x->target->sent_tail, x); send_release(x); }
            else if (x->state == GS_SERVICING) x->state = GS_ABANDONED;
            else send_release(x);
        }
        if (g_fg_q == q) g_fg_q = 0;
        memset(q, 0, sizeof *q);
    }
}
