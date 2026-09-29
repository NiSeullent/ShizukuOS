/* SPDX-License-Identifier: GPL-2.0-only
 * Kernel64 GUI: the clipboard (NtUserClipboard). ONE system-wide clipboard shared by every process, as on Windows:
 *
 *  - At most one thread has it open (OpenClipboard); only that thread may empty it or put data on it. EmptyClipboard makes
 *    the opener's window the owner and bumps the sequence number, as does every SetClipboardData.
 *  - Data are byte strings the kernel keeps (pages of the graphics arena) per format; user32 turns handles into bytes
 *    (HGLOBAL contents, CF_BITMAP -> CF_DIB) and back, and synthesises the text conversions. A format set without data is
 *    delay-rendered: user32 asks the owner (WM_RENDERFORMAT) when somebody wants it.
 *  - On CloseClipboard after a change every registered listener (AddClipboardFormatListener) gets WM_CLIPBOARDUPDATE.
 *  - A window that is destroyed stops being owner/listener; a thread that dies with the clipboard open closes it.
 * Limits: GCLIP_MAX_FORMATS formats, GCLIP_MAX_BYTES bytes in total.
 */
#include "gfx.h"

#define GCLIP_MAX_FORMATS 32
#define GCLIP_MAX_LISTENERS 32
#define GCLIP_MAX_BYTES (32u << 20)
#define WM_CLIPBOARDUPDATE_ 0x031Du

typedef struct { uint32_t format; uint8_t *data; uint64_t size; int delayed; } gclipfmt_t;

static gclipfmt_t g_fmt[GCLIP_MAX_FORMATS];
static uint32_t g_nfmt;
static uint64_t g_total;
static uint32_t g_seq = 1;
static uint64_t g_owner, g_open_hwnd;
static uint32_t g_open_tid;                                  /* thread id of the opener, 0 = closed */
static int g_changed;
static uint64_t g_listen[GCLIP_MAX_LISTENERS];

static void fmt_free(gclipfmt_t *f)
{
    if (f->data) gfx_pages_free(f->data, f->size);
    g_total -= f->data ? f->size : 0;
    f->data = 0;
    f->size = 0;
}

static void clear_all(void)
{
    uint32_t i;
    for (i = 0; i < g_nfmt; ++i) fmt_free(&g_fmt[i]);
    g_nfmt = 0;
}

static gclipfmt_t *fmt_find(uint32_t format)
{
    uint32_t i;
    for (i = 0; i < g_nfmt; ++i) if (g_fmt[i].format == format) return &g_fmt[i];
    return 0;
}

static void notify_listeners(void)
{
    unsigned i;
    for (i = 0; i < GCLIP_MAX_LISTENERS; ++i) {
        gwin_t *w = g_listen[i] ? wm_lookup(g_listen[i]) : 0;
        if (!w) { g_listen[i] = 0; continue; }
        if (w->q) gq_post(w->q, w->handle, WM_CLIPBOARDUPDATE_, 0, 0);
    }
}

void gclip_window_gone(uint64_t hwnd)
{
    unsigned i;
    for (i = 0; i < GCLIP_MAX_LISTENERS; ++i) if (g_listen[i] == hwnd) g_listen[i] = 0;
    if (g_owner == hwnd) g_owner = 0;
    if (g_open_hwnd == hwnd) g_open_hwnd = 0;
}

void gclip_queue_gone(gqueue_t *q)
{
    if (g_open_tid && g_open_tid == q->thread_id) {
        g_open_tid = 0;
        g_open_hwnd = 0;
        if (g_changed) notify_listeners();
        g_changed = 0;
    }
}

int32_t gfx_syscall_clipboard(process_t *cur, uint64_t arg)
{
    shz_clip_t c;
    gqueue_t *q;
    int32_t st = STATUS_SUCCESS;
    uint8_t *tmp = 0;
    uint64_t tmp_size = 0;
    if (copy_from_user(cur, &c, arg, sizeof c)) return STATUS_ACCESS_VIOLATION;
    if (c.op == SHZ_CB_SET && c.buf) {                         /* read the data before taking the lock */
        if (!c.size || c.size > GCLIP_MAX_BYTES) return STATUS_INVALID_PARAMETER;
        tmp = gfx_pages_alloc(c.size);
        if (!tmp) return STATUS_NO_MEMORY;
        tmp_size = c.size;
        if (copy_from_user(cur, tmp, c.buf, c.size)) { gfx_pages_free(tmp, tmp_size); return STATUS_ACCESS_VIOLATION; }
    }
    mutex_lock(&gfx_lock);
    q = gq_current(1);
    if (!q) { st = STATUS_NO_MEMORY; goto out; }
    c.out0 = c.out1 = c.out2 = 0;
    switch (c.op) {
    case SHZ_CB_OPEN: {
        gwin_t *w = c.hwnd ? wm_lookup(c.hwnd) : 0;
        if (c.hwnd && !w) { st = STATUS_INVALID_HANDLE; break; }
        if (g_open_tid && g_open_tid != q->thread_id) { st = STATUS_ACCESS_DENIED; break; }
        g_open_tid = q->thread_id;
        g_open_hwnd = c.hwnd;
        break;
    }
    case SHZ_CB_CLOSE:
        if (g_open_tid != q->thread_id) { st = STATUS_INVALID_PARAMETER; break; }
        g_open_tid = 0;
        g_open_hwnd = 0;
        c.out0 = (uint64_t)g_changed;
        if (g_changed) notify_listeners();
        g_changed = 0;
        break;
    case SHZ_CB_EMPTY:
        if (g_open_tid != q->thread_id) { st = STATUS_ACCESS_DENIED; break; }
        c.out1 = g_owner;                                       /* the previous owner (WM_DESTROYCLIPBOARD) */
        clear_all();
        g_owner = g_open_hwnd;
        ++g_seq;
        g_changed = 1;
        break;
    case SHZ_CB_SET: {
        gclipfmt_t *f;
        if (!c.format) { st = STATUS_INVALID_PARAMETER; break; }
        f = fmt_find(c.format);
        if (g_open_tid != q->thread_id) {                          /* else only the owner rendering a delayed format (WM_RENDERFORMAT) */
            gwin_t *ow = g_owner ? wm_lookup(g_owner) : 0;
            if (!ow || ow->pid != (uint32_t)cur->pid || !f || !f->delayed || !tmp) { st = STATUS_ACCESS_DENIED; break; }
        }
        if (!f) {
            if (g_nfmt >= GCLIP_MAX_FORMATS) { st = STATUS_NO_MEMORY; break; }
            f = &g_fmt[g_nfmt++];
            f->format = c.format;
            f->data = 0;
            f->size = 0;
        }
        if (tmp && g_total - (f->data ? f->size : 0) + tmp_size > GCLIP_MAX_BYTES) { st = STATUS_NO_MEMORY; break; }
        fmt_free(f);
        f->delayed = tmp == 0;
        f->data = tmp;
        f->size = tmp ? tmp_size : 0;
        g_total += f->size;
        tmp = 0;
        ++g_seq;
        g_changed = 1;
        break;
    }
    case SHZ_CB_GET: {
        gclipfmt_t *f = fmt_find(c.format);
        if (!f) { st = STATUS_NOT_FOUND; break; }
        c.out0 = f->size;
        c.out1 = (uint64_t)f->delayed;
        if (f->data && c.buf && c.size >= f->size && copy_to_user(cur, c.buf, f->data, f->size)) st = STATUS_ACCESS_VIOLATION;
        break;
    }
    case SHZ_CB_ENUM: {
        uint32_t i;
        if (!c.format) { c.out0 = g_nfmt ? g_fmt[0].format : 0; break; }
        for (i = 0; i < g_nfmt; ++i)
            if (g_fmt[i].format == c.format) { c.out0 = i + 1 < g_nfmt ? g_fmt[i + 1].format : 0; break; }
        break;
    }
    case SHZ_CB_COUNT: c.out0 = g_nfmt; break;
    case SHZ_CB_INFO:
        c.out0 = g_seq;
        c.out1 = g_owner && wm_lookup(g_owner) ? g_owner : 0;
        c.out2 = g_open_tid ? g_open_hwnd : 0;
        break;
    case SHZ_CB_LISTEN: {
        unsigned i, freei = GCLIP_MAX_LISTENERS;
        gwin_t *w = wm_lookup(c.hwnd);
        if (!w) { st = STATUS_INVALID_HANDLE; break; }
        for (i = 0; i < GCLIP_MAX_LISTENERS; ++i) {
            if (g_listen[i] == c.hwnd) break;
            if (!g_listen[i] && freei == GCLIP_MAX_LISTENERS) freei = i;
        }
        if (c.format) {
            if (i < GCLIP_MAX_LISTENERS) break;                   /* already listening */
            if (freei == GCLIP_MAX_LISTENERS) { st = STATUS_NO_MEMORY; break; }
            g_listen[freei] = c.hwnd;
        } else {
            if (i == GCLIP_MAX_LISTENERS) { st = STATUS_NOT_FOUND; break; }
            g_listen[i] = 0;
        }
        break;
    }
    default: st = STATUS_INVALID_PARAMETER;
    }
out:
    mutex_unlock(&gfx_lock);
    if (tmp) gfx_pages_free(tmp, tmp_size);
    if (!st && copy_to_user(cur, arg, &c, sizeof c)) return STATUS_ACCESS_VIOLATION;
    return st;
}
