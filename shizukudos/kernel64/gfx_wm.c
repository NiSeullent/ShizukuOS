/* SPDX-License-Identifier: GPL-2.0-only
 * Kernel64 window manager ("win32k-lite"): window classes, windows, z-order, non-client frame, compositor, focus and
 * activation state, and the system-call entry for the whole graphics range 0x60-0x7f (sys_ext_graphics, see sysext.c).
 * Messages, timers and paint state live in gfx_msg.c; the display in gfx_fb.c.
 *
 * DESIGN
 *
 *  Profile.   Only the SHZ_STANDALONE profile has a display (gfx_fb.c). Everywhere else every call returns
 *             STATUS_NO_SUCH_DEVICE and nothing here runs. Initialisation is lazy (first system call in the range).
 *
 *  Objects.   Classes (per process, name interned in a small system atom table), windows (one tree rooted at the
 *             desktop pseudo-window; children are kept topmost-first, so a sibling list IS the z-order), and one message
 *             queue per GUI thread (created on first use). Window handles are (generation << 12 | slot + 1): stale handles
 *             are detected, never reused within 2^20 creations of the same slot. One kernel mutex (gfx_lock) protects all
 *             of it; it is never held across a sleep. Blocking waits register in the queue, drop the lock and block with
 *             interrupts off (uniprocessor: no wake-up can slip between the check and the sleep).
 *
 *  Rendering. Each window owns a KERNEL-side client surface (32 bpp 0x00RRGGBB, gfx_pages_alloc). Applications never
 *             touch it directly: gdi32.dll (user mode) draws into a bitmap in the application's own memory and pushes the
 *             changed rectangle with NtGdiPresent, which copies it into the surface and recomposes that rectangle. Copying
 *             instead of sharing keeps the kernel independent of the lifetime of user memory (a process that dies cannot
 *             leave the compositor pointing at freed pages). The compositor is a painter's algorithm over the window
 *             tree (desktop colour, then top-level windows bottom to top, each with its frame, client surface and children
 *             clipped to the parent's client area) into the kernel back buffer, then a present of the damaged rectangle.
 *             The non-client frame (border, caption bar, title text) is drawn here in a fixed classic style; it is not
 *             themable and has no buttons or system menu. Minimised windows are simply not drawn (there is no taskbar).
 *
 *  Callbacks. The kernel NEVER calls a window procedure. Messages posted to a queue are returned by GetMessage/PeekMessage
 *             and user32's DispatchMessage calls the procedure in user mode. A message SENT to a window owned by another
 *             thread of the same process is queued on the owner's queue and the sender blocks; the owner, the next time it
 *             is inside GetMessage/PeekMessage (or itself waiting in SendMessage), gets a shz_callback_t back from the
 *             system call, runs the window procedure in user mode and answers with NtUserReplyMessage, which completes the
 *             sender's wait. This is the KeUserModeCallback contract of real Windows expressed as "return to user mode
 *             and re-enter", with the same consequence: a thread that never pumps messages blocks its senders.
 *             SendMessage across processes is not supported (pointer arguments would need marshalling).
 *             WM_PAINT, WM_TIMER and WM_QUIT are not stored as messages: they are synthesised by GetMessage/PeekMessage
 *             from the update regions, the timer table and the quit flag when nothing else is queued (Windows priority:
 *             sent, posted, quit, paint, timer).
 *
 *  Lifetime.  A kernel thread (gfxd) wakes every 20 ms and destroys the windows, timers and queued messages of threads
 *             that no longer exist (compared by the never-reused thread id), fails pending sends to and from them, and
 *             frees classes of processes that are gone. Blocking waits also poll process termination every 50 ms so a
 *             process killed from outside cannot leave a thread asleep forever.
 *
 *  Input.     PS/2 keyboard and mouse (gfx_input.c) are routed as input messages to the focus window / the window under
 *             the pointer (or the capture window); the compositor draws the pointer sprite last.
 *
 *  Layers.    A top-level WS_EX_LAYERED window is not drawn until it gets content: SetLayeredWindowAttributes (mode 1) draws
 *             it normally and then mixes it with what lies below it (constant alpha; the colour key makes pixels of the
 *             window that have exactly that colour transparent), UpdateLayeredWindow (mode 2) replaces the WHOLE window
 *             rectangle (frame, client and children) by a bitmap the application supplies, blended with its per-pixel
 *             premultiplied alpha and/or a constant alpha, or keyed. Colour-keyed and fully transparent pixels let mouse
 *             input through, as does WS_EX_LAYERED|WS_EX_TRANSPARENT. The two modes exclude each other until the layered
 *             style is removed. Child windows with WS_EX_LAYERED are drawn like ordinary children.
 *  Regions.   SetWindowRgn clips the window (its frame, client area and children) and its hit testing to a set of
 *             rectangles in window coordinates.
 *  Readback.  NtUserWindowOp(PRINT) composes one window alone into a caller buffer (PrintWindow): the compositor draws
 *             into a selectable target, the back buffer being the usual one.
 *
 *  Not implemented: menus, multiple monitors, cross-process SendMessage, WM_NCCALCSIZE customisation (client size
 *  follows shz_nc_insets()).
 */
#include "gfx.h"

kmutex_t gfx_lock;
gwin_t *g_win;
static gclass_t *g_cls;
gqueue_t *g_fg_q;
static uint32_t win_gen;
static uint64_t shell_window;            /* gfx_lock: cleared when this window (or its owning thread) dies */
static int wm_ready;
static kmutex_t wm_init_lock;
#define DESKTOP (&g_win[0])

#define FACE 0x00c0c0c0u
#define CAP_ACTIVE 0x00000080u
#define CAP_INACTIVE 0x00808080u
#define CAP_TEXT_ACTIVE 0x00ffffffu
#define CAP_TEXT_INACTIVE 0x00c0c0c0u
#define CS_VREDRAW 0x0001u
#define CS_HREDRAW 0x0002u
#define SWP_NOSIZE 0x0001u
#define SWP_NOMOVE 0x0002u
#define SWP_NOZORDER 0x0004u
#define SWP_NOREDRAW 0x0008u
#define SWP_NOACTIVATE 0x0010u
#define SWP_FRAMECHANGED 0x0020u
#define SWP_SHOWWINDOW 0x0040u
#define SWP_HIDEWINDOW 0x0080u
#define HWND_MESSAGE_VALUE ((uint64_t)-3)

/* ---------------------------------------------------------------- atoms (class names, window messages, property names) */
typedef struct { int used; uint32_t len; uint16_t name[64]; } gatom_t;
static gatom_t g_atoms[GFX_MAX_ATOMS];

static uint16_t lc16(uint16_t c) { return (uint16_t)(c >= 'A' && c <= 'Z' ? c + 32 : c); }
static int name_eq(const uint16_t *a, uint32_t al, const uint16_t *b, uint32_t bl)
{
    uint32_t i;
    if (al != bl) return 0;
    for (i = 0; i < al; ++i)
        if (lc16(a[i]) != lc16(b[i])) return 0;
    return 1;
}
static uint32_t atom_find(const uint16_t *n, uint32_t len)
{
    unsigned i;
    for (i = 0; i < GFX_MAX_ATOMS; ++i)
        if (g_atoms[i].used && name_eq(g_atoms[i].name, g_atoms[i].len, n, len)) return GFX_ATOM_BASE + i;
    return 0;
}
static uint32_t atom_add(const uint16_t *n, uint32_t len)
{
    unsigned i;
    uint32_t a = atom_find(n, len);
    if (a) return a;
    for (i = 0; i < GFX_MAX_ATOMS; ++i)
        if (!g_atoms[i].used) {
            g_atoms[i].used = 1;
            g_atoms[i].len = len;
            memcpy(g_atoms[i].name, n, len * 2);
            return GFX_ATOM_BASE + i;
        }
    return 0;
}

/* ---------------------------------------------------------------- window lookup and geometry */
gwin_t *wm_desktop(void) { return DESKTOP; }

gwin_t *wm_lookup(uint64_t h)
{
    const uint32_t idx = (uint32_t)(h & 0xfff);
    gwin_t *w;
    if (!idx || idx > GFX_MAX_WINDOWS || (h >> 12) > 0xfffff) return 0;
    w = &g_win[idx - 1];
    if (!w->used || w->handle != h || w->destroying) return 0;
    return w;
}

int wm_is_descendant(gwin_t *anc, gwin_t *w)
{
    for (; w; w = w->parent)
        if (w == anc) return 1;
    return 0;
}

gwin_t *wm_toplevel(gwin_t *w)
{
    while (w->parent && w->parent != DESKTOP) w = w->parent;
    return w;
}

int wm_is_visible(gwin_t *w)
{
    for (; w && w != DESKTOP; w = w->parent)
        if (w->msgonly || !(w->style & SHZ_WS_VISIBLE) || (w->style & SHZ_WS_MINIMIZE)) return 0;
    return 1;
}

int wm_owner_ok(process_t *cur, gwin_t *w) { return w->pid == (uint32_t)cur->pid; }

static int32_t client_w(const gwin_t *w) { const int32_t v = w->w - w->ncl - w->ncr; return v > 0 ? v : 0; }
static int32_t client_h(const gwin_t *w) { const int32_t v = w->h - w->nct - w->ncb; return v > 0 ? v : 0; }

static void abs_origin(gwin_t *w, int32_t *x, int32_t *y)
{
    int32_t ox = 0, oy = 0;
    for (; w && w != DESKTOP; w = w->parent) {
        ox += w->x;
        oy += w->y;
        if (w->parent && w->parent != DESKTOP) { ox += w->parent->ncl; oy += w->parent->nct; }
    }
    *x = ox;
    *y = oy;
}

void wm_client_origin(gwin_t *w, int32_t *sx, int32_t *sy)
{
    if (w == DESKTOP) { *sx = *sy = 0; return; }
    abs_origin(w, sx, sy);
    *sx += w->ncl;
    *sy += w->nct;
}

int wm_screen_rect(gwin_t *w, shz_rect_t *r)
{
    int32_t ox, oy;
    gwin_t *p;
    shz_rect_t scr = { 0, 0, (int32_t)g_fb.width, (int32_t)g_fb.height };
    abs_origin(w, &ox, &oy);
    r->left = ox; r->top = oy; r->right = ox + w->w; r->bottom = oy + w->h;
    for (p = w->parent; p && p != DESKTOP; p = p->parent) {
        int32_t cx, cy;
        shz_rect_t cr, o;
        wm_client_origin(p, &cx, &cy);
        cr.left = cx; cr.top = cy; cr.right = cx + client_w(p); cr.bottom = cy + client_h(p);
        if (!rc_isect(r, &cr, &o)) return 0;
        *r = o;
    }
    if (!rc_isect(r, &scr, r)) return 0;
    return 1;
}

/* ---------------------------------------------------------------- compositor */
/* Where the compositor draws: the back buffer, or a caller's buffer for NtUserWindowOp(PRINT). Coordinates are target
 * pixels; every clip rectangle handed down is already inside the target. */
static uint32_t *tgt_px;
static uint32_t tgt_w, tgt_h;
static void tgt_backbuffer(void) { tgt_px = g_fb.back; tgt_w = g_fb.width; tgt_h = g_fb.height; }
static inline uint32_t *tgt_at(int x, int y) { return tgt_px + (uint64_t)(uint32_t)y * tgt_w + (uint32_t)x; }

static int is_active_root(const gwin_t *w) { return g_fg_q && g_fg_q->active == w->handle; }

static void fillc(int l, int t, int r, int b, uint32_t c, const shz_rect_t *clip)
{
    shz_rect_t q = { l, t, r, b }, o;
    int y;
    if (!rc_isect(&q, clip, &o)) return;
    for (y = o.top; y < o.bottom; ++y) {
        uint32_t *p = tgt_at(o.left, y);
        uint64_t n = (uint64_t)(o.right - o.left);
        __asm__ volatile("rep stosl" : "+D"(p), "+c"(n) : "a"(c) : "memory");
    }
}

static void ring(int l, int t, int r, int b, uint32_t tl, uint32_t br, const shz_rect_t *clip)
{
    fillc(l, t, r, t + 1, tl, clip);
    fillc(l, t, l + 1, b, tl, clip);
    fillc(l, b - 1, r, b, br, clip);
    fillc(r - 1, t, r, b, br, clip);
}

static void draw_nc(gwin_t *w, int ox, int oy, const shz_rect_t *clip)
{
    const int cw = client_w(w), ch = client_h(w);
    const int cx = ox + w->ncl, cy = oy + w->nct;
    const shz_rect_t wr = { ox, oy, ox + w->w, oy + w->h };
    int frame = 0;
    if (!(w->ncl | w->nct | w->ncr | w->ncb)) return;
    if (w->style & SHZ_WS_THICKFRAME) frame = 4;
    else if ((w->style & SHZ_WS_DLGFRAME) || (w->exstyle & SHZ_WS_EX_DLGMODALFRAME)) frame = 3;
    else if (w->style & SHZ_WS_BORDER) frame = 1;
    fillc(wr.left, wr.top, wr.right, cy, FACE, clip);
    fillc(wr.left, cy + ch, wr.right, wr.bottom, FACE, clip);
    fillc(wr.left, cy, cx, cy + ch, FACE, clip);
    fillc(cx + cw, cy, wr.right, cy + ch, FACE, clip);
    if (frame == 1) {
        ring(wr.left, wr.top, wr.right, wr.bottom, 0x00000000, 0x00000000, clip);
    } else if (frame >= 3) {
        ring(wr.left, wr.top, wr.right, wr.bottom, 0x00c0c0c0, 0x00000000, clip);
        ring(wr.left + 1, wr.top + 1, wr.right - 1, wr.bottom - 1, 0x00ffffff, 0x00808080, clip);
    }
    if ((w->style & SHZ_WS_CAPTION) == SHZ_WS_CAPTION) {
        const int active = is_active_root(w);
        const int cl = wr.left + frame, ct = wr.top + frame, cr = wr.right - frame, cb = ct + SHZ_CAPTION_H - 1;
        fillc(cl, ct, cr, cb, active ? CAP_ACTIVE : CAP_INACTIVE, clip);
        if (w->title_len) {
            shz_rect_t cap = { cl, ct, cr, cb }, o;
            if (rc_isect(&cap, clip, &o))
                gfx_text(tgt_px, (int)tgt_w, (int)tgt_w, (int)tgt_h, cl + 4, ct + 1, w->title, w->title_len,
                         active ? CAP_TEXT_ACTIVE : CAP_TEXT_INACTIVE, o.left, o.top, o.right, o.bottom);
        }
    }
    if (w->exstyle & SHZ_WS_EX_CLIENTEDGE) {
        ring(cx - 2, cy - 2, cx + cw + 2, cy + ch + 2, 0x00808080, 0x00ffffff, clip);
        ring(cx - 1, cy - 1, cx + cw + 1, cy + ch + 1, 0x00404040, 0x00c0c0c0, clip);
    }
}

static void blit_surface(const uint32_t *src, int sw, int sh, int ox, int oy, const shz_rect_t *clip)
{
    shz_rect_t sr = { ox, oy, ox + sw, oy + sh }, o;
    int y;
    if (!src || !rc_isect(&sr, clip, &o)) return;
    for (y = o.top; y < o.bottom; ++y) {
        const uint32_t *s = src + (uint64_t)(y - oy) * (uint32_t)sw + (uint32_t)(o.left - ox);
        uint32_t *d = tgt_at(o.left, y);
        uint64_t n = (uint64_t)(o.right - o.left);
        __asm__ volatile("rep movsl" : "+D"(d), "+S"(s), "+c"(n) :: "memory");
    }
}

#define WS_EX_LAYERED_ 0x00080000u
#define WS_EX_TRANSPARENT_ 0x00000020u
#define LWA_COLORKEY_ 1u
#define LWA_ALPHA_ 2u
#define ULW_COLORKEY_ 1u
#define ULW_ALPHA_ 2u
static int is_layered(const gwin_t *w) { return (w->exstyle & WS_EX_LAYERED_) && w->parent == DESKTOP; }

static uint32_t *g_under;                                           /* mode 1: what was below the window (screen sized) */

/* Mode 2: the application's bitmap over the target, blended as UpdateLayeredWindow defines it. */
static void blend_layer(const gwin_t *w, int ox, int oy, const shz_rect_t *clip)
{
    shz_rect_t lr = { ox, oy, ox + w->lw, oy + w->lh }, o;
    const uint32_t k = (w->lflags & ULW_ALPHA_) ? w->lalpha : 255;
    int x, y;
    if (!w->layer || !rc_isect(&lr, clip, &o)) return;
    for (y = o.top; y < o.bottom; ++y) {
        const uint32_t *s = w->layer + (uint64_t)(y - oy) * (uint32_t)w->lw + (uint32_t)(o.left - ox);
        uint32_t *d = tgt_at(o.left, y);
        for (x = o.left; x < o.right; ++x, ++s, ++d) {
            const uint32_t p = *s, q = *d;
            uint32_t a, r, g, b;
            if ((w->lflags & ULW_COLORKEY_) && (p & 0x00ffffffu) == w->lkey) continue;
            if (w->lppa) {                                          /* premultiplied: d = s*k + d*(1 - a*k) */
                a = (p >> 24) * k / 255;
                r = ((p >> 16) & 255) * k / 255 + ((q >> 16) & 255) * (255 - a) / 255;
                g = ((p >> 8) & 255) * k / 255 + ((q >> 8) & 255) * (255 - a) / 255;
                b = (p & 255) * k / 255 + (q & 255) * (255 - a) / 255;
            } else if (k == 255) {
                *d = p & 0x00ffffffu;
                continue;
            } else {
                r = (((p >> 16) & 255) * k + ((q >> 16) & 255) * (255 - k)) / 255;
                g = (((p >> 8) & 255) * k + ((q >> 8) & 255) * (255 - k)) / 255;
                b = ((p & 255) * k + (q & 255) * (255 - k)) / 255;
            }
            *d = (r > 255 ? 255 : r) << 16 | (g > 255 ? 255 : g) << 8 | (b > 255 ? 255 : b);
        }
    }
}

static void compose_plain(gwin_t *w, int ox, int oy, const shz_rect_t *c);

/* one window (and its children) inside `clip`, honouring its region and its layering */
static void compose_win(gwin_t *w, int ox, int oy, const shz_rect_t *clip)
{
    shz_rect_t wr = { ox, oy, ox + w->w, oy + w->h }, c;
    if (w->msgonly || !(w->style & SHZ_WS_VISIBLE) || (w->style & SHZ_WS_MINIMIZE)) return;
    if (!rc_isect(clip, &wr, &c)) return;
    if (w->rgn) {                                                   /* SetWindowRgn: compose once per region rectangle */
        uint32_t i;
        shz_rect_t *rg = w->rgn;
        const uint32_t n = w->nrgn;
        w->rgn = 0;
        for (i = 0; i < n; ++i) {
            shz_rect_t rr = { ox + rg[i].left, oy + rg[i].top, ox + rg[i].right, oy + rg[i].bottom }, cc;
            if (rc_isect(&rr, &c, &cc)) compose_win(w, ox, oy, &cc);
        }
        w->rgn = rg;
        return;
    }
    if (is_layered(w) && tgt_px == g_fb.back) {
        if (w->lmode == 2) { blend_layer(w, ox, oy, &c); return; }
        if (w->lmode == 1 && g_under) {
            int x, y;
            for (y = c.top; y < c.bottom; ++y)
                memcpy(g_under + (uint64_t)y * g_fb.width + (uint32_t)c.left, tgt_at(c.left, y), (size_t)(c.right - c.left) * 4);
            compose_plain(w, ox, oy, &c);
            for (y = c.top; y < c.bottom; ++y) {
                const uint32_t *u = g_under + (uint64_t)y * g_fb.width + (uint32_t)c.left;
                uint32_t *d = tgt_at(c.left, y);
                for (x = c.left; x < c.right; ++x, ++u, ++d) {
                    const uint32_t p = *d, q = *u, a = w->lalpha;
                    if ((w->lflags & LWA_COLORKEY_) && (p & 0x00ffffffu) == w->lkey) { *d = q; continue; }
                    if (!(w->lflags & LWA_ALPHA_) || a == 255) continue;
                    *d = (((p >> 16 & 255) * a + (q >> 16 & 255) * (255 - a)) / 255) << 16 |
                         (((p >> 8 & 255) * a + (q >> 8 & 255) * (255 - a)) / 255) << 8 | (((p & 255) * a + (q & 255) * (255 - a)) / 255);
                }
            }
            return;
        }
        return;                                                     /* layered without content yet: invisible, as on Windows */
    }
    compose_plain(w, ox, oy, &c);
}

static void compose_plain(gwin_t *w, int ox, int oy, const shz_rect_t *c)
{
    shz_rect_t cr, cc;
    gwin_t *ch;
    int cx, cy;
    draw_nc(w, ox, oy, c);
    cx = ox + w->ncl;
    cy = oy + w->nct;
    cr.left = cx; cr.top = cy; cr.right = cx + client_w(w); cr.bottom = cy + client_h(w);
    if (!rc_isect(c, &cr, &cc)) return;
    blit_surface(w->surf, w->sw, w->sh, cx, cy, &cc);
    for (ch = w->child; ch && ch->next; ch = ch->next) { }          /* bottom-most child first */
    for (; ch; ch = ch->prev)
        compose_win(ch, cx + ch->x, cy + ch->y, &cc);
}

/* Does w, composed normally, paint every pixel of r (screen) opaquely? Then nothing below it needs drawing. */
static int covers_opaquely(const gwin_t *w, const shz_rect_t *r)
{
    if (w->msgonly || !(w->style & SHZ_WS_VISIBLE) || (w->style & SHZ_WS_MINIMIZE) || w->rgn || is_layered(w)) return 0;
    return r->left >= w->x && r->top >= w->y && r->right <= w->x + w->w && r->bottom <= w->y + w->h;
}

void wm_damage(const shz_rect_t *r0)
{
    shz_rect_t scr = { 0, 0, (int32_t)g_fb.width, (int32_t)g_fb.height }, r;
    gwin_t *w, *top = 0;
    if (!g_fb.ready || !rc_isect(r0, &scr, &r)) return;
    tgt_backbuffer();
    if (!g_under) {
        uint64_t i;
        for (i = 1; i < GFX_MAX_WINDOWS; ++i)
            if (g_win[i].used && (g_win[i].exstyle & WS_EX_LAYERED_)) { g_under = gfx_pages_alloc((uint64_t)g_fb.width * g_fb.height * 4); break; }
    }
    for (w = DESKTOP->child; w; w = w->next)                        /* occlusion: start at the topmost window covering r */
        if (covers_opaquely(w, &r)) { top = w; break; }
    if (!top) {
        if (DESKTOP->surf) blit_surface(DESKTOP->surf, DESKTOP->sw, DESKTOP->sh, 0, 0, &r);
        else fillc(r.left, r.top, r.right, r.bottom, SHZ_DESKTOP_RGB, &r);
        for (w = DESKTOP->child; w && w->next; w = w->next) { }
    } else {
        w = top;
    }
    for (; w; w = w->prev)
        compose_win(w, w->x, w->y, &r);
    gin_draw_pointer(&r);
    gfx_fb_present(r.left, r.top, r.right - r.left, r.bottom - r.top);
}

void wm_damage_window(gwin_t *w)
{
    shz_rect_t r;
    if (wm_screen_rect(w, &r)) wm_damage(&r);
}

/* ---------------------------------------------------------------- tree and z-order */
static void tree_unlink(gwin_t *w)
{
    if (!w->parent) return;
    if (w->prev) w->prev->next = w->next; else w->parent->child = w->next;
    if (w->next) w->next->prev = w->prev;
    w->prev = w->next = 0;
}

static void link_below(gwin_t *w, gwin_t *sib)          /* directly below sib */
{
    w->parent = sib->parent;
    /* The registered desktop is always the last top-level window. Even a normal
     * HWND_BOTTOM or an insertion after the shell belongs immediately above it. */
    if (sib->handle == shell_window && w->handle != shell_window) {
        w->prev = sib->prev;
        w->next = sib;
        if (sib->prev) sib->prev->next = w; else sib->parent->child = w;
        sib->prev = w;
        return;
    }
    w->prev = sib;
    w->next = sib->next;
    if (sib->next) sib->next->prev = w;
    sib->next = w;
}

static void link_bottom(gwin_t *w, gwin_t *parent)
{
    gwin_t *l = parent->child;
    w->parent = parent;
    if (!l) { parent->child = w; w->prev = w->next = 0; return; }
    while (l->next) l = l->next;
    link_below(w, l);
}

static void link_top(gwin_t *w, gwin_t *parent)         /* top of the non-topmost band (top of everything if w is topmost) */
{
    gwin_t *s = parent->child, *last = 0;
    if (w->handle == shell_window && parent == DESKTOP) { link_bottom(w, parent); return; }
    w->parent = parent;
    if (parent == DESKTOP && !(w->exstyle & SHZ_WS_EX_TOPMOST))
        while (s && (s->exstyle & SHZ_WS_EX_TOPMOST)) { last = s; s = s->next; }
    if (last) { link_below(w, last); return; }
    w->prev = 0;
    w->next = parent->child;
    if (parent->child) parent->child->prev = w;
    parent->child = w;
}

static void raise_top(gwin_t *w)
{
    gwin_t *parent = w->parent;
    if (!parent || parent->child == w) return;
    tree_unlink(w);
    link_top(w, parent);
}

/* ---------------------------------------------------------------- activation */
static uint64_t wm_activate(gwin_t *top, int raise)
{
    gqueue_t *q = top->q;
    const uint64_t prev = g_fg_q ? g_fg_q->active : 0;
    q->active = top->handle;                                            /* focus is NOT moved here: user32's DefWindowProc(WM_ACTIVATE) calls SetFocus */
    g_fg_q = q;
    if (raise) raise_top(top);
    if (prev && prev != top->handle) {                                  /* its caption turns inactive */
        gwin_t *pw = wm_lookup(prev);
        if (pw) wm_damage_window(pw);
    }
    return prev == top->handle ? 0 : prev;
}

/* After a window disappears or is hidden: keep every queue's active/focus/capture valid and hand the foreground to the
 * topmost activatable window if the old one is gone. */
static void wm_fix_activation(void)
{
    unsigned i;
    gwin_t *w;
    for (i = 0; i < GFX_MAX_QUEUES; ++i) {
        gqueue_t *q = &g_queues[i];
        gwin_t *a;
        if (!q->used) continue;
        a = wm_lookup(q->active);
        if (a && !wm_is_visible(a)) a = 0;
        if (!a) q->active = 0;
        {
            gwin_t *f = wm_lookup(q->focus);
            if (!f || !wm_is_visible(f)) q->focus = 0;
        }
        if (!wm_lookup(q->capture)) q->capture = 0;
    }
    if (g_fg_q && g_fg_q->used && g_fg_q->active) return;
    g_fg_q = 0;
    for (w = DESKTOP->child; w; w = w->next)
        if (w->q && wm_is_visible(w) && !(w->exstyle & SHZ_WS_EX_NOACTIVATE) && !(w->style & SHZ_WS_DISABLED)) {
            w->q->active = w->handle;
            g_fg_q = w->q;
            wm_damage_window(w);                                        /* its caption turns active */
            return;
        }
}

/* ---------------------------------------------------------------- window life cycle */
static int32_t win_apply_size(gwin_t *w, int32_t nw, int32_t nh, int *redraw_all)
{
    int32_t l, t, r, b, cw, ch;
    const int32_t ocw = client_w(w), och = client_h(w);
    shz_nc_insets(w->style, w->exstyle, &l, &t, &r, &b);
    cw = nw - l - r;
    ch = nh - t - b;
    if (cw < 0) cw = 0;
    if (ch < 0) ch = 0;
    if ((uint64_t)cw * (uint64_t)ch * 4u > GFX_MAX_SURF_BYTES) return STATUS_NO_MEMORY;
    if (w != DESKTOP && (cw != w->sw || ch != w->sh)) {
        uint32_t *ns = 0;
        if (cw && ch) {
            uint64_t i, n = (uint64_t)cw * (uint64_t)ch;
            int32_t y, cpw = cw < w->sw ? cw : w->sw, cph = ch < w->sh ? ch : w->sh;
            ns = gfx_pages_alloc(n * 4);
            if (!ns) return STATUS_NO_MEMORY;
            for (i = 0; i < n; ++i) ns[i] = FACE;
            if (w->surf)
                for (y = 0; y < cph; ++y)
                    memcpy(ns + (uint64_t)y * (uint32_t)cw, w->surf + (uint64_t)y * (uint32_t)w->sw, (size_t)cpw * 4);
        }
        if (w->surf) gfx_pages_free(w->surf, (uint64_t)w->sw * (uint64_t)w->sh * 4);
        w->surf = ns;
        w->sw = cw;
        w->sh = ch;
    }
    w->ncl = l; w->nct = t; w->ncr = r; w->ncb = b;
    w->w = nw;
    w->h = nh;
    if (redraw_all) {
        const uint32_t cs = w->cls ? w->cls->style : 0;
        *redraw_all = ((cs & CS_HREDRAW) && cw != ocw) || ((cs & CS_VREDRAW) && ch != och);
    }
    return STATUS_SUCCESS;
}

/* Invalidate what a size change exposed: everything for CS_H/VREDRAW classes, else only the new strips. */
static void resize_invalidate(gwin_t *w, int32_t ocw, int32_t och, int all)
{
    const int32_t cw = client_w(w), ch = client_h(w);
    shz_rect_t rc[2];
    uint32_t n = 0;
    if (all || (!ocw && !och)) {
        rc[n].left = 0; rc[n].top = 0; rc[n].right = cw; rc[n].bottom = ch; ++n;
    } else {
        if (cw > ocw) { rc[n].left = ocw; rc[n].top = 0; rc[n].right = cw; rc[n].bottom = ch; ++n; }
        if (ch > och) { rc[n].left = 0; rc[n].top = och; rc[n].right = ocw < cw ? ocw : cw; rc[n].bottom = ch; ++n; }
    }
    if (n) gq_invalidate(w, rc, n, SHZ_INV_ERASE);
}

static void layer_free(gwin_t *w)
{
    if (w->layer) gfx_pages_free(w->layer, (uint64_t)w->lw * (uint64_t)w->lh * 4);
    w->layer = 0;
    w->lw = w->lh = 0;
}

static void free_window_memory(gwin_t *w)
{
    layer_free(w);
    if (w->rgn) kfree(w->rgn);
    w->rgn = 0;
    if (w->surf) gfx_pages_free(w->surf, (uint64_t)w->sw * (uint64_t)w->sh * 4);
    if (w->title) kfree(w->title);
    if (w->extra) kfree(w->extra);
    if (w->cls && w->cls->nwin) --w->cls->nwin;
}

void wm_destroy_tree(gwin_t *w)
{
    shz_rect_t dmg;
    int had = 0;
    if (!w || w == DESKTOP || !w->used) return;
    if (wm_is_visible(w) && wm_screen_rect(w, &dmg)) had = 1;
    if (w->handle == shell_window) shell_window = 0;
    w->destroying = 1;
    while (w->child) wm_destroy_tree(w->child);
    gq_purge_window(w);
    tree_unlink(w);
    free_window_memory(w);
    memset(w, 0, sizeof *w);                            /* used == 0: every stale handle now fails the lookup */
    if (had) wm_damage(&dmg);
}

static void win_set_title(gwin_t *w, const uint16_t *t, uint32_t n)
{
    uint16_t *nt = 0;
    if (n > GFX_MAX_TITLE) n = GFX_MAX_TITLE;
    if (n) {
        nt = kmalloc(n * 2u);
        if (!nt) return;
        memcpy(nt, t, n * 2u);
    }
    if (w->title) kfree(w->title);
    w->title = nt;
    w->title_len = n;
}

static gclass_t *class_find(uint32_t atom, uint32_t pid, uint64_t hinstance)
{
    unsigned i;
    gclass_t *any = 0;
    for (i = 0; i < GFX_MAX_CLASSES; ++i) {
        gclass_t *c = &g_cls[i];
        if (!c->used || c->atom != atom || c->pid != pid) continue;
        if (c->hinstance == hinstance) return c;
        if (!any) any = c;
    }
    return any;
}

static int32_t read_name(process_t *cur, uint64_t uva, uint32_t len, uint16_t *out)
{
    if (!uva || len == 0 || len > 63) return STATUS_INVALID_PARAMETER;
    if (copy_from_user(cur, out, uva, len * 2ull)) return STATUS_ACCESS_VIOLATION;
    return STATUS_SUCCESS;
}

static int32_t class_atom_of(process_t *cur, shz_classop_t *o, uint32_t *atom)
{
    uint16_t nm[64];
    int32_t st;
    if (o->name) {
        st = read_name(cur, o->name, o->name_len, nm);
        if (st) return st;
        *atom = atom_find(nm, o->name_len);
        return STATUS_SUCCESS;
    }
    *atom = o->atom;
    return STATUS_SUCCESS;
}

static int32_t sys_classop(process_t *cur, uint64_t arg)
{
    shz_classop_t o;
    int32_t st = STATUS_SUCCESS;
    gclass_t *c = 0;
    gwin_t *w;
    uint16_t nm[64];
    uint32_t atom = 0, i;
    if (copy_from_user(cur, &o, arg, sizeof o)) return STATUS_ACCESS_VIOLATION;
    mutex_lock(&gfx_lock);
    switch (o.op) {
    case SHZ_CLASS_REGISTER:
        st = read_name(cur, o.name, o.name_len, nm);
        if (st) break;
        if (o.cb_cls < 0 || o.cb_cls > 4096 || o.cb_wnd < 0 || o.cb_wnd > 4096) { st = STATUS_INVALID_PARAMETER; break; }
        atom = atom_add(nm, o.name_len);
        if (!atom) { st = STATUS_NO_MEMORY; break; }
        c = class_find(atom, (uint32_t)cur->pid, o.hinstance);
        if (c && c->hinstance == o.hinstance) { st = STATUS_OBJECT_NAME_COLLISION; break; }
        for (i = 0; i < GFX_MAX_CLASSES && g_cls[i].used; ++i) { }
        if (i == GFX_MAX_CLASSES) { st = STATUS_NO_MEMORY; break; }
        c = &g_cls[i];
        memset(c, 0, sizeof *c);
        if (o.cb_cls) {
            c->extra = kzalloc((size_t)o.cb_cls);
            if (!c->extra) { st = STATUS_NO_MEMORY; break; }
        }
        c->used = 1;
        c->pid = (uint32_t)cur->pid;
        c->atom = (uint16_t)atom;
        c->name_len = o.name_len;
        memcpy(c->name, nm, o.name_len * 2u);
        c->style = o.style;
        c->cb_cls = o.cb_cls;
        c->cb_wnd = o.cb_wnd;
        c->wndproc = o.wndproc;
        c->hinstance = o.hinstance;
        c->hicon = o.hicon;
        c->hcursor = o.hcursor;
        c->hbr = o.hbrbackground;
        c->menu = o.menu_name;
        c->hicon_sm = o.hicon_sm;
        o.atom = atom;
        break;
    case SHZ_CLASS_UNREGISTER:
    case SHZ_CLASS_LOOKUP:
        st = class_atom_of(cur, &o, &atom);
        if (st) break;
        c = atom ? class_find(atom, (uint32_t)cur->pid, o.hinstance) : 0;
        if (!c) { st = STATUS_OBJECT_NAME_NOT_FOUND; break; }
        if (o.op == SHZ_CLASS_UNREGISTER) {
            if (c->nwin) { st = STATUS_UNSUCCESSFUL; break; }
            if (c->extra) kfree(c->extra);
            memset(c, 0, sizeof *c);
            break;
        }
        o.atom = c->atom; o.style = c->style; o.cb_cls = c->cb_cls; o.cb_wnd = c->cb_wnd; o.wndproc = c->wndproc;
        o.hinstance = c->hinstance; o.hicon = c->hicon; o.hcursor = c->hcursor; o.hbrbackground = c->hbr;
        o.menu_name = c->menu; o.hicon_sm = c->hicon_sm;
        break;
    case SHZ_CLASS_GETLONG:
    case SHZ_CLASS_SETLONG:
    case SHZ_CLASS_GETNAME:
        w = wm_lookup(o.hwnd);
        if (!w || !w->cls) { st = STATUS_INVALID_HANDLE; break; }
        c = w->cls;
        if (o.op == SHZ_CLASS_GETNAME) {
            uint32_t n = c->name_len, cap = o.buf_len;
            if (cap == 0) { st = STATUS_BUFFER_TOO_SMALL; break; }
            if (n > cap - 1) n = cap - 1;
            if (copy_to_user(cur, o.buf, c->name, n * 2ull)) { st = STATUS_ACCESS_VIOLATION; break; }
            { const uint16_t z = 0; if (copy_to_user(cur, o.buf + n * 2ull, &z, 2)) { st = STATUS_ACCESS_VIOLATION; break; } }
            o.buf_len = n;
            break;
        }
        {
            uint64_t *slot = 0, v = 0;
            uint32_t v32 = 0;
            int is32 = 0;
            const int set = o.op == SHZ_CLASS_SETLONG;
            switch (o.index) {                              /* GCL_* / GCLP_* */
            case -26: is32 = 1; v32 = c->style; break;      /* GCL_STYLE */
            case -32: is32 = 1; v32 = c->atom; break;       /* GCW_ATOM */
            case -20: v = (uint64_t)c->cb_cls; break;       /* GCL_CBCLSEXTRA (read only) */
            case -18: v = (uint64_t)c->cb_wnd; break;       /* GCL_CBWNDEXTRA (read only) */
            case -10: slot = &c->hbr; break;
            case -12: slot = &c->hcursor; break;
            case -14: slot = &c->hicon; break;
            case -34: slot = &c->hicon_sm; break;
            case -16: slot = &c->hinstance; break;
            case -8: slot = &c->menu; break;
            case -24: slot = &c->wndproc; break;
            default:
                if (o.index >= 0 && o.index + 8 <= c->cb_cls && c->extra) {
                    uint64_t x;
                    memcpy(&x, c->extra + o.index, 8);
                    v = x;
                    if (set) { const uint64_t nv = o.value; memcpy(c->extra + o.index, &nv, 8); }
                    o.value = v;
                    goto class_done;
                }
                st = STATUS_INVALID_PARAMETER;
                goto class_done;
            }
            if (slot) v = *slot;
            if (is32) v = v32;
            if (set) {
                if (is32 && o.index == -26) { c->style = (uint32_t)o.value; }
                else if (slot) *slot = o.value;
                else st = STATUS_ACCESS_DENIED;
            }
            o.value = v;
        }
class_done:
        break;
    default:
        st = STATUS_INVALID_PARAMETER;
    }
    mutex_unlock(&gfx_lock);
    if (!st && copy_to_user(cur, arg, &o, sizeof o)) return STATUS_ACCESS_VIOLATION;
    return st;
}

static int32_t sys_createwindow(process_t *cur, uint64_t arg)
{
    shz_createdef_t d;
    uint16_t nm[64], title[GFX_MAX_TITLE];
    uint32_t atom = 0, i, tl;
    int32_t st = STATUS_SUCCESS;
    gclass_t *c;
    gwin_t *w = 0, *parent = DESKTOP;
    gqueue_t *q;
    int msgonly = 0;
    if (copy_from_user(cur, &d, arg, sizeof d)) return STATUS_ACCESS_VIOLATION;
    if (d.class_name) {
        st = read_name(cur, d.class_name, d.class_name_len, nm);
        if (st) return st;
    }
    tl = d.title_len > GFX_MAX_TITLE ? GFX_MAX_TITLE : d.title_len;
    if (tl && copy_from_user(cur, title, d.title, tl * 2ull)) return STATUS_ACCESS_VIOLATION;
    mutex_lock(&gfx_lock);
    atom = d.class_name ? atom_find(nm, d.class_name_len) : d.class_atom;
    c = atom ? class_find(atom, (uint32_t)cur->pid, d.hinstance) : 0;
    if (!c) { st = STATUS_OBJECT_NAME_NOT_FOUND; goto out; }
    if (d.parent == HWND_MESSAGE_VALUE && !(d.style & SHZ_WS_CHILD)) {
        msgonly = 1;
    } else if (d.style & SHZ_WS_CHILD) {
        parent = d.parent ? wm_lookup(d.parent) : 0;
        if (!parent) { st = d.parent ? STATUS_INVALID_HANDLE : STATUS_INVALID_PARAMETER; goto out; }
        if (!wm_owner_ok(cur, parent)) { st = STATUS_ACCESS_DENIED; goto out; }
    } else if (d.parent && !wm_lookup(d.parent)) {
        st = STATUS_INVALID_HANDLE;                            /* an owner window that does not exist */
        goto out;
    }
    q = gq_current(1);
    if (!q) { st = STATUS_NO_MEMORY; goto out; }
    for (i = 1; i < GFX_MAX_WINDOWS && g_win[i].used; ++i) { }
    if (i == GFX_MAX_WINDOWS) { st = STATUS_NO_MEMORY; goto out; }
    w = &g_win[i];
    memset(w, 0, sizeof *w);
    if (++win_gen > 0xfffff) win_gen = 1;
    w->gen = win_gen;
    w->handle = ((uint64_t)win_gen << 12) | (uint64_t)(i + 1);
    w->used = 1;
    w->cls = c;
    ++c->nwin;
    w->wndproc = c->wndproc;
    w->style = d.style & ~SHZ_WS_VISIBLE;               /* shown by ShowWindow after WM_CREATE, as on Windows */
    w->exstyle = d.exstyle;
    w->x = d.x; w->y = d.y;
    w->q = q;
    w->tid = (uint32_t)thread_current()->tid;
    w->pid = (uint32_t)cur->pid;
    w->id = d.id;
    w->hinstance = d.hinstance;
    w->msgonly = msgonly;
    if (!(d.style & SHZ_WS_CHILD) && d.parent && !msgonly) w->owner = d.parent;      /* owner window (popups, dialogs) */
    if (d.w < 0) d.w = 0;
    if (d.h < 0) d.h = 0;
    st = win_apply_size(w, d.w, d.h, 0);
    if (st) { free_window_memory(w); memset(w, 0, sizeof *w); goto out; }
    if (c->cb_wnd) {
        w->extra = kzalloc((size_t)c->cb_wnd);
        if (!w->extra) { st = STATUS_NO_MEMORY; free_window_memory(w); memset(w, 0, sizeof *w); goto out; }
        w->cb_extra = c->cb_wnd;
    }
    win_set_title(w, title, tl);
    w->parent = parent;
    link_top(w, parent);
    {
        shz_rect_t full = { 0, 0, client_w(w), client_h(w) };
        gq_invalidate(w, &full, 1, SHZ_INV_ERASE);
    }
    d.hwnd_out = w->handle;
    d.wndproc_out = w->wndproc;
out:
    mutex_unlock(&gfx_lock);
    if (!st && copy_to_user(cur, arg, &d, sizeof d)) return STATUS_ACCESS_VIOLATION;
    return st;
}

static int32_t sys_destroywindow(process_t *cur, uint64_t hwnd)
{
    gwin_t *w;
    int32_t st = STATUS_SUCCESS;
    mutex_lock(&gfx_lock);
    w = wm_lookup(hwnd);
    if (!w) st = STATUS_INVALID_HANDLE;
    else if (!wm_owner_ok(cur, w)) st = STATUS_ACCESS_DENIED;
    else { wm_destroy_tree(w); wm_fix_activation(); gin_windows_changed(); }
    mutex_unlock(&gfx_lock);
    return st;
}

/* ---------------------------------------------------------------- queries and setters */
static int32_t copy_units(process_t *cur, uint64_t buf, uint32_t cap, const uint16_t *src, uint32_t n, uint32_t *written)
{
    static const uint16_t z;
    *written = 0;
    if (!cap) return STATUS_SUCCESS;
    if (n > cap - 1) n = cap - 1;
    if ((n && copy_to_user(cur, buf, src, n * 2ull)) || copy_to_user(cur, buf + n * 2ull, &z, 2)) return STATUS_ACCESS_VIOLATION;
    *written = n;
    return STATUS_SUCCESS;
}

static uint64_t win_parent_for_query(gwin_t *w)
{
    if (w->style & SHZ_WS_CHILD) return w->parent && w->parent != DESKTOP ? w->parent->handle : 0;
    return w->owner && wm_lookup(w->owner) ? w->owner : 0;
}

static int32_t sys_wquery(process_t *cur, uint64_t arg)
{
    shz_wnd_t q;
    gwin_t *w, *o = 0;
    int32_t st = STATUS_SUCCESS;
    if (copy_from_user(cur, &q, arg, sizeof q)) return STATUS_ACCESS_VIOLATION;
    mutex_lock(&gfx_lock);
    if (q.what == SHZ_WQ_SHELL) {
        gq_reap_dead();                  /* a just-exited owner must not leave a stale shell until gfxd's next tick */
        q.v0 = wm_lookup(shell_window) ? shell_window : 0;
        if (!q.v0) shell_window = 0;
        goto done;
    }
    w = q.hwnd ? wm_lookup(q.hwnd) : 0;
    if (q.what == SHZ_WQ_DESKTOP) { q.v0 = DESKTOP->handle; goto done; }
    if (q.what == SHZ_WQ_EXISTS) { q.v0 = w != 0; goto done; }
    if (!w) { st = STATUS_INVALID_HANDLE; goto done; }
    switch (q.what) {
    case SHZ_WQ_RECT: {
        int32_t ox, oy;
        abs_origin(w, &ox, &oy);
        q.rect.left = ox; q.rect.top = oy; q.rect.right = ox + w->w; q.rect.bottom = oy + w->h;
        break;
    }
    case SHZ_WQ_POS: q.rect.left = w->x; q.rect.top = w->y; q.rect.right = w->x + w->w; q.rect.bottom = w->y + w->h; break;
    case SHZ_WQ_RESTORE:                                    /* the rectangle a maximised/minimised window returns to (else its own) */
        if (w->has_restore && (w->style & (SHZ_WS_MAXIMIZE | SHZ_WS_MINIMIZE))) q.rect = w->restore;
        else { q.rect.left = w->x; q.rect.top = w->y; q.rect.right = w->x + w->w; q.rect.bottom = w->y + w->h; }
        break;
    case SHZ_WQ_CLIENT: q.rect.left = q.rect.top = 0; q.rect.right = client_w(w); q.rect.bottom = client_h(w); break;
    case SHZ_WQ_CLIENT_ORG: {
        int32_t sx, sy;
        wm_client_origin(w, &sx, &sy);
        q.rect.left = sx; q.rect.top = sy; q.rect.right = sx + client_w(w); q.rect.bottom = sy + client_h(w);
        break;
    }
    case SHZ_WQ_STYLE: q.v0 = w->style; break;
    case SHZ_WQ_EXSTYLE: q.v0 = w->exstyle; break;
    case SHZ_WQ_ID: q.v0 = w->id; break;
    case SHZ_WQ_USERDATA: q.v0 = w->userdata; break;
    case SHZ_WQ_WNDPROC: q.v0 = w->wndproc; break;
    case SHZ_WQ_HINSTANCE: q.v0 = w->hinstance; break;
    case SHZ_WQ_PARENT: q.v0 = win_parent_for_query(w); break;
    case SHZ_WQ_OWNER: q.v0 = w->owner && wm_lookup(w->owner) ? w->owner : 0; break;
    case SHZ_WQ_THREAD: q.v0 = w->tid; q.v1 = w->pid; break;
    case SHZ_WQ_TEXT: {
        uint32_t n;
        q.v0 = w->title_len;
        st = copy_units(cur, q.buf, q.buf_len, w->title, w->title_len, &n);
        q.buf_len = n;
        break;
    }
    case SHZ_WQ_CLASSNAME: {
        uint32_t n;
        st = copy_units(cur, q.buf, q.buf_len, w->cls->name, w->cls->name_len, &n);
        q.buf_len = n;
        break;
    }
    case SHZ_WQ_CLASS_ATOM: q.v0 = w->cls ? w->cls->atom : 0; break;
    case SHZ_WQ_VISIBLE: q.v0 = wm_is_visible(w); break;
    case SHZ_WQ_ENABLED: {
        gwin_t *a;
        q.v0 = 1;
        for (a = w; a && a != DESKTOP; a = a->parent)
            if (a->style & SHZ_WS_DISABLED) { q.v0 = 0; break; }
        break;
    }
    case SHZ_WQ_EXTRA: {
        const uint32_t size = q.buf_len;
        uint64_t v = 0;
        if ((size != 4 && size != 8) || q.index < 0 || (int64_t)q.index + size > w->cb_extra) { st = STATUS_INVALID_PARAMETER; break; }
        memcpy(&v, w->extra + q.index, size);
        q.v0 = v;
        break;
    }
    case SHZ_WQ_GW:
        switch (q.index) {                                  /* GW_HWNDFIRST..GW_CHILD */
        case 0: o = w->parent ? w->parent->child : 0; break;
        case 1: for (o = w; o && o->next; o = o->next) { } break;
        case 2: o = w->next; break;
        case 3: o = w->prev; break;
        case 4: o = w->owner ? wm_lookup(w->owner) : 0; break;
        case 5: o = w->child; break;
        default: st = STATUS_INVALID_PARAMETER;
        }
        q.v0 = o ? o->handle : 0;
        break;
    case SHZ_WQ_ANCESTOR:
        switch (q.index) {                                  /* GA_PARENT, GA_ROOT, GA_ROOTOWNER */
        case 1: o = w->parent; break;
        case 2: o = wm_toplevel(w); break;
        case 3: o = wm_toplevel(w); while (o->owner && wm_lookup(o->owner)) o = wm_toplevel(wm_lookup(o->owner)); break;
        default: st = STATUS_INVALID_PARAMETER;
        }
        q.v0 = o ? o->handle : 0;
        break;
    case SHZ_WQ_ISCHILD: {
        gwin_t *anc = wm_lookup(q.v0);
        q.v0 = anc && anc != w && wm_is_descendant(anc, w) && anc != DESKTOP;
        break;
    }
    default: st = STATUS_INVALID_PARAMETER;
    }
done:
    mutex_unlock(&gfx_lock);
    if (st == STATUS_SUCCESS && copy_to_user(cur, arg, &q, sizeof q)) return STATUS_ACCESS_VIOLATION;
    return st;
}

static int32_t sys_wset(process_t *cur, uint64_t arg)
{
    shz_wnd_t s;
    gwin_t *w;
    int32_t st = STATUS_SUCCESS;
    uint16_t title[GFX_MAX_TITLE];
    uint32_t tl = 0;
    if (copy_from_user(cur, &s, arg, sizeof s)) return STATUS_ACCESS_VIOLATION;
    if (s.what == SHZ_WS_SET_TEXT) {
        tl = s.buf_len > GFX_MAX_TITLE ? GFX_MAX_TITLE : s.buf_len;
        if (tl && copy_from_user(cur, title, s.buf, tl * 2ull)) return STATUS_ACCESS_VIOLATION;
    }
    mutex_lock(&gfx_lock);
    if (s.what == SHZ_WS_SET_SHELL) gq_reap_dead();
    w = wm_lookup(s.hwnd);
    if (!w) { st = STATUS_INVALID_HANDLE; goto done; }
    if (!wm_owner_ok(cur, w)) { st = STATUS_ACCESS_DENIED; goto done; }
    switch (s.what) {
    case SHZ_WS_SET_SHELL:
        if (w == DESKTOP || w->parent != DESKTOP || w->msgonly || w->owner ||
            (w->style & SHZ_WS_CHILD) || (w->exstyle & SHZ_WS_EX_TOPMOST) || wm_lookup(shell_window)) {
            st = STATUS_ACCESS_DENIED;
            break;
        }
        shell_window = w->handle;
        tree_unlink(w);
        link_bottom(w, DESKTOP);
        wm_damage_window(w);
        break;
    case SHZ_WS_SET_STYLE:
    case SHZ_WS_SET_EXSTYLE: {
        shz_rect_t before, after;
        const int was = wm_is_visible(w) && wm_screen_rect(w, &before);
        const int32_t ocw = client_w(w), och = client_h(w);
        if (w->handle == shell_window &&
            ((s.what == SHZ_WS_SET_STYLE && (s.v0 & SHZ_WS_CHILD)) ||
             (s.what == SHZ_WS_SET_EXSTYLE && (s.v0 & SHZ_WS_EX_TOPMOST)))) {
            st = STATUS_ACCESS_DENIED;
            break;
        }
        if (s.what == SHZ_WS_SET_STYLE) { s.v1 = w->style; w->style = (uint32_t)s.v0; }
        else {
            s.v1 = w->exstyle;
            w->exstyle = (uint32_t)s.v0;
            if (!(w->exstyle & WS_EX_LAYERED_)) { layer_free(w); w->lmode = 0; w->lflags = 0; }   /* leaving layered mode resets it */
        }
        if (w->msgonly) w->style &= ~SHZ_WS_VISIBLE;
        st = win_apply_size(w, w->w, w->h, 0);
        if (!st && (client_w(w) != ocw || client_h(w) != och)) resize_invalidate(w, ocw, och, 1);
        if (was || wm_is_visible(w)) {
            shz_rect_t u;
            if (wm_is_visible(w) && wm_screen_rect(w, &after)) { u = after; if (was) rc_union(&u, &before); wm_damage(&u); }
            else if (was) wm_damage(&before);
        }
        if (!wm_is_visible(w)) wm_fix_activation();
        break;
    }
    case SHZ_WS_SET_ID: s.v1 = w->id; w->id = s.v0; break;
    case SHZ_WS_SET_USERDATA: s.v1 = w->userdata; w->userdata = s.v0; break;
    case SHZ_WS_SET_WNDPROC: s.v1 = w->wndproc; w->wndproc = s.v0; break;
    case SHZ_WS_SET_HINSTANCE: s.v1 = w->hinstance; w->hinstance = s.v0; break;
    case SHZ_WS_SET_OWNER:
        if (w->handle == shell_window && s.v0) { st = STATUS_ACCESS_DENIED; break; }
        s.v1 = w->owner; w->owner = s.v0; break;
    case SHZ_WS_SET_EXTRA: {
        const uint32_t size = s.buf_len;
        uint64_t old = 0;
        if ((size != 4 && size != 8) || s.index < 0 || (int64_t)s.index + size > w->cb_extra) { st = STATUS_INVALID_PARAMETER; break; }
        memcpy(&old, w->extra + s.index, size);
        memcpy(w->extra + s.index, &s.v0, size);
        s.v1 = old;
        break;
    }
    case SHZ_WS_SET_TEXT:
        win_set_title(w, title, tl);
        if (wm_is_visible(w)) wm_damage_window(w);
        break;
    case SHZ_WS_SET_ENABLED:
        s.v1 = (w->style & SHZ_WS_DISABLED) != 0;
        if (s.v0) w->style &= ~SHZ_WS_DISABLED; else w->style |= SHZ_WS_DISABLED;
        break;
    case SHZ_WS_SET_PARENT: {
        gwin_t *np = s.v0 ? wm_lookup(s.v0) : DESKTOP;
        shz_rect_t before, after;
        const int was = wm_is_visible(w) && wm_screen_rect(w, &before);
        if (!np || wm_is_descendant(w, np)) { st = STATUS_INVALID_PARAMETER; break; }
        if (w->handle == shell_window && np != DESKTOP) { st = STATUS_ACCESS_DENIED; break; }
        if (np != DESKTOP && !wm_owner_ok(cur, np)) { st = STATUS_ACCESS_DENIED; break; }
        s.v1 = win_parent_for_query(w);
        tree_unlink(w);
        link_top(w, np);
        if (was) wm_damage(&before);
        if (wm_is_visible(w) && wm_screen_rect(w, &after)) wm_damage(&after);
        wm_fix_activation();
        break;
    }
    default: st = STATUS_INVALID_PARAMETER;
    }
done:
    mutex_unlock(&gfx_lock);
    if (!st && copy_to_user(cur, arg, &s, sizeof s)) return STATUS_ACCESS_VIOLATION;
    return st;
}

/* ---------------------------------------------------------------- show / position */
enum { SW_HIDE = 0, SW_SHOWNORMAL = 1, SW_SHOWMINIMIZED = 2, SW_SHOWMAXIMIZED = 3, SW_SHOWNOACTIVATE = 4, SW_SHOW = 5,
       SW_MINIMIZE = 6, SW_SHOWMINNOACTIVE = 7, SW_SHOWNA = 8, SW_RESTORE = 9, SW_SHOWDEFAULT = 10, SW_FORCEMINIMIZE = 11 };

static void maximise(gwin_t *w)
{
    if (!(w->style & (SHZ_WS_MAXIMIZE | SHZ_WS_MINIMIZE))) {
        w->restore.left = w->x; w->restore.top = w->y; w->restore.right = w->x + w->w; w->restore.bottom = w->y + w->h;
        w->has_restore = 1;
    }
    w->style = (w->style | SHZ_WS_MAXIMIZE) & ~SHZ_WS_MINIMIZE;
    w->x = 0; w->y = 0;
    win_apply_size(w, (int32_t)g_fb.width, (int32_t)g_fb.height, 0);
}

static int32_t sys_showwindow(process_t *cur, uint64_t arg)
{
    shz_show_t s;
    gwin_t *w;
    shz_rect_t before, after;
    int32_t st = STATUS_SUCCESS;
    int was_vis, activate = 0, resized = 0;
    int32_t ocw, och;
    if (copy_from_user(cur, &s, arg, sizeof s)) return STATUS_ACCESS_VIOLATION;
    mutex_lock(&gfx_lock);
    w = wm_lookup(s.hwnd);
    if (!w) { st = STATUS_INVALID_HANDLE; goto done; }
    if (!wm_owner_ok(cur, w)) { st = STATUS_ACCESS_DENIED; goto done; }
    was_vis = (w->style & SHZ_WS_VISIBLE) != 0;
    ocw = client_w(w); och = client_h(w);
    memset(&before, 0, sizeof before);
    if (wm_is_visible(w)) wm_screen_rect(w, &before);
    s.was_visible = was_vis;
    switch (s.cmd) {
    case SW_HIDE: w->style &= ~SHZ_WS_VISIBLE; break;
    case SW_SHOWMINIMIZED: case SW_MINIMIZE: case SW_SHOWMINNOACTIVE: case SW_FORCEMINIMIZE:
        if (!(w->style & (SHZ_WS_MINIMIZE | SHZ_WS_MAXIMIZE))) {
            w->restore.left = w->x; w->restore.top = w->y; w->restore.right = w->x + w->w; w->restore.bottom = w->y + w->h;
            w->has_restore = 1;
        }
        w->style |= SHZ_WS_MINIMIZE | SHZ_WS_VISIBLE;
        break;
    case SW_SHOWMAXIMIZED:
        maximise(w);
        w->style |= SHZ_WS_VISIBLE;
        resized = 1;
        activate = 1;
        break;
    case SW_RESTORE: case SW_SHOWNORMAL: case SW_SHOWDEFAULT:
        if ((w->style & (SHZ_WS_MAXIMIZE | SHZ_WS_MINIMIZE)) && w->has_restore) {
            w->style &= ~(SHZ_WS_MAXIMIZE | SHZ_WS_MINIMIZE);
            w->x = w->restore.left; w->y = w->restore.top;
            win_apply_size(w, w->restore.right - w->restore.left, w->restore.bottom - w->restore.top, 0);
            resized = 1;
        }
        w->style |= SHZ_WS_VISIBLE;
        activate = 1;
        break;
    case SW_SHOW:
        w->style |= SHZ_WS_VISIBLE;
        activate = 1;
        break;
    case SW_SHOWNOACTIVATE: case SW_SHOWNA:
        w->style |= SHZ_WS_VISIBLE;
        break;
    default: st = STATUS_INVALID_PARAMETER; goto done;
    }
    if (w->msgonly) { w->style &= ~SHZ_WS_VISIBLE; activate = 0; }
    if (resized && (client_w(w) != ocw || client_h(w) != och)) resize_invalidate(w, ocw, och, 1);
    if (!was_vis && (w->style & SHZ_WS_VISIBLE)) {                 /* hidden -> shown: repaint the whole client */
        shz_rect_t full = { 0, 0, client_w(w), client_h(w) };
        gq_invalidate(w, &full, 1, SHZ_INV_ERASE);
    }
    if (activate && w->parent == DESKTOP && !(w->exstyle & SHZ_WS_EX_NOACTIVATE) && (w->style & SHZ_WS_VISIBLE) &&
        !(w->style & SHZ_WS_MINIMIZE) && !(w->style & SHZ_WS_DISABLED)) {
        s.prev_active = wm_activate(w, 1);
        s.activated = 1;
    }
    if (wm_is_visible(w) && wm_screen_rect(w, &after)) { if (before.right > before.left) rc_union(&after, &before); wm_damage(&after); }
    else if (before.right > before.left) wm_damage(&before);
    if (!wm_is_visible(w)) wm_fix_activation();
    gin_windows_changed();
done:
    mutex_unlock(&gfx_lock);
    if (!st && copy_to_user(cur, arg, &s, sizeof s)) return STATUS_ACCESS_VIOLATION;
    return st;
}

static int32_t sys_setwindowpos(process_t *cur, uint64_t arg)
{
    shz_setpos_t p;
    gwin_t *w, *ref = 0;
    shz_rect_t before, after;
    int32_t st = STATUS_SUCCESS, ocw, och;
    int was_vis, redraw_all = 0, sized = 0, moved = 0;
    if (copy_from_user(cur, &p, arg, sizeof p)) return STATUS_ACCESS_VIOLATION;
    mutex_lock(&gfx_lock);
    w = wm_lookup(p.hwnd);
    if (!w) { st = STATUS_INVALID_HANDLE; goto done; }
    if (!wm_owner_ok(cur, w)) { st = STATUS_ACCESS_DENIED; goto done; }
    if (w->handle == shell_window && !(p.flags & SWP_NOZORDER) && p.insert_after == (uint64_t)-1) {
        st = STATUS_ACCESS_DENIED; goto done;
    }
    if (!(p.flags & SWP_NOZORDER) && p.insert_after > 1 && p.insert_after != (uint64_t)-1 && p.insert_after != (uint64_t)-2) {
        ref = wm_lookup(p.insert_after);
        if (!ref || ref->parent != w->parent) { st = STATUS_INVALID_PARAMETER; goto done; }
    }
    was_vis = wm_is_visible(w);
    memset(&before, 0, sizeof before);
    if (was_vis) wm_screen_rect(w, &before);
    ocw = client_w(w); och = client_h(w);
    p.changed = 0;
    if (!(p.flags & SWP_NOMOVE) && (p.x != w->x || p.y != w->y)) { w->x = p.x; w->y = p.y; moved = 1; }
    if (!(p.flags & SWP_NOSIZE) || (p.flags & SWP_FRAMECHANGED)) {
        const int32_t nw = (p.flags & SWP_NOSIZE) ? w->w : (p.cx < 0 ? 0 : p.cx);
        const int32_t nh = (p.flags & SWP_NOSIZE) ? w->h : (p.cy < 0 ? 0 : p.cy);
        if (nw != w->w || nh != w->h || (p.flags & SWP_FRAMECHANGED)) {
            st = win_apply_size(w, nw, nh, &redraw_all);
            if (st) goto done;
            sized = 1;
            if (w->style & (SHZ_WS_MAXIMIZE | SHZ_WS_MINIMIZE)) w->style &= ~(SHZ_WS_MAXIMIZE | SHZ_WS_MINIMIZE);
        }
    }
    if (sized && (client_w(w) != ocw || client_h(w) != och || (p.flags & SWP_FRAMECHANGED))) resize_invalidate(w, ocw, och, redraw_all || (p.flags & SWP_FRAMECHANGED));
    if (!(p.flags & SWP_NOZORDER) && w->parent) {
        gwin_t *par = w->parent;
        if (w->handle == shell_window) { tree_unlink(w); link_bottom(w, par); }
        else if (p.insert_after == 0 && !ref) { tree_unlink(w); link_top(w, par); }
        else if (p.insert_after == 1 && !ref) { tree_unlink(w); link_bottom(w, par); }
        else if (p.insert_after == (uint64_t)-1) { w->exstyle |= SHZ_WS_EX_TOPMOST; tree_unlink(w); link_top(w, par); }
        else if (p.insert_after == (uint64_t)-2) { w->exstyle &= ~SHZ_WS_EX_TOPMOST; tree_unlink(w); link_top(w, par); }
        else if (ref && ref != w) { tree_unlink(w); link_below(w, ref); }
        p.changed |= SHZ_POS_ZORDER;
    }
    if ((p.flags & SWP_SHOWWINDOW) && !(w->style & SHZ_WS_VISIBLE) && !w->msgonly) {
        shz_rect_t full = { 0, 0, client_w(w), client_h(w) };
        w->style |= SHZ_WS_VISIBLE;
        gq_invalidate(w, &full, 1, SHZ_INV_ERASE);
        p.changed |= SHZ_POS_SHOWN;
    }
    if ((p.flags & SWP_HIDEWINDOW) && (w->style & SHZ_WS_VISIBLE)) { w->style &= ~SHZ_WS_VISIBLE; p.changed |= SHZ_POS_HIDDEN; }
    if (moved) p.changed |= SHZ_POS_MOVED;
    if (sized) p.changed |= SHZ_POS_SIZED;
    if (!(p.flags & SWP_NOACTIVATE) && !(p.flags & SWP_NOZORDER) && w->parent == DESKTOP && wm_is_visible(w) &&
        !(w->exstyle & SHZ_WS_EX_NOACTIVATE) && !(w->style & SHZ_WS_DISABLED))
        p.prev_active = wm_activate(w, 0);
    p.new_rect.left = w->x; p.new_rect.top = w->y; p.new_rect.right = w->x + w->w; p.new_rect.bottom = w->y + w->h;
    if (wm_is_visible(w) && wm_screen_rect(w, &after)) { if (was_vis) rc_union(&after, &before); wm_damage(&after); }
    else if (was_vis) wm_damage(&before);
    if (!wm_is_visible(w)) wm_fix_activation();
    gin_windows_changed();
done:
    mutex_unlock(&gfx_lock);
    if (!st && copy_to_user(cur, arg, &p, sizeof p)) return STATUS_ACCESS_VIOLATION;
    return st;
}

/* ---------------------------------------------------------------- focus, enumeration, hit testing, atoms, props */
static int32_t sys_focus(process_t *cur, uint64_t arg)
{
    shz_focus_t f;
    gqueue_t *q;
    gwin_t *w = 0;
    int32_t st = STATUS_SUCCESS;
    if (copy_from_user(cur, &f, arg, sizeof f)) return STATUS_ACCESS_VIOLATION;
    mutex_lock(&gfx_lock);
    q = gq_current(1);
    if (!q) { st = STATUS_NO_MEMORY; goto done; }
    f.result = f.result2 = 0;
    switch (f.op) {
    case SHZ_FOCUS_GETFOCUS: f.result = wm_lookup(q->focus) ? q->focus : 0; break;
    case SHZ_FOCUS_SETFOCUS:
        if (f.hwnd) {
            w = wm_lookup(f.hwnd);
            if (!w) { st = STATUS_INVALID_HANDLE; break; }
            if (w->q != q) { st = STATUS_ACCESS_DENIED; break; }
            if (!wm_is_visible(w) || (w->style & SHZ_WS_DISABLED)) { st = STATUS_UNSUCCESSFUL; break; }
        }
        f.result = wm_lookup(q->focus) ? q->focus : 0;
        q->focus = w ? w->handle : 0;
        break;
    case SHZ_FOCUS_GETACTIVE: f.result = wm_lookup(q->active) ? q->active : 0; break;
    case SHZ_FOCUS_SETACTIVE:
        w = wm_lookup(f.hwnd);
        if (!w) { st = STATUS_INVALID_HANDLE; break; }
        w = wm_toplevel(w);
        if (w->q != q) { st = STATUS_ACCESS_DENIED; break; }
        f.result = wm_lookup(q->active) ? q->active : 0;
        f.result2 = wm_activate(w, 1);
        wm_damage_window(w);
        break;
    case SHZ_FOCUS_GETFOREGROUND: f.result = g_fg_q && wm_lookup(g_fg_q->active) ? g_fg_q->active : 0; break;
    case SHZ_FOCUS_SETFOREGROUND:
        w = wm_lookup(f.hwnd);
        if (!w) { st = STATUS_INVALID_HANDLE; break; }
        w = wm_toplevel(w);
        if (!wm_is_visible(w) || w == DESKTOP) { st = STATUS_UNSUCCESSFUL; break; }
        f.result2 = wm_activate(w, 1);
        f.result = w->handle;
        wm_damage_window(w);
        break;
    case SHZ_FOCUS_GETCAPTURE: f.result = wm_lookup(q->capture) ? q->capture : 0; break;
    case SHZ_FOCUS_SETCAPTURE:
        if (f.hwnd) {
            w = wm_lookup(f.hwnd);
            if (!w) { st = STATUS_INVALID_HANDLE; break; }
            if (w->q != q) { st = STATUS_ACCESS_DENIED; break; }
        }
        f.result = wm_lookup(q->capture) ? q->capture : 0;
        q->capture = w ? w->handle : 0;
        break;
    default: st = STATUS_INVALID_PARAMETER;
    }
done:
    mutex_unlock(&gfx_lock);
    if (!st && copy_to_user(cur, arg, &f, sizeof f)) return STATUS_ACCESS_VIOLATION;
    return st;
}

static uint64_t enum_collect(gwin_t *parent, const shz_enum_t *e, uint64_t *out, uint64_t max, uint64_t n)
{
    gwin_t *c;
    for (c = parent->child; c; c = c->next) {
        if (!(e->flags & SHZ_ENUM_THREAD) || c->tid == e->tid) {
            if (n < max) out[n] = c->handle;
            ++n;
        }
        if (e->flags & SHZ_ENUM_RECURSE) n = enum_collect(c, e, out, max, n);
    }
    return n;
}

static int32_t sys_enumwindows(process_t *cur, uint64_t arg)
{
    shz_enum_t e;
    static uint64_t tmp[GFX_MAX_WINDOWS];                  /* under gfx_lock */
    gwin_t *parent;
    uint64_t n = 0;
    int32_t st = STATUS_SUCCESS;
    if (copy_from_user(cur, &e, arg, sizeof e)) return STATUS_ACCESS_VIOLATION;
    if (e.max > GFX_MAX_WINDOWS) e.max = GFX_MAX_WINDOWS;
    mutex_lock(&gfx_lock);
    parent = e.parent ? wm_lookup(e.parent) : DESKTOP;
    if (!parent) { st = STATUS_INVALID_HANDLE; goto done; }
    n = enum_collect(parent, &e, tmp, e.max, 0);
    if (n > e.max) n = e.max;
    if (n && copy_to_user(cur, e.out, tmp, n * 8)) st = STATUS_ACCESS_VIOLATION;
    e.count = n;
done:
    mutex_unlock(&gfx_lock);
    if (!st && copy_to_user(cur, arg, &e, sizeof e)) return STATUS_ACCESS_VIOLATION;
    return st;
}

/* The point (x,y) lies in c's rectangle (c at screen (cx,cy)); is c transparent there (window region, layering)? */
static int hit_transparent(const gwin_t *c, int cx, int cy, int x, int y)
{
    const int wx = x - cx, wy = y - cy;
    if (c->rgn) {
        uint32_t i;
        int in = 0;
        for (i = 0; i < c->nrgn && !in; ++i)
            in = wx >= c->rgn[i].left && wx < c->rgn[i].right && wy >= c->rgn[i].top && wy < c->rgn[i].bottom;
        if (!in) return 1;
    }
    if (!is_layered(c)) return 0;
    if (c->lmode == 0) return 1;
    if (c->lmode == 2) {
        uint32_t p;
        if (!c->layer || wx >= c->lw || wy >= c->lh) return 1;
        p = c->layer[(uint64_t)wy * (uint32_t)c->lw + (uint32_t)wx];
        if ((c->lflags & ULW_COLORKEY_) && (p & 0x00ffffffu) == c->lkey) return 1;
        return c->lppa && (p >> 24) == 0;
    }
    if ((c->lflags & LWA_ALPHA_) && c->lalpha == 0) return 1;
    if ((c->lflags & LWA_COLORKEY_) && c->surf && wx >= c->ncl && wy >= c->nct && wx - c->ncl < c->sw && wy - c->nct < c->sh &&
        (c->surf[(uint64_t)(wy - c->nct) * (uint32_t)c->sw + (uint32_t)(wx - c->ncl)] & 0x00ffffffu) == c->lkey)
        return 1;                                                   /* the window's own client pixel (children not considered) */
    return 0;
}

static gwin_t *hit_test(gwin_t *parent, int ox, int oy, int x, int y)
{
    gwin_t *c;
    for (c = parent->child; c; c = c->next) {
        const int cx = ox + c->x, cy = oy + c->y;
        gwin_t *r;
        if (c->msgonly || !(c->style & SHZ_WS_VISIBLE) || (c->style & SHZ_WS_MINIMIZE)) continue;
        if (x < cx || y < cy || x >= cx + c->w || y >= cy + c->h) continue;
        if (hit_transparent(c, cx, cy, x, y)) continue;
        if (x >= cx + c->ncl && y >= cy + c->nct && x < cx + c->ncl + client_w(c) && y < cy + c->nct + client_h(c) &&
            (r = hit_test(c, cx + c->ncl, cy + c->nct, x, y)))
            return r;
        return c;
    }
    return 0;
}

/* The window that gets mouse input at a screen point: like hit_test, but disabled child windows are skipped (the point
 * belongs to what is below them, as on Windows) and WS_EX_LAYERED|WS_EX_TRANSPARENT windows are click-through. */
static gwin_t *input_hit(gwin_t *parent, int ox, int oy, int x, int y)
{
    gwin_t *c;
    for (c = parent->child; c; c = c->next) {
        const int cx = ox + c->x, cy = oy + c->y;
        gwin_t *r;
        if (c->msgonly || !(c->style & SHZ_WS_VISIBLE) || (c->style & SHZ_WS_MINIMIZE)) continue;
        if ((c->exstyle & (WS_EX_TRANSPARENT_ | WS_EX_LAYERED_)) == (WS_EX_TRANSPARENT_ | WS_EX_LAYERED_)) continue;
        if (parent != DESKTOP && (c->style & SHZ_WS_DISABLED)) continue;
        if (x < cx || y < cy || x >= cx + c->w || y >= cy + c->h) continue;
        if (hit_transparent(c, cx, cy, x, y)) continue;
        if (x >= cx + c->ncl && y >= cy + c->nct && x < cx + c->ncl + client_w(c) && y < cy + c->nct + client_h(c) &&
            (r = input_hit(c, cx + c->ncl, cy + c->nct, x, y)))
            return r;
        return c;
    }
    return 0;
}

gwin_t *wm_input_hit(int x, int y) { return input_hit(DESKTOP, 0, 0, x, y); }

static int32_t sys_hittest(process_t *cur, int64_t x, int64_t y, uint64_t out)
{
    gwin_t *w;
    uint64_t h;
    mutex_lock(&gfx_lock);
    w = hit_test(DESKTOP, 0, 0, (int)x, (int)y);
    h = w ? w->handle : DESKTOP->handle;
    mutex_unlock(&gfx_lock);
    return copy_to_user(cur, out, &h, 8) ? STATUS_ACCESS_VIOLATION : STATUS_SUCCESS;
}

static int32_t sys_atom(process_t *cur, uint64_t arg)
{
    shz_atom_t a;
    uint16_t nm[64];
    int32_t st;
    if (copy_from_user(cur, &a, arg, sizeof a)) return STATUS_ACCESS_VIOLATION;
    if (a.op == SHZ_ATOM_GETNAME) {                                    /* atom -> name (GetClipboardFormatName) */
        const uint32_t i = a.atom - GFX_ATOM_BASE;
        uint32_t n = 0;
        mutex_lock(&gfx_lock);
        if (a.atom < GFX_ATOM_BASE || i >= GFX_MAX_ATOMS || !g_atoms[i].used) st = STATUS_INVALID_PARAMETER;
        else st = copy_units(cur, a.name, a.name_len, g_atoms[i].name, g_atoms[i].len, &n);
        mutex_unlock(&gfx_lock);
        a.name_len = n;
        if (!st && copy_to_user(cur, arg, &a, sizeof a)) return STATUS_ACCESS_VIOLATION;
        return st;
    }
    st = read_name(cur, a.name, a.name_len, nm);
    if (st) return st;
    mutex_lock(&gfx_lock);
    if (a.op == SHZ_ATOM_ADD) a.atom = atom_add(nm, a.name_len);
    else if (a.op == SHZ_ATOM_FIND) a.atom = atom_find(nm, a.name_len);
    else st = STATUS_INVALID_PARAMETER;
    if (!st && !a.atom) st = a.op == SHZ_ATOM_ADD ? STATUS_NO_MEMORY : STATUS_OBJECT_NAME_NOT_FOUND;
    mutex_unlock(&gfx_lock);
    if (!st && copy_to_user(cur, arg, &a, sizeof a)) return STATUS_ACCESS_VIOLATION;
    return st;
}

static int32_t sys_prop(process_t *cur, uint64_t arg)
{
    shz_prop_t p;
    gwin_t *w;
    unsigned i;
    int32_t st = STATUS_SUCCESS;
    if (copy_from_user(cur, &p, arg, sizeof p)) return STATUS_ACCESS_VIOLATION;
    mutex_lock(&gfx_lock);
    w = wm_lookup(p.hwnd);
    if (!w) { st = STATUS_INVALID_HANDLE; goto done; }
    if (!wm_owner_ok(cur, w)) { st = STATUS_ACCESS_DENIED; goto done; }
    for (i = 0; i < GFX_MAX_PROPS; ++i)
        if (w->props[i].key == p.key && p.key) break;
    switch (p.op) {
    case SHZ_PROP_SET:
        if (i == GFX_MAX_PROPS)
            for (i = 0; i < GFX_MAX_PROPS && w->props[i].key; ++i) { }
        if (i == GFX_MAX_PROPS) { st = STATUS_NO_MEMORY; break; }
        w->props[i].key = p.key;
        w->props[i].value = p.value;
        break;
    case SHZ_PROP_GET: p.value = i < GFX_MAX_PROPS ? w->props[i].value : 0; break;
    case SHZ_PROP_REMOVE:
        p.value = 0;
        if (i < GFX_MAX_PROPS) { p.value = w->props[i].value; w->props[i].key = 0; w->props[i].value = 0; }
        break;
    default: st = STATUS_INVALID_PARAMETER;
    }
done:
    mutex_unlock(&gfx_lock);
    if (!st && copy_to_user(cur, arg, &p, sizeof p)) return STATUS_ACCESS_VIOLATION;
    return st;
}

/* ---------------------------------------------------------------- present (user-mode bitmap -> window surface) */
int32_t gfx_syscall_present(process_t *cur, uint64_t arg)
{
    shz_present_t p;
    gwin_t *w;
    int32_t st = STATUS_SUCCESS;
    shz_rect_t r, vis, dmg;
    int32_t y, sx, sy;
    if (copy_from_user(cur, &p, arg, sizeof p)) return STATUS_ACCESS_VIOLATION;
    mutex_lock(&gfx_lock);
    w = p.hwnd == DESKTOP->handle ? DESKTOP : wm_lookup(p.hwnd);
    if (!w) { st = STATUS_INVALID_HANDLE; goto done; }
    if (w != DESKTOP && !wm_owner_ok(cur, w)) { st = STATUS_ACCESS_DENIED; goto done; }
    if (w == DESKTOP && !DESKTOP->surf) {                                    /* the desktop surface exists once someone draws on it */
        const uint64_t n = (uint64_t)g_fb.width * g_fb.height;
        uint64_t i;
        DESKTOP->surf = gfx_pages_alloc(n * 4);
        if (!DESKTOP->surf) { st = STATUS_NO_MEMORY; goto done; }
        for (i = 0; i < n; ++i) DESKTOP->surf[i] = SHZ_DESKTOP_RGB;
        DESKTOP->sw = (int32_t)g_fb.width;
        DESKTOP->sh = (int32_t)g_fb.height;
    }
    if (p.surf_w != w->sw || p.surf_h != w->sh) { st = STATUS_INVALID_PARAMETER; goto done; }
    r.left = p.x; r.top = p.y; r.right = p.x + p.w; r.bottom = p.y + p.h;
    vis.left = 0; vis.top = 0; vis.right = w->sw; vis.bottom = w->sh;
    if (!rc_isect(&r, &vis, &r)) goto done;
    for (y = r.top; y < r.bottom; ++y)
        if (copy_from_user(cur, w->surf + (uint64_t)y * (uint32_t)w->sw + (uint32_t)r.left,
                           p.bits + (uint64_t)(uint32_t)y * p.stride + (uint64_t)(uint32_t)r.left * 4, (uint64_t)(r.right - r.left) * 4)) {
            st = STATUS_ACCESS_VIOLATION;
            goto done;
        }
    if (w == DESKTOP || wm_is_visible(w)) {
        wm_client_origin(w, &sx, &sy);
        dmg.left = r.left + sx; dmg.top = r.top + sy; dmg.right = r.right + sx; dmg.bottom = r.bottom + sy;
        if (w == DESKTOP || (wm_screen_rect(w, &vis) && rc_isect(&dmg, &vis, &dmg))) wm_damage(&dmg);
    }
done:
    mutex_unlock(&gfx_lock);
    return st;
}

/* ---------------------------------------------------------------- NtUserWindowOp: layers, regions, readback */
#define WOP_MAX_RGN 256
#define ULW_POS_MOVE 1u
#define ULW_POS_SIZE 2u
#define ULW_POS_PPA 4u

static int32_t winop_update_layered(process_t *cur, gwin_t *w, shz_winop_t *o)
{
    shz_rect_t before, after, dirty;
    const int was = wm_is_visible(w) && wm_screen_rect(w, &before);
    int32_t nw = w->w, nh = w->h, y;
    int32_t st;
    if (!is_layered(w) || w->lmode == 1) return STATUS_INVALID_PARAMETER;   /* not layered, or in attribute mode */
    if (o->pos_flags & ULW_POS_SIZE) {
        if (o->w <= 0 || o->h <= 0) return STATUS_INVALID_PARAMETER;
        nw = o->w; nh = o->h;
    }
    if ((uint64_t)nw * (uint64_t)nh * 4 > GFX_MAX_SURF_BYTES) return STATUS_NO_MEMORY;
    if (!o->bits && (!w->layer || nw != w->lw || nh != w->lh)) return STATUS_INVALID_PARAMETER;   /* a new size needs pixels */
    if (nw != w->w || nh != w->h) {
        st = win_apply_size(w, nw, nh, 0);
        if (st) return st;
    }
    if (!w->layer || w->lw != nw || w->lh != nh) {
        uint32_t *nl = gfx_pages_alloc((uint64_t)nw * (uint64_t)nh * 4);
        if (!nl) return STATUS_NO_MEMORY;
        layer_free(w);
        w->layer = nl;
        w->lw = nw;
        w->lh = nh;
        o->dirty.left = o->dirty.top = o->dirty.right = o->dirty.bottom = 0;   /* a new bitmap: everything is new */
    }
    if (o->pos_flags & ULW_POS_MOVE) { w->x = o->x; w->y = o->y; }
    w->lmode = 2;
    w->lflags = o->flags;
    w->lkey = o->key & 0x00ffffffu;
    w->lalpha = (uint8_t)o->alpha;
    if (o->bits) {
        shz_rect_t all = { 0, 0, nw, nh };
        w->lppa = (o->pos_flags & ULW_POS_PPA) != 0;
        if (rc_empty(&o->dirty) || !rc_isect(&o->dirty, &all, &dirty)) dirty = all;
        for (y = dirty.top; y < dirty.bottom; ++y)
            if (copy_from_user(cur, w->layer + (uint64_t)y * (uint32_t)nw + (uint32_t)dirty.left,
                               o->bits + (uint64_t)(uint32_t)(o->src_y + y) * o->stride + (uint64_t)(uint32_t)(o->src_x + dirty.left) * 4,
                               (uint64_t)(dirty.right - dirty.left) * 4))
                return STATUS_ACCESS_VIOLATION;
    }
    if (wm_is_visible(w) && wm_screen_rect(w, &after)) {
        if (was && (o->pos_flags & (ULW_POS_MOVE | ULW_POS_SIZE))) rc_union(&after, &before);
        wm_damage(&after);
    } else if (was) wm_damage(&before);
    gin_windows_changed();
    return STATUS_SUCCESS;
}

static int32_t winop_print(process_t *cur, gwin_t *w, shz_winop_t *o)
{
    const int client_only = (o->flags & 1) != 0;
    const int32_t pw = client_only ? client_w(w) : w->w, ph = client_only ? client_h(w) : w->h;
    const int32_t cw = o->w < pw ? o->w : pw, chh = o->h < ph ? o->h : ph;
    uint32_t *buf;
    int32_t y;
    if (cw <= 0 || chh <= 0) { o->w = o->h = 0; return STATUS_SUCCESS; }
    buf = gfx_pages_alloc((uint64_t)pw * (uint64_t)ph * 4);
    if (!buf) return STATUS_NO_MEMORY;
    tgt_px = buf; tgt_w = (uint32_t)pw; tgt_h = (uint32_t)ph;
    {
        const shz_rect_t all = { 0, 0, pw, ph };
        if (is_layered(w) && w->lmode == 2 && w->layer && !client_only) {
            for (y = 0; y < ph && y < w->lh; ++y)
                memcpy(buf + (uint64_t)y * (uint32_t)pw, w->layer + (uint64_t)y * (uint32_t)w->lw, (size_t)(pw < w->lw ? pw : w->lw) * 4);
        } else if (client_only) {
            gwin_t *ch;
            blit_surface(w->surf, w->sw, w->sh, 0, 0, &all);
            for (ch = w->child; ch && ch->next; ch = ch->next) { }
            for (; ch; ch = ch->prev) compose_win(ch, ch->x, ch->y, &all);
        } else {
            compose_plain(w, 0, 0, &all);
        }
    }
    tgt_backbuffer();
    for (y = 0; y < chh; ++y)
        if (copy_to_user(cur, o->bits + (uint64_t)(uint32_t)y * o->stride, buf + (uint64_t)y * (uint32_t)pw, (uint64_t)cw * 4)) {
            gfx_pages_free(buf, (uint64_t)pw * (uint64_t)ph * 4);
            return STATUS_ACCESS_VIOLATION;
        }
    gfx_pages_free(buf, (uint64_t)pw * (uint64_t)ph * 4);
    o->w = cw;
    o->h = chh;
    return STATUS_SUCCESS;
}

static int32_t sys_winop(process_t *cur, uint64_t arg)
{
    shz_winop_t o;
    gwin_t *w;
    int32_t st = STATUS_SUCCESS;
    shz_rect_t *rg = 0;
    if (copy_from_user(cur, &o, arg, sizeof o)) return STATUS_ACCESS_VIOLATION;
    if (o.op == SHZ_WOP_SET_REGION && o.bits) {                     /* read the rectangles before taking the lock */
        if (!o.count || o.count > WOP_MAX_RGN) return STATUS_INVALID_PARAMETER;
        rg = kmalloc(o.count * sizeof *rg);
        if (!rg) return STATUS_NO_MEMORY;
        if (copy_from_user(cur, rg, o.bits, o.count * sizeof *rg)) { kfree(rg); return STATUS_ACCESS_VIOLATION; }
    }
    mutex_lock(&gfx_lock);
    w = wm_lookup(o.hwnd);
    if (!w) { st = STATUS_INVALID_HANDLE; goto done; }
    if (!wm_owner_ok(cur, w) && o.op != SHZ_WOP_GET_LAYERED && o.op != SHZ_WOP_GET_REGION && o.op != SHZ_WOP_GET_AFFINITY) {
        st = STATUS_ACCESS_DENIED;
        goto done;
    }
    switch (o.op) {
    case SHZ_WOP_SET_LAYERED:
        if (!(w->exstyle & WS_EX_LAYERED_) || w->lmode == 2) { st = STATUS_INVALID_PARAMETER; break; }
        w->lmode = 1;
        w->lflags = o.flags & (LWA_COLORKEY_ | LWA_ALPHA_);
        w->lkey = o.key & 0x00ffffffu;
        w->lalpha = (uint8_t)o.alpha;
        wm_damage_window(w);
        gin_windows_changed();
        break;
    case SHZ_WOP_GET_LAYERED:
        if (!(w->exstyle & WS_EX_LAYERED_) || w->lmode != 1) { st = STATUS_INVALID_PARAMETER; break; }
        o.flags = w->lflags; o.key = w->lkey; o.alpha = w->lalpha;
        break;
    case SHZ_WOP_UPDATE_LAYERED: st = winop_update_layered(cur, w, &o); break;
    case SHZ_WOP_SET_REGION: {
        shz_rect_t before, after;
        const int was = wm_is_visible(w) && wm_screen_rect(w, &before);
        if (w->rgn) kfree(w->rgn);
        w->rgn = rg;
        w->nrgn = rg ? o.count : 0;
        rg = 0;
        if (wm_is_visible(w) && wm_screen_rect(w, &after)) { if (was) rc_union(&after, &before); wm_damage(&after); }
        else if (was) wm_damage(&before);
        gin_windows_changed();
        break;
    }
    case SHZ_WOP_GET_REGION: {
        const uint32_t n = w->nrgn < o.count ? w->nrgn : o.count;
        if (!w->rgn) { st = STATUS_NOT_FOUND; break; }
        if (n && o.bits && copy_to_user(cur, o.bits, w->rgn, n * sizeof *w->rgn)) { st = STATUS_ACCESS_VIOLATION; break; }
        o.count = w->nrgn;
        break;
    }
    case SHZ_WOP_PRINT: st = winop_print(cur, w, &o); break;
    case SHZ_WOP_SET_AFFINITY: w->affinity = o.alpha; break;
    case SHZ_WOP_GET_AFFINITY: o.alpha = w->affinity; break;
    default: st = STATUS_INVALID_PARAMETER;
    }
done:
    mutex_unlock(&gfx_lock);
    if (rg) kfree(rg);
    if (!st && copy_to_user(cur, arg, &o, sizeof o)) return STATUS_ACCESS_VIOLATION;
    return st;
}

/* Diagnostics for the leak tests (NtUserThreadOp STATS). Called with gfx_lock held. */
uint64_t gfx_stats(uint64_t *pages)
{
    uint64_t w = 0, c = 0, q = 0, s = 0;
    unsigned i;
    for (i = 1; i < GFX_MAX_WINDOWS; ++i) w += g_win[i].used;
    for (i = 0; i < GFX_MAX_CLASSES; ++i) c += g_cls[i].used;
    for (i = 0; i < GFX_MAX_QUEUES; ++i) q += g_queues[i].used;
    s = gfx_pending_sends();
    *pages = gfx_pages_in_use() | (pmm_free_count() << 32);
    return w | (c << 16) | (q << 32) | (s << 48);
}

/* ---------------------------------------------------------------- housekeeping thread */
static void gfxd_main(void *arg)
{
    (void)arg;
    for (;;) {
        unsigned i;
        thread_sleep_ms(20);
        mutex_lock(&gfx_lock);
        gq_reap_dead();
        gin_tick();
        for (i = 0; i < GFX_MAX_CLASSES; ++i) {
            gclass_t *c = &g_cls[i];
            process_t *p;
            if (!c->used || c->nwin) continue;
            p = process_by_pid((int)c->pid);
            if (p && !(p->terminated && p->threads_alive <= 0)) continue;
            if (c->extra) kfree(c->extra);
            memset(c, 0, sizeof *c);
        }
        wm_fix_activation();
        gin_windows_changed();
        mutex_unlock(&gfx_lock);
    }
}

int gfx_tables_init(void)
{
    if (!g_win) g_win = gfx_pages_alloc(sizeof(gwin_t) * GFX_MAX_WINDOWS);
    if (!g_cls) g_cls = gfx_pages_alloc(sizeof(gclass_t) * GFX_MAX_CLASSES);
    if (!g_win || !g_cls || gq_tables_init() || gin_tables_init()) return STATUS_NO_MEMORY;
    return STATUS_SUCCESS;
}

static int32_t wm_init(void)
{
    int32_t st;
    if (wm_ready && g_fb.ready) return STATUS_SUCCESS;                  /* fast path: every GUI system call comes through here */
    st = gfx_fb_init();
    if (st) return st;
    if (wm_ready) return STATUS_SUCCESS;
    mutex_lock(&wm_init_lock);
    if (!wm_ready && gfx_tables_init()) { mutex_unlock(&wm_init_lock); return STATUS_NO_MEMORY; }
    if (!wm_ready) {
        gwin_t *d = DESKTOP;
        memset(d, 0, sizeof *d);
        d->used = 1;
        d->gen = 1;
        d->handle = (1ull << 12) | 1;
        d->style = SHZ_WS_POPUP | SHZ_WS_VISIBLE;
        d->w = (int32_t)g_fb.width;
        d->h = (int32_t)g_fb.height;
        win_gen = 1;
        if (!thread_create("gfxd", gfxd_main, 0)) st = STATUS_NO_MEMORY;
        else { gin_init(); wm_ready = 1; }
    }
    mutex_unlock(&wm_init_lock);
    return st;
}

int32_t sys_ext_graphics(process_t *cur, struct regs *r, uint32_t num, uint64_t a1, uint64_t a2, uint64_t a3, uint64_t a4)
{
    int32_t st = wm_init();
    (void)r;
    if (st) return st;
    switch (num) {
    case SYS_NtUserQueryDisplay:
        if (a2 == SHZ_DISP_RECOMPOSE) {
            const shz_rect_t all = { 0, 0, (int32_t)g_fb.width, (int32_t)g_fb.height };
            mutex_lock(&gfx_lock);
            wm_damage(&all);
            mutex_unlock(&gfx_lock);
            a2 = SHZ_DISP_QUERY;
        }
        return gfx_syscall_display(cur, a1, a2);
    case SYS_NtGdiPresent: return gfx_syscall_present(cur, a1);
    case SYS_NtUserClassOp: return sys_classop(cur, a1);
    case SYS_NtUserCreateWindow: return sys_createwindow(cur, a1);
    case SYS_NtUserDestroyWindow: return sys_destroywindow(cur, a1);
    case SYS_NtUserWindowQuery: return sys_wquery(cur, a1);
    case SYS_NtUserWindowSet: return sys_wset(cur, a1);
    case SYS_NtUserShowWindow: return sys_showwindow(cur, a1);
    case SYS_NtUserSetWindowPos: return sys_setwindowpos(cur, a1);
    case SYS_NtUserFocusOp: return sys_focus(cur, a1);
    case SYS_NtUserEnumWindows: return sys_enumwindows(cur, a1);
    case SYS_NtUserHitTest: return sys_hittest(cur, (int64_t)a1, (int64_t)a2, a3);
    case SYS_NtUserAtom: return sys_atom(cur, a1);
    case SYS_NtUserProp: return sys_prop(cur, a1);
    case SYS_NtUserInput: return gfx_syscall_input(cur, a1);
    case SYS_NtUserWindowOp: return sys_winop(cur, a1);
    case SYS_NtUserClipboard: return gfx_syscall_clipboard(cur, a1);
    case SYS_NtUserPostMessage: case SYS_NtUserSendMessage: case SYS_NtUserGetMessage: case SYS_NtUserReplyMessage:
    case SYS_NtUserThreadOp: case SYS_NtUserTimer: case SYS_NtUserInvalidate: case SYS_NtUserPaint:
        return gfx_syscall_msg(cur, num, a1, a2, a3, a4);
    default: return STATUS_INVALID_SYSTEM_SERVICE;
    }
}
