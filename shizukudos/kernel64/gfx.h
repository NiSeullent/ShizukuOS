/* SPDX-License-Identifier: GPL-2.0-only
 * Kernel64 graphics: internal interfaces shared by gfx_fb.c (display), gfx_wm.c (windows, compositor, syscalls) and
 * gfx_msg.c (message queues, timers, paint state). Only the SHZ_STANDALONE profile has a display device; see gfx_fb.c.
 * The design is written down at the top of gfx_wm.c.
 */
#ifndef K64_GFX_H
#define K64_GFX_H
#include "proc_internal.h"
#include "../win64/include/shzgfx.h"

#define STATUS_NO_SUCH_DEVICE ((int32_t)0xC000000E)
#define STATUS_NO_QUOTA ((int32_t)0xC0000044)           /* STATUS_QUOTA_EXCEEDED family: message pool full */
#define STATUS_DEVICE_NOT_READY ((int32_t)0xC00000A3)

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

/* ---- window manager objects ---- */
#define GFX_MAX_WINDOWS 256
#define GFX_MAX_CLASSES 64
#define GFX_MAX_QUEUES 32
#define GFX_MAX_TIMERS 16
#define GFX_MAX_MSGS 2048
#define GFX_MSG_QUOTA 1024                          /* posted messages per queue */
#define GFX_MAX_SENDS 64
#define GFX_MAX_ATOMS 128
#define GFX_ATOM_BASE 0xc000
#define GFX_MAX_PROPS 8
#define GFX_MAX_TITLE 255
#define GFX_MAX_SURF_BYTES (16u << 20)

typedef struct gclass gclass_t;
typedef struct gwin gwin_t;
typedef struct gqueue gqueue_t;

struct gclass {
    int used;
    uint32_t pid;                                   /* registering process; classes are per process */
    uint16_t atom;
    uint32_t name_len;
    uint16_t name[64];
    uint32_t style;
    int32_t cb_cls, cb_wnd;
    uint64_t wndproc, hinstance, hicon, hcursor, hbr, menu, hicon_sm;
    uint8_t *extra;                                 /* cb_cls bytes */
    uint32_t nwin;                                  /* windows of this class */
};

typedef struct { uint64_t key, value; } gprop_t;

struct gwin {
    int used;
    uint32_t gen;
    uint64_t handle;                                /* (gen << 12) | (slot index + 1) */
    gwin_t *parent, *child, *next, *prev;           /* child = topmost child; next = sibling directly below */
    gclass_t *cls;
    uint64_t wndproc;
    uint32_t style, exstyle;
    int32_t x, y, w, h;                             /* window rectangle: parent client coordinates (screen for top-level) */
    int32_t ncl, nct, ncr, ncb;                     /* non-client insets */
    uint32_t *surf;                                 /* client surface, sw*sh dwords 0x00RRGGBB (gfx_pages_alloc) */
    int32_t sw, sh;
    shz_rect_t upd[SHZ_UPD_RECTS];                  /* update region: disjoint rectangles, client coordinates */
    uint32_t nupd;
    int erase;                                      /* background needs erasing at the next BeginPaint */
    gqueue_t *q;                                    /* owning thread's queue */
    uint32_t tid, pid;
    uint64_t id, userdata, hinstance, owner;
    uint16_t *title;
    uint32_t title_len;
    uint8_t *extra;                                 /* cbWndExtra bytes */
    int32_t cb_extra;
    gprop_t props[GFX_MAX_PROPS];
    int destroying;
    int msgonly;                                    /* HWND_MESSAGE window: never visible, only receives messages */
    shz_rect_t restore;                             /* rectangle before maximise/minimise */
    int has_restore;
};

typedef struct gmsg gmsg_t;
struct gmsg { gmsg_t *next; shz_msg_t m; };

enum { GS_QUEUED = 1, GS_SERVICING, GS_DONE, GS_FAILED, GS_ABANDONED };
typedef struct gsend gsend_t;
struct gsend {
    gsend_t *next;                                  /* link in the target's queued or servicing list */
    uint64_t id;                                    /* 0 = free slot */
    uint64_t hwnd;
    uint32_t message;
    uint64_t wparam;
    int64_t lparam;
    gqueue_t *target;
    uint32_t sender_tid;                            /* thread id of the blocked sender */
    int state;
    int64_t result;
};

typedef struct { int used; uint64_t hwnd, id, proc; uint32_t elapse; uint64_t due; } gtimer_t;

struct gqueue {
    int used;
    thread_t *thread;
    uint32_t thread_id;                             /* thread_t.id: never reused, unlike the thread slot */
    process_t *proc;
    uint32_t pid;
    gmsg_t *head, *tail;
    uint32_t nposted;
    gsend_t *sent_head, *sent_tail;                 /* sent by other threads, not yet handed to user mode */
    gsend_t *servicing;                             /* handed to user mode, reply pending (LIFO) */
    int quit;
    int64_t quit_code;
    gtimer_t timers[GFX_MAX_TIMERS];
    uint64_t next_timer_id;
    uint64_t focus, active, capture;
    volatile int in_wait;                           /* blocked inside a GUI wait: only then may thread_wake() be used */
    kobject_t *event;                               /* NtUserThreadOp(QUEUEEVENT): signalled while the queue has something to retrieve */
    uint32_t event_handle;                          /* its handle in the owning process (0 if never handed out) */
};

/* small rectangle helpers */
static inline int rc_empty(const shz_rect_t *r) { return r->right <= r->left || r->bottom <= r->top; }
static inline int rc_isect(const shz_rect_t *a, const shz_rect_t *b, shz_rect_t *o)
{
    o->left = a->left > b->left ? a->left : b->left;
    o->top = a->top > b->top ? a->top : b->top;
    o->right = a->right < b->right ? a->right : b->right;
    o->bottom = a->bottom < b->bottom ? a->bottom : b->bottom;
    return !rc_empty(o);
}
static inline void rc_union(shz_rect_t *a, const shz_rect_t *b)
{
    if (rc_empty(b)) return;
    if (rc_empty(a)) { *a = *b; return; }
    if (b->left < a->left) a->left = b->left;
    if (b->top < a->top) a->top = b->top;
    if (b->right > a->right) a->right = b->right;
    if (b->bottom > a->bottom) a->bottom = b->bottom;
}

/* gfx_wm.c */
extern kmutex_t gfx_lock;                           /* protects every structure in this file set; never held across a sleep */
extern gwin_t g_win[GFX_MAX_WINDOWS];               /* slot 0 is the desktop */
extern gqueue_t *g_fg_q;                            /* queue whose active window is the foreground window */
extern gqueue_t g_queues[GFX_MAX_QUEUES];
gwin_t *wm_lookup(uint64_t handle);                 /* NULL if stale or destroying */
gwin_t *wm_desktop(void);
int wm_is_visible(gwin_t *w);
int wm_screen_rect(gwin_t *w, shz_rect_t *r);       /* visible screen rectangle of the whole window (clipped by ancestors) */
void wm_client_origin(gwin_t *w, int32_t *sx, int32_t *sy);
void wm_damage(const shz_rect_t *screen);           /* recompose + present a screen rectangle */
void wm_damage_window(gwin_t *w);
void wm_destroy_tree(gwin_t *w);                    /* lock held: removes w and all descendants without messages */
int wm_owner_ok(process_t *cur, gwin_t *w);         /* same process */
void wm_invalidate_client(gwin_t *w, int erase);
int wm_is_descendant(gwin_t *anc, gwin_t *w);       /* w is anc or below it */
gwin_t *wm_toplevel(gwin_t *w);
int32_t gfx_syscall_present(process_t *cur, uint64_t arg);

/* gfx_msg.c */
gqueue_t *gq_current(int create);                   /* lock held */
void gq_wake(gqueue_t *q);                          /* lock held */
void gq_purge_window(gwin_t *w);                    /* lock held: drop queued messages/timers for a destroyed window */
void gq_reap_dead(void);                            /* lock held: destroy windows/queues of threads that no longer exist */
int gq_thread_dead(gqueue_t *q);
int32_t gfx_syscall_msg(process_t *cur, uint32_t num, uint64_t a1, uint64_t a2, uint64_t a3, uint64_t a4);
int32_t gq_invalidate(gwin_t *w, const shz_rect_t *rects, uint32_t n, uint32_t flags);
uint32_t gq_time(void);
#endif
