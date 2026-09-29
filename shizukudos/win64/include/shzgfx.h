/* SPDX-License-Identifier: GPL-2.0-only
 * Kernel64 <-> user-mode ABI of the Win32 GUI subsystem (kernel64/gfx_*.c, win64/dlls/user32, win64/dlls/gdi32).
 *
 * This header is included by BOTH the freestanding kernel and the mingw-w64 user-mode DLLs, so it uses only fixed-width
 * integer types. Syscall numbers live in kernel64/ntsys.h (SYSCALL_LIST_GRAPHICS); the user-mode stubs are generated
 * from that list into ntdll as NtUser and NtGdi exports. Every structure here is passed by pointer to a system call
 * (pointers inside structures are user-space virtual addresses carried as uint64_t).
 *
 * The GUI stack needs a display device (QEMU `-vga std`, Bochs VBE). The Supervisor profile has none, so on it every
 * call fails with STATUS_NO_SUCH_DEVICE (0xC000000E) and user-mode programs report that they cannot show a window.
 */
#ifndef SHZ_GFX_ABI_H
#define SHZ_GFX_ABI_H
#include <stdint.h>

/* ---- display ---- */
typedef struct {
    uint32_t size;                      /* sizeof(shz_display_info_t), filled in by the caller */
    uint32_t flags;                     /* bit 0: the framebuffer is live */
    uint32_t width, height, bpp, pitch; /* pitch in bytes; pixels are 0x00RRGGBB dwords */
    uint32_t bga_version;               /* Bochs VBE dispi ID register (0xB0C0..0xB0C5) */
    uint32_t desktop_rgb;               /* solid desktop colour drawn where no window covers the screen (0x00RRGGBB) */
    uint64_t lfb_pa;                    /* guest-physical address of the linear framebuffer (BAR 0) */
} shz_display_info_t;
#define SHZ_DISP_QUERY 0                /* initialise the display on first use, return the info */
#define SHZ_DISP_TESTPATTERN 1          /* draw the kernel test pattern (see gfx_fb.c) and present it, bypassing the compositor */
#define SHZ_DISP_RECOMPOSE 2            /* redraw the whole screen from the window tree (undoes the test pattern) */
#define SHZ_DESKTOP_RGB 0x00008080u

/* ---- geometry / message layouts (identical to the Windows x64 RECT, POINT and MSG) ---- */
typedef struct { int32_t left, top, right, bottom; } shz_rect_t;
typedef struct { int32_t x, y; } shz_point_t;
typedef struct {
    uint64_t hwnd;
    uint32_t message, pad0;
    uint64_t wparam;
    int64_t lparam;
    uint32_t time;
    shz_point_t pt;
    uint32_t pad1;
} shz_msg_t;

/* ---- non-client metrics: ONE definition used by the kernel compositor and by user32 (AdjustWindowRectEx,
 *      GetSystemMetrics). Classic (Windows 2000 style) sizes: sizing frame 4, dialog frame 3, border 1, caption 19,
 *      client edge 2. No menu bar exists in this system, so no menu height is ever added. ---- */
#define SHZ_WS_POPUP 0x80000000u
#define SHZ_WS_CHILD 0x40000000u
#define SHZ_WS_MINIMIZE 0x20000000u
#define SHZ_WS_VISIBLE 0x10000000u
#define SHZ_WS_DISABLED 0x08000000u
#define SHZ_WS_MAXIMIZE 0x01000000u
#define SHZ_WS_CAPTION 0x00c00000u
#define SHZ_WS_BORDER 0x00800000u
#define SHZ_WS_DLGFRAME 0x00400000u
#define SHZ_WS_THICKFRAME 0x00040000u
#define SHZ_WS_EX_DLGMODALFRAME 0x00000001u
#define SHZ_WS_EX_TOPMOST 0x00000008u
#define SHZ_WS_EX_CLIENTEDGE 0x00000200u
#define SHZ_WS_EX_TOOLWINDOW 0x00000080u
#define SHZ_WS_EX_NOACTIVATE 0x08000000u
#define SHZ_CAPTION_H 19
static inline void shz_nc_insets(uint32_t style, uint32_t exstyle, int32_t *l, int32_t *t, int32_t *r, int32_t *b)
{
    int32_t frame = 0, cap = 0, edge = (exstyle & SHZ_WS_EX_CLIENTEDGE) ? 2 : 0;
    if (style & SHZ_WS_THICKFRAME) frame = 4;
    else if ((style & SHZ_WS_DLGFRAME) || (exstyle & SHZ_WS_EX_DLGMODALFRAME)) frame = 3;
    else if (style & SHZ_WS_BORDER) frame = 1;
    if ((style & SHZ_WS_CAPTION) == SHZ_WS_CAPTION) cap = SHZ_CAPTION_H;
    *l = *r = *b = frame + edge;
    *t = frame + cap + edge;
}

/* ---- callback record: the kernel never calls a window procedure. A thread inside GetMessage/PeekMessage/SendMessage
 *      that has to service a message sent to one of its windows gets one of these back and runs the procedure itself in
 *      user mode (user32), then reports the result with NtUserReplyMessage(id, result). ---- */
typedef struct {
    uint64_t id;                        /* request id for NtUserReplyMessage */
    uint64_t hwnd;
    uint32_t message, pad;
    uint64_t wparam;
    int64_t lparam;
    uint64_t wndproc;                   /* window procedure to call (user address) */
} shz_callback_t;

/* ---- classes: NtUserClassOp ---- */
#define SHZ_CLASS_REGISTER 1            /* name/name_len + fields below -> atom */
#define SHZ_CLASS_UNREGISTER 2          /* name or atom, hinstance */
#define SHZ_CLASS_LOOKUP 3              /* name or atom, hinstance -> all fields (GetClassInfo) */
#define SHZ_CLASS_GETLONG 4             /* hwnd + index (a GCL_ or GCLP_ constant, or >= 0 for extra bytes) -> value */
#define SHZ_CLASS_SETLONG 5             /* hwnd + index + value -> previous value */
#define SHZ_CLASS_GETNAME 6             /* hwnd -> name in buf, name_len */
typedef struct {
    uint32_t op, flags;
    uint64_t hwnd;
    uint64_t name;                      /* UTF-16, not NUL terminated */
    uint32_t name_len;                  /* UTF-16 units */
    uint32_t atom;                      /* in: atom when name == 0; out: registered/found atom */
    uint32_t style;
    int32_t cb_cls, cb_wnd;
    uint32_t pad;
    uint64_t wndproc, hinstance, hicon, hcursor, hbrbackground, menu_name, hicon_sm;
    int64_t index;
    uint64_t value;
    uint64_t buf;                       /* GETNAME: output buffer (UTF-16) */
    uint32_t buf_len;                   /* capacity in units; out: units written */
    uint32_t pad2;
} shz_classop_t;

/* ---- windows: NtUserCreateWindow ---- */
typedef struct {
    uint64_t class_name;                /* UTF-16, or 0 to use class_atom */
    uint32_t class_name_len, class_atom;
    uint64_t title;
    uint32_t title_len, pad;
    uint32_t style, exstyle;
    int32_t x, y, w, h;
    uint64_t parent, id, hinstance, param;
    uint64_t hwnd_out;
    uint64_t wndproc_out;               /* the class window procedure the window starts with */
} shz_createdef_t;

/* NtUserWindowQuery / NtUserWindowSet */
typedef struct {
    uint64_t hwnd;
    uint32_t what;
    int32_t index;
    uint64_t v0, v1;                    /* query: results; set: v0 = new value, v1 = previous value */
    shz_rect_t rect;
    uint64_t buf;
    uint32_t buf_len;
    uint32_t pad;
} shz_wnd_t;
enum {
    SHZ_WQ_EXISTS = 1, SHZ_WQ_RECT, SHZ_WQ_CLIENT, SHZ_WQ_CLIENT_ORG, SHZ_WQ_STYLE, SHZ_WQ_EXSTYLE, SHZ_WQ_ID,
    SHZ_WQ_USERDATA, SHZ_WQ_WNDPROC, SHZ_WQ_HINSTANCE, SHZ_WQ_PARENT, SHZ_WQ_OWNER, SHZ_WQ_THREAD, SHZ_WQ_TEXT,
    SHZ_WQ_CLASSNAME, SHZ_WQ_CLASS_ATOM, SHZ_WQ_VISIBLE, SHZ_WQ_ENABLED, SHZ_WQ_EXTRA, SHZ_WQ_GW, SHZ_WQ_ANCESTOR,
    SHZ_WQ_ISCHILD, SHZ_WQ_POS, SHZ_WQ_DESKTOP, SHZ_WQ_RESTORE
};
enum {
    SHZ_WS_SET_STYLE = 1, SHZ_WS_SET_EXSTYLE, SHZ_WS_SET_ID, SHZ_WS_SET_USERDATA, SHZ_WS_SET_WNDPROC,
    SHZ_WS_SET_HINSTANCE, SHZ_WS_SET_EXTRA, SHZ_WS_SET_TEXT, SHZ_WS_SET_PARENT, SHZ_WS_SET_ENABLED, SHZ_WS_SET_OWNER
};

/* NtUserSetWindowPos (SWP_* values are the Windows ones) */
typedef struct {
    uint64_t hwnd, insert_after;        /* insert_after: 0 top, 1 bottom, -1 topmost, -2 no-topmost, or a sibling hwnd */
    int32_t x, y, cx, cy;
    uint32_t flags, pad;
    uint32_t changed;                   /* out: SHZ_POS_MOVED | SHZ_POS_SIZED | SHZ_POS_ZORDER | SHZ_POS_SHOWN | HIDDEN */
    uint32_t pad2;
    shz_rect_t new_rect;                /* out: window rect in parent coordinates */
    uint64_t prev_active;               /* out: window that lost activation (0 if none) */
} shz_setpos_t;
#define SHZ_POS_MOVED 1u
#define SHZ_POS_SIZED 2u
#define SHZ_POS_ZORDER 4u
#define SHZ_POS_SHOWN 8u
#define SHZ_POS_HIDDEN 0x10u

/* NtUserShowWindow */
typedef struct {
    uint64_t hwnd;
    uint32_t cmd, flags;
    uint32_t was_visible, activated;    /* out */
    uint64_t prev_active;               /* out */
} shz_show_t;

/* ---- messages ---- */
#define SHZ_GM_WAIT 0x80000000u         /* NtUserGetMessage flag (above the PM_QS_* bits 16..26): block until something can be returned */
#define SHZ_GM_RES_NONE 0
#define SHZ_GM_RES_MESSAGE 1
#define SHZ_GM_RES_CALLBACK 2
typedef struct {
    uint64_t hwnd;                      /* filter (0 = any window of the thread plus thread messages) */
    uint32_t min, max;
    uint32_t flags;                     /* PM_REMOVE (1) | PM_QS_* | SHZ_GM_WAIT */
    uint32_t result;                    /* out: SHZ_GM_RES_* */
    shz_msg_t msg;                      /* out */
    shz_callback_t cb;                  /* out */
} shz_getmsg_t;

typedef struct {
    uint64_t id;                        /* 0 = new request; else continue waiting for that request after servicing a callback */
    uint64_t hwnd;
    uint32_t message, flags;
    uint64_t wparam;
    int64_t lparam;
    uint32_t timeout_ms;                /* 0 = wait forever */
    uint32_t result_kind;               /* out: see SHZ_SEND_* */
    int64_t result;                     /* out: the window procedure's result */
    uint64_t wndproc;                   /* out (SHZ_SEND_SAME_THREAD): call this procedure yourself */
    shz_callback_t cb;                  /* out (SHZ_SEND_CALLBACK): service this, then call again with id set */
} shz_send_t;
#define SHZ_SEND_DONE 0
#define SHZ_SEND_SAME_THREAD 1          /* the window belongs to the calling thread: run the procedure in user mode */
#define SHZ_SEND_CALLBACK 2
#define SHZ_SEND_TIMEOUT 3
#define SHZ_SEND_FAILED 4               /* target thread died */

/* NtUserThreadOp */
enum { SHZ_TOP_POSTQUIT = 1, SHZ_TOP_POSTTHREAD, SHZ_TOP_QUEUESTATUS, SHZ_TOP_INSEND, SHZ_TOP_ATTACHINFO };
typedef struct {
    uint32_t op, pad;
    uint64_t a, b, c, d;
    uint64_t out0, out1;
} shz_threadop_t;

/* NtUserTimer */
enum { SHZ_TIMER_SET = 1, SHZ_TIMER_KILL };
typedef struct {
    uint32_t op, elapse;
    uint64_t hwnd, id, proc;
    uint64_t out_id;
} shz_timer_t;

/* NtUserInvalidate: flags */
#define SHZ_INV_VALIDATE 1u             /* remove instead of add */
#define SHZ_INV_ERASE 2u
#define SHZ_INV_CHILDREN 4u
typedef struct {
    uint64_t hwnd;
    uint32_t flags, nrects;             /* nrects == 0: the whole client area */
    uint64_t rects;                     /* user pointer to shz_rect_t[nrects], client coordinates */
} shz_inval_t;

/* NtUserPaint */
enum { SHZ_PAINT_BEGIN = 1, SHZ_PAINT_GETUPDATE };
#define SHZ_UPD_RECTS 8
typedef struct {
    uint32_t op, erase;                 /* erase: out */
    uint64_t hwnd;
    uint32_t nrects, pad;               /* out */
    shz_rect_t bbox;                    /* out */
    shz_rect_t rects[SHZ_UPD_RECTS];    /* out: the update region as disjoint rectangles */
} shz_paint_t;

/* NtGdiPresent: copy a rectangle of a user-mode window bitmap (32 bpp 0x00RRGGBB, top-down) into the window surface */
typedef struct {
    uint64_t hwnd;
    int32_t x, y, w, h;                 /* client coordinates */
    uint64_t bits;                      /* user address of pixel (0,0) of the source bitmap */
    uint32_t stride;                    /* bytes */
    int32_t surf_w, surf_h;             /* the caller's idea of the client size; must match the kernel's */
} shz_present_t;

/* NtUserFocusOp */
enum {
    SHZ_FOCUS_GETFOCUS = 1, SHZ_FOCUS_SETFOCUS, SHZ_FOCUS_GETACTIVE, SHZ_FOCUS_SETACTIVE, SHZ_FOCUS_GETFOREGROUND,
    SHZ_FOCUS_SETFOREGROUND, SHZ_FOCUS_GETCAPTURE, SHZ_FOCUS_SETCAPTURE
};
typedef struct {
    uint32_t op, pad;
    uint64_t hwnd;
    uint64_t result;                    /* out: window handle (previous or current, by op) */
    uint64_t result2;                   /* out */
} shz_focus_t;

/* NtUserEnumWindows */
#define SHZ_ENUM_THREAD 1u              /* only windows of thread `tid` */
#define SHZ_ENUM_RECURSE 2u             /* all descendants (EnumChildWindows) instead of direct children */
typedef struct {
    uint64_t parent;                    /* 0: the desktop (top-level windows) */
    uint32_t flags, tid;
    uint64_t out, max;                  /* user array of uint64_t hwnd, capacity */
    uint64_t count;                     /* out */
} shz_enum_t;

/* NtUserAtom, NtUserProp */
typedef struct { uint32_t op, atom; uint64_t name; uint32_t name_len, pad; } shz_atom_t;
#define SHZ_ATOM_ADD 1
#define SHZ_ATOM_FIND 2
enum { SHZ_PROP_SET = 1, SHZ_PROP_GET, SHZ_PROP_REMOVE };
typedef struct { uint32_t op, pad; uint64_t hwnd, key, value; } shz_prop_t;

#ifdef _WIN32
/* User-mode side: the ntdll stubs generated from SYSCALL_LIST_GRAPHICS. Status is an NTSTATUS (negative = failure). */
#define SHZ_NT __stdcall
int32_t SHZ_NT NtUserQueryDisplay(void *info_out, uint64_t op);
int32_t SHZ_NT NtUserClassOp(void *op);
int32_t SHZ_NT NtUserCreateWindow(void *def);
int32_t SHZ_NT NtUserDestroyWindow(uint64_t hwnd);
int32_t SHZ_NT NtUserWindowQuery(void *q);
int32_t SHZ_NT NtUserWindowSet(void *s);
int32_t SHZ_NT NtUserShowWindow(void *s);
int32_t SHZ_NT NtUserSetWindowPos(void *s);
int32_t SHZ_NT NtUserPostMessage(uint64_t hwnd, uint64_t msg, uint64_t wparam, uint64_t lparam);
int32_t SHZ_NT NtUserSendMessage(void *s);
int32_t SHZ_NT NtUserGetMessage(void *g);
int32_t SHZ_NT NtUserReplyMessage(uint64_t id, uint64_t result);
int32_t SHZ_NT NtUserThreadOp(void *t);
int32_t SHZ_NT NtUserTimer(void *t);
int32_t SHZ_NT NtUserInvalidate(void *i);
int32_t SHZ_NT NtUserPaint(void *p);
int32_t SHZ_NT NtGdiPresent(void *p);
int32_t SHZ_NT NtUserFocusOp(void *f);
int32_t SHZ_NT NtUserEnumWindows(void *e);
int32_t SHZ_NT NtUserHitTest(int64_t x, int64_t y, void *hwnd_out);
int32_t SHZ_NT NtUserAtom(void *a);
int32_t SHZ_NT NtUserProp(void *p);
#endif

#endif
