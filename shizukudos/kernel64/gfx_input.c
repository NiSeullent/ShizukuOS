/* SPDX-License-Identifier: GPL-2.0-only
 * Kernel64 GUI input (standalone profile only, like the rest of the GUI; design notes at the top of gfx_wm.c): the i8042
 * PS/2 controller with its keyboard (IRQ 1) and mouse (IRQ 12), the system input state, the routing of keyboard and mouse
 * events into the per-thread GUI queues (gfx_msg.c) and the pointer sprite drawn over the composed screen.
 *
 *  Hardware.  gin_init (run when the window manager starts, i.e. at the first GUI system call; nothing reads input before)
 *             programs the i8042: both ports on, scan-code translation on (the keyboard then delivers scan code set 1),
 *             the mouse switched to the IntelliMouse wheel protocol when it accepts it, data reporting on. The interrupt
 *             handler only moves bytes into a ring; the kernel thread "gfxin" decodes them under gfx_lock. SendInput and
 *             SetCursorPos enter the same decoding/routing path from a system call.
 *  Keyboard.  Set 1 scan codes (E0/E1 prefixes) become virtual keys of the US layout (the numeric keypad by NumLock and
 *             Shift). The asynchronous key state (GetAsyncKeyState) changes at once. WM_KEYDOWN/WM_KEYUP (WM_SYSKEY* while
 *             Alt is down without Ctrl, and for F10) with the Windows lParam layout go to the focus window of the
 *             foreground thread, or as WM_SYSKEY* to its active window when nothing has the focus; without a foreground
 *             thread they are dropped. A thread's own key state (GetKeyState) follows the input messages it removes from
 *             its queue, as on Windows. A registered hot key becomes WM_HOTKEY instead of key messages.
 *  Mouse.     Relative packets move the pointer 1:1 (no acceleration), clipped to the screen and to ClipCursor. The target
 *             is the capture window of the foreground thread (or of any thread while a button is held), else the window
 *             under the pointer: disabled child windows are skipped, windows with WS_EX_LAYERED|WS_EX_TRANSPARENT are
 *             click-through, a disabled top-level window receives nothing. Consecutive moves to the same window are
 *             coalesced into one WM_MOUSEMOVE. The wheel goes to the focus window of the foreground thread.
 *  Pointer.   Drawn by the compositor on top of everything, but only once a pointing event happened (mouse hardware,
 *             SendInput or SetCursorPos): until then the screen shows no pointer. The image is the cursor last set with
 *             SetCursor (user32 does it for WM_SETCURSOR) by the thread that owns the window under the pointer (or the
 *             capture window), the built-in arrow over the desktop, nothing while that thread's ShowCursor count is
 *             negative. Images are at most 32x32 (user32 scales larger ones).
 *  Not implemented: keyboard LEDs and typematic settings, layouts other than US, IME, the horizontal wheel on PS/2
 *  hardware (SendInput can inject WM_MOUSEHWHEEL), extra mouse buttons on PS/2 hardware, touch and pen, low-level hooks.
 */
#include "gfx.h"
#include "gfx_auth.h"
#include "../dead_screen/native.h"
#include "pci.h"
#include "laptop_input_native.h"
#include "../win64/include/shzpointer.h"
#include "../win64/include/shzkbd.h"

#define WM_KEYDOWN 0x0100u
#define WM_KEYUP 0x0101u
#define WM_SYSKEYDOWN 0x0104u
#define WM_SYSKEYUP 0x0105u
#define WM_HOTKEY 0x0312u
#define WM_MOUSEMOVE 0x0200u
#define WM_LBUTTONDOWN 0x0201u
#define WM_LBUTTONUP 0x0202u
#define WM_RBUTTONDOWN 0x0204u
#define WM_RBUTTONUP 0x0205u
#define WM_MBUTTONDOWN 0x0207u
#define WM_MBUTTONUP 0x0208u
#define WM_MOUSEWHEEL 0x020Au
#define WM_XBUTTONDOWN 0x020Bu
#define WM_XBUTTONUP 0x020Cu
#define WM_MOUSEHWHEEL 0x020Eu
#define WM_NCMOUSEHOVER 0x02A0u
#define WM_MOUSEHOVER 0x02A1u
#define WM_NCMOUSELEAVE 0x02A2u
#define WM_MOUSELEAVE 0x02A3u
#define MK_LBUTTON 0x01u
#define MK_RBUTTON 0x02u
#define MK_SHIFT 0x04u
#define MK_CONTROL 0x08u
#define MK_MBUTTON 0x10u
#define MK_XBUTTON1 0x20u
#define MK_XBUTTON2 0x40u
#define VK_LBUTTON 0x01
#define VK_RBUTTON 0x02
#define VK_MBUTTON 0x04
#define VK_XBUTTON1 0x05
#define VK_XBUTTON2 0x06
#define VK_SHIFT 0x10
#define VK_CONTROL 0x11
#define VK_MENU 0x12
#define VK_PAUSE 0x13
#define VK_CAPITAL 0x14
#define VK_F10 0x79
#define VK_NUMLOCK 0x90
#define VK_LSHIFT 0xA0
#define VK_RSHIFT 0xA1
#define VK_LCONTROL 0xA2
#define VK_RCONTROL 0xA3
#define VK_LMENU 0xA4
#define VK_RMENU 0xA5
#define VK_LWIN 0x5B
#define VK_RWIN 0x5C
#define VK_PACKET 0xE7
#define TME_HOVER 0x00000001u
#define TME_LEAVE 0x00000002u
#define TME_NONCLIENT 0x00000010u
#define TME_QUERY 0x40000000u
#define TME_CANCEL 0x80000000u
#define HOVER_DEFAULT 0xFFFFFFFFu
#define MOD_ALT 1u
#define MOD_CONTROL 2u
#define MOD_SHIFT 4u
#define MOD_WIN 8u
#define MOD_NOREPEAT 0x4000u
#define WS_EX_TRANSPARENT 0x00000020u
#define WS_EX_LAYERED 0x00080000u
#define STATUS_HOTKEY_TAKEN ((int32_t)0xC0000235)            /* mapped by user32 to ERROR_HOTKEY_ALREADY_REGISTERED */

#define WM_INPUT_ 0x00FFu
#define RIDEV_REMOVE_ 0x00000001u
#define RIDEV_NOLEGACY_ 0x00000030u
#define RIDEV_INPUTSINK_ 0x00000100u
#define RIDEV_EXINPUTSINK_ 0x00001000u
#define RI_KEY_BREAK_ 1u
#define RI_KEY_E0_ 2u
#define RI_KEY_E1_ 4u

int32_t g_ptr_x, g_ptr_y;
static int ptr_live;                                        /* a pointing event happened: the sprite is drawn */
static uint8_t g_async[256], g_pressed[256];
static uint32_t g_buttons;                                  /* MK_ button bits physically down */
static shz_rect_t g_clip;
static int g_clip_on;
static uint64_t g_last_input_ms;
static uint32_t g_info;

/* ---------------------------------------------------------------- pointer image cache */
#define GIN_CURSORS 16
typedef struct { int used; uint32_t pid; uint64_t cookie; int w, h, hx, hy; uint32_t ver; uint32_t px[32 * 32]; } gcur_t;
static gcur_t *g_curs;                                      /* [GIN_CURSORS] (gin_tables_init); slot 0: the built-in arrow (cookie 1) */
static int sh_idx = -1, sh_vis;
static uint32_t sh_ver;
static uint64_t sh_cookie = 1;                              /* cookie of the cursor of the pointer's owner (0: SetCursor(NULL)) */
static shz_rect_t sh_rect;

static uint64_t now_ms(void) { return shz_time_ns() / 1000000ull; }    /* the GetTickCount clock */
static void note_input(void) { g_last_input_ms = now_ms(); }

/* ---------------------------------------------------------------- i8042 (polling during setup, IRQ afterwards) */
#ifdef SHZ_STANDALONE
static int mpkt_len = 3;                                    /* 4 with the wheel protocol */
#define I8042_DATA 0x60
#define I8042_STAT 0x64
#define RING 1024
static volatile uint16_t ring[RING];                        /* bit 8: byte came from the mouse port */
static volatile uint32_t ring_head, ring_tail, ring_drops;
static thread_t *gin_thread;
static volatile int gin_waiting;

static int wait_write(void)
{
    unsigned i;
    for (i = 0; i < 200000; ++i) if (!(k_inb(I8042_STAT) & 2)) return 1;
    return 0;
}
static void ctl_cmd(uint8_t c) { if (wait_write()) k_outb(I8042_STAT, c); }
static void dat_write(uint8_t v) { if (wait_write()) k_outb(I8042_DATA, v); }
/* Reads the next byte from the wanted port (aux = mouse), dropping bytes from the other one. -1 on timeout. */
static int dat_read(int aux)
{
    unsigned i;
    for (i = 0; i < 200000; ++i) {
        const uint8_t st = k_inb(I8042_STAT);
        if (!(st & 1)) continue;
        {
            const uint8_t v = k_inb(I8042_DATA);
            if (aux < 0 || ((st & 0x20) != 0) == aux) return v;
        }
    }
    return -1;
}
static int aux_send(uint8_t v)                              /* one byte to the mouse, returns its answer (0xFA = ACK) */
{
    ctl_cmd(0xD4);
    dat_write(v);
    return dat_read(1);
}

static void i8042_irq(struct regs *r)
{
    uint8_t st;
    (void)r;
    while ((st = k_inb(I8042_STAT)) & 1) {
        const uint8_t v = k_inb(I8042_DATA);
        const uint32_t h = ring_head;
        if (h - ring_tail < RING) { ring[h % RING] = (uint16_t)(v | ((st & 0x20) ? 0x100u : 0u)); ring_head = h + 1; }
        else ++ring_drops;
    }
    if (gin_waiting && gin_thread && gin_thread->state == TS_BLOCKED) thread_wake(gin_thread);
}

static void kbd_byte(uint8_t b);
static void mouse_byte(uint8_t b);

static void gin_main(void *arg)
{
    (void)arg;
    for (;;) {
        const uint64_t f = irq_save();
        while (ring_tail == ring_head) {                    /* interrupts off: the IRQ cannot slip in between */
            gin_waiting = 1;
            thread_block_current();
            gin_waiting = 0;
        }
        irq_restore(f);
        mutex_lock(&gfx_lock);
        while (ring_tail != ring_head) {
            const uint16_t v = ring[ring_tail % RING];
            ++ring_tail;
            if (v & 0x100) mouse_byte((uint8_t)v); else kbd_byte((uint8_t)v);
        }
        mutex_unlock(&gfx_lock);
    }
}

static void arrow_init(void)
{
    gcur_t *c = &g_curs[0];
    int x, y;
    memset(c, 0, sizeof *c);
    c->used = 1;
    c->cookie = 1;
    c->w = SHZ_ARROW_W;
    c->h = SHZ_ARROW_H;
    for (y = 0; y < SHZ_ARROW_H; ++y)
        for (x = 0; x < SHZ_ARROW_W; ++x) {
            const char ch = shz_arrow_art[y][x];
            c->px[y * c->w + x] = ch == 'X' ? 0xff000000u : ch == '.' ? 0xffffffffu : 0;
        }
}
#endif

#ifdef SHZ_STANDALONE
/* PS/2 Synaptics transport for laptop_input_native.c (the i8042 aux port). Elapsed-time bounded; IRQ 12 must still be masked
 * (before the final 0x60 write of gin_init) so no other reader steals the replies. */
static int ps2_wait(uint8_t mask, int want, uint32_t us)
{
    const uint64_t end = shz_time_ns() + (uint64_t)us * 1000u;
    for (;;) {
        if (((k_inb(I8042_STAT) & mask) != 0) == want) return 0;
        if (shz_time_ns() >= end) return -1;
    }
}
static int ps2_write_aux(void *c, uint8_t v, uint32_t us)
{
    (void)c;
    if (ps2_wait(2, 0, us)) return -1;
    k_outb(I8042_STAT, 0xD4);
    if (ps2_wait(2, 0, us)) return -1;
    k_outb(I8042_DATA, v);
    return 0;
}
static int ps2_read_aux(void *c, uint8_t *b, uint32_t us)
{
    const uint64_t end = shz_time_ns() + (uint64_t)us * 1000u;
    (void)c;
    for (;;) {
        const uint8_t st = k_inb(I8042_STAT);
        if (st & 1) {
            const uint8_t v = k_inb(I8042_DATA);
            if (st & 0x20) { *b = v; return 0; }            /* keyboard bytes are dropped, as in dat_read(1) */
        } else if (shz_time_ns() >= end) return -1;
    }
}
static int ps2_drain(void *c, uint32_t us)
{
    const uint64_t end = shz_time_ns() + (uint64_t)us * 1000u;
    (void)c;
    while (k_inb(I8042_STAT) & 1) { (void)k_inb(I8042_DATA); if (shz_time_ns() >= end) return -1; }
    return 0;
}
/* NOT called by gin_init (the i8042 bring-up belongs to the core integrator). Contract: call once after the aux "F6 defaults"
 * ACK and BEFORE the IntelliMouse knock, with IRQ 12 still masked. Returns 0: Synaptics absolute mode is active and
 * mouse_byte routes aux bytes to it (skip the knock; mpkt_len stays 3). Otherwise (>0 not Synaptics, <0 error) the standard
 * relative path is untouched: resend aux_send(0xF6) (and F4 after the knock) because the probe left the device streaming. */
int gin_ps2_touchpad_probe(void)
{
    static const struct k64_lin_ps2_transport t = { 0, ps2_write_aux, ps2_read_aux, ps2_drain };
    return k64_laptop_ps2_open(&t);
}
#endif

void gin_init(void)
{
#ifdef SHZ_STANDALONE
    int cfg, id;
    g_ptr_x = (int32_t)g_fb.width / 2;
    g_ptr_y = (int32_t)g_fb.height / 2;
    arrow_init();
    k64_laptop_input_init();                                /* USB HID pointer thread (xHCI); independent of the i8042 */
    ctl_cmd(0xAD);                                          /* keyboard port off */
    ctl_cmd(0xA7);                                          /* mouse port off */
    while (k_inb(I8042_STAT) & 1) (void)k_inb(I8042_DATA);
    ctl_cmd(0x20);
    cfg = dat_read(-1);
    if (cfg < 0) { kprintf("K64 gfx: no i8042 controller answered: no keyboard or mouse input\n"); return; }
    cfg = (cfg & ~0x33) | 0x44;                             /* IRQs off during setup, both clocks on, translation on */
    ctl_cmd(0x60);
    dat_write((uint8_t)cfg);
    ctl_cmd(0xAE);
    ctl_cmd(0xA8);
    dat_write(0xF4);                                        /* keyboard: enable scanning */
    if (dat_read(0) == 0xFA) g_info |= SHZ_INFO_KEYBOARD;
    ds_native_keyboard_ready((g_info & SHZ_INFO_KEYBOARD) != 0);
    if (aux_send(0xF6) == 0xFA) {                           /* mouse: defaults */
        /* shz.touchpad=synaptics (explicit opt-in; default PS/2 path byte-identical): IRQ 12 is still masked here.
         * 0 = Synaptics absolute mode active (probe already sent F4; mouse_byte feeds k64_laptop_ps2_feed, no knock);
         * >0 standard mouse / <0 error: F6 defaults again, then the unchanged relative path. */
        const int tp = k64_cmdline_has("shz.touchpad=synaptics") ? gin_ps2_touchpad_probe() : 1;
        g_info |= SHZ_INFO_MOUSE;
        if (tp != 0) {
        if (k64_cmdline_has("shz.touchpad=synaptics")) aux_send(0xF6);
        aux_send(0xF3); aux_send(200);                      /* the IntelliMouse knock: sample rates 200, 100, 80 */
        aux_send(0xF3); aux_send(100);
        aux_send(0xF3); aux_send(80);
        if (aux_send(0xF2) == 0xFA) {
            id = dat_read(1);
            if (id == 3 || id == 4) { g_info |= SHZ_INFO_WHEEL; mpkt_len = 4; }
        }
        aux_send(0xF3); aux_send(100);                      /* back to a normal sample rate */
        aux_send(0xF4);                                     /* data reporting on */
        }
        kprintf("K64 gfx: PS/2 aux route %s (probe=%d)\n", tp == 0 ? "synaptics-absolute" : "relative", tp);
    }
    while (k_inb(I8042_STAT) & 1) (void)k_inb(I8042_DATA);
    ctl_cmd(0x60);
    dat_write((uint8_t)(cfg | 0x03));                       /* IRQ 1 and IRQ 12 on */
    gin_thread = thread_create("gfxin", gin_main, 0);
    if (!gin_thread) { kprintf("K64 gfx: cannot start the input thread\n"); return; }
    irq_register(standalone_irq_vector(1), i8042_irq);
    irq_register(standalone_irq_vector(12), i8042_irq);
    standalone_irq_unmask(1);
    standalone_irq_unmask(12);
    kprintf("K64 gfx: i8042 keyboard=%d mouse=%d wheel=%d\n", (g_info & SHZ_INFO_KEYBOARD) != 0, (g_info & SHZ_INFO_MOUSE) != 0,
            (g_info & SHZ_INFO_WHEEL) != 0);
#endif
}

/* ---------------------------------------------------------------- key state */
static int is_down(int vk) { return (g_async[vk & 0xff] & 0x80) != 0; }

static uint8_t generic_vk(uint8_t vk)
{
    if (vk == VK_LSHIFT || vk == VK_RSHIFT) return VK_SHIFT;
    if (vk == VK_LCONTROL || vk == VK_RCONTROL) return VK_CONTROL;
    if (vk == VK_LMENU || vk == VK_RMENU) return VK_MENU;
    return vk;
}

/* One key of a 256-byte state array goes down/up; the generic Shift/Ctrl/Alt entry follows its two sides. */
static void state_key(uint8_t *st, uint8_t vk, int down)
{
    const uint8_t gen = generic_vk(vk);
    if (down && !(st[vk] & 0x80)) st[vk] ^= 1;
    st[vk] = (uint8_t)((st[vk] & 1) | (down ? 0x80 : 0));
    if (gen != vk) {
        const int any = (st[gen == VK_SHIFT ? VK_LSHIFT : gen == VK_CONTROL ? VK_LCONTROL : VK_LMENU] |
                         st[gen == VK_SHIFT ? VK_RSHIFT : gen == VK_CONTROL ? VK_RCONTROL : VK_RMENU]) & 0x80;
        if (any && !(st[gen] & 0x80)) st[gen] ^= 1;
        st[gen] = (uint8_t)((st[gen] & 1) | any);
    }
}

void gin_queue_init(gqueue_t *q)
{
    unsigned i;
    int allowed=!g_fg_q || gfx_auth_queue(q->proc,g_fg_q);
    for (i = 0; i < 256; ++i) q->keys[i] = allowed?g_async[i]:0;
    q->cursor = 0;
}

/* The specific (left/right) key of a key message, from its scan code and extended bit. */
static uint8_t specific_vk(uint8_t vk, uint32_t lparam)
{
    const unsigned scan = (lparam >> 16) & 0xff, ext = (lparam >> 24) & 1;
    if (vk == VK_SHIFT) return scan == 0x36 ? VK_RSHIFT : VK_LSHIFT;
    if (vk == VK_CONTROL) return ext ? VK_RCONTROL : VK_LCONTROL;
    if (vk == VK_MENU) return ext ? VK_RMENU : VK_LMENU;
    return vk;
}

void gin_message_removed(gqueue_t *q, const shz_msg_t *m)
{
    if (!(m->pad0 & SHZ_MSGF_INPUT)) return;
    switch (m->message) {
    case WM_KEYDOWN: case WM_SYSKEYDOWN: case WM_KEYUP: case WM_SYSKEYUP: {
        const uint8_t vk = (uint8_t)m->wparam;
        if (vk == VK_PACKET) return;
        state_key(q->keys, specific_vk(vk, (uint32_t)m->lparam), m->message == WM_KEYDOWN || m->message == WM_SYSKEYDOWN);
        return;
    }
    case WM_LBUTTONDOWN: case WM_LBUTTONUP: state_key(q->keys, VK_LBUTTON, m->message == WM_LBUTTONDOWN); return;
    case WM_RBUTTONDOWN: case WM_RBUTTONUP: state_key(q->keys, VK_RBUTTON, m->message == WM_RBUTTONDOWN); return;
    case WM_MBUTTONDOWN: case WM_MBUTTONUP: state_key(q->keys, VK_MBUTTON, m->message == WM_MBUTTONDOWN); return;
    case WM_XBUTTONDOWN: case WM_XBUTTONUP:
        state_key(q->keys, ((m->wparam >> 16) & 0xffff) == 2 ? VK_XBUTTON2 : VK_XBUTTON1, m->message == WM_XBUTTONDOWN);
        return;
    default: return;
    }
}

/* ---------------------------------------------------------------- hot keys */
#define GIN_HOTKEYS 32
typedef struct { int used; uint32_t thread_id; uint64_t hwnd; int64_t id; uint32_t mods; uint8_t vk; } ghotkey_t;
static ghotkey_t g_hot[GIN_HOTKEYS];

static uint32_t current_mods(void)
{
    return (is_down(VK_MENU) ? MOD_ALT : 0) | (is_down(VK_CONTROL) ? MOD_CONTROL : 0) | (is_down(VK_SHIFT) ? MOD_SHIFT : 0) |
           ((is_down(VK_LWIN) || is_down(VK_RWIN)) ? MOD_WIN : 0);
}

static int hotkey_fire(uint8_t vk, int repeat)
{
    unsigned i;
    const uint32_t mods = current_mods();
    for (i = 0; i < GIN_HOTKEYS; ++i) {
        ghotkey_t *h = &g_hot[i];
        gqueue_t *q = 0;
        unsigned k;
        if (!h->used || h->vk != vk || (h->mods & 0xf) != mods) continue;
        for (k = 0; k < GFX_MAX_QUEUES; ++k)
            if (g_queues[k].used && g_queues[k].thread_id == h->thread_id) q = &g_queues[k];
        if(!q || !g_fg_q || !gfx_auth_queue(q->proc,g_fg_q) || !gfx_auth_queue(q->proc,q))continue;
        if (repeat && (h->mods & MOD_NOREPEAT)) return 1;
        gq_post(q, h->hwnd, WM_HOTKEY, (uint64_t)h->id, (int64_t)(mods | ((uint32_t)vk << 16)));
        return 1;
    }
    return 0;
}

/* ---------------------------------------------------------------- raw input (RegisterRawInputDevices) */
/* Registrations are per process (as on Windows) for the keyboard and the mouse; every event produces one record in a
 * ring and a WM_INPUT(RIM_INPUT / RIM_INPUTSINK, HRAWINPUT) posted to the registered target window, or to the focus
 * window of the process when no target was given and it owns the foreground. RIDEV_NOLEGACY suppresses the ordinary
 * key/mouse messages for the foreground process. Records are kept until GIN_RAWRING newer ones overwrite them. */
#define GIN_RAWREG 32
#define GIN_RAWRING 256
typedef struct { int used; uint32_t pid, dev, flags; uint64_t target; } grawreg_t;
static grawreg_t g_rawreg[GIN_RAWREG];
static shz_rawrec_t *g_raw;                                 /* [GIN_RAWRING] (gin_tables_init) */
static uint32_t g_raw_ids[GIN_RAWRING];
static gqueue_t *g_raw_owner[GIN_RAWRING];
static uint32_t g_raw_thread[GIN_RAWRING];
static uint32_t g_raw_next = 1;
static int g_injecting;                                     /* inside SendInput: raw records have no device handle */

int gin_tables_init(void)
{
    if (!g_curs) g_curs = gfx_pages_alloc(sizeof(gcur_t) * GIN_CURSORS);
    if (!g_raw) g_raw = gfx_pages_alloc(sizeof(shz_rawrec_t) * GIN_RAWRING);
    return g_curs && g_raw ? 0 : STATUS_NO_MEMORY;
}

static int raw_nolegacy(uint32_t dev)
{
    unsigned i;
    if (!g_fg_q) return 0;
    for (i = 0; i < GIN_RAWREG; ++i)
        if (g_rawreg[i].used && g_rawreg[i].dev == dev && g_rawreg[i].pid == g_fg_q->pid && (g_rawreg[i].flags & RIDEV_NOLEGACY_)) return 1;
    return 0;
}

static void raw_post(uint32_t dev, shz_rawrec_t *rec)
{
    unsigned i;
    rec->device = g_injecting ? 0 : (dev == SHZ_RAW_KEYBOARD ? SHZ_RAW_HANDLE_KEYBOARD : SHZ_RAW_HANDLE_MOUSE);
    for (i = 0; i < GIN_RAWREG; ++i) {
        grawreg_t *r = &g_rawreg[i];
        const int fg = g_fg_q && g_fg_q->pid == r->pid;
        gwin_t *w;
        uint32_t id, slot;
        if (!r->used || r->dev != dev) continue;
        if (!fg && !(r->flags & (RIDEV_INPUTSINK_ | RIDEV_EXINPUTSINK_))) continue;
        w = r->target ? wm_lookup(r->target) : 0;
        if (r->target && !w) { r->used = 0; continue; }             /* the target window is gone */
        if (!w && fg) { w = wm_lookup(g_fg_q->focus); if (!w) w = wm_lookup(g_fg_q->active); }
        if (!w || !w->q) continue;
        if(w->pid!=r->pid || !g_fg_q || !gfx_auth_queue(w->q->proc,w->q) || !gfx_auth_queue(w->q->proc,g_fg_q))continue;
        id = g_raw_next++;
        if (!g_raw_next) g_raw_next = 1;
        slot = id % GIN_RAWRING;
        rec->wparam = fg ? 0u : 1u;                                 /* RIM_INPUT / RIM_INPUTSINK */
        g_raw[slot] = *rec;
        g_raw_ids[slot] = id;
        g_raw_owner[slot]=w->q;g_raw_thread[slot]=w->q->thread_id;
        gq_post(w->q, w->handle, WM_INPUT_, rec->wparam, (int64_t)id);
    }
}

static void raw_any(uint32_t dev, int *have)
{
    unsigned i;
    *have = 0;
    for (i = 0; i < GIN_RAWREG; ++i) if (g_rawreg[i].used && g_rawreg[i].dev == dev) *have = 1;
}

/* ---------------------------------------------------------------- keyboard */
/* Scan code (set 1, without prefix) -> virtual key, as the keyboard layout (win64/include/shzkbd.h) sees it right now. */
static uint8_t scan_to_vk(uint8_t sc, int ext)
{
    if (ext) return shz_kbd_e0(sc);
    if (sc >= 0x47 && sc <= 0x53 && shz_kbd_numpad[sc - 0x47] && (g_async[VK_NUMLOCK] & 1) && !is_down(VK_SHIFT))
        return shz_kbd_numpad[sc - 0x47];
    return sc < sizeof shz_kbd_set1 ? shz_kbd_set1[sc] : 0;
}

static void post_key(uint32_t msg, uint64_t wparam, uint32_t lparam, uint32_t extra)
{
    gqueue_t *q = g_fg_q;
    gwin_t *w = q ? wm_lookup(q->focus) : 0;
    shz_msg_t m;
    if (!w && q && (w = wm_lookup(q->active)) != 0) {       /* nothing has the focus: WM_SYSKEY* to the active window */
        msg = (msg == WM_KEYUP || msg == WM_SYSKEYUP) ? WM_SYSKEYUP : WM_SYSKEYDOWN;
        lparam &= ~(1u << 29);
    }
    if (!w || !w->q) return;
    memset(&m, 0, sizeof m);
    m.hwnd = w->handle;
    m.message = msg;
    m.wparam = wparam;
    m.lparam = (int64_t)(uint64_t)lparam;
    m.time = gq_time();
    m.pt.x = g_ptr_x;
    m.pt.y = g_ptr_y;
    m.pad0 = SHZ_MSGF_INPUT;
    m.pad1 = extra;
    gq_post_input(w->q, &m, 0);
}

/* A key event: `vk` is the specific key (VK_LSHIFT, not VK_SHIFT), `scan` its set 1 code. */
static void key_input(uint8_t vk, uint16_t scan, int ext, int up, uint32_t extra)
{
    const uint8_t gen = generic_vk(vk);
    const int was_down = is_down(vk), alt_before = is_down(VK_MENU);
    int alt, sys;
    uint32_t msg, lp;
    note_input();
    if (!up) g_pressed[vk] = g_pressed[gen] = 1;
    state_key(g_async, vk, !up);
    alt = up ? alt_before : is_down(VK_MENU);
    sys = !is_down(VK_CONTROL) && (alt || gen == VK_F10);
    msg = up ? (sys ? WM_SYSKEYUP : WM_KEYUP) : (sys ? WM_SYSKEYDOWN : WM_KEYDOWN);
    {
        int have;
        raw_any(SHZ_RAW_KEYBOARD, &have);
        if (have) {
            shz_rawrec_t r;
            memset(&r, 0, sizeof r);
            r.type = 1;
            r.kb_make = scan & 0xff;
            r.kb_flags = (uint16_t)((up ? RI_KEY_BREAK_ : 0) | (ext ? RI_KEY_E0_ : 0) | (vk == VK_PAUSE ? RI_KEY_E1_ : 0));
            r.kb_vkey = gen;
            r.kb_message = msg;
            r.extra = extra;
            raw_post(SHZ_RAW_KEYBOARD, &r);
        }
    }
    if (!up && hotkey_fire(gen, was_down)) return;
    if (raw_nolegacy(SHZ_RAW_KEYBOARD)) return;
    lp = 1u | ((uint32_t)(scan & 0xff) << 16) | ((uint32_t)(ext != 0) << 24) | ((sys && alt) ? 1u << 29 : 0) |
         ((up || was_down) ? 1u << 30 : 0) | (up ? 1u << 31 : 0);
    post_key(msg, gen, lp, extra);
}

#ifdef SHZ_STANDALONE
static int kb_e0, kb_e1;
static void kbd_byte(uint8_t b)
{
    uint8_t sc, vk;
    int up, ext;
    if (b == 0xE0) { kb_e0 = 1; return; }
    if (b == 0xE1) { kb_e1 = 2; return; }
    if (b == 0xFA || b == 0xFE || b == 0x00 || b == 0xFF) return;             /* ACK / resend / overrun */
    up = (b & 0x80) != 0;
    sc = b & 0x7f;
    if (kb_e1) {                                                               /* Pause: E1 1D 45 (make), E1 9D C5 (break) */
        if (--kb_e1 == 0 && sc == 0x45) key_input(VK_PAUSE, 0x45, 0, up, 0);
        return;
    }
    ext = kb_e0;
    kb_e0 = 0;
    if (ext && (sc == 0x2A || sc == 0x36)) return;                            /* fake shifts around extended keys */
    vk = scan_to_vk(sc, ext);
    if (vk) key_input(vk, sc, ext, up, 0);
}
#endif

/* ---------------------------------------------------------------- mouse */
static uint32_t mk_flags(void)
{
    return g_buttons | (is_down(VK_SHIFT) ? MK_SHIFT : 0) | (is_down(VK_CONTROL) ? MK_CONTROL : 0);
}

/* The window that receives mouse input now (and whose thread chooses the pointer image), or NULL. */
static gwin_t *mouse_target(int *captured)
{
    gwin_t *w;
    unsigned i;
    *captured = 0;
    if (g_fg_q && (w = wm_lookup(g_fg_q->capture)) != 0 && gfx_auth_screen_window(w)) { *captured = 1; return w; }
    if (g_buttons)
        for (i = 0; i < GFX_MAX_QUEUES; ++i)
            if (g_queues[i].used && (w = wm_lookup(g_queues[i].capture)) != 0 && gfx_auth_screen_window(w)) { *captured = 1; return w; }
    w = wm_input_hit(g_ptr_x, g_ptr_y);
    if (w && (wm_toplevel(w)->style & SHZ_WS_DISABLED)) return 0;
    return w;
}

static void post_mouse(uint32_t msg, uint32_t xbutton, uint32_t extra)
{
    int captured;
    gwin_t *w = mouse_target(&captured);
    shz_msg_t m;
    if (!w || !w->q) return;
    memset(&m, 0, sizeof m);
    m.hwnd = w->handle;
    m.message = msg;
    m.wparam = mk_flags() | ((uint64_t)xbutton << 16);
    m.lparam = (int64_t)(uint64_t)(((uint32_t)(uint16_t)g_ptr_x) | ((uint32_t)(uint16_t)g_ptr_y << 16));
    m.time = gq_time();
    m.pt.x = g_ptr_x;
    m.pt.y = g_ptr_y;
    m.pad0 = SHZ_MSGF_INPUT | SHZ_MSGF_MOUSE | (captured ? SHZ_MSGF_CAPTURED : 0);
    m.pad1 = extra;
    gq_post_input(w->q, &m, msg == WM_MOUSEMOVE);
}

static void post_wheel(uint32_t msg, int delta, uint32_t extra)
{
    gqueue_t *q = g_fg_q;
    gwin_t *w = q ? wm_lookup(q->focus) : 0;
    shz_msg_t m;
    if (!w && q) w = wm_lookup(q->active);
    if (!w || !w->q) return;
    memset(&m, 0, sizeof m);
    m.hwnd = w->handle;
    m.message = msg;
    m.wparam = (mk_flags() & 0xffff) | ((uint64_t)(uint16_t)(int16_t)delta << 16);
    m.lparam = (int64_t)(uint64_t)(((uint32_t)(uint16_t)g_ptr_x) | ((uint32_t)(uint16_t)g_ptr_y << 16));
    m.time = gq_time();
    m.pt.x = g_ptr_x;
    m.pt.y = g_ptr_y;
    m.pad0 = SHZ_MSGF_INPUT;
    m.pad1 = extra;
    gq_post_input(w->q, &m, 0);
}

static void pointer_update(void);
static void track_check(void);

static void clamp_pointer(int32_t *x, int32_t *y)
{
    int32_t l = 0, t = 0, r = (int32_t)g_fb.width - 1, b = (int32_t)g_fb.height - 1;
    if (g_clip_on) {
        if (g_clip.left > l) l = g_clip.left;
        if (g_clip.top > t) t = g_clip.top;
        if (g_clip.right - 1 < r) r = g_clip.right - 1;
        if (g_clip.bottom - 1 < b) b = g_clip.bottom - 1;
    }
    if (*x < l) *x = l;
    if (*x > r) *x = r;
    if (*y < t) *y = t;
    if (*y > b) *y = b;
}

static void move_pointer_to(int32_t x, int32_t y, uint32_t extra)
{
    clamp_pointer(&x, &y);
    ptr_live = 1;
    if (x != g_ptr_x || y != g_ptr_y) {
        g_ptr_x = x;
        g_ptr_y = y;
        post_mouse(WM_MOUSEMOVE, 0, extra);
    }
    pointer_update();
    track_check();
}

/* One mouse event: movement (relative, or absolute when `absolute`), the new set of MK_ button bits, wheel deltas. */
static void mouse_input(int32_t dx, int32_t dy, int absolute, uint32_t buttons, int wheel, int hwheel, uint32_t extra)
{
    static const struct { uint32_t mk, down, up, vk, x; } btn[5] = {
        { MK_LBUTTON, WM_LBUTTONDOWN, WM_LBUTTONUP, VK_LBUTTON, 0 }, { MK_RBUTTON, WM_RBUTTONDOWN, WM_RBUTTONUP, VK_RBUTTON, 0 },
        { MK_MBUTTON, WM_MBUTTONDOWN, WM_MBUTTONUP, VK_MBUTTON, 0 }, { MK_XBUTTON1, WM_XBUTTONDOWN, WM_XBUTTONUP, VK_XBUTTON1, 1 },
        { MK_XBUTTON2, WM_XBUTTONDOWN, WM_XBUTTONUP, VK_XBUTTON2, 2 } };
    unsigned i;
    int have, legacy;
    note_input();
    raw_any(SHZ_RAW_MOUSE, &have);
    if (have) {                                             /* the event as the device reported it */
        static const uint16_t rdown[5] = { 0x0001, 0x0004, 0x0010, 0x0040, 0x0100 }, rup[5] = { 0x0002, 0x0008, 0x0020, 0x0080, 0x0200 };
        static const uint32_t mk[5] = { MK_LBUTTON, MK_RBUTTON, MK_MBUTTON, MK_XBUTTON1, MK_XBUTTON2 };
        shz_rawrec_t r;
        memset(&r, 0, sizeof r);
        r.type = 0;
        r.ms_flags = absolute ? 1 : 0;                      /* MOUSE_MOVE_ABSOLUTE / MOUSE_MOVE_RELATIVE */
        r.ms_x = absolute ? (int32_t)(((int64_t)dx << 16) / (int64_t)(g_fb.width ? g_fb.width : 1)) : dx;
        r.ms_y = absolute ? (int32_t)(((int64_t)dy << 16) / (int64_t)(g_fb.height ? g_fb.height : 1)) : dy;
        for (i = 0; i < 5; ++i)
            if (((buttons ^ g_buttons) & mk[i])) r.ms_button_flags |= (buttons & mk[i]) ? rdown[i] : rup[i];
        if (wheel) { r.ms_button_flags |= 0x0400; r.ms_button_data = (int16_t)wheel; }        /* RI_MOUSE_WHEEL */
        else if (hwheel) { r.ms_button_flags |= 0x0800; r.ms_button_data = (int16_t)hwheel; } /* RI_MOUSE_HWHEEL */
        r.ms_buttons = buttons;
        r.extra = extra;
        raw_post(SHZ_RAW_MOUSE, &r);
    }
    legacy = !raw_nolegacy(SHZ_RAW_MOUSE);
    if (!legacy) {                                          /* the pointer still moves; no mouse messages are posted */
        int32_t x = absolute ? dx : g_ptr_x + dx, y = absolute ? dy : g_ptr_y + dy;
        clamp_pointer(&x, &y);
        ptr_live = 1;
        g_ptr_x = x;
        g_ptr_y = y;
        pointer_update();
        g_buttons = buttons;
        return;
    }
    move_pointer_to(absolute ? dx : g_ptr_x + dx, absolute ? dy : g_ptr_y + dy, extra);
    for (i = 0; i < 5; ++i) {
        const int now = (buttons & btn[i].mk) != 0;
        if (now == ((g_buttons & btn[i].mk) != 0)) continue;
        if (now) { g_buttons |= btn[i].mk; g_pressed[btn[i].vk] = 1; } else g_buttons &= ~btn[i].mk;
        state_key(g_async, (uint8_t)btn[i].vk, now);
        post_mouse(now ? btn[i].down : btn[i].up, btn[i].x, extra);
        pointer_update();                                   /* a released button can end an implicit capture */
    }
    if (wheel) post_wheel(WM_MOUSEWHEEL, wheel, extra);
    if (hwheel) post_wheel(WM_MOUSEHWHEEL, hwheel, extra);
}

/* A USB HID pointer (laptop_input_native.c): the adapter's relative motion + MK button bits 0..2 (L,R,M). Thread context. */
/* gfx_lock held (the "gfxin" thread decoding the i8042 aux stream). Same semantics as gin_pointer_inject. */
int gin_pointer_inject_locked(int32_t dx, int32_t dy, uint8_t buttons)
{
    uint32_t btn;
    if (buttons > 7u) return -1;
    btn = (g_buttons & (MK_XBUTTON1 | MK_XBUTTON2)) | ((buttons & 1u) ? MK_LBUTTON : 0) | ((buttons & 2u) ? MK_RBUTTON : 0) |
          ((buttons & 4u) ? MK_MBUTTON : 0);
    g_info |= SHZ_INFO_MOUSE;
    mouse_input(dx, dy, 0, btn, 0, 0, 0);
    return 0;
}
int gin_pointer_inject(int32_t dx, int32_t dy, uint8_t buttons)
{
    int r;
    if (buttons > 7u) return -1;
    mutex_lock(&gfx_lock);
    r = gin_pointer_inject_locked(dx, dy, buttons);
    mutex_unlock(&gfx_lock);
    return r;
}

#ifdef SHZ_STANDALONE
static uint8_t mpkt[4];
static int mpos;
static void mouse_byte(uint8_t b)
{
    int dx, dy, dz;
    uint32_t btn;
    if (k64_laptop_ps2_feed(b)) return;                     /* Synaptics absolute route owns this byte: never decoded twice */
    if (mpos == 0 && !(b & 0x08)) return;                   /* resynchronise: bit 3 of the first byte is always set */
    mpkt[mpos++] = b;
    if (mpos < mpkt_len) return;
    mpos = 0;
    dx = (int)mpkt[1] - (int)((mpkt[0] << 4) & 0x100);
    dy = (int)mpkt[2] - (int)((mpkt[0] << 3) & 0x100);
    if (mpkt[0] & 0xC0) dx = dy = 0;                        /* overflow: the counts are meaningless */
    dz = mpkt_len == 4 ? (int)(int8_t)mpkt[3] : 0;
    btn = (g_buttons & (MK_XBUTTON1 | MK_XBUTTON2)) | ((mpkt[0] & 1) ? MK_LBUTTON : 0) | ((mpkt[0] & 2) ? MK_RBUTTON : 0) |
          ((mpkt[0] & 4) ? MK_MBUTTON : 0);
    mouse_input(dx, -dy, 0, btn, -dz * 120, 0, 0);          /* PS/2 y grows upwards; wheel away from the user = +120 */
}
#endif

/* ---------------------------------------------------------------- pointer sprite */
static void pointer_update(void)
{
    int captured, idx, vis;
    gwin_t *w;
    gcur_t *c;
    shz_rect_t nr, old;
    int old_vis;
    if (!ptr_live || !g_fb.ready) return;
    w = mouse_target(&captured);
    if (!w || !w->q) { idx = 0; vis = 1; }
    else { idx = w->q->cursor; vis = idx >= 0 && idx < GIN_CURSORS && g_curs[idx].used && !w->q->cursor_hidden; }
    sh_cookie = (idx >= 0 && idx < GIN_CURSORS && g_curs[idx].used) ? g_curs[idx].cookie : 0;
    if (idx < 0 || idx >= GIN_CURSORS || !g_curs[idx].used) idx = 0;
    c = &g_curs[idx];
    nr.left = g_ptr_x - c->hx; nr.top = g_ptr_y - c->hy; nr.right = nr.left + c->w; nr.bottom = nr.top + c->h;
    if (idx == sh_idx && vis == sh_vis && c->ver == sh_ver && nr.left == sh_rect.left && nr.top == sh_rect.top &&
        nr.right == sh_rect.right && nr.bottom == sh_rect.bottom)
        return;
    old = sh_rect;
    old_vis = sh_vis;
    sh_idx = idx; sh_vis = vis; sh_ver = c->ver; sh_rect = nr;
    if (old_vis) wm_damage(&old);
    if (vis) wm_damage(&nr);
}

void gin_draw_pointer(const shz_rect_t *clip)
{
    shz_rect_t o;
    const gcur_t *c;
    int x, y;
    if (!ptr_live || !sh_vis || sh_idx < 0 || !rc_isect(&sh_rect, clip, &o)) return;
    c = &g_curs[sh_idx];
    for (y = o.top; y < o.bottom; ++y) {
        uint32_t *d = g_fb.back + (uint64_t)y * g_fb.width + (uint32_t)o.left;
        const uint32_t *s = c->px + (y - sh_rect.top) * c->w + (o.left - sh_rect.left);
        for (x = o.left; x < o.right; ++x, ++d, ++s) {
            const uint32_t a = *s >> 24;
            if (a == 255) *d = *s & 0x00ffffffu;
            else if (a) {
                const uint32_t p = *d;
                *d = ((((*s >> 16) & 255) * a + ((p >> 16) & 255) * (255 - a)) / 255) << 16 |
                     ((((*s >> 8) & 255) * a + ((p >> 8) & 255) * (255 - a)) / 255) << 8 | (((*s & 255) * a + (p & 255) * (255 - a)) / 255);
            }
        }
    }
}

/* ---------------------------------------------------------------- TrackMouseEvent */
/* Is the pointer inside the area tracked by q (client area, or the non-client area with TME_NONCLIENT)? */
static int track_inside(gqueue_t *q, gwin_t *tw)
{
    gwin_t *w = wm_input_hit(g_ptr_x, g_ptr_y);
    int32_t cx, cy;
    int in_client;
    if (!w || w != tw) return 0;
    wm_client_origin(tw, &cx, &cy);
    in_client = g_ptr_x >= cx && g_ptr_y >= cy && g_ptr_x < cx + (tw->w - tw->ncl - tw->ncr) && g_ptr_y < cy + (tw->h - tw->nct - tw->ncb);
    return (q->track_flags & TME_NONCLIENT) ? !in_client : in_client;
}

static void track_one(gqueue_t *q)
{
    gwin_t *tw;
    if (!q->track_flags) return;
    tw = wm_lookup(q->track_hwnd);
    if (!tw) { q->track_flags = 0; q->track_hwnd = 0; return; }
    if (!track_inside(q, tw)) {
        if (q->track_flags & TME_LEAVE)
            gq_post(q, tw->handle, (q->track_flags & TME_NONCLIENT) ? WM_NCMOUSELEAVE : WM_MOUSELEAVE, 0, 0);
        q->track_flags = 0;                                  /* leaving cancels all tracking, as on Windows */
        return;
    }
    if ((q->track_flags & TME_HOVER) && (g_ptr_x - q->hover_x > 2 || q->hover_x - g_ptr_x > 2 || g_ptr_y - q->hover_y > 2 || q->hover_y - g_ptr_y > 2)) {
        q->hover_x = g_ptr_x;                               /* moved out of the SM_CXMOUSEHOVER (4 px) square: restart */
        q->hover_y = g_ptr_y;
        q->hover_since = now_ms();
    }
}

static void track_check(void)
{
    unsigned i;
    for (i = 0; i < GFX_MAX_QUEUES; ++i)
        if (g_queues[i].used) track_one(&g_queues[i]);
}

void gin_tick(void)
{
    unsigned i;
    for (i = 0; i < GFX_MAX_QUEUES; ++i) {
        gqueue_t *q = &g_queues[i];
        gwin_t *tw;
        int32_t cx, cy;
        if (!q->used || !(q->track_flags & TME_HOVER)) continue;
        tw = wm_lookup(q->track_hwnd);
        if (!tw || !track_inside(q, tw) || now_ms() - q->hover_since < q->hover_ms) continue;
        wm_client_origin(tw, &cx, &cy);
        if (q->track_flags & TME_NONCLIENT)
            gq_post(q, tw->handle, WM_NCMOUSEHOVER, 0, (int64_t)(((uint32_t)(uint16_t)g_ptr_x) | ((uint32_t)(uint16_t)g_ptr_y << 16)));
        else
            gq_post(q, tw->handle, WM_MOUSEHOVER, mk_flags(),
                    (int64_t)(((uint32_t)(uint16_t)(g_ptr_x - cx)) | ((uint32_t)(uint16_t)(g_ptr_y - cy) << 16)));
        q->track_flags &= ~TME_HOVER;
    }
}

void gin_windows_changed(void)
{
    pointer_update();
    track_check();
}

/* ---------------------------------------------------------------- SendInput */
static void inject_one(const shz_inrec_t *r);
static void inject(const shz_inrec_t *r)
{
    g_injecting = 1;
    inject_one(r);
    g_injecting = 0;
}

static void inject_one(const shz_inrec_t *r)
{
    if (r->type == 1) {                                     /* keyboard */
        const int up = (r->flags & 2u) != 0;
        int ext = (r->flags & 1u) != 0;
        uint8_t vk = (uint8_t)r->vk;
        uint16_t scan = r->scan;
        if (r->flags & 4u) {                                /* KEYEVENTF_UNICODE: VK_PACKET carrying the character */
            note_input();
            post_key(up ? WM_KEYUP : WM_KEYDOWN, VK_PACKET | ((uint64_t)r->scan << 16), 1u | (up ? 3u << 30 : 0), (uint32_t)r->extra);
            return;
        }
        if (r->flags & 8u) {                                /* KEYEVENTF_SCANCODE: the layout picks the key */
            if ((scan >> 8) == 0xE0) ext = 1;
            vk = scan_to_vk((uint8_t)(scan & 0x7f), ext);
        }
        else if (!scan) { int e2; scan = shz_kbd_vk_to_scan(vk, &e2); ext |= e2; }
        if (vk == VK_SHIFT) vk = (scan & 0xff) == 0x36 ? VK_RSHIFT : VK_LSHIFT;
        else if (vk == VK_CONTROL) vk = ext ? VK_RCONTROL : VK_LCONTROL;
        else if (vk == VK_MENU) vk = ext ? VK_RMENU : VK_LMENU;
        if (vk) key_input(vk, scan & 0xff, ext, up, (uint32_t)r->extra);
        return;
    }
    if (r->type == 0) {                                     /* mouse */
        uint32_t b = g_buttons;
        int32_t x = r->dx, y = r->dy;
        const int absolute = (r->flags & 0x8000u) != 0;
        if (!(r->flags & 1u)) { x = absolute ? g_ptr_x : 0; y = absolute ? g_ptr_y : 0; }
        else if (absolute) {
            x = (int32_t)(((int64_t)r->dx * (int64_t)g_fb.width) >> 16);
            y = (int32_t)(((int64_t)r->dy * (int64_t)g_fb.height) >> 16);
        }
        if (r->flags & 0x0002u) b |= MK_LBUTTON;
        if (r->flags & 0x0004u) b &= ~MK_LBUTTON;
        if (r->flags & 0x0008u) b |= MK_RBUTTON;
        if (r->flags & 0x0010u) b &= ~MK_RBUTTON;
        if (r->flags & 0x0020u) b |= MK_MBUTTON;
        if (r->flags & 0x0040u) b &= ~MK_MBUTTON;
        if (r->flags & 0x0080u) b |= (r->data & 1 ? MK_XBUTTON1 : 0) | (r->data & 2 ? MK_XBUTTON2 : 0);
        if (r->flags & 0x0100u) b &= ~((r->data & 1 ? MK_XBUTTON1 : 0) | (r->data & 2 ? MK_XBUTTON2 : 0));
        mouse_input(x, y, absolute, b, (r->flags & 0x0800u) ? r->data : 0, (r->flags & 0x1000u) ? r->data : 0, (uint32_t)r->extra);
    }
}

/* ---------------------------------------------------------------- system call */
static int cursor_slot(uint32_t pid, uint64_t cookie)
{
    unsigned i, k;
    int free_slot = -1;
    for (i = 1; i < GIN_CURSORS; ++i)
        if (g_curs[i].used && g_curs[i].pid == pid && g_curs[i].cookie == cookie) return (int)i;
    for (i = 1; i < GIN_CURSORS && free_slot < 0; ++i) {
        int referenced = 0;
        if (!g_curs[i].used) { free_slot = (int)i; break; }
        for (k = 0; k < GFX_MAX_QUEUES; ++k)
            if (g_queues[k].used && g_queues[k].cursor == (int)i) referenced = 1;
        if (!referenced) free_slot = (int)i;                /* recycle an image no thread shows */
    }
    if (free_slot < 0) return -1;
    memset(&g_curs[free_slot], 0, sizeof g_curs[free_slot]);
    g_curs[free_slot].used = 1;
    g_curs[free_slot].pid = pid;
    g_curs[free_slot].cookie = cookie;
    return free_slot;
}

int32_t gfx_syscall_input(process_t *cur, uint64_t arg)
{
    shz_input_t in;
    gqueue_t *q;
    int32_t st = STATUS_SUCCESS;
    static uint8_t tmp[256];
    static shz_inrec_t recs[64];
    static uint32_t pix[32 * 32];
    if (copy_from_user(cur, &in, arg, sizeof in)) return STATUS_ACCESS_VIOLATION;
    if (in.op == SHZ_IN_SENDINPUT && (in.a < 0 || in.a > 64)) return STATUS_INVALID_PARAMETER;
    mutex_lock(&gfx_lock);
    q = gq_current(1);
    if (!q) { st = STATUS_NO_MEMORY; goto out; }
    in.out0 = in.out1 = 0;
    switch(in.op) {
    case SHZ_IN_GETASYNCKEYSTATE:case SHZ_IN_GETCURSORPOS:case SHZ_IN_SETCURSORPOS:
    case SHZ_IN_SENDINPUT:case SHZ_IN_CLIPCURSOR:case SHZ_IN_GETCLIPCURSOR:
    case SHZ_IN_CURSORINFO:case SHZ_IN_INFO:
        if(!gfx_auth_desktop(cur,1)){st=STATUS_ACCESS_DENIED;goto out;}
        break;
    }
    switch (in.op) {
    case SHZ_IN_GETKEYSTATE: in.out0 = q->keys[in.a & 0xff]; break;
    case SHZ_IN_GETKEYBOARDSTATE:
        if (in.buf_len < 256 || copy_to_user(cur, in.buf, q->keys, 256)) st = STATUS_ACCESS_VIOLATION;
        break;
    case SHZ_IN_SETKEYBOARDSTATE:
        if (in.buf_len < 256 || copy_from_user(cur, tmp, in.buf, 256)) { st = STATUS_ACCESS_VIOLATION; break; }
        memcpy(q->keys, tmp, 256);
        break;
    case SHZ_IN_GETASYNCKEYSTATE: {
        const unsigned vk = (unsigned)(in.a & 0xff);
        in.out0 = (is_down((int)vk) ? 0x8000u : 0) | (g_pressed[vk] ? 1u : 0);
        g_pressed[vk] = 0;
        break;
    }
    case SHZ_IN_GETCURSORPOS: in.out0 = (uint64_t)(int64_t)g_ptr_x; in.out1 = (uint64_t)(int64_t)g_ptr_y; break;
    case SHZ_IN_SETCURSORPOS: move_pointer_to((int32_t)in.a, (int32_t)in.b, 0); break;
    case SHZ_IN_SENDINPUT: {
        int i;
        if (in.a && copy_from_user(cur, recs, in.buf, (uint64_t)in.a * sizeof recs[0])) { st = STATUS_ACCESS_VIOLATION; break; }
        for (i = 0; i < in.a; ++i) inject(&recs[i]);
        in.out0 = (uint64_t)in.a;
        break;
    }
    case SHZ_IN_CLIPCURSOR:
        if (in.a) {
            shz_rect_t scr = { 0, 0, (int32_t)g_fb.width, (int32_t)g_fb.height };
            if (!rc_isect(&in.rect, &scr, &g_clip)) { g_clip.left = in.rect.left < 0 ? 0 : in.rect.left; g_clip.top = in.rect.top < 0 ? 0 : in.rect.top;
                                                       g_clip.right = g_clip.left + 1; g_clip.bottom = g_clip.top + 1; }
            g_clip_on = 1;
            if (ptr_live) move_pointer_to(g_ptr_x, g_ptr_y, 0);
            else clamp_pointer(&g_ptr_x, &g_ptr_y);
        } else g_clip_on = 0;
        break;
    case SHZ_IN_GETCLIPCURSOR:
        if (g_clip_on) in.rect = g_clip;
        else { in.rect.left = in.rect.top = 0; in.rect.right = (int32_t)g_fb.width; in.rect.bottom = (int32_t)g_fb.height; }
        break;
    case SHZ_IN_INFO: in.out0 = g_info; in.out1 = g_last_input_ms; break;
    case SHZ_IN_TRACKMOUSE: {
        const uint32_t fl = (uint32_t)in.b;
        gwin_t *w;
        if (fl & TME_QUERY) {
            in.out0 = q->track_flags ? q->track_hwnd : 0;
            in.out1 = q->track_flags | ((uint64_t)q->hover_ms << 32);
            break;
        }
        w = wm_lookup((uint64_t)in.a);
        if (!w) { st = STATUS_INVALID_HANDLE; break; }
        if (w->q != q) { st = STATUS_ACCESS_DENIED; break; }
        if (fl & TME_CANCEL) {
            if (q->track_hwnd == w->handle) q->track_flags &= ~(fl & (TME_HOVER | TME_LEAVE));
            if (!(q->track_flags & (TME_HOVER | TME_LEAVE))) q->track_flags = 0;
            break;
        }
        if (q->track_hwnd != w->handle || ((q->track_flags ^ fl) & TME_NONCLIENT)) q->track_flags = 0;
        q->track_hwnd = w->handle;
        q->track_flags |= fl & (TME_HOVER | TME_LEAVE | TME_NONCLIENT);
        if (fl & TME_HOVER) {
            q->hover_ms = ((uint32_t)in.c == HOVER_DEFAULT || in.c <= 0) ? 400u : (uint32_t)in.c;
            q->hover_x = g_ptr_x;
            q->hover_y = g_ptr_y;
            q->hover_since = now_ms();
        }
        track_one(q);                                       /* already outside: WM_MOUSELEAVE right away */
        break;
    }
    case SHZ_IN_SETCURSOR: {
        const int w = (int)(in.b & 0xffff), h = (int)((in.b >> 16) & 0xffff);
        int slot = -1;
        if (in.a) {
            if (w <= 0 || h <= 0 || w > 32 || h > 32 || !in.buf) { st = STATUS_INVALID_PARAMETER; break; }
            if (copy_from_user(cur, pix, in.buf, (uint64_t)w * (uint64_t)h * 4)) { st = STATUS_ACCESS_VIOLATION; break; }
            slot = cursor_slot((uint32_t)cur->pid, (uint64_t)in.a);
            if (slot < 0) { st = STATUS_NO_MEMORY; break; }
            if (g_curs[slot].w != w || g_curs[slot].h != h || memcmp(g_curs[slot].px, pix, (size_t)w * (size_t)h * 4) ||
                g_curs[slot].hx != (int)(in.c & 0xffff) || g_curs[slot].hy != (int)((in.c >> 16) & 0xffff)) {
                g_curs[slot].w = w; g_curs[slot].h = h;
                g_curs[slot].hx = (int)(in.c & 0xffff); g_curs[slot].hy = (int)((in.c >> 16) & 0xffff);
                memcpy(g_curs[slot].px, pix, (size_t)w * (size_t)h * 4);
                ++g_curs[slot].ver;
            }
        }
        q->cursor = slot;
        q->cursor_hidden = in.d != 0;
        pointer_update();
        break;
    }
    case SHZ_IN_CURSORINFO:                                 /* before any pointing event: the arrow (cookie 1), not drawn */
        in.out0 = sh_cookie;
        in.out1 = ptr_live && sh_vis;
        break;
    case SHZ_IN_HOTKEY: {
        unsigned i;
        const uint32_t mods = (uint32_t)(in.c & 0xffff);
        const uint8_t vk = (uint8_t)((in.c >> 16) & 0xff);
        if (in.a) {
            gwin_t *w = wm_lookup((uint64_t)in.a);
            if (!w) { st = STATUS_INVALID_HANDLE; break; }
            if (w->q != q) { st = STATUS_ACCESS_DENIED; break; }
        }
        if (in.d) {
            ghotkey_t *slot = 0;
            for (i = 0; i < GIN_HOTKEYS; ++i) {
                if (g_hot[i].used && g_hot[i].vk == vk && (g_hot[i].mods & 0xf) == (mods & 0xf)) { st = STATUS_HOTKEY_TAKEN; break; }
                if (g_hot[i].used && g_hot[i].hwnd == (uint64_t)in.a && g_hot[i].id == in.b && g_hot[i].thread_id == q->thread_id) slot = &g_hot[i];
            }
            if (st) break;
            for (i = 0; i < GIN_HOTKEYS && !slot; ++i) if (!g_hot[i].used) slot = &g_hot[i];
            if (!slot) { st = STATUS_NO_MEMORY; break; }
            slot->used = 1; slot->thread_id = q->thread_id; slot->hwnd = (uint64_t)in.a; slot->id = in.b; slot->mods = mods; slot->vk = vk;
        } else {
            st = STATUS_INVALID_PARAMETER;
            for (i = 0; i < GIN_HOTKEYS; ++i)
                if (g_hot[i].used && g_hot[i].hwnd == (uint64_t)in.a && g_hot[i].id == in.b && g_hot[i].thread_id == q->thread_id) {
                    g_hot[i].used = 0;
                    st = STATUS_SUCCESS;
                }
        }
        break;
    }
    case SHZ_IN_RAWREGISTER: {
        const uint32_t dev = (uint32_t)in.a, pid = (uint32_t)cur->pid;
        unsigned i;
        grawreg_t *slot = 0;
        if (dev != SHZ_RAW_KEYBOARD && dev != SHZ_RAW_MOUSE) { st = STATUS_INVALID_PARAMETER; break; }
        if (in.c) {
            gwin_t *w = wm_lookup((uint64_t)in.c);
            if (!w) { st = STATUS_INVALID_HANDLE; break; }
            if (w->pid != pid) { st = STATUS_ACCESS_DENIED; break; }
        } else if (in.b & (RIDEV_INPUTSINK_ | RIDEV_EXINPUTSINK_)) { st = STATUS_INVALID_PARAMETER; break; }   /* a sink needs a target */
        for (i = 0; i < GIN_RAWREG; ++i) if (g_rawreg[i].used && g_rawreg[i].pid == pid && g_rawreg[i].dev == dev) slot = &g_rawreg[i];
        if (in.b & RIDEV_REMOVE_) {
            if (!slot) { st = STATUS_INVALID_PARAMETER; break; }
            slot->used = 0;
            break;
        }
        for (i = 0; i < GIN_RAWREG && !slot; ++i) if (!g_rawreg[i].used) slot = &g_rawreg[i];
        if (!slot) { st = STATUS_NO_MEMORY; break; }
        slot->used = 1; slot->pid = pid; slot->dev = dev; slot->flags = (uint32_t)in.b; slot->target = (uint64_t)in.c;
        break;
    }
    case SHZ_IN_RAWGET: {
        const uint32_t id = (uint32_t)in.a, slot = id % GIN_RAWRING;
        if (!id || g_raw_ids[slot] != id) { st = STATUS_INVALID_HANDLE; break; }
        if(!g_raw_owner[slot] || g_raw_owner[slot]->thread_id!=g_raw_thread[slot] ||
           !gfx_auth_queue(cur,g_raw_owner[slot])){st=STATUS_ACCESS_DENIED;break;}
        if (in.buf_len < sizeof(shz_rawrec_t) || copy_to_user(cur, in.buf, &g_raw[slot], sizeof(shz_rawrec_t))) st = STATUS_ACCESS_VIOLATION;
        break;
    }
    case SHZ_IN_RAWLIST: {
        uint64_t targets[2] = { 0, 0 };
        unsigned i;
        for (i = 0; i < GIN_RAWREG; ++i)
            if (g_rawreg[i].used && g_rawreg[i].pid == (uint32_t)cur->pid) {
                const int k = g_rawreg[i].dev == SHZ_RAW_MOUSE;
                in.out0 |= g_rawreg[i].dev;
                in.out1 |= (uint64_t)g_rawreg[i].flags << (k ? 32 : 0);
                targets[k] = g_rawreg[i].target;
            }
        if (in.buf && (in.buf_len < sizeof targets || copy_to_user(cur, in.buf, targets, sizeof targets))) st = STATUS_ACCESS_VIOLATION;
        break;
    }
    default: st = STATUS_INVALID_PARAMETER;
    }
out:
    mutex_unlock(&gfx_lock);
    if (!st && copy_to_user(cur, arg, &in, sizeof in)) return STATUS_ACCESS_VIOLATION;
    return st;
}

/* Called by the reaper (lock held) for a queue that is going away: its hot keys and pointer images go with it. */
void gin_queue_gone(gqueue_t *q)
{
    unsigned i;
    for (i = 0; i < GIN_HOTKEYS; ++i)
        if (g_hot[i].used && g_hot[i].thread_id == q->thread_id) g_hot[i].used = 0;
    for(i=0;i<GIN_RAWRING;i++)if(g_raw_owner[i]==q){g_raw_ids[i]=0;g_raw_owner[i]=0;g_raw_thread[i]=0;}
}

void gin_auth_transition(void)
{
    unsigned i;
    memset(g_pressed,0,sizeof g_pressed);g_clip_on=0;
    memset(g_raw_ids,0,sizeof g_raw_ids);memset(g_raw_owner,0,sizeof g_raw_owner);memset(g_raw_thread,0,sizeof g_raw_thread);
    for(i=0;i<GFX_MAX_QUEUES;i++)if(g_queues[i].used) {
        memset(g_queues[i].keys,0,sizeof g_queues[i].keys);
        if(!g_fg_q || !gfx_auth_queue(g_fg_q->proc,g_queues+i) || !gfx_auth_queue(g_queues[i].proc,g_fg_q))g_queues[i].capture=0;
    }
    pointer_update();
}

/* A window is being destroyed (lock held): hot keys registered for it go away. */
void gin_window_gone(uint64_t hwnd)
{
    unsigned i;
    for (i = 0; i < GIN_HOTKEYS; ++i)
        if (g_hot[i].used && g_hot[i].hwnd == hwnd) g_hot[i].used = 0;
    for (i = 0; i < GIN_RAWREG; ++i)
        if (g_rawreg[i].used && g_rawreg[i].target == hwnd) g_rawreg[i].used = 0;
}
