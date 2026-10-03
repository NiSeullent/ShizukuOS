/* SPDX-License-Identifier: GPL-2.0-only
 *
 * ShizukuOS main native shell (Korean default, English fallback).
 *
 * Origin/attribution: this file is ORIGINAL ShizukuOS code. No ReactOS, Wine or
 * Microsoft source or artwork is copied into it. The task-list / start-menu /
 * explorer models are written from scratch; the overall split (desktop window
 * registered as shell window, separate topmost taskbar and start menu windows,
 * a task list rebuilt from top-level windows) follows the public design of
 * ReactOS base/shell/explorer (LGPL-2.1+), which was consulted only as a
 * behavioural reference. The visual style is an original slate-blue design
 * inspired by the "Shorthorn 4074" era; it uses no Microsoft assets.
 *
 * Every action goes through real Win32 calls (FindFirstFileW, CopyFileW,
 * DeleteFileW, MoveFileW, CreateDirectoryW, CreateProcessW, ShellExecuteExW,
 * WaitForSingleObject/GetExitCodeProcess, GlobalMemoryStatusEx, ...). Failures
 * are shown with the GetLastError value; nothing reports success without the
 * API result.
 */
#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <shellapi.h>
#include "shzcrt.h"
#include "strings.h"

/* The shell-only API is exported by user32, but absent from MinGW's public header. */
__declspec(dllimport) BOOL WINAPI SetShellWindow(HWND hwnd);

#define PATH_CAP 260
#define ROW_CAP 512
#define PROC_CAP 16
#define TASK_CAP 24
#define MENU_CAP 16
#define BAR_H 32
#define ROW_H 20
#define LIST_Y 86
#define CFG_PATH L"D:\\SHZSHELL.CFG"
#define CFG_TMP L"D:\\SHZSHNEW.CFG"
#define SYS_DIR L"C:\\SHZ\\SYS64"
#define COPY_DEPTH 8

/* Slate palette (original). */
#define RGBC(r,g,b) RGB(r,g,b)
#define C_BAR_TOP RGBC(74,96,128)
#define C_BAR_BOT RGBC(28,40,60)
#define C_DESK_TOP RGBC(34,56,86)
#define C_DESK_BOT RGBC(8,16,32)
#define C_ACCENT RGBC(92,158,222)
#define C_MENU RGBC(34,46,66)
#define C_HOT RGBC(66,102,156)
#define C_WIN RGBC(240,244,248)
#define C_HEAD RGBC(208,218,230)
#define C_SEL RGBC(60,112,176)
#define C_TEXT RGBC(24,32,44)
#define C_LIGHT RGBC(236,244,252)
#define C_DIM RGBC(120,136,156)
#define C_ERR RGBC(176,32,32)

enum { M_NONE, M_PATH, M_RENAME };
enum { MI_HEADER, MI_EXPLORER, MI_RUN, MI_SETTINGS, MI_APP, MI_SEP, MI_END };

struct row { WCHAR name[PATH_CAP]; DWORD attrs; unsigned long long size; };
struct proc { HANDLE h; DWORD pid; WCHAR name[40]; };
struct task { HWND hwnd; WCHAR title[48]; };
struct mitem { int kind; WCHAR label[64]; WCHAR path[PATH_CAP]; };

static HINSTANCE g_inst;
static HWND g_desk, g_bar, g_menu, g_exp, g_runw, g_set;
static int g_w, g_h;
static int g_en;                    /* effective English fallback */
static WCHAR g_langpref = L'K';     /* Korean on a fresh installation; A auto, K Korean, E English. */
static WCHAR g_status[220];
static int g_status_err;
static struct proc g_procs[PROC_CAP];
static struct task g_tasks[TASK_CAP];
static unsigned g_task_count;
static struct mitem g_items[MENU_CAP];
static unsigned g_item_count;
static int g_menu_open, g_menu_hot = -1;
static WCHAR g_dir[PATH_CAP] = L"C:\\";
static struct row g_rows[ROW_CAP];
static unsigned g_order[ROW_CAP];
static unsigned g_count, g_total, g_top;
static int g_sel = -1;
static int g_mode;
static WCHAR g_input[PATH_CAP];
static unsigned g_input_len;
static WCHAR g_clip[PATH_CAP];
static int g_clip_valid;
static int g_del_armed = -1;
static DWORD g_last_click_tick;
static int g_last_click_row = -1;
static WCHAR g_run_text[PATH_CAP];
static unsigned g_run_len;
static unsigned g_tick_count;
static WORD g_last_minute = 0xffff;
static int g_icon_hot = -1;
static unsigned g_input_pos, g_run_pos;     /* caret positions */
static int g_anim = 6, g_menu_full;          /* start menu slide: 0..6, 6 = settled */
enum { W_BAR, W_EXP, W_SET, W_RUN, W_DESK, W_COUNT };
static int g_hot[W_COUNT] = { -1, -1, -1, -1, -1 };
static RECT g_hot_rc[W_COUNT];
static int g_press_w = -1, g_press_id = -1;
static RECT g_press_rc;

/* ---------- small string helpers (freestanding) ---------- */
static unsigned wlen(const WCHAR *s) { unsigned n = 0; while (s[n]) ++n; return n; }
static void wcopy(WCHAR *d, unsigned cap, const WCHAR *s)
{
    unsigned i = 0;
    if (!cap) return;
    while (s[i] && i + 1 < cap) { d[i] = s[i]; ++i; }
    d[i] = 0;
}
static WCHAR wup(WCHAR c) { return c >= L'a' && c <= L'z' ? (WCHAR)(c - 32) : c; }
static int wicmp(const WCHAR *a, const WCHAR *b)
{
    while (*a && wup(*a) == wup(*b)) { ++a; ++b; }
    return (int)wup(*a) - (int)wup(*b);
}
static int wprefix_i(const WCHAR *s, const WCHAR *prefix)
{
    while (*prefix) { if (wup(*s) != wup(*prefix)) return 0; ++s; ++prefix; }
    return 1;
}
static int wends_i(const WCHAR *s, const WCHAR *suffix)
{
    unsigned a = wlen(s), b = wlen(suffix);
    return a >= b && wicmp(s + a - b, suffix) == 0;
}

struct sb { WCHAR *p; unsigned cap, n; };
static void sb_init(struct sb *b, WCHAR *p, unsigned cap) { b->p = p; b->cap = cap; b->n = 0; if (cap) p[0] = 0; }
static void sb_str(struct sb *b, const WCHAR *s)
{
    while (*s && b->n + 1 < b->cap) b->p[b->n++] = *s++;
    if (b->cap) b->p[b->n] = 0;
}
static void sb_num(struct sb *b, unsigned long long v)
{
    WCHAR t[24]; unsigned n = 0;
    do { t[n++] = (WCHAR)(L'0' + v % 10); v /= 10; } while (v && n < 23);
    while (n && b->n + 1 < b->cap) b->p[b->n++] = t[--n];
    if (b->cap) b->p[b->n] = 0;
}
static void sb_num2(struct sb *b, unsigned v) { if (v < 10) sb_str(b, L"0"); sb_num(b, v); }

static const WCHAR *T(enum shell_string id) { return (g_en ? shell_en : shell_ko)[id]; }

static void resolve_language(void)
{
    if (g_langpref == L'K') g_en = 0;
    else if (g_langpref == L'E') g_en = 1;
    else {
        LANGID id = GetUserDefaultUILanguage();
        g_en = (id & 0x3ff) == 0x09;   /* English UI -> English; everything else keeps the Korean default */
    }
}

static void redraw(HWND w) { if (w) InvalidateRect(w, 0, FALSE); }
static void redraw_all(void) { redraw(g_desk); redraw(g_bar); redraw(g_menu); redraw(g_exp); redraw(g_runw); redraw(g_set); }

static void set_status(const WCHAR *s, int err)
{
    wcopy(g_status, 220, s); g_status_err = err;
    redraw(g_exp); redraw(g_set);
}

static const WCHAR *error_text(DWORD e)
{
    switch (e) {
    case ERROR_FILE_NOT_FOUND: return T(S_ERR_NOT_FOUND);
    case ERROR_PATH_NOT_FOUND: return T(S_ERR_PATH);
    case ERROR_ACCESS_DENIED: return T(S_ERR_ACCESS);
    case ERROR_SHARING_VIOLATION: return T(S_ERR_SHARING);
    case ERROR_FILE_EXISTS: case ERROR_ALREADY_EXISTS: return T(S_ERR_EXISTS);
    case ERROR_DIR_NOT_EMPTY: return T(S_ERR_NOTEMPTY);
    case ERROR_DISK_FULL: case ERROR_HANDLE_DISK_FULL: return T(S_ERR_DISK);
    case ERROR_BAD_EXE_FORMAT: return T(S_ERR_BADEXE);
    default: return 0;
    }
}

static void fail(enum shell_string op, DWORD e)
{
    struct sb b; const WCHAR *t = error_text(e);
    sb_init(&b, g_status, 220);
    sb_str(&b, T(S_FAILED)); sb_str(&b, L": "); sb_str(&b, T(op));
    if (t) { sb_str(&b, L" - "); sb_str(&b, t); }
    sb_str(&b, L" ("); sb_str(&b, T(S_ERROR)); sb_str(&b, L" "); sb_num(&b, e); sb_str(&b, L")");
    g_status_err = 1;
    printf("SHZ-SHELL FAIL op=%d error=%lu\n", (int)op, (unsigned long)e);
    redraw(g_exp); redraw(g_set);
}

static void note(enum shell_string what, const WCHAR *detail)
{
    struct sb b; sb_init(&b, g_status, 220);
    sb_str(&b, T(what));
    if (detail && detail[0]) { sb_str(&b, L": "); sb_str(&b, detail); }
    g_status_err = 0;
    redraw(g_exp); redraw(g_set);
}

/* ---------- drawing helpers ----------
 * Layout is written in design units (96 dpi pixels). Every primitive scales to device pixels with
 * S(); mouse input is converted back with D(). When the shared 32-bpp DIB back buffer exists the
 * primitives write pixels directly (gradients, alpha, rounded AA corners, shadows); text goes
 * through GDI onto the same DIB. gdi32 exports no AlphaBlend/GradientFill/RoundRect, so these
 * are done here on the DIB bits; without a DIB they degrade to opaque FillRect. */
static int g_scale = 100;
#define S(n) ((n) * g_scale / 100)
#define D(n) ((n) * 100 / g_scale)
static void client(HWND w, RECT *rc)
{
    GetClientRect(w, rc);
    rc->right = D(rc->right); rc->bottom = D(rc->bottom);
}
static uint32_t *g_bits;           /* back buffer pixels (top-down), stride g_bw */
static int g_bw, g_bh;
static HBITMAP g_dib;
static RECT g_dirty;                /* device pixels, current dirty rectangle */
static HDC g_dc;
static HFONT g_font;

static COLORREF mix(COLORREF a, COLORREF b, int i, int n)
{
    int ar = GetRValue(a), ag = GetGValue(a), ab = GetBValue(a);
    int br = GetRValue(b), bg = GetGValue(b), bb = GetBValue(b);
    if (n < 1) n = 1;
    return RGB(ar + (br - ar) * i / n, ag + (bg - ag) * i / n, ab + (bb - ab) * i / n);
}
static int rects_hit(int l, int t, int r, int b)
{
    return r > g_dirty.left && l < g_dirty.right && b > g_dirty.top && t < g_dirty.bottom;
}
static void blendpx(uint32_t *p, COLORREF c, unsigned a)
{
    uint32_t d = *p; unsigned ia = 255 - a;
    unsigned r = (GetRValue(c) * a + ((d >> 16) & 255) * ia + 127) / 255;
    unsigned g = (GetGValue(c) * a + ((d >> 8) & 255) * ia + 127) / 255;
    unsigned bl = (GetBValue(c) * a + (d & 255) * ia + 127) / 255;
    *p = (r << 16) | (g << 8) | bl;
}
static unsigned isqrt_u(unsigned v)
{
    unsigned lo = 0, hi = 65535;
    while (lo < hi) { unsigned m = (lo + hi + 1) / 2; if (m * m <= v) lo = m; else hi = m - 1; }
    return lo;
}
/* Corner coverage 0..255 of pixel (x,y) inside the rounded rectangle (device pixels). */
static unsigned corner_cov(int x, int y, int l, int t, int r, int b, int rad)
{
    int dx = 0, dy = 0, d16, c;
    if (rad <= 0) return 255;
    if (x < l + rad) dx = 2 * (l + rad) - (2 * x + 1); else if (x >= r - rad) dx = (2 * x + 1) - 2 * (r - rad);
    if (y < t + rad) dy = 2 * (t + rad) - (2 * y + 1); else if (y >= b - rad) dy = (2 * y + 1) - 2 * (b - rad);
    if (dx <= 0 || dy <= 0) return 255;
    d16 = (int)isqrt_u((unsigned)(dx * dx + dy * dy) * 64u);
    c = rad * 16 - d16 + 8;
    return c <= 0 ? 0 : c >= 16 ? 255 : (unsigned)(c * 255 / 16);
}
/* Device-pixel rounded gradient with alpha (0..255). */
static void px_round(int l, int t, int r, int b, int rad, COLORREF top, COLORREF bot, unsigned alpha)
{
    int x, y, h = b - t, x0 = l, x1 = r, y0 = t, y1 = b;
    if (r <= l || b <= t) return;
    if (x0 < g_dirty.left) x0 = g_dirty.left;
    if (x1 > g_dirty.right) x1 = g_dirty.right;
    if (y0 < g_dirty.top) y0 = g_dirty.top;
    if (y1 > g_dirty.bottom) y1 = g_dirty.bottom;
    if (rad * 2 > r - l) rad = (r - l) / 2;
    if (rad * 2 > b - t) rad = (b - t) / 2;
    if (!g_bits) {
        RECT rc; HBRUSH br = CreateSolidBrush(mix(top, bot, 1, 2));
        rc.left = l; rc.top = t; rc.right = r; rc.bottom = b;
        if (br) { FillRect(g_dc, &rc, br); DeleteObject(br); }
        return;
    }
    if (x1 > g_bw) x1 = g_bw;
    if (y1 > g_bh) y1 = g_bh;
    for (y = y0; y < y1; ++y) {
        COLORREF c = top == bot ? top : mix(top, bot, y - t, h);
        uint32_t *row = g_bits + (size_t)y * (size_t)g_bw;
        for (x = x0; x < x1; ++x) {
            unsigned a = alpha;
            if (rad) a = a * corner_cov(x, y, l, t, r, b, rad) / 255;
            if (a == 255) row[x] = ((uint32_t)GetRValue(c) << 16) | ((uint32_t)GetGValue(c) << 8) | GetBValue(c);
            else if (a) blendpx(&row[x], c, a);
        }
    }
}
static void fill(HDC dc, int l, int t, int r, int b, COLORREF c)
{
    (void)dc; px_round(S(l), S(t), S(r), S(b), 0, c, c, 255);
}
static void vgrad(HDC dc, int l, int t, int r, int b, COLORREF top, COLORREF bot)
{
    (void)dc; px_round(S(l), S(t), S(r), S(b), 0, top, bot, 255);
}
static void rgrad(int l, int t, int r, int b, int rad, COLORREF top, COLORREF bot, unsigned alpha)
{
    px_round(S(l), S(t), S(r), S(b), S(rad), top, bot, alpha);
}
static void frame(HDC dc, int l, int t, int r, int b, COLORREF c)
{
    fill(dc, l, t, r, t + 1, c); fill(dc, l, b - 1, r, b, c);
    fill(dc, l, t, l + 1, b, c); fill(dc, r - 1, t, r, b, c);
}
/* Rounded 1px outline plus fill. */
static void rbox(int l, int t, int r, int b, int rad, COLORREF edge, COLORREF top, COLORREF bot)
{
    rgrad(l, t, r, b, rad, edge, edge, 255);
    px_round(S(l) + 1, S(t) + 1, S(r) - 1, S(b) - 1, S(rad) > 1 ? S(rad) - 1 : 0, top, bot, 255);
}
/* Soft drop shadow made of expanding translucent rounded rectangles. */
static void shadow(int l, int t, int r, int b, int rad, unsigned strength)
{
    int i;
    for (i = 4; i >= 1; --i)
        px_round(S(l) - i, S(t) - i + S(2), S(r) + i, S(b) + i + S(2), S(rad) + i, RGB(0,0,0), RGB(0,0,0), strength / (unsigned)(i + 1));
}
static void text(HDC dc, int l, int t, int r, int b, const WCHAR *s, COLORREF c, UINT flags)
{
    RECT rc; (void)dc;
    rc.left = S(l); rc.top = S(t); rc.right = S(r); rc.bottom = S(b);
    if (!rects_hit(rc.left, rc.top, rc.right, rc.bottom)) return;
    SetBkMode(g_dc, TRANSPARENT); SetTextColor(g_dc, c);
    DrawTextW(g_dc, s, -1, &rc, flags | DT_NOPREFIX | DT_SINGLELINE | DT_END_ELLIPSIS);
}
#define TL (DT_LEFT | DT_VCENTER)
#define TC (DT_CENTER | DT_VCENTER)
#define TR (DT_RIGHT | DT_VCENTER)

/* state: 0 normal, 1 hover, 2 pressed, 3 focus/default */
static void button(HDC dc, int x, int y, int w, int h, const WCHAR *s, int state)
{
    COLORREF top = state == 2 ? RGB(150,172,198) : state == 1 ? RGB(246,250,255) : RGB(232,239,247);
    COLORREF bot = state == 2 ? RGB(190,206,224) : state == 1 ? RGB(204,224,246) : RGB(184,198,214);
    (void)dc;
    if (state != 2) shadow(x, y, x + w, y + h, 4, 40);
    rbox(x, y, x + w, y + h, 4, state == 1 || state == 3 ? C_ACCENT : C_DIM, top, bot);
    text(dc, x + 4, y + (state == 2 ? 1 : 0), x + w - 4, y + h + (state == 2 ? 1 : 0), s, C_TEXT, TC);
}

/* Visible caret at character index pos of s, drawn inside [l,r) x [t,b). */
static void caret(const WCHAR *s, unsigned pos, int l, int t, int b)
{
    SIZE sz; int x;
    if (((GetTickCount() / 500) & 1) != 0) return;
    sz.cx = 0; sz.cy = 0;
    if (pos) GetTextExtentPoint32W(g_dc, s, (int)pos, &sz);
    x = l + D(sz.cx);
    fill(0, x, t + 3, x + 1, b - 3, C_TEXT);
}

static void fmt_size(struct sb *b, unsigned long long v)
{
    if (v < 1024) { sb_num(b, v); sb_str(b, L" B"); }
    else if (v < 1024ull * 1024) { sb_num(b, (v + 1023) / 1024); sb_str(b, L" KB"); }
    else { sb_num(b, (v + 1048575) / 1048576); sb_str(b, L" MB"); }
}

/* ---------- configuration persistence ---------- */
static int cfg_encode(WCHAR pref, char out[18])
{
    static const char head[] = "SHZSHELL1\nlang=";
    unsigned i;
    if (pref != L'A' && pref != L'K' && pref != L'E') return 0;
    for (i = 0; i < 15; ++i) out[i] = head[i];
    out[15] = (char)pref; out[16] = '\n'; out[17] = 0;
    return 1;
}
/* 1 loaded, 0 absent, -1 error. */
static int cfg_read(const WCHAR *path, WCHAR *pref, DWORD *err)
{
    char buf[18], want[18]; DWORD got = 0, total = 0, size; HANDLE f; unsigned i;
    f = CreateFileW(path, GENERIC_READ, FILE_SHARE_READ, 0, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, 0);
    if (f == INVALID_HANDLE_VALUE) {
        DWORD e = GetLastError();
        if (e == ERROR_FILE_NOT_FOUND || e == ERROR_PATH_NOT_FOUND) { *err = 0; return 0; }
        *err = e ? e : ERROR_READ_FAULT; return -1;
    }
    size = GetFileSize(f, 0);
    if (size != 17) { CloseHandle(f); *err = ERROR_INVALID_DATA; return -1; }
    while (total < 17) {
        if (!ReadFile(f, buf + total, 17 - total, &got, 0) || !got) { *err = GetLastError(); CloseHandle(f); if (!*err) *err = ERROR_READ_FAULT; return -1; }
        total += got;
    }
    CloseHandle(f);
    buf[17] = 0;
    for (i = 0; i < 3; ++i) {
        static const WCHAR opts[3] = { L'A', L'K', L'E' };
        cfg_encode(opts[i], want);
        if (memcmp(buf, want, 17) == 0) { *pref = opts[i]; *err = 0; return 1; }
    }
    *err = ERROR_INVALID_DATA; return -1;
}
static int cfg_save(WCHAR pref, DWORD *err)
{
    char bytes[18]; HANDLE f; DWORD written = 0, total = 0; WCHAR back = 0; int ok = 1;
    if (!cfg_encode(pref, bytes)) { *err = ERROR_INVALID_PARAMETER; return 0; }
    f = CreateFileW(CFG_TMP, GENERIC_WRITE, 0, 0, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, 0);
    if (f == INVALID_HANDLE_VALUE) { *err = GetLastError(); return 0; }
    while (total < 17) {
        if (!WriteFile(f, bytes + total, 17 - total, &written, 0) || !written) { *err = GetLastError(); ok = 0; break; }
        total += written;
    }
    if (ok && !FlushFileBuffers(f)) { *err = GetLastError(); ok = 0; }
    if (!CloseHandle(f) && ok) { *err = GetLastError(); ok = 0; }
    if (ok && cfg_read(CFG_TMP, &back, err) != 1) ok = 0;
    if (ok && back != pref) { *err = ERROR_INVALID_DATA; ok = 0; }
    if (ok && !MoveFileExW(CFG_TMP, CFG_PATH, MOVEFILE_REPLACE_EXISTING)) { *err = GetLastError(); ok = 0; }
    if (!ok) { DWORD e = *err; DeleteFileW(CFG_TMP); *err = e ? e : ERROR_WRITE_FAULT; return 0; }
    *err = 0; return 1;
}

/* ---------- process launch / tracking ---------- */
static void base_name(WCHAR *out, unsigned cap, const WCHAR *cmd)
{
    WCHAR tok[PATH_CAP]; unsigned i = 0, j = 0, start = 0;
    if (cmd[0] == L'"') { i = 1; while (cmd[i] && cmd[i] != L'"' && j + 1 < PATH_CAP) tok[j++] = cmd[i++]; }
    else while (cmd[i] && cmd[i] != L' ' && j + 1 < PATH_CAP) tok[j++] = cmd[i++];
    tok[j] = 0;
    for (i = 0; tok[i]; ++i) if (tok[i] == L'\\' || tok[i] == L'/') start = i + 1;
    wcopy(out, cap, tok + start);
}

static void poll_procs(void)
{
    unsigned i;
    for (i = 0; i < PROC_CAP; ++i) {
        DWORD r, code = 0;
        if (!g_procs[i].h) continue;
        r = WaitForSingleObject(g_procs[i].h, 0);
        if (r == WAIT_TIMEOUT) continue;
        if (r == WAIT_OBJECT_0 && GetExitCodeProcess(g_procs[i].h, &code)) {
            struct sb b; sb_init(&b, g_status, 220);
            sb_str(&b, g_procs[i].name); sb_str(&b, L": "); sb_str(&b, T(S_EXITED)); sb_str(&b, L" "); sb_num(&b, code);
            g_status_err = 0;
            printf("SHZ-SHELL EXIT pid=%lu code=%lu\n", (unsigned long)g_procs[i].pid, (unsigned long)code);
        } else fail(S_OP_STATUS, GetLastError());
        CloseHandle(g_procs[i].h); g_procs[i].h = 0;
        redraw(g_exp); redraw(g_set);
    }
}

static int free_proc_slot(void)
{
    unsigned i;
    for (i = 0; i < PROC_CAP; ++i) if (!g_procs[i].h) return (int)i;
    return -1;
}

static void track(int slot, HANDLE h, DWORD pid, const WCHAR *cmd)
{
    g_procs[slot].h = h; g_procs[slot].pid = pid;
    base_name(g_procs[slot].name, 40, cmd);
    {
        struct sb b; sb_init(&b, g_status, 220);
        sb_str(&b, g_procs[slot].name); sb_str(&b, L": "); sb_str(&b, T(S_LAUNCHED)); sb_str(&b, L" (PID "); sb_num(&b, pid); sb_str(&b, L")");
        g_status_err = 0;
    }
    printf("SHZ-SHELL LAUNCH pid=%lu\n", (unsigned long)pid);
    redraw(g_exp); redraw(g_set);
}

/* cmdline: a command line (program path possibly quoted, plus arguments). */
static int launch(const WCHAR *cmdline, const WCHAR *dir)
{
    STARTUPINFOW si; PROCESS_INFORMATION pi; WCHAR buf[PATH_CAP * 2]; int slot; DWORD e;
    if (!cmdline[0]) return 0;
    slot = free_proc_slot();
    if (slot < 0) { note(S_NO_SLOT, 0); g_status_err = 1; return 0; }
    wcopy(buf, PATH_CAP * 2, cmdline);
    memset(&si, 0, sizeof si); si.cb = sizeof si;
    memset(&pi, 0, sizeof pi);
    if (CreateProcessW(0, buf, 0, 0, FALSE, 0, 0, dir && dir[0] ? dir : 0, &si, &pi)) {
        CloseHandle(pi.hThread);
        track(slot, pi.hProcess, pi.dwProcessId, cmdline);
        return 1;
    }
    e = GetLastError();
    /* Only formats CreateProcess cannot run (documents, scripts) go to the
       association path. Access/permission failures are never retried elsewhere. */
    if (e == ERROR_BAD_EXE_FORMAT || e == ERROR_FILE_NOT_FOUND || e == ERROR_PATH_NOT_FOUND) {
        SHELLEXECUTEINFOW sx; WCHAR file[PATH_CAP]; unsigned i = 0, j = 0; const WCHAR *args = L"";
        if (cmdline[0] == L'"') {
            i = 1; while (cmdline[i] && cmdline[i] != L'"' && j + 1 < PATH_CAP) file[j++] = cmdline[i++];
            if (cmdline[i] == L'"') ++i;
        } else while (cmdline[i] && cmdline[i] != L' ' && j + 1 < PATH_CAP) file[j++] = cmdline[i++];
        file[j] = 0;
        while (cmdline[i] == L' ') ++i;
        args = cmdline + i;
        memset(&sx, 0, sizeof sx);
        sx.cbSize = sizeof sx; sx.fMask = SEE_MASK_NOCLOSEPROCESS; sx.lpVerb = L"open"; sx.lpFile = file;
        sx.lpParameters = args[0] ? args : 0; sx.lpDirectory = dir && dir[0] ? dir : 0; sx.nShow = SW_SHOWNORMAL;
        SetLastError(0);
        if (ShellExecuteExW(&sx)) {
            if (sx.hProcess) {
                DWORD pid = 0; /* GetProcessId is not required for tracking */
                track(slot, sx.hProcess, pid, file);
            } else { note(S_LAUNCHED, file); }
            return 1;
        }
        { DWORD se = GetLastError(); fail(S_OP_LAUNCH, se ? se : e); }
        return 0;
    }
    fail(S_OP_LAUNCH, e);
    return 0;
}

/* ---------- explorer model ---------- */
static int row_less(unsigned a, unsigned b)
{
    int da = (g_rows[a].attrs & FILE_ATTRIBUTE_DIRECTORY) != 0, db = (g_rows[b].attrs & FILE_ATTRIBUTE_DIRECTORY) != 0;
    if (da != db) return da > db;
    return wicmp(g_rows[a].name, g_rows[b].name) < 0;
}

static int join_path(WCHAR *out, const WCHAR *dir, const WCHAR *name)
{
    unsigned a = wlen(dir), b = wlen(name);
    int slash = a && dir[a - 1] != L'\\';
    if (a + b + (unsigned)slash + 1 > PATH_CAP) return 0;
    wcopy(out, PATH_CAP, dir);
    if (slash) out[a++] = L'\\';
    wcopy(out + a, PATH_CAP - a, name);
    return 1;
}

/* Enumerates g_dir into g_rows. Returns 1 on success, otherwise 0 with *err set. */
static int list_dir(DWORD *err)
{
    WCHAR pattern[PATH_CAP]; WIN32_FIND_DATAW fd; HANDLE h; unsigned i, j;
    g_count = 0; g_total = 0; g_top = 0; g_sel = -1; g_del_armed = -1;
    if (!join_path(pattern, g_dir, L"*")) { *err = ERROR_BUFFER_OVERFLOW; return 0; }
    h = FindFirstFileW(pattern, &fd);
    if (h == INVALID_HANDLE_VALUE) {
        DWORD e = GetLastError();
        if (e == ERROR_FILE_NOT_FOUND) { *err = 0; return 1; }   /* no entries */
        *err = e ? e : ERROR_PATH_NOT_FOUND; return 0;
    }
    do {
        if (fd.cFileName[0] == L'.' && (!fd.cFileName[1] || (fd.cFileName[1] == L'.' && !fd.cFileName[2]))) continue;
        ++g_total;
        if (g_count < ROW_CAP) {
            struct row *r = &g_rows[g_count];
            wcopy(r->name, PATH_CAP, fd.cFileName);
            r->attrs = fd.dwFileAttributes;
            r->size = ((unsigned long long)fd.nFileSizeHigh << 32) | fd.nFileSizeLow;
            g_order[g_count] = g_count; ++g_count;
        }
    } while (FindNextFileW(h, &fd));
    {
        DWORD e = GetLastError();
        FindClose(h);
        if (e != ERROR_NO_MORE_FILES) { *err = e ? e : ERROR_READ_FAULT; g_count = 0; g_total = 0; return 0; }
    }
    for (i = 1; i < g_count; ++i) {
        unsigned v = g_order[i];
        for (j = i; j > 0 && row_less(v, g_order[j - 1]); --j) g_order[j] = g_order[j - 1];
        g_order[j] = v;
    }
    *err = 0; return 1;
}

static void refresh(void)
{
    DWORD e;
    if (!list_dir(&e)) fail(S_OP_LIST, e);
    else { WCHAR t[40]; struct sb b; sb_init(&b, t, 40); sb_num(&b, g_total); sb_str(&b, T(S_ITEMS)); if (g_total > g_count) sb_str(&b, T(S_TRUNCATED)); note(S_OP_LIST, t); }
    redraw(g_exp);
}

static void navigate(const WCHAR *path)
{
    WCHAR old[PATH_CAP]; DWORD e;
    wcopy(old, PATH_CAP, g_dir);
    wcopy(g_dir, PATH_CAP, path);
    if (list_dir(&e)) { refresh(); return; }
    wcopy(g_dir, PATH_CAP, old);
    { DWORD e2; list_dir(&e2); }
    fail(S_OP_LIST, e);
    redraw(g_exp);
}

static void up_dir(void)
{
    unsigned n = wlen(g_dir), i;
    WCHAR p[PATH_CAP];
    if (n > 0 && g_dir[n - 1] == L'\\') --n;
    wcopy(p, PATH_CAP, g_dir); p[n] = 0;
    for (i = n; i > 0 && p[i - 1] != L'\\'; --i) {}
    if (i == 0) return;                       /* already a bare root */
    if (i <= 3 && p[1] == L':') { p[3] = 0; if (n <= 2) return; }
    else p[i - 1] = 0;
    if (!p[0]) return;
    navigate(p);
}

static struct row *sel_row(void)
{
    if (g_sel < 0 || (unsigned)g_sel >= g_count) return 0;
    return &g_rows[g_order[g_sel]];
}

static void ensure_visible(void)
{
    RECT r; unsigned vis;
    if (g_sel < 0) return;
    client(g_exp, &r);
    vis = r.bottom > LIST_Y + 40 ? (unsigned)(r.bottom - LIST_Y - 40) / ROW_H : 1;
    if ((unsigned)g_sel < g_top) g_top = (unsigned)g_sel;
    if ((unsigned)g_sel >= g_top + vis) g_top = (unsigned)g_sel - vis + 1;
}

static void open_selected(void)
{
    struct row *r = sel_row(); WCHAR full[PATH_CAP], cmd[PATH_CAP + 4];
    if (!r) { note(S_NOTHING_SELECTED, 0); return; }
    if (!join_path(full, g_dir, r->name)) { fail(S_OP_OPEN, ERROR_BUFFER_OVERFLOW); return; }
    if (r->attrs & FILE_ATTRIBUTE_DIRECTORY) { navigate(full); return; }
    cmd[0] = L'"'; wcopy(cmd + 1, PATH_CAP + 2, full); cmd[wlen(cmd) + 1] = 0; cmd[wlen(cmd)] = L'"';
    launch(cmd, g_dir);
}

static int valid_name(const WCHAR *n)
{
    unsigned i;
    if (!n[0] || wlen(n) >= 255) return 0;
    if (n[0] == L'.' && (!n[1] || (n[1] == L'.' && !n[2]))) return 0;
    for (i = 0; n[i]; ++i) {
        WCHAR c = n[i];
        if (c < 32 || c == L'\\' || c == L'/' || c == L':' || c == L'*' || c == L'?' || c == L'"' || c == L'<' || c == L'>' || c == L'|') return 0;
    }
    return 1;
}

static void select_name(const WCHAR *name)
{
    unsigned i;
    for (i = 0; i < g_count; ++i) if (wicmp(g_rows[g_order[i]].name, name) == 0) { g_sel = (int)i; ensure_visible(); return; }
}

static void new_folder(void)
{
    unsigned n; WCHAR name[80], full[PATH_CAP];
    for (n = 1; n < 100; ++n) {
        struct sb b; sb_init(&b, name, 80); sb_str(&b, T(S_NEW_FOLDER_NAME));
        if (n > 1) { sb_str(&b, L" ("); sb_num(&b, n); sb_str(&b, L")"); }
        if (!join_path(full, g_dir, name)) { fail(S_OP_MKDIR, ERROR_BUFFER_OVERFLOW); return; }
        if (CreateDirectoryW(full, 0)) {
            DWORD e; list_dir(&e);
            if (e) fail(S_OP_LIST, e); else { select_name(name); note(S_CREATED, name); }
            redraw(g_exp); return;
        }
        { DWORD e = GetLastError(); if (e != ERROR_ALREADY_EXISTS && e != ERROR_FILE_EXISTS) { fail(S_OP_MKDIR, e); return; } }
    }
    fail(S_OP_MKDIR, ERROR_ALREADY_EXISTS);
}

static void delete_selected(void)
{
    struct row *r = sel_row(); WCHAR full[PATH_CAP]; BOOL ok; DWORD e;
    if (!r) { note(S_NOTHING_SELECTED, 0); g_status_err = 1; redraw(g_exp); return; }
    if (g_del_armed != g_sel) { g_del_armed = g_sel; note(S_DELETE_AGAIN, r->name); g_status_err = 1; redraw(g_exp); return; }
    g_del_armed = -1;
    if (!join_path(full, g_dir, r->name)) { fail(S_OP_DELETE, ERROR_BUFFER_OVERFLOW); return; }
    ok = (r->attrs & FILE_ATTRIBUTE_DIRECTORY) ? RemoveDirectoryW(full) : DeleteFileW(full);
    if (!ok) { fail(S_OP_DELETE, GetLastError()); return; }
    { WCHAR nm[PATH_CAP]; wcopy(nm, PATH_CAP, r->name);
      list_dir(&e); if (e) fail(S_OP_LIST, e); else note(S_DELETED, nm); }
    redraw(g_exp);
}

static void begin_edit(int mode)
{
    if (mode == M_RENAME) {
        struct row *r = sel_row();
        if (!r) { note(S_NOTHING_SELECTED, 0); g_status_err = 1; redraw(g_exp); return; }
        wcopy(g_input, PATH_CAP, r->name);
    } else wcopy(g_input, PATH_CAP, g_dir);
    g_input_len = wlen(g_input); g_input_pos = g_input_len; g_mode = mode;
    redraw(g_exp);
}

static void commit_edit(void)
{
    int mode = g_mode; g_mode = M_NONE;
    if (mode == M_PATH) {
        if (!g_input[0]) { note(S_PATH_TOO_LONG, 0); g_status_err = 1; redraw(g_exp); return; }
        navigate(g_input);
    } else if (mode == M_RENAME) {
        struct row *r = sel_row(); WCHAR from[PATH_CAP], to[PATH_CAP], newname[PATH_CAP]; DWORD e;
        if (!r) return;
        if (!valid_name(g_input)) { note(S_BAD_NAME, 0); g_status_err = 1; redraw(g_exp); return; }
        wcopy(newname, PATH_CAP, g_input);
        if (!join_path(from, g_dir, r->name) || !join_path(to, g_dir, newname)) { fail(S_OP_RENAME, ERROR_BUFFER_OVERFLOW); return; }
        if (!MoveFileW(from, to)) { fail(S_OP_RENAME, GetLastError()); return; }
        list_dir(&e); if (e) fail(S_OP_LIST, e); else { select_name(newname); note(S_RENAMED, newname); }
        redraw(g_exp);
    }
}

static void copy_selected(void)
{
    struct row *r = sel_row();
    if (!r) { note(S_NOTHING_SELECTED, 0); g_status_err = 1; redraw(g_exp); return; }
    if (!join_path(g_clip, g_dir, r->name)) { fail(S_OP_COPY, ERROR_BUFFER_OVERFLOW); return; }
    g_clip_valid = 1; note(S_COPIED, r->name); redraw(g_exp);
}

/* Recursive copy with bounded depth. Stops at the first failing API and returns its error. */
static DWORD copy_tree(const WCHAR *src, const WCHAR *dst, int depth)
{
    DWORD attrs = GetFileAttributesW(src);
    if (attrs == INVALID_FILE_ATTRIBUTES) return GetLastError();
    if (!(attrs & FILE_ATTRIBUTE_DIRECTORY)) return CopyFileW(src, dst, TRUE) ? 0 : GetLastError();
    if (depth >= COPY_DEPTH) return ERROR_BUFFER_OVERFLOW;
    if (!CreateDirectoryW(dst, 0)) return GetLastError();
    {
        WCHAR pat[PATH_CAP]; WIN32_FIND_DATAW fd; HANDLE h; DWORD err = 0;
        if (!join_path(pat, src, L"*")) return ERROR_BUFFER_OVERFLOW;
        h = FindFirstFileW(pat, &fd);
        if (h == INVALID_HANDLE_VALUE) { DWORD e = GetLastError(); return e == ERROR_FILE_NOT_FOUND ? 0 : e; }
        do {
            WCHAR s2[PATH_CAP], d2[PATH_CAP];
            if (fd.cFileName[0] == L'.' && (!fd.cFileName[1] || (fd.cFileName[1] == L'.' && !fd.cFileName[2]))) continue;
            if (!join_path(s2, src, fd.cFileName) || !join_path(d2, dst, fd.cFileName)) { err = ERROR_BUFFER_OVERFLOW; break; }
            err = copy_tree(s2, d2, depth + 1);
            if (err) break;
        } while (FindNextFileW(h, &fd));
        if (!err) { DWORD e = GetLastError(); if (e != ERROR_NO_MORE_FILES) err = e ? e : ERROR_READ_FAULT; }
        FindClose(h);
        return err;
    }
}

static void paste_clip(void)
{
    WCHAR name[PATH_CAP], dst[PATH_CAP], srcdir[PATH_CAP]; unsigned i, start = 0, n; DWORD e;
    if (!g_clip_valid) { note(S_NOTHING_COPIED, 0); g_status_err = 1; redraw(g_exp); return; }
    for (i = 0; g_clip[i]; ++i) if (g_clip[i] == L'\\') start = i + 1;
    wcopy(name, PATH_CAP, g_clip + start);
    if (!join_path(dst, g_dir, name)) { fail(S_OP_COPY, ERROR_BUFFER_OVERFLOW); return; }
    n = wlen(g_clip);
    wcopy(srcdir, PATH_CAP, g_clip);
    if (n + 1 < PATH_CAP) { srcdir[n] = L'\\'; srcdir[n + 1] = 0; }
    if (wprefix_i(dst, srcdir)) { fail(S_OP_COPY, ERROR_INVALID_PARAMETER); return; }   /* folder into itself */
    e = copy_tree(g_clip, dst, 0);
    if (e) { fail(S_OP_COPY, e); return; }
    { DWORD le; list_dir(&le); if (le) fail(S_OP_LIST, le); else { select_name(name); note(S_PASTED, name); } }
    redraw(g_exp);
}

/* ---------- start menu model ---------- */
static void menu_add(int kind, const WCHAR *label, const WCHAR *path)
{
    struct mitem *m;
    if (g_item_count >= MENU_CAP) return;
    m = &g_items[g_item_count++];
    m->kind = kind; wcopy(m->label, 64, label); wcopy(m->path, PATH_CAP, path ? path : L"");
}

static void build_menu(void)
{
    WIN32_FIND_DATAW fd; HANDLE h; unsigned apps = 0;
    g_item_count = 0;
    menu_add(MI_EXPLORER, T(S_EXPLORER), 0);
    menu_add(MI_RUN, T(S_RUN), 0);
    menu_add(MI_SETTINGS, T(S_SETTINGS), 0);
    menu_add(MI_SEP, L"", 0);
    menu_add(MI_HEADER, T(S_PROGRAMS), 0);
    h = FindFirstFileW(SYS_DIR L"\\*.EXE", &fd);
    if (h != INVALID_HANDLE_VALUE) {
        do {
            WCHAR full[PATH_CAP];
            if (fd.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) continue;
            if (wicmp(fd.cFileName, L"SHIZUKU_SHELL.EXE") == 0) continue;
            if (apps >= 6 || !join_path(full, SYS_DIR, fd.cFileName)) break;
            menu_add(MI_APP, fd.cFileName, full); ++apps;
        } while (FindNextFileW(h, &fd));
        FindClose(h);
    }
    if (!apps) menu_add(MI_HEADER, T(S_NO_PROGRAMS), 0);
    menu_add(MI_SEP, L"", 0);
    menu_add(MI_END, T(S_END_SHELL), 0);
}

static int item_h(int kind) { return kind == MI_SEP ? 8 : 26; }
static int menu_height(void)
{
    unsigned i; int h = 8;
    for (i = 0; i < g_item_count; ++i) h += item_h(g_items[i].kind);
    return h;
}

static void close_menu(void)
{
    if (!g_menu_open) return;
    g_menu_open = 0; g_menu_hot = -1; g_anim = 6;
    KillTimer(g_bar, 2);
    if (GetCapture() == g_menu) ReleaseCapture();
    ShowWindow(g_menu, SW_HIDE);
    redraw(g_bar);
}

static void menu_place(int h)   /* h in design units */
{
    SetWindowPos(g_menu, HWND_TOPMOST, 0, g_h - S(BAR_H) - S(h), S(280), S(h), SWP_NOACTIVATE);
}

static void open_menu(void)
{
    build_menu();
    g_menu_full = menu_height();
    g_anim = 0;
    if (SetTimer(g_bar, 2, 30, 0)) menu_place(g_menu_full / 6);
    else { g_anim = 6; menu_place(g_menu_full); }
    ShowWindow(g_menu, SW_SHOWNOACTIVATE);
    g_menu_open = 1; g_menu_hot = -1;
    SetCapture(g_menu);
    redraw(g_menu); redraw(g_bar);
}

static void menu_step(void)
{
    if (!g_menu_open) { KillTimer(g_bar, 2); g_anim = 6; return; }
    if (g_anim < 6) ++g_anim;
    menu_place(g_menu_full * g_anim / 6);
    if (g_anim >= 6) KillTimer(g_bar, 2);
    redraw(g_menu);
}

/* ---------- window opening ---------- */
static void show_window(HWND w)
{
    ShowWindow(w, SW_SHOW);
    if (IsIconic(w)) ShowWindow(w, SW_RESTORE);
    BringWindowToTop(w);
    SetForegroundWindow(w); SetFocus(w);
    redraw(w); redraw(g_bar);
}
static void show_explorer(void) { if (!g_total && !g_count) refresh(); show_window(g_exp); }
static void show_run(void) { g_run_len = 0; g_run_pos = 0; g_run_text[0] = 0; show_window(g_runw); }
static void show_settings(void) { show_window(g_set); }

static void end_shell(void)
{
    if (MessageBoxW(g_desk, T(S_END_CONFIRM), T(S_END_SHELL), MB_YESNO | MB_ICONQUESTION) != IDYES) return;
    printf("SHZ-SHELL EXIT requested=1\n");
    PostQuitMessage(0);
}

static void menu_action(const struct mitem *m)
{
    close_menu();
    switch (m->kind) {
    case MI_EXPLORER: show_explorer(); break;
    case MI_RUN: show_run(); break;
    case MI_SETTINGS: show_settings(); break;
    case MI_APP: { WCHAR cmd[PATH_CAP + 4]; cmd[0] = L'"'; wcopy(cmd + 1, PATH_CAP, m->path); { unsigned n = wlen(cmd); cmd[n] = L'"'; cmd[n + 1] = 0; } launch(cmd, 0); break; }
    case MI_END: end_shell(); break;
    default: break;
    }
}

/* ---------- task list ---------- */
static BOOL CALLBACK enum_tasks(HWND w, LPARAM lp)
{
    (void)lp;
    if (w == g_desk || w == g_bar || w == g_menu) return TRUE;
    if (!IsWindowVisible(w) || GetWindow(w, GW_OWNER)) return TRUE;
    if (g_task_count >= TASK_CAP) return FALSE;
    {
        struct task *t = &g_tasks[g_task_count];
        t->title[0] = 0;
        if (GetWindowTextW(w, t->title, 48) <= 0) return TRUE;
        t->hwnd = w; ++g_task_count;
    }
    return TRUE;
}

/* Returns nonzero when the list differs from the previous one. */
static int refresh_tasks(void)
{
    struct task old[TASK_CAP]; unsigned old_count = g_task_count, i, same = 1;
    memcpy(old, g_tasks, sizeof old);
    g_task_count = 0;
    EnumWindows(enum_tasks, 0);
    if (old_count != g_task_count) return 1;
    for (i = 0; i < g_task_count; ++i) if (old[i].hwnd != g_tasks[i].hwnd || wicmp(old[i].title, g_tasks[i].title)) same = 0;
    return !same;
}

static void bar_geometry(int *tasks_l, int *tasks_r, int *tray_l)
{
    *tray_l = D(g_w) - 176; *tasks_l = 100; *tasks_r = *tray_l - 8;
}
static int task_width(int l, int r)
{
    int w = g_task_count ? (r - l) / (int)g_task_count : 160;
    return w > 160 ? 160 : w < 40 ? 40 : w;
}

static void activate_task(unsigned i)
{
    HWND w;
    if (i >= g_task_count) return;
    w = g_tasks[i].hwnd;
    if (!IsWindow(w)) return;
    if (IsIconic(w)) ShowWindow(w, SW_RESTORE);
    BringWindowToTop(w); SetForegroundWindow(w);
    redraw(g_bar);
}

/* ---------- widget geometry (design units) ---------- */
static void rc_set(RECT *rc, int l, int t, int r, int b) { rc->left = l; rc->top = t; rc->right = r; rc->bottom = b; }
static int hit(int x, int y, int l, int t, int r, int b) { return x >= l && x < r && y >= t && y < b; }
static int widx(HWND w)
{
    return w == g_bar ? W_BAR : w == g_exp ? W_EXP : w == g_set ? W_SET : w == g_runw ? W_RUN : w == g_desk ? W_DESK : -1;
}
#define SET_LANG_Y (14 + 24 * 4 + 30)

/* Returns the widget id under (x,y) and its rectangle, or -1. */
static int hot_id(HWND hwnd, int x, int y, RECT *rc)
{
    RECT c; unsigned i, mask; int dx = 60;
    if (hwnd == g_bar) {
        int tl, tr, tray, w;
        if (hit(x, y, 4, 3, 92, BAR_H - 3)) { rc_set(rc, 4, 3, 92, BAR_H - 3); return 0; }
        bar_geometry(&tl, &tr, &tray);
        if (x >= tray) { rc_set(rc, tray, 0, tray + 400, BAR_H); return 100; }
        w = task_width(tl, tr);
        if (x >= tl && x < tl + w * (int)g_task_count && y >= 4 && y < BAR_H - 3) {
            int k = (x - tl) / w; rc_set(rc, tl + k * w, 4, tl + k * w + w - 3, BAR_H - 3); return 1 + k;
        }
    } else if (hwnd == g_exp) {
        client(g_exp, &c);
        if (y >= 4 && y < 28 && x >= 4 && x < 4 + 8 * 86 && (x - 4) % 86 < 82) { int b = (x - 4) / 86; rc_set(rc, 4 + b * 86, 4, 4 + b * 86 + 82, 28); return b; }
        if (hit(x, y, 4, 34, c.right - 4, 56)) { rc_set(rc, 4, 34, c.right - 4, 56); return 50; }
        mask = GetLogicalDrives();
        if (y >= 60 && y < 80) {
            for (i = 0; i < 26 && dx < c.right - 40; ++i) if (mask & (1u << i)) {
                if (x >= dx && x < dx + 34) { rc_set(rc, dx, 60, dx + 34, 80); return 100 + (int)i; }
                dx += 38;
            }
        }
        if (y >= LIST_Y && y < c.bottom - 24) {
            unsigned idx = g_top + (unsigned)(y - LIST_Y) / ROW_H;
            if (idx < g_count) { int yy = LIST_Y + (int)(idx - g_top) * ROW_H; rc_set(rc, 0, yy, c.right, yy + ROW_H); return 1000 + (int)idx; }
        }
    } else if (hwnd == g_set) {
        for (i = 0; i < 3; ++i) if (hit(x, y, 100 + (int)i * 88, SET_LANG_Y, 180 + (int)i * 88, SET_LANG_Y + 24)) {
            rc_set(rc, 100 + (int)i * 88, SET_LANG_Y, 180 + (int)i * 88, SET_LANG_Y + 24); return (int)i;
        }
    } else if (hwnd == g_runw) {
        client(g_runw, &c);
        if (hit(x, y, c.right - 180, c.bottom - 36, c.right - 100, c.bottom - 10)) { rc_set(rc, c.right - 180, c.bottom - 36, c.right - 100, c.bottom - 10); return 0; }
        if (hit(x, y, c.right - 92, c.bottom - 36, c.right - 12, c.bottom - 10)) { rc_set(rc, c.right - 92, c.bottom - 36, c.right - 12, c.bottom - 10); return 1; }
    } else if (hwnd == g_desk) {
        for (i = 0; i < 3; ++i) if (hit(x, y, 16, 14 + (int)i * 100, 76, 90 + (int)i * 100)) { rc_set(rc, 8, 8 + (int)i * 100, 84, 96 + (int)i * 100); return (int)i; }
    }
    return -1;
}

/* Invalidate only a design-unit rectangle. */
static void redraw_r(HWND w, const RECT *r)
{
    RECT px;
    if (!w) return;
    px.left = S(r->left) - 2; px.top = S(r->top) - 2; px.right = S(r->right) + 6; px.bottom = S(r->bottom) + 8;
    if (px.left < 0) px.left = 0;
    if (px.top < 0) px.top = 0;
    InvalidateRect(w, &px, FALSE);
}

static int wstate(HWND w, int id)
{
    int k = widx(w);
    if (k < 0 || id < 0) return 0;
    if (g_press_w == k && g_press_id == id) return 2;
    return g_hot[k] == id ? 1 : 0;
}

static void set_hot(HWND w, int id, const RECT *rc)
{
    int k = widx(w);
    if (k < 0 || g_hot[k] == id) return;
    if (g_hot[k] >= 0) redraw_r(w, &g_hot_rc[k]);
    g_hot[k] = id;
    if (id >= 0) { g_hot_rc[k] = *rc; redraw_r(w, rc); }
}

/* ---------- painting ---------- */
static void paint_icon(HDC dc, int x, int y, int kind, int state)
{
    if (state) rgrad(x - 8, y - 6, x + 64, y + 78, 8, RGB(110,160,220), RGB(60,104,172), state == 2 ? 150 : 100);
    if (kind == 0) {        /* folder */
        shadow(x, y + 8, x + 48, y + 44, 4, 70);
        rbox(x, y + 6, x + 26, y + 16, 3, RGB(176,128,40), RGB(226,182,80), RGB(214,170,70));
        rbox(x, y + 12, x + 48, y + 44, 4, RGB(176,128,40), RGB(252,222,140), RGB(232,184,80));
    } else if (kind == 1) { /* run window */
        shadow(x, y + 4, x + 48, y + 44, 4, 70);
        rbox(x, y + 4, x + 48, y + 44, 4, RGB(70,92,124), RGB(246,250,255), RGB(214,226,240));
        rgrad(x + 1, y + 5, x + 47, y + 15, 3, C_ACCENT, C_SEL, 255);
        fill(dc, x + 6, y + 22, x + 30, y + 26, C_DIM);
    } else {                /* status/settings */
        shadow(x + 4, y + 4, x + 44, y + 44, 20, 70);
        rbox(x + 4, y + 4, x + 44, y + 44, 20, RGB(70,92,124), RGB(176,198,222), RGB(130,156,186));
        rbox(x + 14, y + 14, x + 34, y + 34, 10, RGB(60,80,110), C_DESK_TOP, C_DESK_BOT);
    }
}

static void paint_desk(HDC dc, RECT *rc)
{
    static const enum shell_string names[3] = { S_EXPLORER, S_RUN, S_SETTINGS };
    int i;
    vgrad(dc, 0, 0, rc->right, rc->bottom, C_DESK_TOP, C_DESK_BOT);
    for (i = 0; i < 3; ++i) {
        int x = 28, y = 20 + i * 100;
        paint_icon(dc, x, y, i, wstate(g_desk, i));
        text(dc, x - 12, y + 52, x + 60, y + 74, T(names[i]), RGB(4,8,16), TC);
        text(dc, x - 13, y + 51, x + 59, y + 73, T(names[i]), C_LIGHT, TC);
    }
}

static void clock_text(WCHAR *out, unsigned cap, int date)
{
    SYSTEMTIME st; struct sb b;
    GetLocalTime(&st);
    sb_init(&b, out, cap);
    if (date) { sb_num(&b, st.wYear); sb_str(&b, L"-"); sb_num2(&b, st.wMonth); sb_str(&b, L"-"); sb_num2(&b, st.wDay); sb_str(&b, L" "); }
    sb_num2(&b, st.wHour); sb_str(&b, L":"); sb_num2(&b, st.wMinute);
    if (date) { sb_str(&b, L":"); sb_num2(&b, st.wSecond); }
}

static int memory_percent(unsigned long long *used_mb, unsigned long long *total_mb)
{
    MEMORYSTATUSEX m; memset(&m, 0, sizeof m); m.dwLength = sizeof m;
    if (!GlobalMemoryStatusEx(&m) || !m.ullTotalPhys) return -1;
    *total_mb = m.ullTotalPhys >> 20; *used_mb = (m.ullTotalPhys - m.ullAvailPhys) >> 20;
    return (int)(100 - (m.ullAvailPhys * 100) / m.ullTotalPhys);
}

static void paint_bar(HDC dc, RECT *rc)
{
    int tl, tr, tray, w, i, x; WCHAR buf[64]; unsigned long long um, tm; int pct, st;
    vgrad(dc, 0, 0, rc->right, rc->bottom, C_BAR_TOP, C_BAR_BOT);
    fill(dc, 0, 0, rc->right, 1, RGB(140,170,210));
    fill(dc, 0, 1, rc->right, 2, RGB(96,122,160));
    st = wstate(g_bar, 0);
    rbox(4, 3, 92, BAR_H - 3, 10, RGB(150,196,240),
         g_menu_open || st == 2 ? RGB(40,92,160) : st == 1 ? RGB(130,190,250) : RGB(96,156,220),
         g_menu_open || st == 2 ? RGB(30,70,130) : st == 1 ? RGB(50,110,190) : RGB(30,80,150));
    rgrad(14, 10, 24, 20, 5, RGB(250,253,255), RGB(190,220,248), 255);
    text(dc, 28, 3, 90, BAR_H - 3, T(S_START), RGB(255,255,255), TL);
    bar_geometry(&tl, &tr, &tray);
    w = task_width(tl, tr); x = tl;
    for (i = 0; i < (int)g_task_count; ++i) {
        int active = GetForegroundWindow() == g_tasks[i].hwnd, s2 = wstate(g_bar, 1 + i);
        COLORREF top = active ? RGB(88,128,184) : s2 == 2 ? RGB(30,42,62) : s2 == 1 ? RGB(78,100,134) : RGB(56,76,106);
        COLORREF bot = active ? RGB(54,92,148) : s2 == 2 ? RGB(22,32,50) : s2 == 1 ? RGB(50,68,98) : RGB(34,50,74);
        rbox(x, 4, x + w - 3, BAR_H - 3, 6, active ? C_ACCENT : s2 ? RGB(150,176,208) : C_DIM, top, bot);
        text(dc, x + 8, 4, x + w - 10, BAR_H - 3, g_tasks[i].title, C_LIGHT, TL);
        x += w;
    }
    if (wstate(g_bar, 100)) rgrad(tray + 2, 4, rc->right - 2, BAR_H - 3, 5, RGB(120,150,190), RGB(80,108,148), 80);
    fill(dc, tray, 5, tray + 1, BAR_H - 5, C_DIM);
    clock_text(buf, 64, 0);
    text(dc, tray + 6, 2, rc->right - 8, 17, buf, C_LIGHT, TR);
    pct = memory_percent(&um, &tm);
    { struct sb b; sb_init(&b, buf, 64); sb_str(&b, T(S_MEMORY)); sb_str(&b, L" ");
      if (pct >= 0) { sb_num(&b, (unsigned)pct); sb_str(&b, L"%"); } else sb_str(&b, L"?"); }
    text(dc, tray + 6, 16, rc->right - 8, BAR_H - 2, buf, RGB(170,196,224), TR);
}

static void paint_menu(HDC dc, RECT *rc)
{
    unsigned i; int y = 4 + (rc->bottom - g_menu_full);
    vgrad(dc, 0, 0, rc->right, rc->bottom, RGB(44,58,82), C_MENU);
    frame(dc, 0, 0, rc->right, rc->bottom, C_ACCENT);
    fill(dc, 1, 1, rc->right - 1, 2, RGB(120,160,210));
    for (i = 0; i < g_item_count; ++i) {
        int h = item_h(g_items[i].kind);
        if (g_items[i].kind == MI_SEP) fill(dc, 10, y + 3, rc->right - 10, y + 4, C_DIM);
        else if (g_items[i].kind == MI_HEADER) text(dc, 14, y, rc->right - 8, y + h, g_items[i].label, C_DIM, TL);
        else {
            if ((int)i == g_menu_hot) rbox(4, y + 1, rc->right - 4, y + h - 1, 6, RGB(130,176,230), C_HOT, C_SEL);
            text(dc, 18, y, rc->right - 8, y + h, g_items[i].label, C_LIGHT, TL);
        }
        y += h;
    }
}

static void paint_exp(HDC dc, RECT *rc)
{
    unsigned i, mask; int y, dx = 60; WCHAR buf[PATH_CAP + 16]; int cw = rc->right;
    static const enum shell_string tb[8] = { S_UP, S_REFRESH, S_NEW_FOLDER, S_COPY, S_PASTE, S_RENAME, S_DELETE, S_OPEN };
    fill(dc, 0, 0, cw, rc->bottom, C_WIN);
    vgrad(dc, 0, 0, cw, 32, RGB(230,238,248), C_HEAD);
    for (i = 0; i < 8; ++i) button(dc, 4 + (int)i * 86, 4, 82, 24, T(tb[i]), wstate(g_exp, (int)i));
    rbox(4, 34, cw - 4, 56, 4, g_mode == M_PATH ? C_ACCENT : C_DIM, RGB(255,255,255), RGB(246,249,253));
    if (g_mode == M_PATH) {
        text(dc, 8, 34, cw - 8, 56, g_input, C_TEXT, TL);
        caret(g_input, g_input_pos, 8, 34, 56);
        text(dc, 8, 56, cw - 8, 70, T(S_PATH_EDIT), C_DIM, TL);
    } else text(dc, 8, 34, cw - 8, 56, g_dir, C_TEXT, TL);
    text(dc, 6, 60, 58, 80, T(S_DRIVE), C_TEXT, TL);
    mask = GetLogicalDrives();
    for (i = 0; i < 26 && dx < cw - 40; ++i) if (mask & (1u << i)) {
        WCHAR d[3]; d[0] = (WCHAR)(L'A' + i); d[1] = L':'; d[2] = 0;
        if (!g_mode) button(dc, dx, 60, 34, 20, d, wstate(g_exp, 100 + (int)i));
        dx += 38;
    }
    vgrad(dc, 0, LIST_Y - 18, cw, LIST_Y, RGB(222,230,240), C_HEAD);
    text(dc, 26, LIST_Y - 18, cw - 220, LIST_Y, T(S_COL_NAME), C_TEXT, TL);
    text(dc, cw - 210, LIST_Y - 18, cw - 100, LIST_Y, T(S_COL_SIZE), C_TEXT, TR);
    text(dc, cw - 90, LIST_Y - 18, cw - 4, LIST_Y, T(S_COL_TYPE), C_TEXT, TL);
    y = LIST_Y;
    if (!g_count) text(dc, 26, y, cw - 8, y + ROW_H, T(S_EMPTY), C_DIM, TL);
    for (i = g_top; i < g_count && y + ROW_H <= rc->bottom - 24; ++i, y += ROW_H) {
        struct row *r = &g_rows[g_order[i]]; int sel = (int)i == g_sel, hov = g_hot[W_EXP] == 1000 + (int)i;
        struct sb b; int dir = (r->attrs & FILE_ATTRIBUTE_DIRECTORY) != 0; COLORREF fg = sel ? C_LIGHT : C_TEXT;
        if (S(y + ROW_H) <= g_dirty.top || S(y) >= g_dirty.bottom) continue;
        if (sel) rbox(2, y, cw - 2, y + ROW_H, 4, RGB(40,90,150), RGB(90,140,200), C_SEL);
        else if (hov) rgrad(2, y, cw - 2, y + ROW_H, 4, RGB(214,230,248), RGB(196,216,240), 255);
        rbox(6, y + 4, 20, y + 16, 3, dir ? RGB(176,128,40) : C_DIM, dir ? RGB(252,222,140) : RGB(232,238,246), dir ? RGB(236,190,84) : RGB(196,206,220));
        if (sel && g_mode == M_RENAME) {
            rbox(24, y + 1, cw - 220, y + ROW_H - 1, 3, C_ACCENT, RGB(255,255,255), RGB(255,255,255));
            text(dc, 26, y, cw - 220, y + ROW_H, g_input, C_TEXT, TL);
            caret(g_input, g_input_pos, 26, y, y + ROW_H);
        } else text(dc, 26, y, cw - 220, y + ROW_H, r->name, fg, TL);
        sb_init(&b, buf, 64);
        if (!dir) fmt_size(&b, r->size);
        text(dc, cw - 210, y, cw - 100, y + ROW_H, buf, fg, TR);
        text(dc, cw - 90, y, cw - 4, y + ROW_H, dir ? T(S_FOLDER) : wends_i(r->name, L".EXE") ? T(S_PROGRAM) : T(S_FILE), sel ? C_LIGHT : C_DIM, TL);
    }
    vgrad(dc, 0, rc->bottom - 22, cw, rc->bottom, RGB(222,230,240), C_HEAD);
    text(dc, 6, rc->bottom - 22, cw - 6, rc->bottom, g_status, g_status_err ? C_ERR : C_TEXT, TL);
}

static void paint_run(HDC dc, RECT *rc)
{
    fill(dc, 0, 0, rc->right, rc->bottom, C_WIN);
    text(dc, 12, 10, rc->right - 12, 32, T(S_RUN_PROMPT), C_TEXT, TL);
    rbox(12, 38, rc->right - 12, 62, 4, C_ACCENT, RGB(255,255,255), RGB(246,249,253));
    text(dc, 16, 38, rc->right - 16, 62, g_run_text, C_TEXT, TL);
    caret(g_run_text, g_run_pos, 16, 38, 62);
    button(dc, rc->right - 180, rc->bottom - 36, 80, 26, T(S_RUN_OK), wstate(g_runw, 0) ? wstate(g_runw, 0) : 3);
    button(dc, rc->right - 92, rc->bottom - 36, 80, 26, T(S_CANCEL), wstate(g_runw, 1));
    text(dc, 12, rc->bottom - 36, rc->right - 190, rc->bottom - 10, g_status, g_status_err ? C_ERR : C_TEXT, TL);
}

static void paint_set(HDC dc, RECT *rc)
{
    WCHAR line[200], name[64], t[40]; DWORD n; struct sb b; unsigned long long um = 0, tm = 0; int pct, y = 14;
    ULONGLONG up = GetTickCount64() / 1000;
    fill(dc, 0, 0, rc->right, rc->bottom, C_WIN);
    rbox(6, 6, rc->right - 6, 6 + 24 * 5 + 12, 8, RGB(190,204,222), RGB(252,253,255), RGB(238,243,250));
    n = 64; if (!GetUserNameW(name, &n)) wcopy(name, 64, T(S_UNKNOWN));
    sb_init(&b, line, 200); sb_str(&b, T(S_USER)); sb_str(&b, L": "); sb_str(&b, name);
    text(dc, 14, y, rc->right - 10, y + 22, line, C_TEXT, TL); y += 24;
    n = 64; if (!GetComputerNameW(name, &n)) wcopy(name, 64, T(S_UNKNOWN));
    sb_init(&b, line, 200); sb_str(&b, T(S_COMPUTER)); sb_str(&b, L": "); sb_str(&b, name);
    text(dc, 14, y, rc->right - 10, y + 22, line, C_TEXT, TL); y += 24;
    clock_text(t, 40, 1);
    sb_init(&b, line, 200); sb_str(&b, T(S_TIME)); sb_str(&b, L": "); sb_str(&b, t);
    text(dc, 14, y, rc->right - 10, y + 22, line, C_TEXT, TL); y += 24;
    sb_init(&b, line, 200); sb_str(&b, T(S_UPTIME)); sb_str(&b, L": ");
    sb_num(&b, (unsigned long long)(up / 3600)); sb_str(&b, L":"); sb_num2(&b, (unsigned)(up / 60 % 60)); sb_str(&b, L":"); sb_num2(&b, (unsigned)(up % 60));
    text(dc, 14, y, rc->right - 10, y + 22, line, C_TEXT, TL); y += 24;
    pct = memory_percent(&um, &tm);
    sb_init(&b, line, 200); sb_str(&b, T(S_MEMORY)); sb_str(&b, L": ");
    if (pct >= 0) { sb_num(&b, um); sb_str(&b, L" / "); sb_num(&b, tm); sb_str(&b, L" "); sb_str(&b, T(S_MB)); sb_str(&b, L" ("); sb_num(&b, (unsigned)pct); sb_str(&b, L"%)"); }
    else sb_str(&b, T(S_UNKNOWN));
    text(dc, 14, y, rc->right - 10, y + 22, line, C_TEXT, TL);
    if (pct >= 0) {   /* memory gauge */
        rgrad(14, y + 22, rc->right - 14, y + 28, 3, RGB(200,210,224), RGB(200,210,224), 255);
        rgrad(14, y + 22, 14 + (rc->right - 28) * pct / 100, y + 28, 3, RGB(110,176,236), RGB(50,110,190), 255);
    }
    y = SET_LANG_Y;
    sb_init(&b, line, 200); sb_str(&b, T(S_LANGUAGE)); sb_str(&b, L":");
    text(dc, 14, y, 100, y + 24, line, C_TEXT, TL);
    { int k; for (k = 0; k < 3; ++k) {
        static const WCHAR pref[3] = { L'A', L'K', L'E' };
        const WCHAR *lab = k == 0 ? T(S_LANG_AUTO) : k == 1 ? T(S_LANG_KO) : T(S_LANG_EN);
        int stt = wstate(g_set, k); if (!stt && g_langpref == pref[k]) stt = 3;
        button(dc, 100 + k * 88, y, 80, 24, lab, stt);
    } }
    text(dc, 10, rc->bottom - 24, rc->right - 10, rc->bottom - 2, g_status, g_status_err ? C_ERR : C_TEXT, TL);
}

static int ensure_dib(int w, int h)
{
    BITMAPINFO bi; void *bits = 0; int nw, nh;
    if (g_dib && w <= g_bw && h <= g_bh) return 1;
    nw = w > g_bw ? w : g_bw; nh = h > g_bh ? h : g_bh;
    if (g_dib) { DeleteObject(g_dib); g_dib = 0; g_bits = 0; g_bw = g_bh = 0; }
    memset(&bi, 0, sizeof bi);
    bi.bmiHeader.biSize = sizeof bi.bmiHeader; bi.bmiHeader.biWidth = nw; bi.bmiHeader.biHeight = -nh;
    bi.bmiHeader.biPlanes = 1; bi.bmiHeader.biBitCount = 32; bi.bmiHeader.biCompression = BI_RGB;
    g_dib = CreateDIBSection(0, &bi, DIB_RGB_COLORS, &bits, 0, 0);
    if (!g_dib || !bits) { if (g_dib) DeleteObject(g_dib); g_dib = 0; return 0; }
    g_bits = (uint32_t *)bits; g_bw = nw; g_bh = nh;
    return 1;
}

static void paint(HWND hwnd)
{
    PAINTSTRUCT ps; HDC dc = BeginPaint(hwnd, &ps), mem = 0; RECT rc, px; HGDIOBJ oldbmp = 0, oldfont = 0; int use_dib;
    if (!dc) return;
    GetClientRect(hwnd, &px);
    use_dib = ensure_dib(px.right, px.bottom);
    if (use_dib) mem = CreateCompatibleDC(dc);
    if (mem) oldbmp = SelectObject(mem, g_dib); else { g_bits = 0; use_dib = 0; }
    g_dc = mem ? mem : dc;
    g_dirty = ps.rcPaint;
    if (g_dirty.right <= g_dirty.left || g_dirty.bottom <= g_dirty.top || g_dirty.right > px.right || g_dirty.bottom > px.bottom) g_dirty = px;
    if (g_dirty.left < 0) g_dirty.left = 0;
    if (g_dirty.top < 0) g_dirty.top = 0;
    if (g_font) oldfont = SelectObject(g_dc, g_font);
    rc.left = 0; rc.top = 0; rc.right = D(px.right); rc.bottom = D(px.bottom);
    if (hwnd == g_desk) paint_desk(g_dc, &rc);
    else if (hwnd == g_bar) paint_bar(g_dc, &rc);
    else if (hwnd == g_menu) paint_menu(g_dc, &rc);
    else if (hwnd == g_exp) paint_exp(g_dc, &rc);
    else if (hwnd == g_runw) paint_run(g_dc, &rc);
    else if (hwnd == g_set) paint_set(g_dc, &rc);
    if (oldfont) SelectObject(g_dc, oldfont);
    if (mem) {
        BitBlt(dc, g_dirty.left, g_dirty.top, g_dirty.right - g_dirty.left, g_dirty.bottom - g_dirty.top, mem, g_dirty.left, g_dirty.top, SRCCOPY);
        if (oldbmp) SelectObject(mem, oldbmp);
        DeleteDC(mem);
    }
    g_bits = 0; g_dc = 0;
    EndPaint(hwnd, &ps);
}

/* ---------- input ---------- */
static void set_language(WCHAR pref)
{
    DWORD e = 0;
    g_langpref = pref; resolve_language();
    if (cfg_save(pref, &e)) { note(S_SAVED, 0); printf("SHZ-SHELL SETTINGS lang=%c saved=1\n", (char)pref); }
    else { fail(S_OP_SAVE, e); printf("SHZ-SHELL SETTINGS lang=%c saved=0 error=%lu\n", (char)pref, (unsigned long)e); }
    SetWindowTextW(g_exp, T(S_EXPLORER_TITLE)); SetWindowTextW(g_runw, T(S_RUN_TITLE)); SetWindowTextW(g_set, T(S_SETTINGS_TITLE));
    redraw_all();
}

static void click_exp(int x, int y)
{
    RECT rc, r2; unsigned i; int id;
    client(g_exp, &rc);
    if (g_mode) g_mode = M_NONE;
    id = hot_id(g_exp, x, y, &r2);
    if (id >= 0 && id < 8) {
        switch (id) {
        case 0: up_dir(); break;
        case 1: refresh(); break;
        case 2: new_folder(); break;
        case 3: copy_selected(); break;
        case 4: paste_clip(); break;
        case 5: begin_edit(M_RENAME); break;
        case 6: delete_selected(); break;
        case 7: open_selected(); break;
        }
        redraw(g_exp); return;
    }
    if (id == 50) { begin_edit(M_PATH); return; }
    if (id >= 100 && id < 126) {
        WCHAR p[4]; i = (unsigned)(id - 100);
        p[0] = (WCHAR)(L'A' + i); p[1] = L':'; p[2] = L'\\'; p[3] = 0; navigate(p); return;
    }
    if (id >= 1000) {
        unsigned idx = (unsigned)(id - 1000);
        DWORD now = GetTickCount();
        if ((int)idx == g_last_click_row && now - g_last_click_tick < 500) { g_sel = (int)idx; g_last_click_row = -1; open_selected(); }
        else { g_sel = (int)idx; g_del_armed = -1; g_last_click_row = (int)idx; g_last_click_tick = now; }
        redraw(g_exp);
    } else if (y >= LIST_Y && y < rc.bottom - 24) { g_sel = -1; redraw(g_exp); }
}

static void do_run(void)
{
    if (!g_run_text[0]) return;
    if (launch(g_run_text, 0)) { ShowWindow(g_runw, SW_HIDE); }
    redraw(g_runw);
}

/* Edit helpers shared by explorer fields and Run: insert/delete at the caret. */
static void ed_insert(WCHAR *buf, unsigned *len, unsigned *pos, WCHAR c)
{
    unsigned i;
    if (*len + 1 >= PATH_CAP) return;
    for (i = *len + 1; i > *pos; --i) buf[i] = buf[i - 1];
    buf[*pos] = c; ++*pos; ++*len;
}
static void ed_delete(WCHAR *buf, unsigned *len, unsigned pos)
{
    unsigned i;
    if (pos >= *len) return;
    for (i = pos; i < *len; ++i) buf[i] = buf[i + 1];
    --*len;
}
/* Returns 1 when the key was consumed as an editing key. */
static int ed_key(WCHAR *buf, unsigned *len, unsigned *pos, WPARAM vk)
{
    switch (vk) {
    case VK_LEFT: if (*pos) --*pos; return 1;
    case VK_RIGHT: if (*pos < *len) ++*pos; return 1;
    case VK_HOME: *pos = 0; return 1;
    case VK_END: *pos = *len; return 1;
    case VK_BACK: if (*pos) { --*pos; ed_delete(buf, len, *pos); } return 1;
    case VK_DELETE: ed_delete(buf, len, *pos); return 1;
    }
    return 0;
}

static void key_exp(WPARAM vk)
{
    int ctrl = GetKeyState(VK_CONTROL) < 0;
    if (g_mode) {
        if (vk == VK_RETURN) commit_edit();
        else if (vk == VK_ESCAPE) { g_mode = M_NONE; redraw(g_exp); }
        else if (ed_key(g_input, &g_input_len, &g_input_pos, vk)) redraw(g_exp);
        return;
    }
    if (ctrl && vk == 'C') { copy_selected(); return; }
    if (ctrl && vk == 'V') { paste_clip(); return; }
    if (ctrl && vk == 'L') { begin_edit(M_PATH); return; }
    switch (vk) {
    case VK_DOWN: if (g_count && g_sel < (int)g_count - 1) { ++g_sel; g_del_armed = -1; } break;
    case VK_UP: if (g_sel > 0) { --g_sel; g_del_armed = -1; } break;
    case VK_RETURN: open_selected(); break;
    case VK_BACK: up_dir(); break;
    case VK_F5: refresh(); break;
    case VK_F2: begin_edit(M_RENAME); break;
    case VK_F7: new_folder(); break;
    case VK_DELETE: delete_selected(); break;
    case VK_ESCAPE: ShowWindow(g_exp, SW_HIDE); redraw(g_bar); return;
    default: return;
    }
    ensure_visible(); redraw(g_exp);
}

static void char_input(HWND hwnd, WCHAR c)
{
    if (c < 32 || c == 127) return;
    if (hwnd == g_exp && g_mode) {
        if (g_mode == M_RENAME && (c == L'\\' || c == L'/' || c == L':' || c == L'*' || c == L'?' || c == L'"' || c == L'<' || c == L'>' || c == L'|')) return;
        ed_insert(g_input, &g_input_len, &g_input_pos, c); redraw(g_exp);
    } else if (hwnd == g_runw) {
        ed_insert(g_run_text, &g_run_len, &g_run_pos, c); redraw(g_runw);
    }
}

static int menu_hit(int y)
{
    int yy = 4 + (D(0) + (int)0), i; RECT rc;
    client(g_menu, &rc);
    yy = 4 + (rc.bottom - g_menu_full);
    for (i = 0; i < (int)g_item_count; ++i) {
        int h = item_h(g_items[i].kind);
        if (y >= yy && y < yy + h) return g_items[i].kind != MI_SEP && g_items[i].kind != MI_HEADER ? i : -1;
        yy += h;
    }
    return -1;
}

static void do_click(HWND hwnd, int x, int y)
{
    RECT r;
    if (hwnd == g_desk) {
        int id = hot_id(g_desk, x, y, &r);
        close_menu();
        if (id >= 0) {
            DWORD now = GetTickCount();
            if (g_icon_hot == id && now - g_last_click_tick < 500) {
                g_icon_hot = -1;
                if (id == 0) show_explorer(); else if (id == 1) show_run(); else show_settings();
            } else { g_icon_hot = id; g_last_click_tick = now; }
            return;
        }
        g_icon_hot = -1;
    } else if (hwnd == g_bar) {
        int id = hot_id(g_bar, x, y, &r);
        if (id == 0) { if (g_menu_open) close_menu(); else open_menu(); return; }
        close_menu();
        if (id == 100) show_settings();
        else if (id >= 1) activate_task((unsigned)(id - 1));
    } else if (hwnd == g_menu) {
        RECT rc; int i;
        client(g_menu, &rc);
        if (x < 0 || y < 0 || x >= rc.right || y >= rc.bottom) { close_menu(); return; }   /* click outside (incl. Start) only dismisses */
        i = menu_hit(y);
        if (i >= 0) menu_action(&g_items[i]);
    } else if (hwnd == g_exp) click_exp(x, y);
    else if (hwnd == g_runw) {
        int id = hot_id(g_runw, x, y, &r);
        if (id == 0) do_run(); else if (id == 1) ShowWindow(g_runw, SW_HIDE);
    } else if (hwnd == g_set) {
        int id = hot_id(g_set, x, y, &r);
        if (id == 0) set_language(L'A'); else if (id == 1) set_language(L'K'); else if (id == 2) set_language(L'E');
    }
}

/* Clear hover when the cursor has left a window (no WM_MOUSELEAVE dependency). */
static void hover_sweep(void)
{
    static HWND *const wins[W_COUNT] = { &g_bar, &g_exp, &g_set, &g_runw, &g_desk };
    POINT pt; int k;
    if (!GetCursorPos(&pt)) return;
    for (k = 0; k < W_COUNT; ++k) {
        RECT wr;
        if (g_hot[k] < 0 || !*wins[k]) continue;
        if (GetWindowRect(*wins[k], &wr) && pt.x >= wr.left && pt.x < wr.right && pt.y >= wr.top && pt.y < wr.bottom) continue;
        redraw_r(*wins[k], &g_hot_rc[k]); g_hot[k] = -1;
    }
}

static LRESULT CALLBACK shell_proc(HWND hwnd, UINT msg, WPARAM wp, LPARAM lp)
{
    switch (msg) {
    case WM_ERASEBKGND: return 1;
    case WM_PAINT: paint(hwnd); return 0;
    case WM_LBUTTONDBLCLK: /* CS_DBLCLKS replaces the second DOWN; keep icon/row activation reachable. */
    case WM_LBUTTONDOWN: {
        int x = D((short)LOWORD(lp)), y = D((short)HIWORD(lp)), k = widx(hwnd); RECT r;
        if (k >= 0) {
            int id = hot_id(hwnd, x, y, &r);
            if (id >= 0) { g_press_w = k; g_press_id = id; g_press_rc = r; g_hot[k] = id; g_hot_rc[k] = r; redraw_r(hwnd, &r); }
        }
        do_click(hwnd, x, y);
        return 0;
    }
    case WM_LBUTTONUP:
        if (g_press_w >= 0) {
            HWND w = g_press_w == W_BAR ? g_bar : g_press_w == W_EXP ? g_exp : g_press_w == W_SET ? g_set : g_press_w == W_RUN ? g_runw : g_desk;
            g_press_w = -1; g_press_id = -1; redraw_r(w, &g_press_rc);
        }
        return 0;
    case WM_MOUSEMOVE: {
        int x = D((short)LOWORD(lp)), y = D((short)HIWORD(lp));
        if (hwnd == g_menu && g_menu_open) {
            int hot = menu_hit(y);
            if (hot != g_menu_hot) { g_menu_hot = hot; redraw(g_menu); }
        } else if (widx(hwnd) >= 0) {
            RECT r; int id = hot_id(hwnd, x, y, &r);
            set_hot(hwnd, id, &r);
        }
        return 0;
    }
    case WM_KEYDOWN:
        if (hwnd == g_exp) key_exp(wp);
        else if (hwnd == g_runw) {
            if (wp == VK_RETURN) do_run();
            else if (wp == VK_ESCAPE) ShowWindow(g_runw, SW_HIDE);
            else if (ed_key(g_run_text, &g_run_len, &g_run_pos, wp)) redraw(g_runw);
        } else if (hwnd == g_set && wp == VK_ESCAPE) ShowWindow(g_set, SW_HIDE);
        else if (hwnd == g_desk && wp == VK_ESCAPE) close_menu();
        return 0;
    case WM_CHAR: char_input(hwnd, (WCHAR)wp); return 0;
    case WM_MOUSEWHEEL:
        if (hwnd == g_exp) {
            int d = (short)HIWORD(wp);
            if (d > 0) g_top = g_top > 3 ? g_top - 3 : 0;
            else if (g_top + 3 < g_count) g_top += 3;
            redraw(g_exp);
        }
        return 0;
    case WM_TIMER:
        if (hwnd == g_bar && wp == 2) { menu_step(); return 0; }
        if (hwnd == g_bar) {
            SYSTEMTIME st;
            int changed = 0;
            poll_procs();
            if (refresh_tasks()) changed = 1;
            GetLocalTime(&st);
            if (st.wMinute != g_last_minute) { g_last_minute = st.wMinute; changed = 1; }
            if (changed) redraw(g_bar);
            hover_sweep();
            if (++g_tick_count % 4 == 0 && IsWindowVisible(g_set)) redraw(g_set);
            if ((g_mode || (IsWindowVisible(g_runw) && GetForegroundWindow() == g_runw)) && g_tick_count % 2 == 0) {   /* caret blink */
                RECT r;
                if (g_mode) { rc_set(&r, 0, 30, 4000, LIST_Y + 4000); redraw(g_exp); }
                else { rc_set(&r, 0, 30, 4000, 70); redraw_r(g_runw, &r); }
            }
        }
        return 0;
    case WM_CLOSE:
        if (hwnd == g_exp || hwnd == g_runw || hwnd == g_set) { ShowWindow(hwnd, SW_HIDE); redraw(g_bar); }
        return 0;           /* the desktop and taskbar are only removed by End shell */
    case WM_DESTROY:
        if (hwnd == g_desk) PostQuitMessage(0);
        return 0;
    }
    return DefWindowProcW(hwnd, msg, wp, lp);
}

/* Derive the UI scale (percent) from the system DPI, the display height and the font height. */
static void compute_scale(void)
{
    HDC dc = GetDC(0); int dpi = 96, fh = 16, sc;
    if (dc) {
        TEXTMETRICW tm; int d = GetDeviceCaps(dc, LOGPIXELSY);
        if (d > 0) dpi = d;
        if (GetTextMetricsW(dc, &tm) && tm.tmHeight > 0) fh = tm.tmHeight;
        ReleaseDC(0, dc);
    }
    sc = dpi * 100 / 96;
    if (fh * 100 / 16 > sc) sc = fh * 100 / 16;
    if (g_h >= 2160 && sc < 200) sc = 200;
    else if (g_h >= 1440 && sc < 150) sc = 150;
    else if (g_h >= 1080 && sc < 100) sc = 100;
    sc = (sc + 12) / 25 * 25;
    g_scale = sc < 100 ? 100 : sc > 300 ? 300 : sc;
}

int main(void)
{
    WNDCLASSEXW wc; MSG m; int r, code = 0; unsigned i; DWORD cfg_err = 0; WCHAR pref = L'K';
    int cfg = cfg_read(CFG_PATH, &pref, &cfg_err);
    if (cfg == 1) g_langpref = pref;
    resolve_language();
    g_inst = GetModuleHandleW(0);
    g_w = GetSystemMetrics(SM_CXSCREEN); g_h = GetSystemMetrics(SM_CYSCREEN);
    if (g_w < 640 || g_h < 480) { printf("SHZ-SHELL ERROR operation=Display error=%u width=%d height=%d\n", ERROR_NOT_SUPPORTED, g_w, g_h); return 1; }
    compute_scale();
    g_font = CreateFontW(-S(14), 0, 0, 0, FW_NORMAL, 0, 0, 0, DEFAULT_CHARSET, OUT_DEFAULT_PRECIS, CLIP_DEFAULT_PRECIS, ANTIALIASED_QUALITY, DEFAULT_PITCH, L"");
    memset(&wc, 0, sizeof wc);
    wc.cbSize = sizeof wc; wc.style = CS_HREDRAW | CS_VREDRAW | CS_DBLCLKS; wc.lpfnWndProc = shell_proc;
    wc.hInstance = g_inst; wc.lpszClassName = L"ShizukuShellWindow"; wc.hCursor = LoadCursorW(0, MAKEINTRESOURCEW(32512));
    if (!RegisterClassExW(&wc)) { printf("SHZ-SHELL ERROR operation=RegisterClass error=%lu\n", (unsigned long)GetLastError()); return 1; }
    g_desk = CreateWindowExW(0, wc.lpszClassName, T(S_DESKTOP), WS_POPUP | WS_VISIBLE, 0, 0, g_w, g_h, 0, 0, g_inst, 0);
    g_bar = CreateWindowExW(WS_EX_TOPMOST | WS_EX_TOOLWINDOW, wc.lpszClassName, L"ShizukuTaskbar", WS_POPUP | WS_VISIBLE, 0, g_h - S(BAR_H), g_w, S(BAR_H), 0, 0, g_inst, 0);
    g_menu = CreateWindowExW(WS_EX_TOPMOST | WS_EX_TOOLWINDOW, wc.lpszClassName, L"ShizukuStartMenu", WS_POPUP, 0, 0, S(280), S(100), 0, 0, g_inst, 0);
    {
        int ew = g_w - S(160) > S(860) ? S(860) : g_w - S(160), eh = g_h - S(BAR_H + 100) > S(580) ? S(580) : g_h - S(BAR_H + 100);
        g_exp = CreateWindowExW(0, wc.lpszClassName, T(S_EXPLORER_TITLE), WS_OVERLAPPEDWINDOW, S(60), S(40), ew, eh, 0, 0, g_inst, 0);
    }
    g_runw = CreateWindowExW(0, wc.lpszClassName, T(S_RUN_TITLE), WS_CAPTION | WS_SYSMENU, (g_w - S(480)) / 2, g_h / 3, S(480), S(160), 0, 0, g_inst, 0);
    g_set = CreateWindowExW(0, wc.lpszClassName, T(S_SETTINGS_TITLE), WS_CAPTION | WS_SYSMENU, (g_w - S(480)) / 2, g_h / 4, S(480), S(300), 0, 0, g_inst, 0);
    if (!g_desk || !g_bar || !g_menu || !g_exp || !g_runw || !g_set) {
        printf("SHZ-SHELL ERROR operation=CreateWindows error=%lu\n", (unsigned long)GetLastError()); code = 1;
    } else if (!SetShellWindow(g_desk) || GetShellWindow() != g_desk) {
        printf("SHZ-SHELL ERROR operation=SetShellWindow error=%lu\n", (unsigned long)GetLastError()); code = 1;
    } else if (!SetTimer(g_bar, 1, 250, 0)) {
        printf("SHZ-SHELL ERROR operation=SetTimer error=%lu\n", (unsigned long)GetLastError()); code = 1;
    } else {
        if (cfg < 0) { fail(S_OP_OPEN, cfg_err); }
        refresh_tasks();
        UpdateWindow(g_desk); UpdateWindow(g_bar);
        printf("SHZ-SHELL READY hwnd=%llx width=%d height=%d scale=%d lang=%s cfg=%d\n", (unsigned long long)(uintptr_t)g_desk, g_w, g_h, g_scale, g_en ? "en" : "ko", cfg);
        while ((r = GetMessageW(&m, 0, 0, 0)) > 0) { TranslateMessage(&m); DispatchMessageW(&m); }
        if (r < 0) { printf("SHZ-SHELL ERROR operation=MessageLoop error=%lu\n", (unsigned long)GetLastError()); code = 1; }
    }
    for (i = 0; i < PROC_CAP; ++i) if (g_procs[i].h) CloseHandle(g_procs[i].h);
    if (g_bar) { KillTimer(g_bar, 1); KillTimer(g_bar, 2); }
    close_menu();
    if (g_set) DestroyWindow(g_set);
    if (g_runw) DestroyWindow(g_runw);
    if (g_exp) DestroyWindow(g_exp);
    if (g_menu) DestroyWindow(g_menu);
    if (g_bar) DestroyWindow(g_bar);
    if (g_desk) DestroyWindow(g_desk);
    if (g_font) DeleteObject(g_font);
    if (g_dib) DeleteObject(g_dib);
    UnregisterClassW(wc.lpszClassName, g_inst);
    return code;
}
