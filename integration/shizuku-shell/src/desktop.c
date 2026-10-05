/*
 * ShizukuOS shell candidate: desktop window with icons.
 *
 * Adapted in role from ReactOS Explorer (pinned commit ce41f2e98e0450ce624c5fc6155fb671af7cc3b5): the desktop
 * window is the one other window besides the tray that IsTaskWnd must exclude (traywnd.cpp IsSpecialHWND,
 * lines 2239-2243, m_DesktopWnd). ReactOS hosts the desktop as an IShellView/DesktopWindow COM object; that
 * shell namespace is NOT implemented. This is a plain Win32 window with three static icons. It is a window on
 * the existing desktop, NOT a separate Win32 desktop object (CreateDesktopW is not used).
 * Shell registration: SetShellWindow (real user32 export, see shell.h) with this caller-owned window.
 * Upstream notices: ReactOS Explorer, LGPL-2.1-or-later, Copyright ReactOS contributors.
 * Derived file is LGPL-2.1-or-later; see ../upstream/reactos/COPYING.LIB.
 */
#include "shzcrt.h"
#include "shell.h"
#include "layout.h"
#include "icons.h"
#include "wallpaper.h"
#include "shz_text_diag.h" /* existing genuine Noto pixel measurement declaration */

#define ICON_W ShzPx(TH()->icons_cell_w)         /* theme metrics (Slade 84x84, as before); paint and hit-test share IconRect */
#define ICON_H ShzPx(TH()->icons_cell_h)
#define ICON_COUNT 3

static int g_isel = 0, g_ihover = -1;

static void IconRect(int i, RECT *r)
{
    int margin = ShzPx(8), gap = ShzPx(4);   /* Windows-like: flush top-left, column-major, tight spacing */
    r->left = margin; r->top = margin + i * (ICON_H + gap);
    r->right = r->left + ICON_W; r->bottom = r->top + ICON_H;
}

static int IconLabel(int i) { return i == 0 ? IDS_COMPUTER : i == 1 ? IDS_FILES : IDS_RUN; }

/* Hit box = glyph + measured Noto label extent (one line, clamped to the cell), not the whole empty cell. */
static void IconHitRect(int i, RECT *h)
{
    const WCHAR *t = ShzStr(IconLabel(i)); RECT r, g; SIZE e; int n = 0, size = ShzPx(TH()->icons_size), px, lw, lh;
    while (t[n]) ++n;
    IconRect(i, &r);
    g.left = r.left + (ICON_W - size) / 2; g.right = g.left + size; g.top = r.top + ShzPx(12); g.bottom = g.top + size;
    px = ShzScaleMetric(TH()->typography_size, ShzUiScale());
    lw = ICON_W; lh = r.bottom - ShzPx(4) - (g.bottom + ShzPx(TH()->icons_label_gap));
    if (n && ShzTextMeasurePxExW(t, n, px, &e, NULL, NULL)) {
        if (e.cx + ShzPx(8) < lw) lw = e.cx + ShzPx(8);
        if (e.cy > 0 && e.cy < lh) lh = e.cy;
    }
    h->left = r.left + (ICON_W - lw) / 2; h->right = h->left + lw;
    h->top = g.top; h->bottom = g.bottom + ShzPx(TH()->icons_label_gap) + lh;
    if (h->left > g.left) h->left = g.left;
    if (h->right < g.right) h->right = g.right;
    if (h->bottom > r.bottom) h->bottom = r.bottom;
}

static void IconOpen(int i)
{
    if (i == 0) ShzFilesOpen(NULL);
    else if (i == 1) ShzFilesOpen(L"C:\\");
    else ShzRunDialogOpen();
}

static void OnPaint(HWND hwnd)
{
    PAINTSTRUCT ps;
    RECT c, r, g;
    unsigned gen = (unsigned)ShzThemeGeneration();   /* captured before painting */
    HDC dc = BeginPaint(hwnd, &ps);
    const SHZ_THEME *th = TH();
    int i;
    if (!dc) return;
    GetClientRect(hwnd, &c);
    if (th->wallpaper_mode != SHZ_WP_IMAGE || !ShzWallpaperPaint(dc, &c)) {
        if (th->wallpaper_mode == SHZ_WP_IMAGE && ShzWallpaperStatus()->image_ready) {
            DWORD error = GetLastError();
            if (!error) error = ERROR_INVALID_DATA;
            ShzWallpaperRelease(); /* draw failure clears image capability; fallback erases any partial image */
            ShzSetStatus(IDS_THEME_REFUSED, error); /* actual draw failure stays visible in the existing tray error */
            printf("SHZ-SHELL WALLPAPER paint-failed gen=%u win32=0x%x fallback=gradient\n", gen, (unsigned)error);
        }
        if (th->wallpaper_mode == SHZ_WP_SOLID) ShzFill(dc, &c, TC(th->wallpaper_color));
        else ShzFillGradientV(dc, &c, TC(th->background_desktop_top), TC(th->background_desktop_bottom));
    }
    for (i = 0; i < ICON_COUNT; ++i) {
        int size = ShzPx(th->icons_size), x;
        IconRect(i, &r);
        if (i == g_isel || i == g_ihover) {
            ShzFillGradientV(dc, &r, TC(i == g_isel ? th->selection_top : th->buttons_normal_top),
                             TC(i == g_isel ? th->selection_bottom : th->buttons_normal_bottom));
            ShzFrame(dc, &r, TC(th->selection_border), 1);
        }
        x = (ICON_W-size)/2;
        g.left = r.left+x; g.right = g.left+size; g.top = r.top+ShzPx(12); g.bottom = g.top+size;
        ShzDrawIcon(dc, &g, i, TC(i == 0 ? th->icons_glyph_computer : i == 1 ? th->icons_glyph_files : th->icons_glyph_run));
        r.top = g.bottom+ShzPx(th->icons_label_gap); r.bottom -= ShzPx(4);
        SetTextColor(dc, TC(i == g_isel ? th->selection_text : i == g_ihover ? th->buttons_text : th->background_desktop_text));
        ShzDrawText(dc, ShzStr(IconLabel(i)), &r, DT_CENTER|DT_WORDBREAK|DT_NOPREFIX);
    }
    if (EndPaint(hwnd, &ps)) {
        static unsigned last_gen; static int have_last;   /* suppress identical idle repaints */
        if (!have_last || last_gen != gen) { have_last = 1; last_gen = gen; printf("SHZ-SHELL UI desktop gen=%u\n", gen); }
    }
    ShzMarkPainted(FALSE);
}

static int HitIcon(int x, int y)
{
    int i; RECT r; POINT p; p.x = x; p.y = y;
    for (i = 0; i < ICON_COUNT; ++i) { IconHitRect(i, &r); if (PtInRect(&r, p)) return i; }
    return -1;
}

static LRESULT CALLBACK DesktopProc(HWND hwnd, UINT msg, WPARAM wp, LPARAM lp)
{
    int i;
    switch (msg) {
    case WM_WINDOWPOSCHANGING: {        /* keep the desktop at the bottom of the z-order whatever the request */
        WINDOWPOS *wpos = (WINDOWPOS *)lp;
        wpos->hwndInsertAfter = HWND_BOTTOM;
        wpos->flags &= ~SWP_NOZORDER;
        wpos->flags |= SWP_NOACTIVATE;
        return 0; }
    case WM_MOUSEACTIVATE: return MA_NOACTIVATE;   /* clicking the desktop must not raise/activate it */
    case WM_PAINT: OnPaint(hwnd); return 0;
    case WM_ERASEBKGND: return 1;
    case WM_MOUSEMOVE:
        i = HitIcon((short)LOWORD(lp), (short)HIWORD(lp));
        if (i != g_ihover) { g_ihover = i; InvalidateRect(hwnd, NULL, FALSE); }
        return 0;
    case WM_LBUTTONDOWN:
        i = HitIcon((short)LOWORD(lp), (short)HIWORD(lp));
        if (i >= 0) { g_isel = i; InvalidateRect(hwnd, NULL, FALSE); }
        return 0;
    case WM_LBUTTONDBLCLK:
        i = HitIcon((short)LOWORD(lp), (short)HIWORD(lp));
        if (i >= 0) IconOpen(i);
        return 0;
    case WM_KEYDOWN: case WM_SYSKEYDOWN:
        if (ShzGlobalKey((UINT)wp)) return 0;
        if (wp == VK_DOWN) g_isel = (g_isel + 1) % ICON_COUNT;
        else if (wp == VK_UP) g_isel = (g_isel + ICON_COUNT - 1) % ICON_COUNT;
        else if (wp == VK_RETURN) { IconOpen(g_isel); return 0; }
        else if (wp == VK_F5) ShzTasksRefresh();
        else break;
        InvalidateRect(hwnd, NULL, FALSE);
        return 0;
    }
    return DefWindowProcW(hwnd, msg, wp, lp);
}

void ShzDesktopRelayout(void)
{
    if (g_shell.desktop) InvalidateRect(g_shell.desktop, NULL, FALSE);   /* icon geometry/colours are read at paint and hit-test */
}

BOOL ShzDesktopCreate(void)
{
    WNDCLASSEXW wc;
    int sw = GetSystemMetrics(SM_CXSCREEN), sh = GetSystemMetrics(SM_CYSCREEN);
    wc.cbSize = sizeof wc; wc.style = CS_DBLCLKS; wc.lpfnWndProc = DesktopProc; wc.cbClsExtra = wc.cbWndExtra = 0;
    wc.hInstance = g_shell.inst; wc.hIcon = NULL; wc.hCursor = LoadCursorW(NULL, IDC_ARROW);
    wc.hbrBackground = NULL; wc.lpszMenuName = NULL; wc.lpszClassName = SHZ_CLASS_DESKTOP; wc.hIconSm = NULL;
    if (!RegisterClassExW(&wc)) { ShzSetStatus(IDS_ERR_CLASS, GetLastError()); return FALSE; }
    g_shell.desktop = CreateWindowExW(WS_EX_TOOLWINDOW, SHZ_CLASS_DESKTOP, ShzStr(IDS_DESKTOP), WS_POPUP,
                                      0, 0, sw, sh, NULL, NULL, g_shell.inst, NULL);
    if (!g_shell.desktop) { ShzSetStatus(IDS_ERR_WINDOW, GetLastError()); return FALSE; }
    /* Register the caller-owned top-level window as THE shell window (user32 SetShellWindow, backend-defined
     * scope; one shell only: a refusal, e.g. because a shell window already exists, is reported, not hidden).
     * The backend clears the registration when the window is destroyed. */
    SetLastError(0);
    if (!SetShellWindow(g_shell.desktop)) {
        DWORD err = GetLastError();
        DestroyWindow(g_shell.desktop);
        g_shell.desktop = NULL;
        ShzSetStatus(IDS_ERR_SHELL, err ? err : ERROR_ACCESS_DENIED);   /* ERROR_ACCESS_DENIED only if the API set no error */
        return FALSE;
    }
    g_shell.shell_registered = TRUE;
    ShowWindow(g_shell.desktop, SW_SHOWNOACTIVATE);
    SetWindowPos(g_shell.desktop, HWND_BOTTOM, 0, 0, 0, 0, SWP_NOMOVE | SWP_NOSIZE | SWP_NOACTIVATE);
    /* Keyboard: ask for focus on the desktop WITHOUT raising or activating it (no SetForegroundWindow/SetActiveWindow).
     * Whether this takes effect in a guest is unverified; the result is only recorded in the REGISTERED marker. */
    SetFocus(g_shell.desktop);
    g_shell.focus_on_desktop = (GetFocus() == g_shell.desktop);
    ShzMarkRegistered();
    UpdateWindow(g_shell.desktop);
    return TRUE;
}
