/*
 * ShizukuOS shell candidate: Shell_TrayWnd taskbar (start button, task buttons, status, clock).
 *
 * Structure adapted from ReactOS Explorer, pinned commit ce41f2e98e0450ce624c5fc6155fb671af7cc3b5:
 *   - base/shell/explorer/traywnd.cpp CTrayWindow::RegLoadSettings, non-themed minimum size (lines 1659-1686):
 *     taskbar height = start button height + 2 * (SM_CYEDGE + SM_CYDLGFRAME).
 *   - traywnd.cpp start button push/pop state (m_StartButton BM_SETSTATE, lines 1957, 1971; 821-824 approximate): here the
 *     button is painted by the tray itself and g_shell.start_open stands in for BST_PUSHED.
 *   - traywnd.cpp work-area reservation (ResizeWorkArea, line 1583, call at 1652): SPI_SETWORKAREA, restored on destroy.
 *   - taskswnd.cpp task button row model (see tasks.c).
 * Upstream notices: PROJECT ReactOS Explorer; LICENSE LGPL-2.1-or-later;
 *   COPYRIGHT Copyright 2006-2007 Thomas Weidenmueller <w3seek@reactos.org> and other ReactOS contributors.
 * Derived file is LGPL-2.1-or-later; see ../upstream/reactos/COPYING.LIB.
 *
 * Taskbar layout: Start left, live task buttons, clock right; one TrayGeometry() feeds paint/hover/click.
 *
 * Visual style: tentative "glass-like gradient" direction only (flat vertical gradients drawn with FillRect).
 * No DWM, theme API or Longhorn/Aero resource is used or implied.
 */
#include "shzcrt.h"
#include "shell.h"
#include "layout.h"
#include "icons.h"

/* Published theme metrics are scaled consistently for painting, hit testing
 * and work-area reservation. Start | live task windows | status/clock form
 * separate groups, independently inspired by Seelen's visibleGroupedItems
 * and panel edge spacing; no Seelen code is incorporated (AGPL-3.0). */
#define START_W  ShzPx(TH()->buttons_start_width)
#define START_H  ShzPx(TH()->buttons_height)
#define CLOCK_W  ShzPx(TH()->taskbar_clock_width)
#define STATUS_W ShzPx(TH()->taskbar_status_width)
#define OVF_W    ShzPx(TH()->taskbar_overflow_width)
#define BTN_H    ShzPx(TH()->buttons_height)
#define BTN_GAP  ShzPx(TH()->buttons_gap)

static RECT g_old_workarea;
static BOOL g_workarea_changed;
static int  g_tray_h;
static int  g_hover_hidden;
static int  g_hover = -2; /* -1=start, 0..63=task, -2=none */

void ShzTaskbarInvalidate(void) { if (g_shell.tray) InvalidateRect(g_shell.tray, NULL, FALSE); }

/* Single geometry source for paint, hover and click: Start | task buttons | [+N] | [status] | clock.
 * Nothing is reserved for idle branding; the status box exists only while a real transient message is visible,
 * and the overflow box only while task buttons really do not fit. */
typedef struct {
    RECT start, area, overflow, status, clock;
    BOOL status_on;
    int task_count;
    HWND task_handles[SHZ_MAX_TASKS]; /* paint snapshot: live table compaction cannot retarget a click */
    SHZ_TASKLAYOUT lay;
} TRAYGEOM;
static TRAYGEOM g_painted_geometry;
static BOOL g_geometry_valid;
static int g_painted_width, g_painted_height;

static void TaskLayout(int width, int count, SHZ_TASKLAYOUT *out)
{
    SHZ_TASK_ROW row = ShzTaskRow(width, count, ShzUiScale(), BTN_GAP);
    out->btn_w = row.width; out->per_line = row.shown;
    out->rows = row.shown ? 1 : 0; out->hidden = row.hidden;
}

static void TrayGeometry(const RECT *c, TRAYGEOM *g)
{
    int right = c->right, left, i;
    ZeroMemory(g, sizeof *g);
    g->task_count = ShzClamp(g_shell.ntasks, 0, SHZ_MAX_TASKS);
    for (i = 0; i < g->task_count; ++i) g->task_handles[i] = g_shell.tasks[i].hwnd;
    g->clock.left = right - CLOCK_W; g->clock.right = right - ShzPx(12);
    g->clock.top = c->top; g->clock.bottom = c->bottom;
    right = g->clock.left;
    g->status_on = g_shell.status[0] && GetTickCount() - g_shell.status_tick < 8000;
    if (g->status_on) {
        g->status.right = right - ShzPx(4); g->status.left = right - STATUS_W;
        g->status.top = c->top; g->status.bottom = c->bottom;
        right = g->status.left;
    }
    g->start.left = ShzPx(8); g->start.right = g->start.left + START_W;
    g->start.top = (c->bottom - START_H) / 2; g->start.bottom = g->start.top + START_H;
    left = g->start.right + ShzPx(10);
    g->area.left = left; g->area.right = right - ShzPx(6);
    g->area.top = (c->bottom - BTN_H) / 2; g->area.bottom = g->area.top + BTN_H;
    if (g->area.right < g->area.left) g->area.right = g->area.left;
    TaskLayout(g->area.right - g->area.left, g->task_count, &g->lay);
    if (g->lay.hidden > 0) {
        g->overflow = g->area; g->overflow.left = g->area.right - OVF_W;
        if (g->overflow.left < g->area.left) g->overflow.left = g->area.left;
        g->area.right = g->overflow.left;
        TaskLayout(g->area.right - g->area.left, g->task_count, &g->lay);
    }
}

/* Hit tests use what is visibly painted; the next timer paint updates expiry geometry. */
static void TrayInputGeometry(const RECT *c, TRAYGEOM *g)
{
    if (g_geometry_valid && g_painted_width == c->right && g_painted_height == c->bottom) *g = g_painted_geometry;
    else TrayGeometry(c, g);
}

static void TaskRect(const TRAYGEOM *g, int i, RECT *r)
{
    r->left = g->area.left + i * (g->lay.btn_w + BTN_GAP); r->right = r->left + g->lay.btn_w;
    r->top = g->area.top; r->bottom = g->area.bottom;
}

/* Returns -1 for Start, 0..n for a task, -2 for nothing. */
static int TrayHit(const TRAYGEOM *g, POINT pt)
{
    RECT r; int i;
    if (PtInRect(&g->start, pt)) return -1;
    for (i = 0; i < g->lay.per_line && i < g->task_count && i < SHZ_MAX_TASKS; ++i) {
        TaskRect(g, i, &r);
        if (PtInRect(&r, pt)) return i;
    }
    return -2;
}

void ShzTaskbarGetStartRect(RECT *rc)
{
    RECT c; TRAYGEOM g;
    GetClientRect(g_shell.tray, &c);
    TrayInputGeometry(&c, &g);
    *rc = g.start;
}

static void PaintButton(HDC dc, RECT r, const WCHAR *text, BOOL pushed, BOOL active, BOOL hover, int icon_kind)
{
    const SHZ_THEME *th = TH();
    RECT icon;
    COLORREF top = TC(pushed ? th->buttons_pressed_top : active || hover ? th->buttons_active_top : th->buttons_normal_top);
    COLORREF bottom = TC(pushed ? th->buttons_pressed_bottom : active || hover ? th->buttons_active_bottom : th->buttons_normal_bottom);
    ShzFillGradientV(dc, &r, top, bottom);
    ShzFrame(dc, &r, TC(th->buttons_edge), 1);
    if (active || pushed) {
        RECT mark = r; mark.left += ShzPx(8); mark.right -= ShzPx(8);
        mark.top = mark.bottom - ShzPx(3);
        ShzFill(dc, &mark, TC(th->border_focus));
    }
    icon = r; icon.left += ShzPx(10); icon.top += (r.bottom-r.top-ShzPx(22))/2;
    icon.right = icon.left+ShzPx(22); icon.bottom = icon.top+ShzPx(22);
    ShzDrawIcon(dc, &icon, icon_kind, TC(th->buttons_text));
    r.left += ShzPx(42); r.right -= ShzPx(10);
    SetTextColor(dc, TC(pushed ? th->buttons_text_pressed : th->buttons_text));
    ShzDrawText(dc, text, &r, DT_SINGLELINE|DT_VCENTER|DT_LEFT|DT_END_ELLIPSIS|DT_NOPREFIX);
}

static void OnPaint(HWND hwnd)
{
    PAINTSTRUCT ps;
    RECT c, r;
    TRAYGEOM g;
    unsigned gen = (unsigned)ShzThemeGeneration();   /* captured before painting */
    HDC dc = BeginPaint(hwnd, &ps);
    SYSTEMTIME st;
    WCHAR tm[8];
    HWND fg = GetForegroundWindow();
    int i;
    if (!dc) return;
    GetClientRect(hwnd, &c);
    ShzFillGradientV(dc, &c, TC(TH()->taskbar_bg_top), TC(TH()->taskbar_bg_bottom));
    r = c; r.bottom = r.top + (c.bottom - c.top) / 2;           /* upper "gloss" band: opaque overlay stripe (no alpha/blur) */
    ShzFillGradientV(dc, &r, TC(TH()->taskbar_gloss_top), TC(TH()->taskbar_gloss_bottom));

    TrayGeometry(&c, &g);
    PaintButton(dc, g.start, ShzStr(IDS_START), g_shell.start_open, FALSE, g_hover == -1, SHZ_ICON_DROP);
    g_hover_hidden = g.lay.hidden;
    for (i = 0; i < g.lay.per_line && i < g.task_count && i < SHZ_MAX_TASKS; ++i) {
        TaskRect(&g, i, &r);
        PaintButton(dc, r, g_shell.tasks[i].title[0] ? g_shell.tasks[i].title : L"-",
                    FALSE, g.task_handles[i] == fg, g_hover == i, SHZ_ICON_DOCUMENT);
    }
    if (g.lay.hidden > 0) {                             /* visible "+N": buttons that do not fit are not drawn */
        WCHAR n[24] = L"+";
        ShzFormatU64((unsigned long long)g.lay.hidden, n + 1, 22);
        SetTextColor(dc, TC(TH()->taskbar_overflow_text));
        ShzDrawText(dc, n, &g.overflow, DT_SINGLELINE | DT_VCENTER | DT_RIGHT);
    }
    if (g.status_on) {                                  /* real transient status only; no idle branding */
        SetTextColor(dc, TC(TH()->taskbar_warn_text));
        ShzDrawText(dc, g_shell.status, &g.status, DT_SINGLELINE | DT_VCENTER | DT_RIGHT | DT_END_ELLIPSIS | DT_NOPREFIX);
    }

    GetLocalTime(&st);
    ShzFormatTime(&st, tm);
    SetTextColor(dc, TC(TH()->taskbar_text));
    ShzDrawText(dc, tm, &g.clock, DT_SINGLELINE | DT_VCENTER | DT_RIGHT);
    if (EndPaint(hwnd, &ps)) {
        g_painted_geometry = g; g_painted_width = c.right; g_painted_height = c.bottom; g_geometry_valid = TRUE;
        static unsigned last_gen; static int have_last;   /* suppress identical idle repaints (clock ticks) */
        if (!have_last || last_gen != gen) { have_last = 1; last_gen = gen; printf("SHZ-SHELL UI tray gen=%u\n", gen); }
    }
    ShzMarkPainted(TRUE);
}

static void OnClick(HWND hwnd, int x, int y)
{
    RECT c; TRAYGEOM g; POINT pt; int hit;
    pt.x = x; pt.y = y;
    GetClientRect(hwnd, &c);
    TrayInputGeometry(&c, &g);
    hit = TrayHit(&g, pt);
    if (hit == -1) {
        /* A click that dismissed the menu by deactivating it must not reopen it at once (ReactOS tracks the
         * same race around the start button, traywnd.cpp ~lines 1950-1975). */
        if (!(g_shell.start_open == FALSE && GetTickCount() - g_shell.start_closed_tick < 250))
            ShzStartMenuToggle();
    } else if (hit >= 0 && hit < g.task_count && IsWindow(g.task_handles[hit])) {
        ShzTaskActivate(g.task_handles[hit]); ShzTasksRefresh(); ShzTaskbarInvalidate();
    }
}

static void OnHover(HWND hwnd, int x, int y)
{
    RECT c; TRAYGEOM g; POINT pt = { x, y }; int hover;
    GetClientRect(hwnd, &c); TrayInputGeometry(&c, &g);
    hover = TrayHit(&g, pt);
    if (hover != g_hover) { g_hover = hover; InvalidateRect(hwnd, NULL, FALSE); }
}

static LRESULT CALLBACK TrayProc(HWND hwnd, UINT msg, WPARAM wp, LPARAM lp)
{
    switch (msg) {
    case WM_PAINT: OnPaint(hwnd); return 0;
    case WM_ERASEBKGND: return 1;
    case WM_MOUSEMOVE: OnHover(hwnd, (short)LOWORD(lp), (short)HIWORD(lp)); return 0;
    case WM_LBUTTONDOWN: OnClick(hwnd, (short)LOWORD(lp), (short)HIWORD(lp)); return 0;
    case WM_TIMER:
        if (wp == SHZ_TIMER_TASKS) ShzTasksRefresh();
        InvalidateRect(hwnd, NULL, FALSE);
        return 0;
    case WM_KEYDOWN: case WM_SYSKEYDOWN:
        if (ShzGlobalKey((UINT)wp)) return 0;
        break;
    case WM_MOUSEACTIVATE: return MA_NOACTIVATE;
    case WM_DESTROY:
        KillTimer(hwnd, SHZ_TIMER_CLOCK);
        KillTimer(hwnd, SHZ_TIMER_TASKS);
        if (g_shell.tray == hwnd) g_shell.tray = NULL;      /* no dangling handle for ShzSetStatus/cleanup */
        if (g_workarea_changed)
            SystemParametersInfoW(SPI_SETWORKAREA, 0, &g_old_workarea, SPIF_SENDCHANGE);
        PostQuitMessage(0);                    /* the tray owns the shell lifetime, as Explorer's tray does */
        return 0;
    }
    return DefWindowProcW(hwnd, msg, wp, lp);
}

/* Theme reload: new height/widths/colours. Same tray window and class; work area re-reserved (the ORIGINAL work area
 * saved at creation is still what WM_DESTROY restores). Position stays at the bottom: top/left/right/autohide
 * requests are retained and reported as unsupported (SHZ_CAP_TASKBAR_EDGE). */
void ShzTaskbarRelayout(void)
{
    int sw = GetSystemMetrics(SM_CXSCREEN), sh = GetSystemMetrics(SM_CYSCREEN);
    RECT wa;
    if (!g_shell.tray || sw <= 0 || sh <= 0) return;
    g_geometry_valid = FALSE;
    g_tray_h = ShzPx(TH()->taskbar_height);
    if (g_tray_h < START_H + 4) g_tray_h = START_H + 4;
    if (!SetWindowPos(g_shell.tray, HWND_TOPMOST, 0, sh - g_tray_h, sw, g_tray_h, SWP_NOACTIVATE))
        ShzSetStatus(IDS_ERR_WINDOW, GetLastError());
    wa.left = 0; wa.top = 0; wa.right = sw; wa.bottom = sh - g_tray_h;
    if (SystemParametersInfoW(SPI_SETWORKAREA, 0, &wa, SPIF_SENDCHANGE)) g_workarea_changed = TRUE;
    InvalidateRect(g_shell.tray, NULL, FALSE);
}

BOOL ShzTaskbarCreate(void)
{
    WNDCLASSEXW wc;
    int sw = GetSystemMetrics(SM_CXSCREEN), sh = GetSystemMetrics(SM_CYSCREEN);
    RECT wa;
    if (sw <= 0 || sh <= 0) { ShzSetStatus(IDS_ERR_WINDOW, GetLastError()); return FALSE; }
    /* RegLoadSettings minimum height (traywnd.cpp 1659-1686) is replaced by the theme's taskbar.height, which the
     * schema bounds to >= buttons.height + 4 (the old formula gave 34 with the system metrics of the default scheme). */
    g_geometry_valid = FALSE;
    g_tray_h = ShzPx(TH()->taskbar_height);
    if (g_tray_h < START_H + 4) g_tray_h = START_H + 4;

    wc.cbSize = sizeof wc; wc.style = CS_DBLCLKS; wc.lpfnWndProc = TrayProc; wc.cbClsExtra = wc.cbWndExtra = 0;
    wc.hInstance = g_shell.inst; wc.hIcon = NULL; wc.hCursor = LoadCursorW(NULL, IDC_ARROW);
    wc.hbrBackground = NULL; wc.lpszMenuName = NULL; wc.lpszClassName = SHZ_CLASS_TRAY; wc.hIconSm = NULL;
    if (!RegisterClassExW(&wc)) { ShzSetStatus(IDS_ERR_CLASS, GetLastError()); return FALSE; }

    g_shell.tray = CreateWindowExW(WS_EX_TOOLWINDOW | WS_EX_TOPMOST, SHZ_CLASS_TRAY, ShzStr(IDS_TASKBAR),
                                   WS_POPUP | WS_CLIPCHILDREN, 0, sh - g_tray_h, sw, g_tray_h,
                                   NULL, NULL, g_shell.inst, NULL);
    if (!g_shell.tray) { ShzSetStatus(IDS_ERR_WINDOW, GetLastError()); return FALSE; }

    if (SystemParametersInfoW(SPI_GETWORKAREA, 0, &g_old_workarea, 0)) {
        wa.left = 0; wa.top = 0; wa.right = sw; wa.bottom = sh - g_tray_h;
        g_workarea_changed = SystemParametersInfoW(SPI_SETWORKAREA, 0, &wa, SPIF_SENDCHANGE) != 0;
    }
    if (!SetTimer(g_shell.tray, SHZ_TIMER_CLOCK, 1000, NULL) || !SetTimer(g_shell.tray, SHZ_TIMER_TASKS, 1000, NULL)) {
        DWORD err = GetLastError();
        KillTimer(g_shell.tray, SHZ_TIMER_CLOCK);
        KillTimer(g_shell.tray, SHZ_TIMER_TASKS);
        ShzSetStatus(IDS_ERR_TIMER, err);
        return FALSE;       /* tray window/work area are released by ShzShellCleanup() (main.c) after the message is shown */
    }
    g_shell.timers_ok = TRUE;
    ShowWindow(g_shell.tray, SW_SHOWNOACTIVATE);
    UpdateWindow(g_shell.tray);
    return TRUE;
}
