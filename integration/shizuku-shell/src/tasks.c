/*
 * ShizukuOS shell candidate: task window eligibility, task table refresh and button layout.
 *
 * Adapted (rewritten in C, reduced) from ReactOS Explorer, pinned commit
 * ce41f2e98e0450ce624c5fc6155fb671af7cc3b5:
 *   - base/shell/explorer/traywnd.cpp  CTrayWindow::IsSpecialHWND  (lines 2239-2243)
 *   - base/shell/explorer/traywnd.cpp  CTrayWindow::IsTaskWnd      (lines 2300-2316)
 *   - base/shell/explorer/taskswnd.cpp CTaskSwitchWnd::EnumWindowsProc/RefreshWindowList (lines 1486-1508)
 *   - base/shell/explorer/taskswnd.cpp CTaskSwitchWnd::UpdateButtonsSize, horizontal branch (lines 1351-1440)
 *   - base/shell/explorer/taskswnd.cpp task array growth bound (TASK_ITEM_ARRAY_ALLOC, lines 22, 1025-1060):
 *     ReactOS grows the array on the heap; here the table is fixed at SHZ_MAX_TASKS and overflow is reported.
 *
 * Original upstream notices (taskswnd.cpp / traywnd.cpp):
 * PROJECT:     ReactOS Explorer
 * LICENSE:     LGPL-2.1-or-later (https://spdx.org/licenses/LGPL-2.1-or-later)
 * COPYRIGHT:   Copyright 2006-2007 Thomas Weidenmueller <w3seek@reactos.org>
 *              Copyright 2026 Vitaly Orekhov <vkvo2000@vivaldi.net>   (taskswnd.cpp header)
 * See ../upstream/reactos/COPYING.LIB and ../PROVENANCE.md. This derived file is LGPL-2.1-or-later.
 */
#include "shell.h"

/* ReactOS IsSpecialHWND: the tray window and the desktop window are never tasks. */
static BOOL IsSpecialHWND(HWND hwnd)
{
    return hwnd == g_shell.tray || (g_shell.desktop != NULL && hwnd == g_shell.desktop);
}

/* ReactOS IsTaskWnd: visible, not special, not WS_EX_TOOLWINDOW, and (WS_EX_APPWINDOW or no owner). */
BOOL ShzIsTaskWnd(HWND hwnd)
{
    if (IsWindow(hwnd) && IsWindowVisible(hwnd) && !IsSpecialHWND(hwnd)) {
        DWORD ex = (DWORD)GetWindowLongPtrW(hwnd, GWL_EXSTYLE);
        if (((ex & WS_EX_APPWINDOW) || GetWindow(hwnd, GW_OWNER) == NULL) && !(ex & WS_EX_TOOLWINDOW))
            return TRUE;
    }
    return FALSE;
}

static int FindTask(HWND hwnd)       /* ReactOS FindTaskItem, linear search */
{
    int i;
    for (i = 0; i < g_shell.ntasks; ++i)
        if (g_shell.tasks[i].hwnd == hwnd) return i;
    return -1;
}

static BOOL CALLBACK EnumProc(HWND hwnd, LPARAM lp)      /* ReactOS EnumWindowsProc -> AddTask */
{
    int ix;
    (void)lp;
    if (!ShzIsTaskWnd(hwnd)) return TRUE;
    ix = FindTask(hwnd);
    if (ix < 0) {
        if (g_shell.ntasks >= SHZ_MAX_TASKS) {            /* never write past the table; remember and report */
            g_shell.tasks_overflow = TRUE;
            return TRUE;
        }
        ix = g_shell.ntasks++;
        g_shell.tasks[ix].hwnd = hwnd;
    }
    g_shell.tasks[ix].seen = TRUE;
    {
        int n = GetWindowTextW(hwnd, g_shell.tasks[ix].title, (int)(sizeof g_shell.tasks[ix].title / sizeof(WCHAR)));
        if (n <= 0) g_shell.tasks[ix].title[0] = 0;       /* untitled (or API failure): empty text, button still shown */
    }
    return TRUE;
}

void ShzTasksRefresh(void)
{
    int i, out = 0;
    BOOL was_overflow = g_shell.tasks_overflow;
    for (i = 0; i < g_shell.ntasks; ++i) g_shell.tasks[i].seen = FALSE;
    g_shell.tasks_overflow = FALSE;
    if (!EnumWindows(EnumProc, 0)) ShzSetStatus(IDS_ERR_ENUM, GetLastError());
    for (i = 0; i < g_shell.ntasks; ++i) {                 /* sweep closed windows, keep order of survivors */
        if (g_shell.tasks[i].seen) {
            if (out != i) g_shell.tasks[out] = g_shell.tasks[i];
            ++out;
        }
    }
    g_shell.ntasks = out;
    if (g_shell.tasks_overflow && !was_overflow) ShzSetStatus(IDS_ERR_TASKS_FULL, 0);
}

/* Click on a task button: restore if minimized, minimize if it already is the foreground window, otherwise
 * bring to front. Behaviour modelled on ReactOS CTaskSwitchWnd task activation; failures are shown, not hidden. */
void ShzTaskActivate(HWND hwnd)
{
    if (!IsWindow(hwnd)) { ShzTasksRefresh(); return; }
    if (IsIconic(hwnd)) {
        ShowWindow(hwnd, SW_RESTORE);
    } else if (GetForegroundWindow() == hwnd) {
        ShowWindow(hwnd, SW_MINIMIZE);
        return;
    }
    if (!IsWindow(hwnd)) { ShzTasksRefresh(); return; }   /* closed while restoring: drop stale snapshot entry */
    SetLastError(0);
    if (!SetForegroundWindow(hwnd)) { ShzSetStatus(IDS_ERR_FOCUS, GetLastError()); return; }
    /* A TRUE return alone is not proof of focus: verify the window really became foreground, else report refusal. */
    if (GetForegroundWindow() != hwnd) ShzSetStatus(IDS_ERR_FOCUS, 0);
}

/* Port of the horizontal branch of CTaskSwitchWnd::UpdateButtonsSize (taskswnd.cpp 1351-1440): rows from the
 * client height, button width = even share clamped to [SM_CXSIZE + 2*SM_CXEDGE, SM_CXMINIMIZED], then how many
 * actually fit per line. Button spacing (toolbar metric upstream) is fixed to 2. Buttons that still do not fit
 * are counted in 'hidden' so the taskbar can show a visible "+N" instead of overflowing its children. */
void ShzTaskLayout(int client_w, int client_h, int count, SHZ_TASKLAYOUT *out)
{
    const int cyBtn = TH()->buttons_height, spacing = TH()->buttons_gap;   /* theme metrics (Slade: 24 / 2, as before) */
    int rows, per_line, sz, mn, mx;
    out->btn_w = 0; out->per_line = 0; out->rows = 0; out->hidden = 0;
    if (count <= 0 || client_w <= 0 || client_h <= 0) return;
    rows = (client_h + spacing) / (cyBtn + spacing);
    if (rows < 1) rows = 1;
    per_line = (count + rows - 1) / rows;
    mn = GetSystemMetrics(SM_CXSIZE) + 2 * GetSystemMetrics(SM_CXEDGE);
    mx = GetSystemMetrics(SM_CXMINIMIZED);
    if (mn <= 0) mn = 24;                        /* GetSystemMetrics failure returns 0: use a sane floor */
    if (mn < TH()->buttons_min_width) mn = TH()->buttons_min_width;   /* theme floor (schema: 48..120) */
    if (mx < mn) mx = mn;
    sz = (client_w - per_line * spacing) / per_line;
    if (sz < mn) sz = mn;
    if (sz > mx) sz = mx;
    per_line = client_w / (sz + spacing);
    if (per_line == 0) per_line = 1;
    out->btn_w = sz; out->per_line = per_line; out->rows = rows;
    out->hidden = count > per_line * rows ? count - per_line * rows : 0;
}

/* Settings stays in this shell's existing window/task module. Original
 * ShizukuOS work: documented Win32 behaviour, no upstream UI code copied.
 * The same owning UI thread uses the existing atomic theme loader and Noto.
 * main cleanup and ui theme propagation must consume the declared hooks. */
#include "shzcrt.h"
#include "layout.h"
#include "icons.h"
#define SETTINGS_CLASS L"ShizukuSettings"
#define SETTINGS_ACTIONS 5
static HWND g_settings;
static BOOL g_settings_registered;
static unsigned g_settings_epoch;
static int g_settings_sel, g_settings_hover = -1, g_settings_result;
static BOOL g_settings_custom_available;
static BOOL g_settings_unsaved;
static const WCHAR *const g_settings_names[4] = { L"Slade", L"Flute", L"Jade", L"\uC0AC\uC6A9\uC790 \uD14C\uB9C8" };

static void SettingsCheckCustom(void)
{
    DWORD attr = GetFileAttributesW(L"E:\\SHZ\\THEME\\CUSTOM.INI");
    g_settings_custom_available = attr != INVALID_FILE_ATTRIBUTES && !(attr & FILE_ATTRIBUTE_DIRECTORY);
}

static BOOL SettingsActionEnabled(int action)
{
    return action >= 0 && action < SETTINGS_ACTIONS &&
           (action != SHZ_THEME_CUSTOM || g_settings_custom_available);
}

static void SettingsMoveFocus(int direction)
{
    int i;
    for (i = 0; i < SETTINGS_ACTIONS; ++i) {
        g_settings_sel = (g_settings_sel + SETTINGS_ACTIONS + direction) % SETTINGS_ACTIONS;
        if (SettingsActionEnabled(g_settings_sel)) break;
    }
}

typedef struct { RECT title, preview, intro, row[SETTINGS_ACTIONS], status; int sidebar; } SETTINGS_LAYOUT;
static void SettingsLayout(const RECT *c, SETTINGS_LAYOUT *g)
{
    int i, margin = ShzPx(24), top, row, left, right;
    g->sidebar = c->right >= ShzPx(720) ? ShzPx(168) : 0;
    left = g->sidebar + margin; right = c->right - margin;
    g->title = *c; g->title.left = left; g->title.right = right;
    g->title.top = ShzPx(16); g->title.bottom = ShzPx(52);
    /* Windows Settings: current-theme preview card (real SHZ_THEME colours) under the page heading. */
    g->preview = g->title; g->preview.top = ShzPx(58); g->preview.bottom = c->bottom >= ShzPx(440) ? ShzPx(138) : ShzPx(58);
    g->intro = g->title; g->intro.top = g->preview.bottom + ShzPx(10); g->intro.bottom = g->intro.top + ShzPx(26);
    top = g->intro.bottom + ShzPx(4);
    if (c->bottom < ShzPx(440)) { g->intro.top = g->intro.bottom = ShzPx(56); top = ShzPx(56); }
    /* compact native list rows (Windows ~32px), shrink on small windows, never giant buttons */
    row = (c->bottom - top - ShzPx(64)) / 5;
    row = ShzClamp(row, ShzPx(24), ShzPx(36));
    if (top + 5 * row + ShzPx(18) > c->bottom) row = (c->bottom - top - ShzPx(18)) / 5;
    if (row < 1) row = 1;
    for (i = 0; i < 4; ++i) {
        g->row[i].left = left; g->row[i].right = right;
        g->row[i].top = top + i * row; g->row[i].bottom = top + (i + 1) * row - ShzPx(2);
        if (g->row[i].bottom <= g->row[i].top) g->row[i].bottom = g->row[i].top + 1;
    }
    /* reload: standard-width command button, left aligned */
    g->row[4] = g->row[3]; g->row[4].top = top + 4 * row + ShzPx(10);
    g->row[4].bottom = g->row[4].top + ShzClamp(row, ShzPx(24), ShzPx(32));
    g->row[4].right = left + ShzPx(200) < right ? left + ShzPx(200) : right;
    g->status = g->row[4]; g->status.right = right; g->status.top = g->row[4].bottom + ShzPx(8);
    g->status.bottom = c->bottom - ShzPx(8);
}

static void SettingsAction(HWND hwnd, int action)
{
    unsigned before = (unsigned)ShzThemeGeneration(), refused = g_shell.theme_refusals;
    unsigned persist = g_shell.theme_persist_failures;
    if (!SettingsActionEnabled(action)) return;
    if (action < 4) ShzThemeShellSelect(action); else ShzThemeShellReload();
    if (g_shell.theme_refusals != refused || (unsigned)ShzThemeGeneration() == before) g_settings_result = IDS_THEME_LOAD_FAILED;
    else if (g_shell.theme_persist_failures != persist) {
        g_settings_unsaved = TRUE;
        g_settings_result = IDS_THEME_NOPERSIST;
    } else {
        if (action < 4) g_settings_unsaved = FALSE;
        g_settings_result = g_settings_unsaved ? IDS_THEME_NOPERSIST :
                            action < 4 ? IDS_THEME_SAVED : IDS_THEME_RELOADED;
    }
    SettingsCheckCustom();
    InvalidateRect(hwnd, NULL, FALSE);
    UpdateWindow(hwnd);
}

static void SettingsPaint(HWND hwnd)
{
    PAINTSTRUCT ps; RECT c, r, icon; SETTINGS_LAYOUT g;
    unsigned gen = (unsigned)ShzThemeGeneration();
    const SHZ_THEME *th = TH(); int i, current = ShzThemeCurrentId();
    HDC dc = BeginPaint(hwnd, &ps);
    if (!dc) return;
    GetClientRect(hwnd, &c); SettingsLayout(&c, &g);
    /* Semantic surface and text colours stay readable for built-ins and Custom. */
    ShzFill(dc, &c, TC(th->background_surface));
    if (g.sidebar) {
        r = c; r.right = g.sidebar;
        ShzFill(dc, &r, TC(th->background_panel_face));
        r.left = r.right - 1; ShzFill(dc, &r, TC(th->buttons_edge));
        r.left = ShzPx(20); r.right = g.sidebar - ShzPx(16); r.top = ShzPx(26); r.bottom = ShzPx(58);
        SetTextColor(dc, TC(th->background_panel_text));
        ShzDrawText(dc, ShzStr(IDS_SETTINGS), &r, DT_SINGLELINE | DT_VCENTER);
        r.left = ShzPx(8); r.top = ShzPx(86); r.bottom = ShzPx(122);
        ShzFill(dc, &r, TC(th->selection_top));
        icon = r; icon.left += ShzPx(8); icon.top += ShzPx(6);
        icon.right = icon.left + ShzPx(24); icon.bottom = icon.top + ShzPx(24);
        ShzDrawIcon(dc, &icon, SHZ_ICON_THEME, TC(th->selection_text));
        r.left += ShzPx(40); r.right -= ShzPx(6); SetTextColor(dc, TC(th->selection_text));
        ShzDrawText(dc, ShzStr(IDS_PERSONALIZATION), &r, DT_SINGLELINE | DT_VCENTER | DT_END_ELLIPSIS);
    }
    ShzHeading(dc, ShzStr(IDS_PERSONALIZATION), &g.title, TC(th->background_surface_text));
    if (g.preview.bottom > g.preview.top + ShzPx(8)) {
        /* preview of the active theme: swatches are the live SHZ_THEME fields, not a screenshot */
        RECT w = g.preview, t, s2; int sw = ShzPx(40), k;
        ShzFill(dc, &w, TC(th->background_panel_face));
        ShzFrame(dc, &w, TC(th->buttons_edge), 1);
        t = w; t.left += ShzPx(12); t.top += ShzPx(10); t.bottom = t.top + ShzPx(28);
        ShzFill(dc, &t, TC(th->selection_top));
        t.left += ShzPx(8); SetTextColor(dc, TC(th->selection_text));
        ShzDrawText(dc, current >= 0 && current < 4 ? g_settings_names[current] : g_settings_names[3], &t,
                    DT_SINGLELINE | DT_VCENTER | DT_END_ELLIPSIS | DT_NOPREFIX);
        s2 = w; s2.left += ShzPx(12); s2.top = w.bottom - ShzPx(36); s2.bottom = w.bottom - ShzPx(10);
        for (k = 0; k < 4 && s2.left + sw < w.right; ++k) {
            COLORREF col[4]; RECT q = s2;
            col[0] = TC(th->buttons_normal_top); col[1] = TC(th->buttons_normal_bottom);
            col[2] = TC(th->selection_top); col[3] = TC(th->selection_bottom);
            q.right = q.left + sw; ShzFill(dc, &q, col[k]); ShzFrame(dc, &q, TC(th->buttons_edge), 1);
            s2.left += sw + ShzPx(6);
        }
    }
    if (g.intro.bottom > g.intro.top && g.row[0].top >= g.intro.bottom) {
        SetTextColor(dc, TC(th->background_surface_text));
        ShzDrawText(dc, ShzStr(IDS_THEME_CHOOSE), &g.intro, DT_SINGLELINE | DT_VCENTER | DT_END_ELLIPSIS);
    }
    for (i = 0; i < SETTINGS_ACTIONS; ++i) {
        BOOL active = i < 4 && i == current, focus = i == g_settings_sel, hover = i == g_settings_hover;
        BOOL enabled = SettingsActionEnabled(i);
        COLORREF label = TC(!enabled ? th->background_surface_dim_text : active ? th->selection_text : i == 4 || hover ? th->buttons_text : th->background_surface_text);
        r = g.row[i];
        if (i < 4) {   /* list row: flat, accent bar when current, hover tint */
            if (active) ShzFill(dc, &r, TC(th->selection_top));
            else if (hover) ShzFillGradientV(dc, &r, TC(th->buttons_normal_top), TC(th->buttons_normal_bottom));
            if (focus) ShzFrame(dc, &r, TC(th->selection_border), 2);
            else if (active || hover) ShzFrame(dc, &r, TC(th->selection_border), 1);
        } else {       /* native command button */
            ShzFillGradientV(dc, &r, TC(th->buttons_normal_top), TC(th->buttons_normal_bottom));
            ShzFrame(dc, &r, TC(focus || hover ? th->selection_border : th->buttons_edge), focus ? 2 : 1);
        }
        icon = r; icon.left += ShzPx(12); icon.top += (r.bottom - r.top - ShzPx(16)) / 2;
        icon.right = icon.left + ShzPx(16); icon.bottom = icon.top + ShzPx(16);
        SetTextColor(dc, label);
        if (i < 4) {   /* radio-style mark */
            RECT mark = icon; ShzFrame(dc, &mark, label, 1);
            if (active) { mark.left += ShzPx(4); mark.right -= ShzPx(4); mark.top += ShzPx(4); mark.bottom -= ShzPx(4); ShzFill(dc, &mark, TC(th->selection_text)); }
        } else ShzDrawIcon(dc, &icon, SHZ_ICON_REFRESH, TC(th->buttons_text));
        r.left += ShzPx(40); r.right -= ShzPx(12);
        if ((active || !enabled) && r.right - r.left >= ShzPx(280)) {
            RECT note = r;
            note.left = note.right - ShzPx(180); r.right = note.left - ShzPx(8);
            ShzDrawText(dc, ShzStr(active ? IDS_THEME_CURRENT : IDS_THEME_CUSTOM_MISSING), &note,
                        DT_SINGLELINE | DT_VCENTER | DT_RIGHT | DT_END_ELLIPSIS);
        }
        ShzDrawText(dc, i < 4 ? g_settings_names[i] : ShzStr(IDS_THEME_RELOAD), &r,
                    DT_SINGLELINE | DT_VCENTER | DT_END_ELLIPSIS | DT_NOPREFIX);
    }
    if (g.status.bottom > g.status.top) {
        SetTextColor(dc, TC(th->background_surface_text));
        ShzDrawText(dc, ShzStr(g_settings_result ? g_settings_result : IDS_SETTINGS_HINT), &g.status,
                    DT_WORDBREAK);
    }
    if (EndPaint(hwnd, &ps)) {
        static unsigned last_epoch, last_gen; static int last_sel = -1, last_fg = -1, last_focus = -1;
        int fg = GetForegroundWindow() == hwnd, focus = GetFocus() == hwnd;
        if (last_epoch != g_settings_epoch || last_gen != gen || last_sel != g_settings_sel || last_fg != fg || last_focus != focus) {
            last_epoch = g_settings_epoch; last_gen = gen; last_sel = g_settings_sel; last_fg = fg; last_focus = focus;
            printf("SHZ-SHELL UI settings epoch=%u foreground=%d focus=%d sel=%d theme=%d gen=%u\n", g_settings_epoch, fg, focus, g_settings_sel, current, gen);
        }
    }
}

static LRESULT CALLBACK ShzSettingsProc(HWND hwnd, UINT msg, WPARAM wp, LPARAM lp)
{
    switch (msg) {
    case WM_PAINT: SettingsPaint(hwnd); return 0;
    case WM_ERASEBKGND: return 1;
    case WM_SETFOCUS:
        SettingsCheckCustom();
        if (!SettingsActionEnabled(g_settings_sel)) SettingsMoveFocus(1);
        g_settings_hover = -1;
        InvalidateRect(hwnd, NULL, FALSE); return 0;
    case WM_SIZE: case WM_KILLFOCUS: InvalidateRect(hwnd, NULL, FALSE); return 0;
    case WM_MOUSEMOVE: {
        RECT c; SETTINGS_LAYOUT g; POINT p = { (short)LOWORD(lp), (short)HIWORD(lp) }; int i, hover = -1;
        GetClientRect(hwnd, &c); SettingsLayout(&c, &g);
        for (i = 0; i < SETTINGS_ACTIONS; ++i) if (SettingsActionEnabled(i) && PtInRect(&g.row[i], p)) { hover = i; break; }
        if (hover != g_settings_hover) { g_settings_hover = hover; InvalidateRect(hwnd, NULL, FALSE); }
        return 0; }
    case WM_LBUTTONUP: {
        RECT c; SETTINGS_LAYOUT g; POINT p = { (short)LOWORD(lp), (short)HIWORD(lp) }; int i;
        GetClientRect(hwnd, &c); SettingsLayout(&c, &g);
        for (i = 0; i < SETTINGS_ACTIONS; ++i) if (SettingsActionEnabled(i) && PtInRect(&g.row[i], p)) { g_settings_sel = i; SettingsAction(hwnd, i); break; }
        return 0; }
    case WM_KEYDOWN: case WM_SYSKEYDOWN:
        if (wp == VK_ESCAPE) { DestroyWindow(hwnd); return 0; }
        if (wp == VK_TAB || wp == VK_DOWN || wp == VK_RIGHT) {
            int dir = wp == VK_TAB && GetKeyState(VK_SHIFT) < 0 ? -1 : 1;
            SettingsMoveFocus(dir);
        } else if (wp == VK_UP || wp == VK_LEFT) SettingsMoveFocus(-1);
        else if (wp == VK_RETURN || wp == VK_SPACE) { SettingsAction(hwnd, g_settings_sel); return 0; }
        else if (!ShzGlobalKey((UINT)wp)) break;
        InvalidateRect(hwnd, NULL, FALSE); return 0;
    case WM_CLOSE: DestroyWindow(hwnd); return 0;
    case WM_DESTROY:
        if (g_settings == hwnd) g_settings = NULL;
        printf("SHZ-SHELL UI settings-closed epoch=%u\n", g_settings_epoch);
        return 0;
    }
    return DefWindowProcW(hwnd, msg, wp, lp);
}

void ShzSettingsRelayout(void)
{
    if (g_settings && IsWindow(g_settings)) InvalidateRect(g_settings, NULL, FALSE);
}

void ShzSettingsClose(void)
{
    if (g_settings && IsWindow(g_settings)) DestroyWindow(g_settings);
    g_settings = NULL;
}

HWND ShzSettingsOpen(void)
{
    RECT work; WNDCLASSEXW wc; int w, h, current;
    if (!g_settings_registered) {
        ZeroMemory(&wc, sizeof wc); wc.cbSize = sizeof wc; wc.lpfnWndProc = ShzSettingsProc;
        wc.hInstance = g_shell.inst; wc.hCursor = LoadCursorW(NULL, IDC_ARROW); wc.lpszClassName = SETTINGS_CLASS;
        if (!RegisterClassExW(&wc)) { ShzSetStatus(IDS_ERR_CLASS, GetLastError()); return NULL; }
        g_settings_registered = TRUE;
    }
    if (!g_settings || !IsWindow(g_settings)) {
        work.left = work.top = 0; work.right = GetSystemMetrics(SM_CXSCREEN); work.bottom = GetSystemMetrics(SM_CYSCREEN);
        SystemParametersInfoW(SPI_GETWORKAREA, 0, &work, 0);
        if (work.right <= work.left || work.bottom <= work.top) { ShzSetStatus(IDS_ERR_WINDOW, ERROR_INVALID_DATA); return NULL; }
        w = ShzClamp(ShzPx(790), 1, work.right - work.left);
        h = ShzClamp(ShzPx(570), 1, work.bottom - work.top);
        g_settings = CreateWindowExW(0, SETTINGS_CLASS, ShzStr(IDS_SETTINGS), WS_OVERLAPPED | WS_CAPTION | WS_SYSMENU | WS_MINIMIZEBOX,
                                     work.left + (work.right - work.left - w) / 2, work.top + (work.bottom - work.top - h) / 2,
                                     w, h, NULL, NULL, g_shell.inst, NULL);
        if (!g_settings) { ShzSetStatus(IDS_ERR_WINDOW, GetLastError()); return NULL; }
    }
    SettingsCheckCustom();
    current = ShzThemeCurrentId(); g_settings_sel = current >= 0 && current < 4 && SettingsActionEnabled(current) ? current : 0;
    g_settings_result = g_settings_unsaved ? IDS_THEME_NOPERSIST : 0; g_settings_hover = -1;
    if (++g_settings_epoch == 0) g_settings_epoch = 1;
    ShowWindow(g_settings, IsIconic(g_settings) ? SW_RESTORE : SW_SHOW);
    SetLastError(0);
    if (!SetForegroundWindow(g_settings) || GetForegroundWindow() != g_settings) ShzSetStatus(IDS_ERR_FOCUS, GetLastError());
    SetFocus(g_settings);
    if (GetFocus() != g_settings) ShzSetStatus(IDS_ERR_FOCUS, GetLastError());
    InvalidateRect(g_settings, NULL, FALSE); UpdateWindow(g_settings);
    return g_settings;
}
