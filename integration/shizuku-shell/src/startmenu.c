/*
 * ShizukuOS shell candidate: start menu popup (flat list, keyboard + mouse).
 *
 * Lifecycle adapted from ReactOS Explorer (pinned commit ce41f2e98e0450ce624c5fc6155fb671af7cc3b5):
 *   - traywnd.cpp CTrayWindow popup positioning relative to the start button (lines ~2947-2990) and the
 *     "menu open <-> start button pushed" coupling (lines 1957-1971). ReactOS uses an IMenuBand/IDeskBand COM
 *     shell namespace menu (CreateStartMenu, lines 2376, 2567); that COM menu is NOT implemented here -- this is
 *     a plain owner-drawn Win32 window. Entries are static (programs) plus a live list of the task table.
 * Upstream notices: ReactOS Explorer, LGPL-2.1-or-later, Copyright ReactOS contributors
 * (traywnd.cpp: Thomas Weidenmueller et al.). Derived file is LGPL-2.1-or-later; see COPYING.LIB.
 */
#include "shzcrt.h"
#include "shell.h"
#include "layout.h"
#include "icons.h"
#include "catalog.h"

/* Windows 7-style two-column popup: staged apps/window list left, shortcuts right, Exit bar at the bottom.
 * Displays narrower than two columns need fall back to the original single column at theme start_width. */
#define MENU_MAXW (GetSystemMetrics(SM_CXSCREEN) > 4 ? GetSystemMetrics(SM_CXSCREEN)-4 : 1)
#define MENU_W MenuWidth()
#define HDR_H  ShzPx(56)                    /* compact identity header; only real product name/subtitle, no profile */
#define MENU_PAD ShzPx(8)
#define ROW_H  g_row_height                    /* shared paint/hit/popup geometry */
#define SEP_H  ShzPx(TH()->menu_sep_height)
#define MAX_TASK_ROWS 8                     /* array bound; the theme's start.max_task_rows (1..8) limits the used rows */
#define MAX_ROWS (15 + MAX_TASK_ROWS) /* 10 actions, 3 headers, 2 separators */

typedef enum { K_HEADER, K_COMPUTER, K_FILES, K_RUN, K_TASK, K_SEP, K_EXIT, K_SETTINGS, K_APP, K_DOCUMENTS, K_SEARCH } KIND;
/* 'task' is a string id for fixed rows; task rows carry a snapshot (hwnd+title) taken in BuildRows so the 1 s
 * task-table compaction cannot retarget a row. The hwnd is revalidated with IsWindow at activation. */
typedef struct { KIND kind; int task; int theme; int column; HWND hwnd; WCHAR title[96]; } ROW;
static ROW g_rows[MAX_ROWS];
/* IDs reference the one shared command catalogue; labels and dispatch are not
 * another application registry. */
static const SHZ_COMMAND left_commands[] = { SHZ_CMD_TEXT, SHZ_CMD_SAPPHIRE, SHZ_CMD_MUZIK, SHZ_CMD_GAMES };
static const SHZ_COMMAND right_commands[] = { SHZ_CMD_DOCUMENTS, SHZ_CMD_FILES, SHZ_CMD_SEARCH, SHZ_CMD_SETTINGS, SHZ_CMD_RUN };
static int g_nrows, g_sel = -1;
static int g_row_height;
static RECT g_rect[MAX_ROWS];   /* single geometry source for paint, hit test and popup size */
static int g_two_col, g_menu_h, g_menu_scroll, g_body_end, g_body_extent, g_split;
static int MenuWidth(void)
{
    return ShzClamp(ShzPx(TH()->start_width), 1, MENU_MAXW);
}
static unsigned g_menu_epoch;   /* nonzero uint32, incremented per actual open (0 skipped on wrap) */

static void LayoutRows(void);
static void AddCommand(SHZ_COMMAND id, int column)
{
    if (g_nrows >= MAX_ROWS) return;
    ROW *r=&g_rows[g_nrows++];
    r->column=column; r->theme=id;
    r->kind=id==SHZ_CMD_FILES?K_FILES:id==SHZ_CMD_DOCUMENTS?K_DOCUMENTS:
        id==SHZ_CMD_SEARCH?K_SEARCH:id==SHZ_CMD_SETTINGS?K_SETTINGS:id==SHZ_CMD_RUN?K_RUN:K_APP;
    for (unsigned n=0;n<ShzCommandCount();++n) {
        const SHZ_COMMAND_INFO *c=ShzCommandAt(n);
        if (c->id==id) { ShzWcsCopy(r->title,96,c->name); break; }
    }
}
static void BuildRows(void)
{
    int i, task_limit, available;
    g_row_height=ShzClamp(ShzPx(TH()->menu_row_height),ShzPx(28),ShzPx(48));
    available=GetSystemMetrics(SM_CYSCREEN)-ShzPx(TH()->taskbar_height)-HDR_H-ShzPx(84)-2*SEP_H;
    available-=10*g_row_height;
    task_limit=available>0?available/g_row_height:0;
    task_limit=ShzClamp(task_limit,0,TH()->start_max_task_rows);
    g_nrows=0; g_menu_scroll=0; memset(g_rows,0,sizeof g_rows);
    ShzTasksRefresh();
    g_rows[g_nrows].kind=K_HEADER; g_rows[g_nrows++].task=IDS_PROGRAMS;
    for (unsigned n=0;n<sizeof left_commands/sizeof left_commands[0];++n) AddCommand(left_commands[n],0);
    g_rows[g_nrows].kind=K_HEADER; g_rows[g_nrows].column=1;g_rows[g_nrows++].task=IDS_SHORTCUTS;
    for (unsigned n=0;n<sizeof right_commands/sizeof right_commands[0];++n) AddCommand(right_commands[n],1);
    g_rows[g_nrows].kind=K_SEP; ++g_nrows;
    g_rows[g_nrows].kind=K_HEADER; g_rows[g_nrows++].task=IDS_WINDOW_LIST;
    for (i=0;i<g_shell.ntasks && i<MAX_TASK_ROWS && i<task_limit;++i) {
        ROW *r=&g_rows[g_nrows++];r->kind=K_TASK;r->hwnd=g_shell.tasks[i].hwnd;
        ShzWcsCopy(r->title,96,g_shell.tasks[i].title);
    }
    g_rows[g_nrows].kind=K_SEP; ++g_nrows;
    g_rows[g_nrows].kind=K_EXIT;g_rows[g_nrows++].task=IDS_EXIT_SHELL;
    LayoutRows();
}

static BOOL Selectable(int i) { return i >= 0 && i < g_nrows && g_rows[i].kind != K_HEADER && g_rows[i].kind != K_SEP; }

static int RowHeight(int i) { return g_rows[i].kind == K_SEP ? SEP_H : g_rows[i].kind == K_HEADER ? ShzPx(28) : ROW_H; }

/* Assign every row a rectangle. g_rows order/indices are unchanged; only placement differs:
 * rows 0..3 (Programs + apps) and the window list stay left, shortcut rows 4..8 go right, the final
 * separator + Exit span the bottom. Narrow display: all rows stacked in one column as before. */
static void LayoutRows(void)
{
    int w=MENU_W,ly=HDR_H,ry=HDR_H,last=g_nrows-1;
    g_two_col=w>=ShzPx(400);
    g_split=g_two_col?MENU_PAD+(w-2*MENU_PAD)*55/100:w;
    for (int i=0;i<last-1;++i) {
        int right=g_two_col && g_rows[i].column;
        int *y=right?&ry:&ly;
        g_rect[i]=(RECT){right?g_split+MENU_PAD/2:MENU_PAD,*y,
            g_two_col?(right?w-MENU_PAD:g_split-MENU_PAD/2):w-MENU_PAD,*y+RowHeight(i)};
        *y+=RowHeight(i);if (!g_two_col) ry=ly;
    }
    g_body_extent=ly>ry?ly:ry;
    int maxh=GetSystemMetrics(SM_CYSCREEN)-ShzPx(TH()->taskbar_height)-4;
    if (maxh<HDR_H+ROW_H+SEP_H+MENU_PAD/2+1) maxh=HDR_H+ROW_H+SEP_H+MENU_PAD/2+1;
    g_body_end=ShzClamp(g_body_extent,HDR_H,maxh-ROW_H-SEP_H-MENU_PAD/2);
    g_menu_scroll=ShzClamp(g_menu_scroll,0,g_body_extent-g_body_end);
    for (int i=0;i<last-1;++i) { g_rect[i].top-=g_menu_scroll;g_rect[i].bottom-=g_menu_scroll; }
    g_rect[last-1]=(RECT){MENU_PAD,g_body_end,w-MENU_PAD,g_body_end+SEP_H};
    g_rect[last]=(RECT){0,g_body_end+SEP_H,w,g_body_end+SEP_H+ROW_H+MENU_PAD/2};
    g_menu_h=g_rect[last].bottom;
}
static void RevealSelected(void)
{
    if (g_sel<0 || g_sel>=g_nrows-2) return;
    if (g_rect[g_sel].top<HDR_H) g_menu_scroll-=HDR_H-g_rect[g_sel].top;
    if (g_rect[g_sel].bottom>g_body_end) g_menu_scroll+=g_rect[g_sel].bottom-g_body_end;
    LayoutRows();
}

static void RowRect(int i, RECT *r) { *r = g_rect[i]; }

static void Activate(int i)
{
    if (!Selectable(i)) return;
    ROW chosen=g_rows[i];
    ShzStartMenuClose();
    if (chosen.kind==K_TASK) ShzTaskActivate(chosen.hwnd);
    else if (chosen.kind==K_EXIT) ShzCommandInvoke(SHZ_CMD_EXIT);
    else ShzCommandInvoke((SHZ_COMMAND)chosen.theme);
}

static void Step(int dir)
{
    int i = g_sel, n;
    for (n = 0; n < g_nrows; ++n) {
        i += dir;
        if (i < 0) i = g_nrows - 1;
        if (i >= g_nrows) i = 0;
        if (Selectable(i)) { g_sel = i; RevealSelected(); return; }
    }
}

/* Retain Up/Down index order and add explicit Windows-style column navigation.
 * Real selectable row rectangles, not invented menu entries, decide the target. */
static void StepColumn(int dir)
{
    int i, best = -1, distance = 0x7fffffff, cy;
    if (!g_two_col || !Selectable(g_sel)) return;
    cy = (g_rect[g_sel].top + g_rect[g_sel].bottom) / 2;
    for (i = 0; i < g_nrows - 1; ++i) {
        int right, dy;
        if (!Selectable(i)) continue;
        right = g_rect[i].left > MENU_W / 2;
        if ((dir > 0) != right) continue;
        dy = (g_rect[i].top + g_rect[i].bottom) / 2 - cy;
        if (dy < 0) dy = -dy;
        if (dy < distance) { distance = dy; best = i; }
    }
    if (best >= 0) { g_sel = best; RevealSelected(); }
}

static void OnPaint(HWND hwnd)
{
    PAINTSTRUCT ps;
    RECT c, r, icon, header;
    unsigned gen = (unsigned)ShzThemeGeneration();   /* captured before painting */
    HDC dc = BeginPaint(hwnd, &ps);
    const SHZ_THEME *th = TH();
    int i;
    if (!dc) return;
    GetClientRect(hwnd, &c);
    ShzFillGradientV(dc, &c, TC(th->start_bg_top), TC(th->start_bg_bottom));
    header = c; header.bottom = HDR_H;
    ShzFillGradientV(dc, &header, TC(th->buttons_normal_top), TC(th->buttons_normal_bottom));
    icon.left = ShzPx(12); icon.top = ShzPx(10); icon.right = icon.left+ShzPx(36); icon.bottom = icon.top+ShzPx(36);
    ShzDrawIcon(dc, &icon, SHZ_ICON_DROP, TC(th->buttons_text));
    r = header; r.left = ShzPx(56); r.right -= ShzPx(12); r.top = ShzPx(4); r.bottom = ShzPx(32);
    ShzHeading(dc, L"ShizukuOS", &r, TC(th->buttons_text));
    r.top = ShzPx(32); r.bottom = ShzPx(52); SetTextColor(dc, TC(th->buttons_text));
    ShzDrawText(dc, L"\uD504\uB85C\uADF8\uB7A8\uACFC \uD30C\uC77C", &r, DT_SINGLELINE|DT_VCENTER|DT_END_ELLIPSIS);
    if (g_two_col && g_nrows > 2) {   /* column divider between apps and shortcuts */
        RECT d; d.left = g_split - 1; d.right = d.left + 1; d.top = HDR_H + ShzPx(6);
        d.bottom = g_rect[g_nrows - 2].top - ShzPx(6);
        ShzFill(dc, &d, TC(th->menu_separator));
    }
    if (g_nrows > 1) {                /* bottom Exit bar */
        RECT eb = g_rect[g_nrows - 1];
        ShzFillGradientV(dc, &eb, TC(th->buttons_normal_top), TC(th->buttons_normal_bottom));
    }
    int saved=SaveDC(dc);
    if (saved) IntersectClipRect(dc,0,HDR_H,c.right,g_body_end);
    for (i = 0; i < g_nrows; ++i) {
        if (i==g_nrows-2 && saved) { RestoreDC(dc,saved); saved=0; }
        int kind = g_rows[i].kind;
        RowRect(i, &r);
        if (kind == K_SEP && i == g_nrows - 2) continue;   /* Exit bar edge replaces the final separator */
        if (kind == K_SEP) {
            RECT l = r; l.left += ShzPx(10); l.right -= ShzPx(10); l.top += SEP_H/2; l.bottom = l.top+1;
            ShzFill(dc, &l, TC(th->menu_separator)); continue;
        }
        if (i == g_sel) {
            ShzFillGradientV(dc, &r, TC(th->selection_top), TC(th->selection_bottom));
            ShzFrame(dc, &r, TC(th->selection_border), 1);
        }
        if (kind != K_HEADER) {
            icon = r; icon.left += ShzPx(10); icon.top += (RowHeight(i)-ShzPx(24))/2;
            icon.right = icon.left+ShzPx(24); icon.bottom = icon.top+ShzPx(24);
            ShzDrawIcon(dc, &icon, kind == K_COMPUTER ? SHZ_ICON_COMPUTER : (kind == K_FILES || kind == K_DOCUMENTS) ? SHZ_ICON_FOLDER :
                kind == K_RUN || kind == K_EXIT || kind == K_SEARCH ? SHZ_ICON_RUN : kind == K_TASK || kind == K_APP ? SHZ_ICON_DOCUMENT : SHZ_ICON_THEME,
                TC(i == g_sel ? th->selection_text : th->menu_header_text));
        }
        r.left += ShzPx(kind == K_HEADER ? 12 : 46); r.right -= ShzPx(12);
        SetTextColor(dc, TC(i == g_sel ? th->selection_text : kind == K_EXIT ? th->buttons_text :
                            kind == K_HEADER ? th->menu_header_text : th->menu_text));
        if (kind == K_TASK) ShzDrawText(dc, g_rows[i].title[0] ? g_rows[i].title : L"-", &r, DT_SINGLELINE|DT_VCENTER|DT_END_ELLIPSIS|DT_NOPREFIX);
        else ShzDrawText(dc, g_rows[i].title[0] ? g_rows[i].title : ShzStr(g_rows[i].task), &r, DT_SINGLELINE|DT_VCENTER|DT_END_ELLIPSIS);
    }
    ShzFrame(dc, &c, TC(th->start_frame), 1);
    if (EndPaint(hwnd, &ps) && g_shell.start_open) {
        static unsigned l_ep, l_gen; static int l_fg = -1, l_focus = -1, l_sel = -2, l_kind = -1;   /* suppress identical repaints */
        int fg = GetForegroundWindow() == hwnd ? 1 : 0, focus = GetFocus() == hwnd ? 1 : 0, kind = g_sel >= 0 && g_sel < g_nrows ? (int)g_rows[g_sel].kind : -1;
        if (l_ep != g_menu_epoch || l_fg != fg || l_focus != focus || l_sel != g_sel || l_kind != kind || l_gen != gen) {
            const char *kn = "other";
            l_ep = g_menu_epoch; l_fg = fg; l_focus = focus; l_sel = g_sel; l_kind = kind; l_gen = gen;
            switch (kind) {
            case K_FILES: kn = "files"; break;       case K_COMPUTER: kn = "computer"; break;
            case K_RUN: kn = "run"; break;           case K_TASK: kn = "task"; break;
            case K_EXIT: kn = "exit"; break;         case K_SETTINGS: kn = "settings"; break;
            case K_DOCUMENTS: kn="documents"; break; case K_SEARCH: kn="search"; break;
            case K_APP: kn = g_rows[g_sel].theme == SHZ_CMD_TEXT ? "editor" : g_rows[g_sel].theme == SHZ_CMD_SAPPHIRE ? "sapphire" : g_rows[g_sel].theme == SHZ_CMD_MUZIK ? "muzik" : "games"; break;
            default: break;
            }
            printf("SHZ-SHELL UI menu epoch=%u open=1 foreground=%d focus=%d sel=%d kind=%s gen=%u\n", g_menu_epoch, fg, focus, g_sel, kn, gen);
        }
    }
}

static int HitRow(int x, int y)
{
    int i; RECT r;
    for (i = 0; i < g_nrows; ++i) { if (i<g_nrows-2 && (y<HDR_H || y>=g_body_end)) continue; RowRect(i, &r); if (x >= r.left && x < r.right && y >= r.top && y < r.bottom) return i; }
    return -1;
}

static LRESULT CALLBACK MenuProc(HWND hwnd, UINT msg, WPARAM wp, LPARAM lp)
{
    switch (msg) {
    case WM_PAINT: OnPaint(hwnd); return 0;
    case WM_ERASEBKGND: return 1;
    case WM_MOUSEMOVE: {
        int i = HitRow((short)LOWORD(lp), (short)HIWORD(lp));
        if (Selectable(i) && i != g_sel) { g_sel = i; InvalidateRect(hwnd, NULL, FALSE); }
        return 0; }
    case WM_MOUSEWHEEL:
        g_menu_scroll += (short)HIWORD(wp)>0 ? -ROW_H*2 : ROW_H*2;
        LayoutRows(); InvalidateRect(hwnd,NULL,FALSE); return 0;
    case WM_LBUTTONUP: Activate(HitRow((short)LOWORD(lp), (short)HIWORD(lp))); return 0;
    case WM_KEYDOWN: case WM_SYSKEYDOWN:
        switch (wp) {
        case VK_ESCAPE: ShzStartMenuClose(); return 0;
        case VK_LWIN: case VK_RWIN: ShzStartMenuClose(); return 0;
        case VK_UP: Step(-1); InvalidateRect(hwnd, NULL, FALSE); return 0;
        case VK_DOWN: Step(1); InvalidateRect(hwnd, NULL, FALSE); return 0;
        case VK_LEFT: StepColumn(-1); InvalidateRect(hwnd, NULL, FALSE); return 0;
        case VK_RIGHT: StepColumn(1); InvalidateRect(hwnd, NULL, FALSE); return 0;
        case VK_RETURN: Activate(g_sel); return 0;
        }
        if (ShzGlobalKey((UINT)wp)) return 0;
        break;
    case WM_ACTIVATE:
        if (LOWORD(wp) == WA_INACTIVE && g_shell.start_open) ShzStartMenuClose();   /* click-away dismiss */
        return 0;
    }
    return DefWindowProcW(hwnd, msg, wp, lp);
}

/* Theme reload: the popup size depends on theme metrics, so an open menu is closed (rebuilt at the next toggle) and
 * the hidden window is repainted on show (WM_PAINT always reads the current theme). */
void ShzStartMenuRelayout(void)
{
    ShzStartMenuClose();
    if (g_shell.startmenu) InvalidateRect(g_shell.startmenu, NULL, TRUE);
}

BOOL ShzStartMenuRegister(void)
{
    WNDCLASSEXW wc;
    wc.cbSize = sizeof wc; wc.style = CS_DROPSHADOW; wc.lpfnWndProc = MenuProc; wc.cbClsExtra = wc.cbWndExtra = 0;
    wc.hInstance = g_shell.inst; wc.hIcon = NULL; wc.hCursor = LoadCursorW(NULL, IDC_ARROW);
    wc.hbrBackground = NULL; wc.lpszMenuName = NULL; wc.lpszClassName = SHZ_CLASS_START; wc.hIconSm = NULL;
    if (!RegisterClassExW(&wc)) { ShzSetStatus(IDS_ERR_CLASS, GetLastError()); return FALSE; }
    return TRUE;
}

void ShzStartMenuClose(void)
{
    if (!g_shell.start_open) return;
    g_shell.start_open = FALSE;
    g_shell.start_closed_tick = GetTickCount();
    if (g_shell.startmenu) ShowWindow(g_shell.startmenu, SW_HIDE);
    ShzTaskbarInvalidate();
}

void ShzStartMenuToggle(void)
{
    RECT sr, tr;
    int h, x, y;
    if (g_shell.start_open) { ShzStartMenuClose(); return; }
    BuildRows();
    h = g_menu_h + 2;   /* same rectangles as painting/hit-testing */
    ShzTaskbarGetStartRect(&sr);
    GetWindowRect(g_shell.tray, &tr);
    x = tr.left + sr.left;
    if (x + MENU_W + 2 > GetSystemMetrics(SM_CXSCREEN)) x = GetSystemMetrics(SM_CXSCREEN) - MENU_W - 2;
    if (x < 0) x = 0;
    y = tr.top - h;                                    /* above the taskbar (bottom edge); ReactOS picks edge by tray position */
    if (y < 0) y = 0;
    if (!g_shell.startmenu) {
        g_shell.startmenu = CreateWindowExW(WS_EX_TOOLWINDOW | WS_EX_TOPMOST, SHZ_CLASS_START, ShzStr(IDS_START),
                                            WS_POPUP | WS_BORDER, x, y, MENU_W + 2, h, g_shell.tray, NULL,
                                            g_shell.inst, NULL);
        if (!g_shell.startmenu) { ShzSetStatus(IDS_ERR_WINDOW, GetLastError()); return; }
    } else {
        MoveWindow(g_shell.startmenu, x, y, MENU_W + 2, h, TRUE);
    }
    g_sel = 1; /* First staged app; Up wraps to the final Exit Shell row. */
    if (++g_menu_epoch == 0) g_menu_epoch = 1;
    g_shell.start_open = TRUE;
    ShowWindow(g_shell.startmenu, SW_SHOW);
    if (!SetForegroundWindow(g_shell.startmenu)) ShzSetStatus(IDS_ERR_FOCUS, GetLastError());
    SetFocus(g_shell.startmenu);
    InvalidateRect(g_shell.startmenu, NULL, TRUE);
    ShzTaskbarInvalidate();
}
