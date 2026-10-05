/*
 * ShizukuOS shell candidate: process launcher and Run dialog.
 * Original ShizukuOS code (LGPL-2.1-or-later). The Run dialog is a custom-painted Windows-style box with its own
 * text entry (no EDIT class, no autocomplete, no Browse, no shell-execute verbs/associations); ReactOS's RunFileDlg
 * is not adapted. Layout is a native-geometry approximation; no Microsoft images/assets are used.
 */
#include "shzcrt.h"
#include "shell.h"
#include "catalog.h"
#include "layout.h" /* same bounded screen-density scale as shell text and hit boxes */

static unsigned g_run_epoch;   /* nonzero uint32, incremented per actual dialog creation (0 skipped on wrap) */

/* CreateProcessW wrapper. The command line is copied into a writable, bounded buffer (CreateProcessW may modify
 * it). On success BOTH returned handles are closed exactly once: the shell does not track children, so a leaked
 * hProcess/hThread would be a permanent handle leak. On failure the handles are never touched (they are not
 * valid after a failed call) and the Win32 error is shown on the taskbar. */
/* Native process cleanup command; forwarded verbatim to the executable that
 * validates targets, generations and destructive acknowledgement. This only
 * routes SAW, with a complete verb boundary; it performs no shell expansion. */
static BOOL SawVerb(const WCHAR *s)
{
    return (s[0] == L'S' || s[0] == L's') &&
           (s[1] == L'A' || s[1] == L'a') &&
           (s[2] == L'W' || s[2] == L'w') &&
           (!s[3] || s[3] == L' ' || s[3] == L'\t');
}

BOOL ShzLaunch(const WCHAR *cmdline, const WCHAR *cwd)
{
    WCHAR buf[SHZ_MAX_PATH];
    STARTUPINFOW si;
    PROCESS_INFORMATION pi;
    BOOL ok;
    if (!cmdline || !cmdline[0]) { ShzSetStatus(IDS_ERR_NOCMD, 0); return FALSE; }
    {
        const WCHAR *verb = cmdline;
        while (*verb == L' ' || *verb == L'\t') ++verb;
        if (SawVerb(verb)) {
            if (!ShzWcsCopy(buf, SHZ_MAX_PATH, L"C:\\SHZ\\SYS64\\CHAINSAW.EXE ") ||
                !ShzWcsCat(buf, SHZ_MAX_PATH, verb)) {
                ShzSetStatus(IDS_ERR_PATH_LONG, 0); return FALSE;
            }
        } else if (!ShzWcsCopy(buf, SHZ_MAX_PATH, cmdline)) {
            ShzSetStatus(IDS_ERR_PATH_LONG, 0); return FALSE;
        }
    }
    ZeroMemory(&si, sizeof si);
    ZeroMemory(&pi, sizeof pi);
    si.cb = sizeof si;
    ok = CreateProcessW(NULL, buf, NULL, NULL, FALSE, 0, NULL, (cwd && cwd[0]) ? cwd : NULL, &si, &pi);
    {   DWORD le = ok ? 0 : GetLastError();   /* captured before any status call; no command text is logged */
        printf("SHZ-SHELL UI launch ok=%d win32=0x%x\n", ok ? 1 : 0, (unsigned)le);
        if (!ok) SetLastError(le);
    }
    if (!ok) { ShzSetStatus(IDS_ERR_LAUNCH, GetLastError()); return FALSE; }
    if (pi.hThread && !CloseHandle(pi.hThread)) ShzSetStatus(IDS_ERR_LAUNCH, GetLastError());
    if (pi.hProcess && !CloseHandle(pi.hProcess)) ShzSetStatus(IDS_ERR_LAUNCH, GetLastError());
    ShzSetStatus(IDS_LAUNCHED, 0);
    return TRUE;
}

/* ---- Run dialog ----
 * Windows-style Run box: icon + description, "Open:" label, single-line input, OK/Cancel (OK disabled while empty),
 * Tab focus cycle, default-button emphasis. Colours come only from the active theme; text that would fall below a
 * approximate gamma-squared contrast threshold against the top background is replaced by black/white. This is
 * a readability guard, not an exact WCAG guarantee (theme data is never modified). The command is
 * still run only through ShzLaunch/CreateProcessW: no shell verbs, folders, documents or URLs, and no Browse button
 * (no file-open dialog exists in this shell, so none is drawn rather than a dead control). */
typedef struct { WCHAR text[SHZ_MAX_PATH]; int len; BOOL too_long; } RUNSTATE;
static RUNSTATE g_run;
enum { RF_EDIT, RF_OK, RF_CANCEL, RF_COUNT };
static int g_run_focus;      /* RF_* control that owns the keyboard */
static int g_run_down = -1;  /* button (RF_OK/RF_CANCEL) held by the mouse, else -1 */

#define RUN_CW ShzPx(400)    /* baseline client size using the shared screen-density fallback */
#define RUN_CH ShzPx(168)
#define RUN_MARGIN ShzPx(12)

static void RunDo(HWND hwnd)
{
    if (g_run.len == 0) { ShzSetStatus(IDS_ERR_NOCMD, 0); return; }
    if (ShzRunInput(g_run.text)) DestroyWindow(hwnd);
}

static void RunActivate(HWND hwnd, int which)
{
    if (which == RF_OK) RunDo(hwnd);
    else if (which == RF_CANCEL) DestroyWindow(hwnd);
}

static void BtnRects(const RECT *c, RECT *ok, RECT *cancel)       /* theme metrics (Slade 76x24); 6px gap, 12px margin */
{
    int bw = ShzPx(TH()->buttons_start_width), bh = ShzPx(TH()->buttons_height);
    cancel->right = c->right - RUN_MARGIN; cancel->left = cancel->right - bw;
    ok->right = cancel->left - ShzPx(6); ok->left = ok->right - bw;
    ok->bottom = c->bottom - RUN_MARGIN; ok->top = ok->bottom - bh;
    cancel->top = ok->top; cancel->bottom = ok->bottom;
}

static void EditRect(const RECT *c, RECT *e)
{
    e->left = ShzPx(64); e->right = c->right - RUN_MARGIN; e->top = ShzPx(72); e->bottom = ShzPx(96);
}

static unsigned Lum(COLORREF c)     /* relative luminance x10000 (sRGB gamma approximated by squaring) */
{
    unsigned r = GetRValue(c), g = GetGValue(c), b = GetBValue(c);
    return (2126u * r * r + 7152u * g * g + 722u * b * b) / 65025u;
}

static COLORREF Readable(COLORREF fg, COLORREF bg)     /* approximate gamma-squared guard, sampled against the top colour only */
{
    unsigned a = Lum(fg) + 500, b = Lum(bg) + 500, hi = a > b ? a : b, lo = a > b ? b : a;
    if (hi * 10 >= lo * 45) return fg;
    return (Lum(bg) > 2500) ? RGB(0, 0, 0) : RGB(255, 255, 255);
}

static void DrawButton(HDC dc, const RECT *r, const WCHAR *label, BOOL enabled, BOOL is_default, BOOL focused, BOOL down)
{
    const SHZ_THEME *t = TH();
    COLORREF top, bot, fg;
    if (down && enabled) { top = TC(t->buttons_pressed_top); bot = TC(t->buttons_pressed_bottom); fg = TC(t->buttons_text_pressed); }
    else if (is_default && enabled) { top = TC(t->buttons_active_top); bot = TC(t->buttons_active_bottom); fg = TC(t->buttons_text); }
    else { top = TC(t->buttons_normal_top); bot = TC(t->buttons_normal_bottom); fg = TC(t->buttons_text); }
    if (!enabled) fg = TC(t->menu_disabled_text);
    ShzFillGradientV(dc, r, top, bot);
    ShzFrame(dc, r, TC(t->buttons_edge), 1);
    if (focused || is_default) {                         /* inner focus/default frame */
        RECT in = *r; InflateRect(&in, -ShzPx(2), -ShzPx(2));
        ShzFrame(dc, &in, TC(focused ? t->border_focus : t->buttons_edge), 1);
    }
    SetTextColor(dc, enabled ? Readable(fg, top) : fg);
    { RECT tr = *r; if (down && enabled) OffsetRect(&tr, ShzPx(1), ShzPx(1)); ShzDrawText(dc, label, &tr, DT_SINGLELINE | DT_VCENTER | DT_CENTER); }
}

static void DrawRunIcon(HDC dc, int x, int y)     /* native GDI pictogram (theme glyph_run colour), no image assets */
{
    const SHZ_THEME *t = TH();
    RECT w = { x, y, x + ShzPx(32), y + ShzPx(26) },
         bar = { x + ShzPx(1), y + ShzPx(1), x + ShzPx(31), y + ShzPx(7) },
         body = { x + ShzPx(1), y + ShzPx(7), x + ShzPx(31), y + ShzPx(25) };
    HBRUSH b = CreateSolidBrush(TC(t->background_input_bg));
    if (b) { FillRect(dc, &body, b); DeleteObject(b); }
    b = CreateSolidBrush(TC(t->icons_glyph_run));
    if (b) { FillRect(dc, &bar, b); DeleteObject(b); }
    ShzFrame(dc, &w, TC(t->icons_glyph_run), 1);
    { RECT arrow = { x + ShzPx(8), y + ShzPx(13), x + ShzPx(22), y + ShzPx(15) }; b = CreateSolidBrush(TC(t->icons_glyph_run)); if (b) { FillRect(dc, &arrow, b); DeleteObject(b); } }
}

static void RunSetFocus(HWND hwnd, int f) { g_run_focus = f; InvalidateRect(hwnd, NULL, FALSE); }

static LRESULT CALLBACK RunProc(HWND hwnd, UINT msg, WPARAM wp, LPARAM lp)
{
    switch (msg) {
    case WM_PAINT: {
        PAINTSTRUCT ps; RECT c, f, ok, cancel; unsigned gen = (unsigned)ShzThemeGeneration(); HDC dc = BeginPaint(hwnd, &ps);
        COLORREF face, fg;
        HBRUSH br;
        if (!dc) return 0;
        GetClientRect(hwnd, &c);
        face = TC(TH()->background_panel_face);
        br = CreateSolidBrush(face); if (br) { FillRect(dc, &c, br); DeleteObject(br); }
        fg = Readable(TC(TH()->background_panel_text), face);
        DrawRunIcon(dc, RUN_MARGIN, ShzPx(16));
        SetTextColor(dc, fg);
        f = c; f.left = ShzPx(56); f.right = c.right - RUN_MARGIN; f.top = ShzPx(12); f.bottom = ShzPx(60);
        ShzDrawText(dc, ShzStr(IDS_RUN_PROMPT), &f, DT_WORDBREAK);
        f.left = RUN_MARGIN; f.right = ShzPx(62); f.top = ShzPx(72); f.bottom = ShzPx(96);
        ShzDrawText(dc, L"\uC5F4\uAE30:", &f, DT_SINGLELINE | DT_VCENTER | DT_NOPREFIX);      /* 열기: (Open:) */
        EditRect(&c, &f);
        {   COLORREF ibg = TC(TH()->background_input_bg), ifg = Readable(TC(TH()->background_surface_text), ibg);
            WCHAR show[SHZ_MAX_PATH + 2]; UINT fmt = DT_SINGLELINE | DT_VCENTER | DT_NOPREFIX;
            br = CreateSolidBrush(ibg); if (br) { FillRect(dc, &f, br); DeleteObject(br); }
            ShzFrame(dc, &f, TC(g_run_focus == RF_EDIT ? TH()->border_focus : TH()->background_input_border), 1);
            f.left += ShzPx(5); f.right -= ShzPx(3);
            SetTextColor(dc, ifg);
            ShzWcsCopy(show, SHZ_MAX_PATH + 2, g_run.text);
            if (g_run_focus == RF_EDIT && GetFocus() == hwnd) ShzWcsCat(show, SHZ_MAX_PATH + 2, L"|");   /* caret (static, no blink timer) */
            fmt |= (g_run.len > 40) ? DT_RIGHT : 0;               /* long input: keep the tail (and caret) visible */
            ShzDrawText(dc, show, &f, fmt);
        }
        BtnRects(&c, &ok, &cancel);
        {   /* hint lives between the input box and the buttons; skipped if text cannot fit */
            TEXTMETRICW tm; int need = ShzPx(20);
            if (GetTextMetricsW(dc, &tm) && tm.tmHeight + ShzPx(2) > need) need = tm.tmHeight + ShzPx(2);
            f.left = RUN_MARGIN; f.right = c.right - RUN_MARGIN; f.top = ShzPx(102); f.bottom = ok.top - ShzPx(4);
            if (f.bottom - f.top >= need) {
                SetTextColor(dc, Readable(TC(TH()->background_surface_dim_text), face));
                ShzDrawText(dc, L"Enter: \uC2E4\uD589   Esc: \uB2EB\uAE30   Tab: \uC774\uB3D9", &f, DT_SINGLELINE | DT_VCENTER | DT_NOPREFIX);   /* Enter: 실행   Esc: 닫기   Tab: 이동 */
            }
        }
        DrawButton(dc, &ok, ShzStr(IDS_OK), g_run.len > 0, g_run_focus != RF_CANCEL, g_run_focus == RF_OK, g_run_down == RF_OK);
        DrawButton(dc, &cancel, ShzStr(IDS_CANCEL), TRUE, FALSE, g_run_focus == RF_CANCEL, g_run_down == RF_CANCEL);
        if (EndPaint(hwnd, &ps)) {
            static unsigned l_ep, l_gen; static int l_fg = -1, l_focus = -1, l_chars = -1;   /* suppress identical repaints */
            int fgw = GetForegroundWindow() == hwnd ? 1 : 0, focus = GetFocus() == hwnd ? 1 : 0;
            if (l_ep != g_run_epoch || l_fg != fgw || l_focus != focus || l_chars != g_run.len || l_gen != gen) {
                l_ep = g_run_epoch; l_fg = fgw; l_focus = focus; l_chars = g_run.len; l_gen = gen;
                printf("SHZ-SHELL UI run epoch=%u foreground=%d focus=%d chars=%d gen=%u\n", g_run_epoch, fgw, focus, g_run.len, gen);
            }
        }
        return 0; }
    case WM_ERASEBKGND: return 1;
    case WM_SETFOCUS: case WM_KILLFOCUS:
        InvalidateRect(hwnd, NULL, FALSE);
        return 0;
    case WM_CHAR:
        if (wp == VK_ESCAPE) { DestroyWindow(hwnd); return 0; }
        if (wp == VK_RETURN) { if (g_run_focus == RF_CANCEL) DestroyWindow(hwnd); else RunDo(hwnd); return 0; }
        if (wp == VK_SPACE && g_run_focus != RF_EDIT) { RunActivate(hwnd, g_run_focus); return 0; }
        if (g_run_focus != RF_EDIT) return 0;
        if (wp == VK_BACK) {                                        /* Bksp: drop a whole surrogate pair */
            if (g_run.len > 1 && g_run.text[g_run.len - 1] >= 0xDC00 && g_run.text[g_run.len - 1] <= 0xDFFF &&
                g_run.text[g_run.len - 2] >= 0xD800 && g_run.text[g_run.len - 2] <= 0xDBFF) g_run.len--;
            if (g_run.len > 0) g_run.text[--g_run.len] = 0;
        } else if (wp >= 32) {
            if (g_run.len + 1 >= SHZ_MAX_PATH) { ShzSetStatus(IDS_ERR_PATH_LONG, 0); return 0; }   /* reject, never truncate */
            g_run.text[g_run.len++] = (WCHAR)wp; g_run.text[g_run.len] = 0;
        }
        InvalidateRect(hwnd, NULL, FALSE);
        return 0;
    case WM_KEYDOWN:
        if (wp == VK_LWIN || wp == VK_RWIN) { ShzGlobalKey((UINT)wp); return 0; }
        if (wp == VK_TAB) {
            int back = (GetKeyState(VK_SHIFT) & 0x8000) != 0;
            RunSetFocus(hwnd, (g_run_focus + (back ? RF_COUNT - 1 : 1)) % RF_COUNT);
            return 0;
        }
        break;
    case WM_LBUTTONDOWN: {
        RECT c, e, ok, cancel; POINT p; p.x = (short)LOWORD(lp); p.y = (short)HIWORD(lp);
        GetClientRect(hwnd, &c); BtnRects(&c, &ok, &cancel); EditRect(&c, &e);
        g_run_down = -1;
        if (PtInRect(&ok, p) && g_run.len > 0) g_run_down = RF_OK;
        else if (PtInRect(&cancel, p)) g_run_down = RF_CANCEL;
        else if (PtInRect(&e, p)) { RunSetFocus(hwnd, RF_EDIT); return 0; }
        if (g_run_down >= 0) { g_run_focus = g_run_down; SetCapture(hwnd); }
        InvalidateRect(hwnd, NULL, FALSE);
        return 0; }
    case WM_LBUTTONUP: {
        RECT c, ok, cancel; POINT p; int which = g_run_down; p.x = (short)LOWORD(lp); p.y = (short)HIWORD(lp);
        if (which < 0) return 0;
        g_run_down = -1; ReleaseCapture();
        GetClientRect(hwnd, &c); BtnRects(&c, &ok, &cancel);
        InvalidateRect(hwnd, NULL, FALSE);
        if (PtInRect(which == RF_OK ? &ok : &cancel, p)) RunActivate(hwnd, which);   /* release inside the pressed button only */
        return 0; }
    case WM_CAPTURECHANGED:
        if (g_run_down >= 0) { g_run_down = -1; InvalidateRect(hwnd, NULL, FALSE); }
        return 0;
    case WM_DESTROY:
        if (hwnd == g_shell.runwnd) g_shell.runwnd = NULL;
        printf("SHZ-SHELL UI run-closed epoch=%u\n", g_run_epoch);
        return 0;
    }
    return DefWindowProcW(hwnd, msg, wp, lp);
}

BOOL ShzRunDialogRegister(void)
{
    WNDCLASSEXW wc;
    wc.cbSize = sizeof wc; wc.style = 0; wc.lpfnWndProc = RunProc; wc.cbClsExtra = wc.cbWndExtra = 0;
    wc.hInstance = g_shell.inst; wc.hIcon = NULL; wc.hCursor = LoadCursorW(NULL, IDC_ARROW);
    wc.hbrBackground = NULL; wc.lpszMenuName = NULL; wc.lpszClassName = SHZ_CLASS_RUN; wc.hIconSm = NULL;
    if (!RegisterClassExW(&wc)) { ShzSetStatus(IDS_ERR_CLASS, GetLastError()); return FALSE; }
    return TRUE;
}

void ShzRunDialogRelayout(void)
{
    if (g_shell.runwnd && IsWindow(g_shell.runwnd)) InvalidateRect(g_shell.runwnd, NULL, FALSE);
}

static BOOL RunForeground(HWND w)       /* clears stale error; reports 0 when TRUE but wrong foreground */
{
    DWORD err;
    SetLastError(0);
    if (SetForegroundWindow(w)) {
        if (GetForegroundWindow() == w) return TRUE;
        err = 0;
    } else err = GetLastError();
    ShzSetStatus(IDS_ERR_FOCUS, err);
    return FALSE;
}

void ShzRunDialogOpen(void)
{
    int sw = GetSystemMetrics(SM_CXSCREEN), sh = GetSystemMetrics(SM_CYSCREEN);
    if (g_shell.runwnd && IsWindow(g_shell.runwnd)) {
        if (IsIconic(g_shell.runwnd)) ShowWindow(g_shell.runwnd, SW_RESTORE);
        if (RunForeground(g_shell.runwnd)) SetFocus(g_shell.runwnd);
        InvalidateRect(g_shell.runwnd, NULL, FALSE);
        UpdateWindow(g_shell.runwnd);
        return;
    }
    RECT wr = { 0, 0, RUN_CW, RUN_CH };
    DWORD style = WS_OVERLAPPED | WS_CAPTION | WS_SYSMENU;
    g_run.text[0] = 0; g_run.len = 0; g_run_focus = RF_EDIT; g_run_down = -1;
    if (!AdjustWindowRectEx(&wr, style, FALSE, 0)) { wr.left = 0; wr.top = 0; wr.right = RUN_CW + ShzPx(8); wr.bottom = RUN_CH + ShzPx(27); }   /* fallback frame estimate */
    if (++g_run_epoch == 0) g_run_epoch = 1;
    g_shell.runwnd = CreateWindowExW(0, SHZ_CLASS_RUN, ShzStr(IDS_RUN), style,
                                     (sw - (wr.right - wr.left)) / 2, (sh - (wr.bottom - wr.top)) / 2,
                                     wr.right - wr.left, wr.bottom - wr.top, NULL, NULL, g_shell.inst, NULL);
    if (!g_shell.runwnd) { ShzSetStatus(IDS_ERR_WINDOW, GetLastError()); return; }
    ShowWindow(g_shell.runwnd, SW_SHOW);
    RunForeground(g_shell.runwnd);
    SetFocus(g_shell.runwnd);
    UpdateWindow(g_shell.runwnd);
}
