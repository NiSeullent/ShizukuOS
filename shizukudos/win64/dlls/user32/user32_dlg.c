/* SPDX-License-Identifier: GPL-2.0-only
 * user32: the dialog manager, the BUTTON and STATIC control classes, and MessageBox.
 *
 *  - Dialogs are created from DLGTEMPLATE / DLGTEMPLATEEX (memory or RT_DIALOG resources) with the dialog class
 *    "#32770" (DefDlgProc: the DLGPROC protocol with DWLP_MSGRESULT, default button, focus save/restore, WM_CLOSE ->
 *    IDCANCEL) or the template's own class. Dialog units use the one system font (8x16): 4 horizontal units per 8
 *    pixels, 8 vertical units per 16 pixels. Modal dialogs (DialogBox*) disable their owner and run the loop with
 *    IsDialogMessage (Tab / Shift+Tab over WS_TABSTOP, arrows within a WS_GROUP, Enter -> default button, Escape ->
 *    IDCANCEL, Alt+mnemonic); EndDialog ends it.
 *  - Control classes "Button" (push/default push, check boxes incl. 3-state and auto, radio buttons incl. auto with the
 *    group rule, group boxes; BM_* messages, BN_CLICKED) and "Static" (text left/centre/right, SS_SIMPLE, icons,
 *    rectangles and frames, etched lines; transparent to the mouse unless SS_NOTIFY) are registered in every process on
 *    first use. Edit, list box, combo box and scroll bar controls do not exist: a template that needs one fails to
 *    create (unless DS_NOFAILCREATE), as Windows does for an unknown class.
 *  - MessageBox builds such a dialog in memory: the icon, the text wrapped at 60 characters, the button row.
 */
#include "user32_int.h"

/* ---------------------------------------------------------------- the system control classes */
static LRESULT CALLBACK button_proc(HWND, UINT, WPARAM, LPARAM);
static LRESULT CALLBACK static_proc(HWND, UINT, WPARAM, LPARAM);
static LRESULT CALLBACK dialog_proc(HWND, UINT, WPARAM, LPARAM);

static void register_classes(void)
{
    static volatile LONG done;
    WNDCLASSEXW wc;
    if (done) return;
    memset(&wc, 0, sizeof wc);
    wc.cbSize = sizeof wc;
    wc.style = CS_DBLCLKS | CS_PARENTDC | CS_GLOBALCLASS;
    wc.hCursor = LoadCursorW(0, (LPCWSTR)IDC_ARROW);
    wc.cbWndExtra = 2 * sizeof(LONG_PTR);
    wc.lpfnWndProc = button_proc;
    wc.lpszClassName = L"Button";
    RegisterClassExW(&wc);
    wc.lpfnWndProc = static_proc;
    wc.lpszClassName = L"Static";
    RegisterClassExW(&wc);
    wc.style = CS_DBLCLKS | CS_SAVEBITS | CS_GLOBALCLASS;
    wc.cbWndExtra = DLGWINDOWEXTRA;
    wc.lpfnWndProc = dialog_proc;
    wc.lpszClassName = L"#32770";
    RegisterClassExW(&wc);
    done = 1;
}

void u32_register_controls(void) { register_classes(); }

/* ---------------------------------------------------------------- Button */
#define BTN_STATE 0                                   /* window extra: BST_* check state | BST_PUSHED | BST_FOCUS */
#define BTN_IMAGE sizeof(LONG_PTR)

static UINT btn_type(HWND h) { return (UINT)GetWindowLongW(h, GWL_STYLE) & BS_TYPEMASK; }
static LONG_PTR btn_state(HWND h) { return GetWindowLongPtrW(h, BTN_STATE); }
static void btn_set_state(HWND h, LONG_PTR s) { SetWindowLongPtrW(h, BTN_STATE, s); InvalidateRect(h, 0, TRUE); }

static void btn_text(HWND h, HDC dc, RECT *r, UINT fmt, int disabled)
{
    WCHAR t[256];
    const int n = GetWindowTextW(h, t, 256);
    if (n <= 0) return;
    SetBkMode(dc, TRANSPARENT);
    if (disabled) {                                                     /* etched grey text, as the classic look draws it */
        RECT o = *r;
        OffsetRect(&o, 1, 1);
        SetTextColor(dc, GetSysColor(COLOR_3DHIGHLIGHT));
        DrawTextW(dc, t, n, &o, fmt);
        SetTextColor(dc, GetSysColor(COLOR_GRAYTEXT));
    } else {
        SetTextColor(dc, GetSysColor(COLOR_BTNTEXT));
    }
    DrawTextW(dc, t, n, r, fmt);
}

static void btn_paint(HWND h, HDC dc)
{
    RECT r;
    const UINT type = btn_type(h), style = (UINT)GetWindowLongW(h, GWL_STYLE);
    const LONG_PTR st = btn_state(h);
    const int disabled = !IsWindowEnabled(h), focused = GetFocus() == h;
    HBRUSH bk;
    GetClientRect(h, &r);
    bk = (HBRUSH)SendMessageW(GetParent(h), WM_CTLCOLORBTN, (WPARAM)dc, (LPARAM)h);
    switch (type) {
    case BS_GROUPBOX: {
        RECT f = r;
        WCHAR t[256];
        const int n = GetWindowTextW(h, t, 256);
        f.top += 7;
        DrawEdge(dc, &f, EDGE_ETCHED, BF_RECT);
        if (n > 0) {
            SIZE ts = { n * 8, 16 };
            RECT tr;
            GetTextExtentPoint32W(dc, t, n, &ts);
            SetRect(&tr, 8, 0, 8 + ts.cx + 4, 16);
            FillRect(dc, &tr, bk ? bk : GetSysColorBrush(COLOR_3DFACE));
            OffsetRect(&tr, 2, 0);
            btn_text(h, dc, &tr, DT_LEFT | DT_TOP | DT_SINGLELINE, disabled);
        }
        return;
    }
    case BS_CHECKBOX: case BS_AUTOCHECKBOX: case BS_3STATE: case BS_AUTO3STATE: case BS_RADIOBUTTON: case BS_AUTORADIOBUTTON: {
        const int radio = type == BS_RADIOBUTTON || type == BS_AUTORADIOBUTTON;
        RECT box, tr = r;
        UINT dfcs = radio ? DFCS_BUTTONRADIO : ((st & 3) == BST_INDETERMINATE ? DFCS_BUTTON3STATE : DFCS_BUTTONCHECK);
        FillRect(dc, &r, bk ? bk : GetSysColorBrush(COLOR_3DFACE));
        if (st & BST_CHECKED) dfcs |= DFCS_CHECKED;
        if (st & BST_INDETERMINATE) dfcs |= DFCS_CHECKED;
        if (st & BST_PUSHED) dfcs |= DFCS_PUSHED;
        if (disabled) dfcs |= DFCS_INACTIVE;
        box.left = (style & BS_LEFTTEXT) ? r.right - 13 : 0;
        box.right = box.left + 13;
        box.top = (r.top + r.bottom) / 2 - 6;
        box.bottom = box.top + 13;
        DrawFrameControl(dc, &box, DFC_BUTTON, dfcs);
        if (style & BS_LEFTTEXT) tr.right -= 17; else tr.left += 17;
        btn_text(h, dc, &tr, DT_LEFT | DT_VCENTER | DT_SINGLELINE, disabled);
        if (focused) {
            WCHAR t[256];
            SIZE ts = { 0, 16 };
            RECT fr = tr;
            const int n = GetWindowTextW(h, t, 256);
            if (n > 0) GetTextExtentPoint32W(dc, t, n, &ts);
            fr.right = fr.left + ts.cx + 2;
            DrawFocusRect(dc, &fr);
        }
        return;
    }
    case BS_OWNERDRAW: {
        DRAWITEMSTRUCT di;
        di.CtlType = ODT_BUTTON; di.CtlID = (UINT)GetDlgCtrlID(h); di.itemID = 0; di.itemAction = ODA_DRAWENTIRE;
        di.itemState = (disabled ? ODS_DISABLED : 0) | (focused ? ODS_FOCUS : 0) | ((st & BST_PUSHED) ? ODS_SELECTED : 0);
        di.hwndItem = h; di.hDC = dc; di.rcItem = r; di.itemData = 0;
        SendMessageW(GetParent(h), WM_DRAWITEM, di.CtlID, (LPARAM)&di);
        return;
    }
    default: {                                                          /* push buttons */
        RECT in = r;
        const int def = type == BS_DEFPUSHBUTTON;
        if (def) { FrameRect(dc, &in, GetSysColorBrush(COLOR_WINDOWFRAME)); InflateRect(&in, -1, -1); }
        DrawFrameControl(dc, &in, DFC_BUTTON, DFCS_BUTTONPUSH | ((st & BST_PUSHED) ? DFCS_PUSHED : 0));
        if (st & BST_PUSHED) OffsetRect(&in, 1, 1);
        btn_text(h, dc, &in, DT_CENTER | DT_VCENTER | DT_SINGLELINE, disabled);
        if (focused) { RECT fr = r; InflateRect(&fr, -4, -4); DrawFocusRect(dc, &fr); }
        return;
    }
    }
}

static void btn_notify(HWND h, WORD code)
{
    HWND p = GetParent(h);
    if (p) SendMessageW(p, WM_COMMAND, MAKEWPARAM((WORD)GetDlgCtrlID(h), code), (LPARAM)h);
}

static void btn_click(HWND h)
{
    const UINT type = btn_type(h);
    const LONG_PTR st = btn_state(h);
    switch (type) {
    case BS_AUTOCHECKBOX: btn_set_state(h, (st & ~3) | ((st & BST_CHECKED) ? BST_UNCHECKED : BST_CHECKED)); break;
    case BS_AUTO3STATE: btn_set_state(h, (st & ~3) | (((st & 3) + 1) % 3)); break;
    case BS_AUTORADIOBUTTON: {                                          /* checks this one, clears the rest of its group */
        HWND p = GetParent(h), c = h;
        if (p) {
            while ((c = GetNextDlgGroupItem(p, c, FALSE)) != 0 && c != h)
                if (btn_type(c) == BS_AUTORADIOBUTTON) SendMessageW(c, BM_SETCHECK, BST_UNCHECKED, 0);
        }
        btn_set_state(h, (st & ~3) | BST_CHECKED);
        break;
    }
    default: break;
    }
    btn_notify(h, BN_CLICKED);
}

static LRESULT CALLBACK button_proc(HWND h, UINT msg, WPARAM wp, LPARAM lp)
{
    const UINT type = btn_type(h);
    switch (msg) {
    case WM_CREATE: SetWindowLongPtrW(h, BTN_STATE, 0); return 0;
    case WM_PAINT: {
        PAINTSTRUCT ps;
        HDC dc = BeginPaint(h, &ps);
        btn_paint(h, dc);
        EndPaint(h, &ps);
        return 0;
    }
    case WM_ERASEBKGND: return 1;
    case WM_ENABLE: case WM_SETTEXT: {
        const LRESULT r = DefWindowProcW(h, msg, wp, lp);
        InvalidateRect(h, 0, TRUE);
        return r;
    }
    case WM_SETFOCUS: case WM_KILLFOCUS:
        if (msg == WM_KILLFOCUS && (btn_state(h) & BST_PUSHED)) SetWindowLongPtrW(h, BTN_STATE, btn_state(h) & ~BST_PUSHED);
        InvalidateRect(h, 0, TRUE);
        btn_notify(h, msg == WM_SETFOCUS ? BN_SETFOCUS : BN_KILLFOCUS);
        return 0;
    case WM_GETDLGCODE:
        switch (type) {
        case BS_DEFPUSHBUTTON: return DLGC_BUTTON | DLGC_DEFPUSHBUTTON;
        case BS_PUSHBUTTON: return DLGC_BUTTON | DLGC_UNDEFPUSHBUTTON;
        case BS_RADIOBUTTON: case BS_AUTORADIOBUTTON: return DLGC_BUTTON | DLGC_RADIOBUTTON;
        case BS_GROUPBOX: return DLGC_STATIC;
        default: return DLGC_BUTTON;
        }
    case WM_LBUTTONDOWN: case WM_LBUTTONDBLCLK:
        if (type == BS_GROUPBOX) return 0;
        SetFocus(h);
        SetCapture(h);
        btn_set_state(h, btn_state(h) | BST_PUSHED);
        return 0;
    case WM_MOUSEMOVE:
        if (GetCapture() == h) {
            RECT r;
            POINT pt = { (short)LOWORD(lp), (short)HIWORD(lp) };
            const int in = GetClientRect(h, &r) && PtInRect(&r, pt);
            if (in != ((btn_state(h) & BST_PUSHED) != 0)) btn_set_state(h, in ? btn_state(h) | BST_PUSHED : btn_state(h) & ~BST_PUSHED);
        }
        return 0;
    case WM_LBUTTONUP:
        if (GetCapture() == h) {
            const int was = (btn_state(h) & BST_PUSHED) != 0;
            ReleaseCapture();
            btn_set_state(h, btn_state(h) & ~BST_PUSHED);
            if (was) btn_click(h);
        }
        return 0;
    case WM_CAPTURECHANGED:
        if (btn_state(h) & BST_PUSHED) btn_set_state(h, btn_state(h) & ~BST_PUSHED);
        return 0;
    case WM_KEYDOWN:
        if (wp == VK_SPACE && !(lp & (1 << 30))) btn_set_state(h, btn_state(h) | BST_PUSHED);
        return 0;
    case WM_KEYUP:
        if (wp == VK_SPACE && (btn_state(h) & BST_PUSHED)) { btn_set_state(h, btn_state(h) & ~BST_PUSHED); btn_click(h); }
        return 0;
    case BM_GETCHECK: return btn_state(h) & 3;
    case BM_SETCHECK:
        if (type == BS_PUSHBUTTON || type == BS_DEFPUSHBUTTON || type == BS_GROUPBOX) return 0;
        btn_set_state(h, (btn_state(h) & ~3) | (wp & 3));
        return 0;
    case BM_GETSTATE: return btn_state(h) | (GetFocus() == h ? BST_FOCUS : 0);
    case BM_SETSTATE: btn_set_state(h, wp ? btn_state(h) | BST_PUSHED : btn_state(h) & ~BST_PUSHED); return 0;
    case BM_SETSTYLE:
        SetWindowLongW(h, GWL_STYLE, (LONG)((GetWindowLongW(h, GWL_STYLE) & ~0xffff) | (wp & 0xffff)));
        if (LOWORD(lp)) InvalidateRect(h, 0, TRUE);
        return 0;
    case BM_CLICK:
        if (IsWindowEnabled(h)) btn_click(h);
        return 0;
    case BM_SETIMAGE: { const LONG_PTR o = GetWindowLongPtrW(h, BTN_IMAGE); SetWindowLongPtrW(h, BTN_IMAGE, lp); return o; }
    case BM_GETIMAGE: return GetWindowLongPtrW(h, BTN_IMAGE);
    case WM_SETFONT: return 0;
    case WM_GETFONT: return (LRESULT)GetStockObject(SYSTEM_FONT);
    default: break;
    }
    return DefWindowProcW(h, msg, wp, lp);
}

/* ---------------------------------------------------------------- Static */
#define STATIC_ICON 0

static LRESULT CALLBACK static_proc(HWND h, UINT msg, WPARAM wp, LPARAM lp)
{
    const UINT style = (UINT)GetWindowLongW(h, GWL_STYLE), type = style & SS_TYPEMASK;
    switch (msg) {
    case WM_CREATE:
        if (type == SS_ICON) {
            const CREATESTRUCTW *cs = (const CREATESTRUCTW *)lp;
            HICON ic = 0;
            if (cs->lpszName && (IS_INTRESOURCE(cs->lpszName) || cs->lpszName[0] == 0xffff))
                ic = LoadIconW(cs->hInstance, IS_INTRESOURCE(cs->lpszName) ? cs->lpszName : MAKEINTRESOURCEW(cs->lpszName[1]));
            else if (cs->lpszName && cs->lpszName[0]) ic = LoadIconW(cs->hInstance, cs->lpszName);
            SetWindowLongPtrW(h, STATIC_ICON, (LONG_PTR)ic);
        }
        return 0;
    case WM_NCHITTEST: return (style & SS_NOTIFY) ? HTCLIENT : HTTRANSPARENT;
    case WM_ERASEBKGND: return 1;
    case WM_PAINT: {
        PAINTSTRUCT ps;
        HDC dc = BeginPaint(h, &ps);
        RECT r;
        HBRUSH bk = (HBRUSH)SendMessageW(GetParent(h), WM_CTLCOLORSTATIC, (WPARAM)dc, (LPARAM)h);
        GetClientRect(h, &r);
        switch (type) {
        case SS_ICON: {
            HICON ic = (HICON)GetWindowLongPtrW(h, STATIC_ICON);
            FillRect(dc, &r, bk ? bk : GetSysColorBrush(COLOR_3DFACE));
            if (ic) DrawIconEx(dc, 0, 0, ic, 0, 0, 0, 0, DI_NORMAL | DI_DEFAULTSIZE);
            break;
        }
        case SS_BLACKRECT: FillRect(dc, &r, GetSysColorBrush(COLOR_3DDKSHADOW)); break;
        case SS_GRAYRECT: FillRect(dc, &r, GetSysColorBrush(COLOR_3DSHADOW)); break;
        case SS_WHITERECT: FillRect(dc, &r, GetSysColorBrush(COLOR_3DHIGHLIGHT)); break;
        case SS_BLACKFRAME: FrameRect(dc, &r, GetSysColorBrush(COLOR_3DDKSHADOW)); break;
        case SS_GRAYFRAME: FrameRect(dc, &r, GetSysColorBrush(COLOR_3DSHADOW)); break;
        case SS_WHITEFRAME: FrameRect(dc, &r, GetSysColorBrush(COLOR_3DHIGHLIGHT)); break;
        case SS_ETCHEDHORZ: r.bottom = r.top + 2; DrawEdge(dc, &r, EDGE_ETCHED, BF_TOP); break;
        case SS_ETCHEDVERT: r.right = r.left + 2; DrawEdge(dc, &r, EDGE_ETCHED, BF_LEFT); break;
        case SS_ETCHEDFRAME: DrawEdge(dc, &r, EDGE_ETCHED, BF_RECT); break;
        default: {
            WCHAR t[1024];
            const int n = GetWindowTextW(h, t, 1024);
            UINT fmt = type == SS_CENTER ? DT_CENTER | DT_WORDBREAK : type == SS_RIGHT ? DT_RIGHT | DT_WORDBREAK :
                       type == SS_SIMPLE || type == SS_LEFTNOWORDWRAP ? DT_LEFT | DT_SINGLELINE : DT_LEFT | DT_WORDBREAK;
            if (style & SS_NOPREFIX) fmt |= DT_NOPREFIX;
            if (style & SS_CENTERIMAGE) fmt = (fmt & ~DT_WORDBREAK) | DT_VCENTER | DT_SINGLELINE;
            FillRect(dc, &r, bk ? bk : GetSysColorBrush(COLOR_3DFACE));
            SetBkMode(dc, TRANSPARENT);
            SetTextColor(dc, GetSysColor(IsWindowEnabled(h) ? COLOR_WINDOWTEXT : COLOR_GRAYTEXT));
            if (n > 0) DrawTextW(dc, t, n, &r, fmt);
            break;
        }
        }
        EndPaint(h, &ps);
        return 0;
    }
    case WM_SETTEXT: case WM_ENABLE: {
        const LRESULT r = DefWindowProcW(h, msg, wp, lp);
        InvalidateRect(h, 0, TRUE);
        return r;
    }
    case STM_SETICON: case STM_SETIMAGE: {
        const LONG_PTR o = GetWindowLongPtrW(h, STATIC_ICON);
        SetWindowLongPtrW(h, STATIC_ICON, msg == STM_SETICON ? (LONG_PTR)wp : lp);
        InvalidateRect(h, 0, TRUE);
        return o;
    }
    case STM_GETICON: case STM_GETIMAGE: return GetWindowLongPtrW(h, STATIC_ICON);
    case WM_GETDLGCODE: return DLGC_STATIC;
    case WM_LBUTTONDOWN:
        if (style & SS_NOTIFY) SendMessageW(GetParent(h), WM_COMMAND, MAKEWPARAM((WORD)GetDlgCtrlID(h), STN_CLICKED), (LPARAM)h);
        return 0;
    case WM_SETFONT: return 0;
    case WM_GETFONT: return (LRESULT)GetStockObject(SYSTEM_FONT);
    default: break;
    }
    return DefWindowProcW(h, msg, wp, lp);
}

/* ---------------------------------------------------------------- dialog helpers */
DLLAPI HWND WINAPI GetDlgItem(HWND dlg, int id)
{
    HWND c;
    for (c = GetWindow(dlg, GW_CHILD); c; c = GetWindow(c, GW_HWNDNEXT))
        if (GetWindowLongPtrW(c, GWLP_ID) == id) return c;
    SetLastError(ERROR_CONTROL_ID_NOT_FOUND);
    return 0;
}

DLLAPI int WINAPI GetDlgCtrlID(HWND h) { return (int)GetWindowLongPtrW(h, GWLP_ID); }

DLLAPI LRESULT WINAPI SendDlgItemMessageW(HWND dlg, int id, UINT msg, WPARAM wp, LPARAM lp)
{
    HWND c = GetDlgItem(dlg, id);
    return c ? SendMessageW(c, msg, wp, lp) : 0;
}
DLLAPI LRESULT WINAPI SendDlgItemMessageA(HWND dlg, int id, UINT msg, WPARAM wp, LPARAM lp) { return SendDlgItemMessageW(dlg, id, msg, wp, lp); }

DLLAPI BOOL WINAPI SetDlgItemTextW(HWND dlg, int id, LPCWSTR text) { HWND c = GetDlgItem(dlg, id); return c && SetWindowTextW(c, text); }
DLLAPI UINT WINAPI GetDlgItemTextW(HWND dlg, int id, LPWSTR buf, int cap)
{
    HWND c = GetDlgItem(dlg, id);
    if (!c) { if (buf && cap > 0) buf[0] = 0; return 0; }
    return (UINT)GetWindowTextW(c, buf, cap);
}
DLLAPI BOOL WINAPI SetDlgItemTextA(HWND dlg, int id, LPCSTR text)
{
    WCHAR w[1024];
    if (!MultiByteToWideChar(CP_ACP, 0, text ? text : "", -1, w, 1024)) return FALSE;
    return SetDlgItemTextW(dlg, id, w);
}
DLLAPI UINT WINAPI GetDlgItemTextA(HWND dlg, int id, LPSTR buf, int cap)
{
    WCHAR w[1024];
    int n;
    if (!buf || cap <= 0) return 0;
    n = (int)GetDlgItemTextW(dlg, id, w, 1024);
    n = WideCharToMultiByte(CP_ACP, 0, w, n, buf, cap - 1, 0, 0);
    buf[n] = 0;
    return (UINT)n;
}

DLLAPI BOOL WINAPI SetDlgItemInt(HWND dlg, int id, UINT v, BOOL sign)
{
    WCHAR b[16], t[16];
    int n = 0, k = 0;
    int neg = sign && (int)v < 0;
    unsigned u = neg ? (unsigned)(-(int)v) : v;
    do { t[n++] = (WCHAR)('0' + u % 10); u /= 10; } while (u);
    if (neg) b[k++] = '-';
    while (n) b[k++] = t[--n];
    b[k] = 0;
    return SetDlgItemTextW(dlg, id, b);
}

DLLAPI UINT WINAPI GetDlgItemInt(HWND dlg, int id, BOOL *ok, BOOL sign)
{
    WCHAR b[32];
    const WCHAR *p = b;
    int neg = 0, any = 0;
    uint64_t v = 0;
    if (ok) *ok = FALSE;
    if (!GetDlgItemTextW(dlg, id, b, 32)) return 0;
    while (*p == ' ') ++p;
    if (sign && *p == '-') { neg = 1; ++p; }
    while (*p >= '0' && *p <= '9') { v = v * 10 + (uint64_t)(*p++ - '0'); any = 1; if (v > 0xffffffffu) return 0; }
    while (*p == ' ') ++p;
    if (!any || *p || (sign && v > (neg ? 0x80000000u : 0x7fffffffu))) return 0;
    if (ok) *ok = TRUE;
    return neg ? (UINT)(-(int64_t)v) : (UINT)v;
}

DLLAPI BOOL WINAPI CheckDlgButton(HWND dlg, int id, UINT check) { SendDlgItemMessageW(dlg, id, BM_SETCHECK, check, 0); return GetDlgItem(dlg, id) != 0; }
DLLAPI UINT WINAPI IsDlgButtonChecked(HWND dlg, int id) { return (UINT)SendDlgItemMessageW(dlg, id, BM_GETCHECK, 0, 0); }
DLLAPI BOOL WINAPI CheckRadioButton(HWND dlg, int first, int last, int check)
{
    int id;
    for (id = first; id <= last; ++id) SendDlgItemMessageW(dlg, id, BM_SETCHECK, id == check ? BST_CHECKED : BST_UNCHECKED, 0);
    return TRUE;
}

static int tabbable(HWND c)
{
    const LONG s = GetWindowLongW(c, GWL_STYLE);
    return (s & WS_TABSTOP) && (s & WS_VISIBLE) && !(s & WS_DISABLED);
}

DLLAPI HWND WINAPI GetNextDlgTabItem(HWND dlg, HWND ctl, BOOL prev)
{
    HWND list[256], c;
    int n = 0, i, cur = -1, k;
    for (c = GetWindow(dlg, GW_CHILD); c && n < 256; c = GetWindow(c, GW_HWNDNEXT)) { if (c == ctl) cur = n; list[n++] = c; }
    if (!n) return 0;
    for (k = 1; k <= n; ++k) {
        i = cur < 0 ? (prev ? n - k : k - 1) : ((cur + (prev ? -k : k)) % n + n) % n;
        if (tabbable(list[i])) return list[i];
    }
    return ctl;
}

DLLAPI HWND WINAPI GetNextDlgGroupItem(HWND dlg, HWND ctl, BOOL prev)
{
    HWND list[256], c;
    int n = 0, i, cur = -1, start, end, k;
    for (c = GetWindow(dlg, GW_CHILD); c && n < 256; c = GetWindow(c, GW_HWNDNEXT)) { if (c == ctl) cur = n; list[n++] = c; }
    if (!n) return 0;
    if (cur < 0) cur = 0;
    for (start = cur; start > 0 && !(GetWindowLongW(list[start], GWL_STYLE) & WS_GROUP); --start) { }   /* the group: from a WS_GROUP */
    for (end = cur + 1; end < n && !(GetWindowLongW(list[end], GWL_STYLE) & WS_GROUP); ++end) { }       /* to before the next one */
    for (k = 1; k <= end - start; ++k) {
        i = start + ((cur - start + (prev ? -k : k)) % (end - start) + (end - start)) % (end - start);
        {
            const LONG s = GetWindowLongW(list[i], GWL_STYLE);
            if ((s & WS_VISIBLE) && !(s & WS_DISABLED)) return list[i];
        }
    }
    return ctl;
}

DLLAPI LONG WINAPI GetDialogBaseUnits(void) { return MAKELONG(8, 16); }  /* the 8x16 system font */

DLLAPI BOOL WINAPI MapDialogRect(HWND dlg, LPRECT r)
{
    (void)dlg;
    if (!r) return FALSE;
    r->left = r->left * 8 / 4; r->right = r->right * 8 / 4;
    r->top = r->top * 16 / 8; r->bottom = r->bottom * 16 / 8;
    return TRUE;
}

/* ---------------------------------------------------------------- DefDlgProc */
typedef struct { int ended; INT_PTR result; HWND focus; int modal; } dlginfo_t;
#define DLG_INFO_PROP L"ShzDlgInfo"

static dlginfo_t *dlg_info(HWND h, int create)
{
    dlginfo_t *d = (dlginfo_t *)GetPropW(h, DLG_INFO_PROP);
    if (!d && create) {
        d = HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, sizeof *d);
        if (d) SetPropW(h, DLG_INFO_PROP, d);
    }
    return d;
}

/* SetFocus on a control of a dialog that is not shown yet (WM_INITDIALOG): the window manager only focuses visible
 * windows, so the dialog remembers it and gives it the focus when it is activated. */
int u32_dlg_remember_focus(HWND ctl)
{
    HWND top = GetAncestor(ctl, GA_ROOT);
    dlginfo_t *d = top ? dlg_info(top, 0) : 0;
    if (!d || IsWindowVisible(top)) return 0;
    d->focus = ctl;
    return 1;
}

static LRESULT def_dlg(HWND h, UINT msg, WPARAM wp, LPARAM lp)
{
    dlginfo_t *d = dlg_info(h, 0);
    switch (msg) {
    case WM_ERASEBKGND: {
        RECT r;
        HBRUSH b = (HBRUSH)SendMessageW(h, WM_CTLCOLORDLG, wp, (LPARAM)h);
        GetClientRect(h, &r);
        FillRect((HDC)wp, &r, b ? b : GetSysColorBrush(COLOR_3DFACE));
        return 1;
    }
    case WM_CLOSE: {
        HWND c = GetDlgItem(h, IDCANCEL);
        if (!c || IsWindowEnabled(c)) PostMessageW(h, WM_COMMAND, MAKEWPARAM(IDCANCEL, BN_CLICKED), (LPARAM)c);
        return 0;
    }
    case WM_ACTIVATE:
        if (d && LOWORD(wp) == WA_INACTIVE) { HWND f = GetFocus(); if (f && IsChild(h, f)) d->focus = f; }
        else if (d && d->focus && IsWindow(d->focus)) { SetFocus(d->focus); return 0; }
        break;
    case WM_SETFOCUS:
        if (d && d->focus && IsWindow(d->focus)) SetFocus(d->focus);
        else { HWND f = GetNextDlgTabItem(h, 0, FALSE); if (f) SetFocus(f); }
        return 0;
    case DM_GETDEFID: {
        HWND c;
        for (c = GetWindow(h, GW_CHILD); c; c = GetWindow(c, GW_HWNDNEXT))
            if (SendMessageW(c, WM_GETDLGCODE, 0, 0) & DLGC_DEFPUSHBUTTON) return MAKELRESULT(GetDlgCtrlID(c), DC_HASDEFID);
        return 0;
    }
    case DM_SETDEFID: {
        HWND c;
        for (c = GetWindow(h, GW_CHILD); c; c = GetWindow(c, GW_HWNDNEXT)) {
            const LRESULT code = SendMessageW(c, WM_GETDLGCODE, 0, 0);
            if (code & DLGC_DEFPUSHBUTTON) SendMessageW(c, BM_SETSTYLE, BS_PUSHBUTTON, TRUE);
            if ((code & (DLGC_DEFPUSHBUTTON | DLGC_UNDEFPUSHBUTTON)) && GetDlgCtrlID(c) == (int)wp) SendMessageW(c, BM_SETSTYLE, BS_DEFPUSHBUTTON, TRUE);
        }
        return TRUE;
    }
    case WM_NEXTDLGCTL: {
        HWND f = LOWORD(lp) ? (HWND)wp : GetNextDlgTabItem(h, GetFocus(), wp != 0);
        if (f) SetFocus(f);
        return 0;
    }
    case WM_NCDESTROY:
        if (d) { RemovePropW(h, DLG_INFO_PROP); HeapFree(GetProcessHeap(), 0, d); }
        break;
    default: break;
    }
    return DefWindowProcW(h, msg, wp, lp);
}

static int dlgproc_returns_directly(UINT msg)
{
    return msg == WM_CTLCOLORMSGBOX || msg == WM_CTLCOLOREDIT || msg == WM_CTLCOLORLISTBOX || msg == WM_CTLCOLORBTN || msg == WM_CTLCOLORDLG ||
           msg == WM_CTLCOLORSCROLLBAR || msg == WM_CTLCOLORSTATIC || msg == WM_COMPAREITEM || msg == WM_VKEYTOITEM || msg == WM_CHARTOITEM ||
           msg == WM_QUERYDRAGICON || msg == WM_INITDIALOG;
}

DLLAPI LRESULT WINAPI DefDlgProcW(HWND h, UINT msg, WPARAM wp, LPARAM lp)
{
    DLGPROC proc = (DLGPROC)GetWindowLongPtrW(h, DWLP_DLGPROC);
    if (proc) {
        INT_PTR r;
        SetWindowLongPtrW(h, DWLP_MSGRESULT, 0);
        r = proc(h, msg, wp, lp);
        if (!IsWindow(h)) return r;
        if (r) return dlgproc_returns_directly(msg) ? r : GetWindowLongPtrW(h, DWLP_MSGRESULT);
    }
    return def_dlg(h, msg, wp, lp);
}
DLLAPI LRESULT WINAPI DefDlgProcA(HWND h, UINT msg, WPARAM wp, LPARAM lp) { return DefDlgProcW(h, msg, wp, lp); }

static LRESULT CALLBACK dialog_proc(HWND h, UINT msg, WPARAM wp, LPARAM lp) { return DefDlgProcW(h, msg, wp, lp); }

/* ---------------------------------------------------------------- IsDialogMessage */
DLLAPI BOOL WINAPI IsDialogMessageW(HWND dlg, LPMSG msg)
{
    HWND f;
    LRESULT code = 0;
    if (!msg || !dlg || (msg->hwnd != dlg && !IsChild(dlg, msg->hwnd))) return FALSE;
    if (CallMsgFilterW(msg, MSGF_DIALOGBOX)) return TRUE;
    f = GetFocus();
    if (f && (f == dlg || IsChild(dlg, f))) code = SendMessageW(f, WM_GETDLGCODE, msg->wParam, (LPARAM)msg);
    if (msg->message == WM_KEYDOWN && !(code & DLGC_WANTALLKEYS)) {
        switch (msg->wParam) {
        case VK_TAB:
            if (code & DLGC_WANTTAB) break;
            {
                HWND n = GetNextDlgTabItem(dlg, f, GetKeyState(VK_SHIFT) < 0);
                if (n) SetFocus(n);
            }
            return TRUE;
        case VK_LEFT: case VK_UP: case VK_RIGHT: case VK_DOWN:
            if (code & DLGC_WANTARROWS) break;
            {
                HWND n = GetNextDlgGroupItem(dlg, f, msg->wParam == VK_LEFT || msg->wParam == VK_UP);
                if (n && n != f) {
                    SetFocus(n);
                    if (SendMessageW(n, WM_GETDLGCODE, 0, 0) & DLGC_RADIOBUTTON) SendMessageW(n, BM_CLICK, 0, 0);
                }
            }
            return TRUE;
        case VK_RETURN: {
            const LRESULT def = SendMessageW(dlg, DM_GETDEFID, 0, 0);
            WORD id = HIWORD(def) == DC_HASDEFID ? LOWORD(def) : IDOK;
            HWND b;
            if (code & DLGC_DEFPUSHBUTTON) id = (WORD)GetDlgCtrlID(f);
            else if (code & DLGC_UNDEFPUSHBUTTON) id = (WORD)GetDlgCtrlID(f);
            b = GetDlgItem(dlg, id);
            if (!b || IsWindowEnabled(b)) SendMessageW(dlg, WM_COMMAND, MAKEWPARAM(id, BN_CLICKED), (LPARAM)b);
            return TRUE;
        }
        case VK_ESCAPE:
            SendMessageW(dlg, WM_COMMAND, MAKEWPARAM(IDCANCEL, BN_CLICKED), (LPARAM)GetDlgItem(dlg, IDCANCEL));
            return TRUE;
        default: break;
        }
    }
    if ((msg->message == WM_SYSCHAR || (msg->message == WM_CHAR && !(code & (DLGC_WANTCHARS | DLGC_WANTMESSAGE)))) && msg->wParam > ' ') {
        HWND c;                                                         /* a mnemonic: the control whose text has &x */
        WCHAR want = (WCHAR)msg->wParam;
        if (want >= 'a' && want <= 'z') want = (WCHAR)(want - 32);
        for (c = GetWindow(dlg, GW_CHILD); c; c = GetWindow(c, GW_HWNDNEXT)) {
            WCHAR t[128];
            int n = GetWindowTextW(c, t, 128), i;
            for (i = 0; i + 1 < n; ++i)
                if (t[i] == '&' && t[i + 1] != '&') {
                    WCHAR m = t[i + 1];
                    if (m >= 'a' && m <= 'z') m = (WCHAR)(m - 32);
                    if (m == want && IsWindowEnabled(c) && IsWindowVisible(c)) {
                        const LRESULT cc = SendMessageW(c, WM_GETDLGCODE, 0, 0);
                        if (cc & DLGC_STATIC) { HWND n2 = GetNextDlgTabItem(dlg, c, FALSE); if (n2) SetFocus(n2); }
                        else { SetFocus(c); if (cc & DLGC_BUTTON) SendMessageW(c, BM_CLICK, 0, 0); }
                        return TRUE;
                    }
                    break;
                }
        }
        if (msg->message == WM_SYSCHAR) return TRUE;
    }
    TranslateMessage(msg);
    DispatchMessageW(msg);
    return TRUE;
}
DLLAPI BOOL WINAPI IsDialogMessageA(HWND dlg, LPMSG msg) { return IsDialogMessageW(dlg, msg); }

/* ---------------------------------------------------------------- templates */
static const WORD *skip_sz_or_ord(const WORD *p, LPCWSTR *out)
{
    if (*p == 0) { if (out) *out = 0; return p + 1; }
    if (*p == 0xffff) { if (out) *out = MAKEINTRESOURCEW(p[1]); return p + 2; }
    if (out) *out = (LPCWSTR)p;
    while (*p) ++p;
    return p + 1;
}

static const WCHAR *control_class(LPCWSTR c)
{
    if (!IS_INTRESOURCE(c)) return c;
    switch ((uintptr_t)c) {
    case 0x80: return L"Button";
    case 0x81: return L"Edit";
    case 0x82: return L"Static";
    case 0x83: return L"ListBox";
    case 0x84: return L"ScrollBar";
    case 0x85: return L"ComboBox";
    default: return 0;
    }
}

static int du_x(int v) { return v * 8 / 4; }
static int du_y(int v) { return v * 16 / 8; }

DLLAPI HWND WINAPI CreateDialogIndirectParamW(HINSTANCE inst, LPCDLGTEMPLATEW tpl, HWND owner, DLGPROC proc, LPARAM init)
{
    const WORD *p = (const WORD *)tpl;
    const int ex = p[0] == 1 && p[1] == 0xffff;
    DWORD style, exstyle;
    int count, x, y, cx, cy, i;
    LPCWSTR menu, cls, title;
    RECT r;
    HWND dlg, focus = 0;
    U32_NEED_GFX(0);
    register_classes();
    if (ex) {
        const DWORD *d = (const DWORD *)(p + 2);
        exstyle = d[1]; style = d[2];
        p = (const WORD *)(d + 3);
    } else {
        style = *(const DWORD *)p; exstyle = *(const DWORD *)(p + 2);
        p += 4;
    }
    count = *p++;
    x = (short)*p++; y = (short)*p++; cx = (short)*p++; cy = (short)*p++;
    p = skip_sz_or_ord(p, &menu);
    p = skip_sz_or_ord(p, &cls);
    p = skip_sz_or_ord(p, &title);
    if (style & (DS_SETFONT | DS_SHELLFONT)) {                          /* the font is noted and ignored: one font exists */
        ++p;
        if (ex) p += 2;
        while (*p) ++p;
        ++p;
    }
    r.left = 0; r.top = 0; r.right = du_x(cx); r.bottom = du_y(cy);
    AdjustWindowRectEx(&r, style, FALSE, exstyle);
    if (style & DS_CENTER || (style & DS_CENTERMOUSE)) {
        const int sw = u32_metric(SM_CXSCREEN), sh = u32_metric(SM_CYSCREEN);
        x = (sw - (r.right - r.left)) / 2;
        y = (sh - (r.bottom - r.top)) / 2;
    } else {
        POINT o = { du_x(x), du_y(y) };
        if (owner && !(style & WS_CHILD)) ClientToScreen(owner, &o);
        x = o.x + r.left; y = o.y + r.top;
    }
    dlg = CreateWindowExW(exstyle, cls ? cls : L"#32770", title ? title : L"", style & ~WS_VISIBLE, x, y, r.right - r.left, r.bottom - r.top, owner,
                          (menu && !(style & WS_CHILD)) ? LoadMenuW(inst, menu) : 0, inst, 0);
    if (!dlg) return 0;
    SetWindowLongPtrW(dlg, DWLP_DLGPROC, (LONG_PTR)proc);
    dlg_info(dlg, 1);
    for (i = 0; i < count; ++i) {
        DWORD cstyle, cex, id;
        int ix, iy, icx, icy;
        LPCWSTR ccls, ctitle;
        WORD extra;
        const void *cdata;
        HWND c;
        p = (const WORD *)(((uintptr_t)p + 3) & ~(uintptr_t)3);        /* each item is DWORD aligned */
        if (ex) {
            const DWORD *d = (const DWORD *)p;
            cex = d[1]; cstyle = d[2];
            p = (const WORD *)(d + 3);
            ix = (short)p[0]; iy = (short)p[1]; icx = (short)p[2]; icy = (short)p[3];
            id = *(const DWORD *)(p + 4);
            p += 6;
        } else {
            cstyle = *(const DWORD *)p; cex = *(const DWORD *)(p + 2);
            p += 4;
            ix = (short)p[0]; iy = (short)p[1]; icx = (short)p[2]; icy = (short)p[3];
            id = p[4];
            p += 5;
        }
        p = skip_sz_or_ord(p, &ccls);
        p = skip_sz_or_ord(p, &ctitle);
        if (ex) {                                                       /* WORD byte count, then the data */
            extra = *p++;
            cdata = extra ? (const void *)p : 0;
            p = (const WORD *)((const uint8_t *)p + extra);
        } else {                                                        /* the size word counts itself */
            const WORD *ws = p;
            extra = *p++;
            cdata = extra ? (const void *)ws : 0;
            if (extra > 2) p = (const WORD *)((const uint8_t *)ws + extra);
        }
        {
            const WCHAR *cname = control_class(ccls);
            WCHAR icon_title[3] = { 0xffff, 0, 0 };
            LPCWSTR t = ctitle;
            if (t && IS_INTRESOURCE(t)) { icon_title[1] = (WCHAR)(uintptr_t)t; t = icon_title; }   /* ordinal titles (icons) */
            c = cname ? CreateWindowExW(cex | WS_EX_NOPARENTNOTIFY, cname, t ? t : L"", cstyle | WS_CHILD, du_x(ix), du_y(iy), du_x(icx), du_y(icy), dlg,
                                        (HMENU)(uintptr_t)id, inst, (LPVOID)cdata)
                      : 0;
        }
        if (!c && !(style & DS_NOFAILCREATE)) { DestroyWindow(dlg); return 0; }
        if (c) SetWindowPos(c, HWND_BOTTOM, 0, 0, 0, 0, SWP_NOSIZE | SWP_NOMOVE | SWP_NOACTIVATE);   /* z-order = template order = tab order */
        if (c && !focus && tabbable(c)) focus = c;
    }
    if (SendMessageW(dlg, WM_INITDIALOG, (WPARAM)focus, init) && focus && IsWindow(focus)) SetFocus(focus);
    if (!IsWindow(dlg)) return 0;
    if (style & WS_VISIBLE) { ShowWindow(dlg, SW_SHOWNORMAL); UpdateWindow(dlg); }
    return dlg;
}

DLLAPI HWND WINAPI CreateDialogParamW(HINSTANCE inst, LPCWSTR name, HWND owner, DLGPROC proc, LPARAM init)
{
    const void *t = u32_find_resource(inst, (LPCWSTR)RT_DIALOG, name, 0);
    if (!t) { SetLastError(ERROR_RESOURCE_NAME_NOT_FOUND); return 0; }
    return CreateDialogIndirectParamW(inst, t, owner, proc, init);
}

DLLAPI BOOL WINAPI EndDialog(HWND dlg, INT_PTR result)
{
    dlginfo_t *d = dlg_info(dlg, 0);
    if (!d) { SetLastError(ERROR_INVALID_WINDOW_HANDLE); return FALSE; }
    d->ended = 1;
    d->result = result;
    if (d->modal) ShowWindow(dlg, SW_HIDE);
    PostMessageW(dlg, WM_NULL, 0, 0);                                   /* wake the modal loop */
    return TRUE;
}

/* Dialog callbacks can destroy their HWND synchronously, which also frees
 * ShzDlgInfo in WM_NCDESTROY. Never retain that heap pointer across a call
 * that can deliver application messages. Destruction without EndDialog is a
 * failed modal operation and returns -1 after restoring the owner's state. */
static dlginfo_t *live_dialog_info(HWND dlg)
{
    return IsWindow(dlg) ? dlg_info(dlg, 0) : 0;
}

DLLAPI INT_PTR WINAPI DialogBoxIndirectParamW(HINSTANCE inst, LPCDLGTEMPLATEW tpl, HWND owner, DLGPROC proc, LPARAM init)
{
    HWND dlg;
    dlginfo_t *d;
    INT_PTR result;
    MSG msg;
    int owner_enabled = 0;
    if (owner && (GetWindowLongW(owner, GWL_STYLE) & WS_CHILD)) owner = GetAncestor(owner, GA_ROOT);
    dlg = CreateDialogIndirectParamW(inst, tpl, owner, proc, init);
    if (!dlg) return -1;
    d = dlg_info(dlg, 1);
    if (!d) {
        DestroyWindow(dlg);
        SetLastError(ERROR_NOT_ENOUGH_MEMORY);
        return -1;
    }
    d->modal = 1;
    if (!d->ended) {
        if (owner && IsWindowEnabled(owner)) { owner_enabled = 1; EnableWindow(owner, FALSE); }
        if ((d = live_dialog_info(dlg)) && !d->ended) ShowWindow(dlg, SW_SHOWNORMAL);
        if ((d = live_dialog_info(dlg)) && !d->ended) UpdateWindow(dlg);
        while ((d = live_dialog_info(dlg)) && !d->ended) {
            const BOOL got = GetMessageW(&msg, 0, 0, 0);
            if (got <= 0) { if (got == 0) PostQuitMessage((int)msg.wParam); break; }
            d = live_dialog_info(dlg);                 /* GetMessage can dispatch sent messages */
            if (!d || d->ended) break;
            if (!IsDialogMessageW(dlg, &msg)) {
                d = live_dialog_info(dlg);             /* dialog routing also calls application code */
                if (!d || d->ended) break;
                TranslateMessage(&msg);
                DispatchMessageW(&msg);
            }
        }
        if (owner_enabled) EnableWindow(owner, TRUE);
        if (owner && IsWindow(owner)) SetForegroundWindow(owner);
    }
    d = live_dialog_info(dlg);
    result = d && d->ended ? d->result : -1;
    if (IsWindow(dlg)) DestroyWindow(dlg);
    return result;
}

DLLAPI INT_PTR WINAPI DialogBoxParamW(HINSTANCE inst, LPCWSTR name, HWND owner, DLGPROC proc, LPARAM init)
{
    const void *t = u32_find_resource(inst, (LPCWSTR)RT_DIALOG, name, 0);
    if (!t) { SetLastError(ERROR_RESOURCE_NAME_NOT_FOUND); return -1; }
    return DialogBoxIndirectParamW(inst, t, owner, proc, init);
}

/* ---------------------------------------------------------------- MessageBox */
typedef struct { WORD *p, *end; } tb_t;
static void tb_w(tb_t *b, WORD v) { if (b->p < b->end) *b->p++ = v; }
static void tb_d(tb_t *b, DWORD v) { tb_w(b, (WORD)v); tb_w(b, (WORD)(v >> 16)); }
static void tb_s(tb_t *b, LPCWSTR s) { while (s && *s) tb_w(b, *s++); tb_w(b, 0); }
static void tb_align(tb_t *b) { while (((uintptr_t)b->p) & 3) tb_w(b, 0); }
static void tb_item(tb_t *b, DWORD style, int x, int y, int cx, int cy, WORD id, WORD cls, LPCWSTR text, WORD ord_text)
{
    tb_align(b);
    tb_d(b, style | WS_CHILD | WS_VISIBLE);
    tb_d(b, 0);
    tb_w(b, (WORD)x); tb_w(b, (WORD)y); tb_w(b, (WORD)cx); tb_w(b, (WORD)cy);
    tb_w(b, id);
    tb_w(b, 0xffff); tb_w(b, cls);
    if (ord_text) { tb_w(b, 0xffff); tb_w(b, ord_text); } else tb_s(b, text);
    tb_w(b, 0);
}

static INT_PTR CALLBACK msgbox_proc(HWND h, UINT msg, WPARAM wp, LPARAM lp)
{
    switch (msg) {
    case WM_INITDIALOG: {
        const int def = (int)lp;
        HWND b = def ? GetDlgItem(h, def) : 0;
        SetForegroundWindow(h);
        if (b) { SetFocus(b); return FALSE; }
        return TRUE;
    }
    case WM_COMMAND:
        if (HIWORD(wp) == BN_CLICKED) {
            const WORD id = LOWORD(wp);
            if (id == IDCANCEL && !GetDlgItem(h, IDCANCEL)) {               /* Escape without a Cancel button: OK if it is the only one */
                if (GetDlgItem(h, IDOK) && !GetDlgItem(h, IDNO)) EndDialog(h, IDOK);
                return TRUE;
            }
            EndDialog(h, id);
            return TRUE;
        }
        return FALSE;
    default: return FALSE;
    }
}

static int wrap_lines(LPCWSTR text, int *width)
{
    /* *width = widest line in half-cells (one per 8 px, as 4 dlu): ASCII 1, Hangul and other full-width glyphs 2 */
    int lines = 1, col = 0, maxc = 0, i, start = 0, px = 0, maxpx = 0;
    for (i = 0; text && text[i]; ++i) {
        if (text[i] == '\n' || col >= 60) {
            px = u32_text_px(text + start, i - start - (i > start && text[i - 1] == '\r'));
            if (px > maxpx) maxpx = px;
            ++lines; if (col > maxc) maxc = col; col = 0; start = i;
            if (text[i] == '\n') { start = i + 1; continue; }
        }
        if (text[i] != '\r') ++col;
    }
    if (col > maxc) maxc = col;
    px = text ? u32_text_px(text + start, i - start - (i > start && text[i - 1] == '\r')) : 0;
    if (px > maxpx) maxpx = px;
    *width = (maxpx + 7) / 8 > maxc ? (maxpx + 7) / 8 : maxc;
    return lines;
}

DLLAPI int WINAPI MessageBoxExW(HWND owner, LPCWSTR text, LPCWSTR caption, UINT type, WORD lang)
{
    static const struct { UINT kind; WORD ids[3]; LPCWSTR names[3]; } sets[7] = {
        { MB_OK, { IDOK }, { L"OK" } },
        { MB_OKCANCEL, { IDOK, IDCANCEL }, { L"OK", L"Cancel" } },
        { MB_ABORTRETRYIGNORE, { IDABORT, IDRETRY, IDIGNORE }, { L"&Abort", L"&Retry", L"&Ignore" } },
        { MB_YESNOCANCEL, { IDYES, IDNO, IDCANCEL }, { L"&Yes", L"&No", L"Cancel" } },
        { MB_YESNO, { IDYES, IDNO }, { L"&Yes", L"&No" } },
        { MB_RETRYCANCEL, { IDRETRY, IDCANCEL }, { L"&Retry", L"Cancel" } },
        { MB_CANCELTRYCONTINUE, { IDCANCEL, IDTRYAGAIN, IDCONTINUE }, { L"Cancel", L"&Try Again", L"&Continue" } } };
    WORD buf[4096];
    tb_t b = { buf, buf + 4096 };
    const UINT kind = type & MB_TYPEMASK, icon = type & MB_ICONMASK;
    int set = 0, nb = 0, i, chars, lines, tw, th, w, h, icon_w, bx, defidx;
    WORD icon_id = 0;
    (void)lang;
    if (!u32_display(0)) { SetLastError(ERROR_NOT_SUPPORTED); return 0; }
    for (i = 0; i < 7; ++i) if (sets[i].kind == kind) set = i;
    for (nb = 0; nb < 3 && sets[set].ids[nb]; ++nb) { }
    switch (icon) {
    case MB_ICONHAND: icon_id = 32513; break;
    case MB_ICONQUESTION: icon_id = 32514; break;
    case MB_ICONEXCLAMATION: icon_id = 32515; break;
    case MB_ICONASTERISK: icon_id = 32516; break;
    default: break;
    }
    lines = wrap_lines(text, &chars);
    icon_w = icon_id ? 28 : 0;                                          /* dialog units: 32 px icon + gap */
    tw = chars * 4 + 4;                                                 /* 8 px = 4 dlu per character */
    th = lines * 8;
    w = 8 + icon_w + tw + 8;
    if (w < nb * 56 + 16) w = nb * 56 + 16;
    h = 8 + (th > 20 ? th : 20) + 8 + 14 + 8;
    defidx = (int)((type & MB_DEFMASK) >> 8);
    if (defidx >= nb) defidx = 0;
    tb_d(&b, WS_POPUP | WS_CAPTION | WS_SYSMENU | DS_MODALFRAME | DS_CENTER | WS_VISIBLE | ((type & MB_SYSTEMMODAL) ? DS_SYSMODAL : 0));
    tb_d(&b, (type & MB_TOPMOST) || (type & MB_SYSTEMMODAL) ? WS_EX_TOPMOST : 0);
    tb_w(&b, (WORD)((icon_id ? 1 : 0) + 1 + nb));
    tb_w(&b, 0); tb_w(&b, 0); tb_w(&b, (WORD)w); tb_w(&b, (WORD)h);
    tb_w(&b, 0);                                                        /* menu */
    tb_w(&b, 0);                                                        /* class */
    tb_s(&b, caption ? caption : L"Error");
    if (icon_id) tb_item(&b, SS_ICON, 8, 8, 20, 20, 0xffff, 0x82, 0, icon_id);
    tb_item(&b, SS_LEFT | SS_NOPREFIX, 8 + icon_w, 8 + (th < 20 ? (20 - th) / 2 : 0), tw, th, 0xffff, 0x82, text ? text : L"", 0);
    bx = (w - nb * 56 + 6) / 2;
    for (i = 0; i < nb; ++i)
        tb_item(&b, (i == defidx ? BS_DEFPUSHBUTTON : BS_PUSHBUTTON) | WS_TABSTOP | (i == 0 ? WS_GROUP : 0), bx + i * 56, h - 8 - 14, 50, 14,
                sets[set].ids[i], 0x80, sets[set].names[i], 0);
    if (b.p >= b.end) { SetLastError(ERROR_NOT_ENOUGH_MEMORY); return 0; }
    return (int)DialogBoxIndirectParamW(0, (LPCDLGTEMPLATEW)buf, owner, msgbox_proc, sets[set].ids[defidx]);
}

DLLAPI int WINAPI MessageBoxW(HWND owner, LPCWSTR text, LPCWSTR caption, UINT type) { return MessageBoxExW(owner, text, caption, type, 0); }

static WCHAR *a2w_heap(LPCSTR s)
{
    int n;
    WCHAR *w;
    if (!s) return 0;
    n = MultiByteToWideChar(CP_ACP, 0, s, -1, 0, 0);
    w = HeapAlloc(GetProcessHeap(), 0, (size_t)(n > 0 ? n : 1) * 2);
    if (w) MultiByteToWideChar(CP_ACP, 0, s, -1, w, n);
    return w;
}

DLLAPI int WINAPI MessageBoxExA(HWND owner, LPCSTR text, LPCSTR caption, UINT type, WORD lang)
{
    WCHAR *t = a2w_heap(text), *c = a2w_heap(caption);
    const int r = MessageBoxExW(owner, t, c, type, lang);
    if (t) HeapFree(GetProcessHeap(), 0, t);
    if (c) HeapFree(GetProcessHeap(), 0, c);
    return r;
}
DLLAPI int WINAPI MessageBoxA(HWND owner, LPCSTR text, LPCSTR caption, UINT type) { return MessageBoxExA(owner, text, caption, type, 0); }
DLLAPI int WINAPI MessageBoxIndirectW(const MSGBOXPARAMSW *p)
{
    if (!p) { SetLastError(ERROR_INVALID_PARAMETER); return 0; }
    return MessageBoxExW(p->hwndOwner, p->lpszText, p->lpszCaption, p->dwStyle & ~MB_USERICON, (WORD)p->dwLanguageId);
}
