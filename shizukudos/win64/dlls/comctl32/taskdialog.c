/* SPDX-License-Identifier: GPL-2.0-only
 * Original TaskDialog subset over the real user32 modal dialog manager.
 * Contracts: Microsoft TaskDialogIndirect/TASKDIALOGCONFIG/TDN_BUTTON_CLICKED;
 * caller checked: Electron v43.2.0 shell/browser/ui/message_box_win.cc.
 * Actual HWNDs, controls, modal input and EndDialog determine the result.
 * Command links use classic push-button rows with a separate visible note;
 * theme glyphs and instruction typography are not reproduced. Resource strings,
 * custom resource icons, radio/expandable/footer/progress/timer/hyperlink modes
 * and oversized content fail explicitly. No dialog is accepted automatically.
 */
#define _COMCTL32_
#include "nt.h"
#include <winuser.h>
#include <winnls.h>
#include <commctrl.h>
#include <string.h>

#define TD_MAX_BUTTONS 32
#define TD_VERIFY_ID 0x6000
#define TD_CUSTOM_ID 0x5000
#define TD_TEXT_LIMIT 1023              /* existing STATIC renderer's full text capacity */
#define TD_ALLOWED (TDF_ALLOW_DIALOG_CANCELLATION | TDF_USE_COMMAND_LINKS | TDF_USE_COMMAND_LINKS_NO_ICON | \
                    TDF_VERIFICATION_FLAG_CHECKED | TDF_SIZE_TO_CONTENT | TDF_POSITION_RELATIVE_TO_WINDOW | TDF_USE_HICON_MAIN)

typedef struct {
    int id, control, custom, x, y, width, note_height;
    LPCWSTR text, note;
    WCHAR *owned_title;
    HWND hwnd;
} td_button;
typedef struct {
    const TASKDIALOGCONFIG *cfg;
    td_button buttons[TD_MAX_BUTTONS];
    int count, default_index, selected, allow_cancel, width, height;
    int instruction_height, content_height, text_x, text_width, buttons_y;
    BOOL verification, verification_enabled, ended, destroyed, created;
    HWND checkbox;
    HICON icon;
    HRESULT error;
} td_state;

static HRESULT unsupported(const char *reason)
{
    WCHAR value[4];
    if (GetEnvironmentVariableW(L"SHZ_K32TRACE", value, 4) == 1 && value[0] == '1') {
        const char prefix[] = "K32 unsupported: comctl32 TaskDialog ";
        NtShzDebugPrint(prefix, sizeof prefix - 1);
        NtShzDebugPrint(reason, strlen(reason));
        NtShzDebugPrint("\n", 1);
    }
    SetLastError(ERROR_NOT_SUPPORTED);
    return E_NOTIMPL;
}

static int text_length(LPCWSTR text)
{
    int n;
    if (!text) return 0;
    if (IS_INTRESOURCE(text)) return -1;
    for (n = 0; n <= TD_TEXT_LIMIT && text[n]; ++n) {}
    return n > TD_TEXT_LIMIT ? -1 : n;
}

/* Measure with the same DrawText/font/wrapping used by real STATIC controls. */
static int text_height(LPCWSTR text, int width)
{
    RECT bounds = {0, 0, width, 0};
    HDC dc;
    int height;
    if (!text || !text[0]) return 0;
    dc = GetDC(0);
    if (!dc) return -1;
    height = DrawTextW(dc, text, -1, &bounds, DT_LEFT | DT_WORDBREAK | DT_NOPREFIX | DT_CALCRECT);
    ReleaseDC(0, dc);
    /* Existing DrawText caps its line list at 64. Reject the cap so content
     * cannot appear successful after the renderer discarded later lines. */
    return height > 0 && height < 64 * 16 ? height + 8 : -1;
}

static int line_width(LPCWSTR text)
{
    int column = 0, longest = 0;
    for (; text && *text; ++text) {
        if (*text == '\n') column = 0;
        else if (*text != '\r') ++column;
        if (column > longest) longest = column;
    }
    return longest * 8;
}

static HRESULT notify(td_state *s, HWND h, UINT message, WPARAM value)
{
    return s->cfg->pfCallback ? s->cfg->pfCallback(h, message, value, 0, s->cfg->lpCallbackData) : S_OK;
}

static void select_button(td_state *s, HWND h, int id)
{
    HRESULT result;
    if (s->ended || s->destroyed) return;
    result = notify(s, h, TDN_BUTTON_CLICKED, (WPARAM)(INT_PTR)id);
    /* A callback can reenter and select another button, or destroy the HWND. */
    if (result == S_FALSE || s->ended || s->destroyed) return;
    s->selected = id;
    s->ended = TRUE;
    EndDialog(h, id);
}

static HWND control(HWND parent, LPCWSTR cls, LPCWSTR text, DWORD style, int x, int y, int width, int height, int id)
{
    return CreateWindowExW(0, cls, text ? text : L"", WS_CHILD | WS_VISIBLE | style,
                           x, y, width, height, parent, (HMENU)(INT_PTR)id, 0, 0);
}

static void trace_text(LPCWSTR text)
{
    char bytes[3072];
    int n;
    WCHAR value[4];
    if (!text || GetEnvironmentVariableW(L"SHZ_K32TRACE", value, 4) != 1 || value[0] != '1') return;
    n = WideCharToMultiByte(CP_UTF8, 0, text, -1, bytes, sizeof bytes, 0, 0);
    if (n > 1) { NtShzDebugPrint("TaskDialog text: ", 17); NtShzDebugPrint(bytes, n - 1); NtShzDebugPrint("\n", 1); }
}

static INT_PTR CALLBACK dialog_proc(HWND h, UINT message, WPARAM wp, LPARAM lp)
{
    td_state *s = (td_state *)GetWindowLongPtrW(h, DWLP_USER);
    int i;
    if (message == WM_INITDIALOG) {
        int y = 16;
        s = (td_state *)lp;
        SetWindowLongPtrW(h, DWLP_USER, (LONG_PTR)s);
        if (s->icon) {
            HWND image = control(h, L"Static", L"", SS_ICON, 16, 16, 32, 32, -1);
            if (!image) goto failed;
            SendMessageW(image, STM_SETICON, (WPARAM)s->icon, 0);
        }
        if (s->instruction_height) {
            if (!control(h, L"Static", s->cfg->pszMainInstruction, SS_LEFT | SS_NOPREFIX,
                         s->text_x, y, s->text_width, s->instruction_height, -1)) goto failed;
            y += s->instruction_height + 4;
        }
        if (s->content_height && !control(h, L"Static", s->cfg->pszContent, SS_LEFT | SS_NOPREFIX,
                                         s->text_x, y, s->text_width, s->content_height, -1)) goto failed;
        for (i = 0; i < s->count; ++i) {
            td_button *b = &s->buttons[i];
            b->hwnd = control(h, L"Button", b->text, WS_TABSTOP | (i == 0 ? WS_GROUP : 0) |
                              (i == s->default_index ? BS_DEFPUSHBUTTON : BS_PUSHBUTTON),
                              b->x, b->y, b->width, 28, b->control);
            if (!b->hwnd) goto failed;
            if (b->note_height && !control(h, L"Static", b->note, SS_LEFT | SS_NOPREFIX,
                                           b->x + 8, b->y + 30, b->width - 8, b->note_height, -1)) goto failed;
        }
        if (s->cfg->pszVerificationText) {
            s->checkbox = control(h, L"Button", s->cfg->pszVerificationText, BS_AUTOCHECKBOX | WS_TABSTOP,
                                  16, s->height - 40, s->width - 32, 24, TD_VERIFY_ID);
            if (!s->checkbox) goto failed;
            SendMessageW(s->checkbox, BM_SETCHECK, s->verification ? BST_CHECKED : BST_UNCHECKED, 0);
            if (!s->verification_enabled) EnableWindow(s->checkbox, FALSE);
        }
        SendMessageW(h, DM_SETDEFID, s->buttons[s->default_index].control, 0);
        if ((s->cfg->dwFlags & TDF_POSITION_RELATIVE_TO_WINDOW) && s->cfg->hwndParent) {
            RECT parent, dlg;
            if (GetWindowRect(s->cfg->hwndParent, &parent) && GetWindowRect(h, &dlg))
                SetWindowPos(h, 0, parent.left + ((parent.right - parent.left) - (dlg.right - dlg.left)) / 2,
                             parent.top + ((parent.bottom - parent.top) - (dlg.bottom - dlg.top)) / 2,
                             0, 0, SWP_NOSIZE | SWP_NOZORDER | SWP_NOACTIVATE);
        }
        trace_text(s->cfg->pszWindowTitle); trace_text(s->cfg->pszMainInstruction); trace_text(s->cfg->pszContent);
        s->created = TRUE;
        notify(s, h, TDN_DIALOG_CONSTRUCTED, 0);
        if (!s->destroyed) notify(s, h, TDN_CREATED, 0);
        if (!s->ended && !s->destroyed) SetFocus(s->buttons[s->default_index].hwnd);
        return FALSE;
failed:
        s->error = HRESULT_FROM_WIN32(GetLastError() ? GetLastError() : ERROR_NOT_ENOUGH_MEMORY);
        EndDialog(h, 0);
        return FALSE;
    }
    if (!s) return FALSE;
    switch (message) {
    case WM_COMMAND:
        if (HIWORD(wp) != BN_CLICKED) return FALSE;
        if (LOWORD(wp) == TD_VERIFY_ID && s->checkbox) {
            s->verification = SendMessageW(s->checkbox, BM_GETCHECK, 0, 0) == BST_CHECKED;
            notify(s, h, TDN_VERIFICATION_CLICKED, s->verification);
            return TRUE;
        }
        for (i = 0; i < s->count; ++i)
            if (s->buttons[i].control == LOWORD(wp)) {
                if (IsWindowEnabled(s->buttons[i].hwnd)) select_button(s, h, s->buttons[i].id);
                return TRUE;
            }
        if (LOWORD(wp) == IDCANCEL) { if (s->allow_cancel) select_button(s, h, IDCANCEL); return TRUE; }
        return TRUE;
    case WM_CLOSE:
        if (s->allow_cancel) select_button(s, h, IDCANCEL);
        return TRUE;
    case TDM_CLICK_BUTTON:
        for (i = 0; i < s->count; ++i)
            if (s->buttons[i].id == (int)wp) { SendMessageW(s->buttons[i].hwnd, BM_CLICK, 0, 0); return TRUE; }
        if ((int)wp == IDCANCEL && s->allow_cancel) select_button(s, h, IDCANCEL);
        return TRUE;
    case TDM_ENABLE_BUTTON:
        for (i = 0; i < s->count; ++i)
            if (s->buttons[i].id == (int)wp) { EnableWindow(s->buttons[i].hwnd, (BOOL)lp); return TRUE; }
        return TRUE;
    case TDM_CLICK_VERIFICATION:
        if (s->checkbox && s->verification_enabled) {
            SendMessageW(s->checkbox, BM_SETCHECK, wp ? BST_CHECKED : BST_UNCHECKED, 0);
            s->verification = !!wp;
            if (lp) SetFocus(s->checkbox);
            notify(s, h, TDN_VERIFICATION_CLICKED, s->verification);
        }
        return TRUE;
    case WM_DESTROY:
        s->destroyed = TRUE;
        SetWindowLongPtrW(h, DWLP_USER, 0);
        if (s->created) notify(s, h, TDN_DESTROYED, 0);
        return TRUE;
    default:
        if (message >= WM_USER + 101 && message <= WM_USER + 116) {
            SetWindowLongPtrW(h, DWLP_MSGRESULT,
                              (LONG_PTR)unsupported("dynamic navigation/progress/text/radio/icon messages"));
            return TRUE;
        }
        return FALSE;
    }
}

static HRESULT prepare(td_state *s)
{
    static const struct { DWORD flag; int id; LPCWSTR text; } common[] = {
        {TDCBF_OK_BUTTON, IDOK, L"OK"}, {TDCBF_YES_BUTTON, IDYES, L"Yes"}, {TDCBF_NO_BUTTON, IDNO, L"No"},
        {TDCBF_CANCEL_BUTTON, IDCANCEL, L"Cancel"}, {TDCBF_RETRY_BUTTON, IDRETRY, L"Retry"}, {TDCBF_CLOSE_BUTTON, IDCLOSE, L"Close"}
    };
    const TASKDIALOGCONFIG *c = s->cfg;
    int i, k, y, button_width = 80, columns, rows, links, screen_w = GetSystemMetrics(SM_CXSCREEN), screen_h = GetSystemMetrics(SM_CYSCREEN);
    if ((c->dwFlags & ~TD_ALLOWED) || c->cRadioButtons || c->pszExpandedInformation || c->pszFooter)
        return unsupported("unsupported flags/radio/expanded/footer configuration");
    if ((c->dwCommonButtons & ~0x3f) || (c->cButtons && !c->pButtons)) return E_INVALIDARG;
    if (c->cButtons > TD_MAX_BUTTONS - 6) return unsupported("more than 26 custom buttons");
    if (text_length(c->pszWindowTitle) < 0 || text_length(c->pszMainInstruction) < 0 ||
        text_length(c->pszContent) < 0 || text_length(c->pszVerificationText) < 0)
        return unsupported("resource strings or text beyond 1023 UTF-16 units");
    if (c->hwndParent && !IsWindow(c->hwndParent)) return E_INVALIDARG;
    if (c->dwFlags & TDF_USE_HICON_MAIN) s->icon = c->hMainIcon;
    else if (c->pszMainIcon) {
        LPCWSTR resource;
        if (c->pszMainIcon == TD_WARNING_ICON) resource = MAKEINTRESOURCEW(32515);
        else if (c->pszMainIcon == TD_ERROR_ICON) resource = MAKEINTRESOURCEW(32513);
        else if (c->pszMainIcon == TD_INFORMATION_ICON) resource = MAKEINTRESOURCEW(32516);
        else return unsupported("custom resource/shield icon");
        s->icon = LoadIconW(0, resource);
        if (!s->icon) return E_FAIL;
    }
    for (i = 0; i < (int)c->cButtons; ++i) {
        td_button *b = &s->buttons[s->count++];
        if (c->pButtons[i].nButtonID <= 0 || !c->pButtons[i].pszButtonText) return E_INVALIDARG;
        if (text_length(c->pButtons[i].pszButtonText) < 0) return unsupported("resource or oversized button text");
        b->id = c->pButtons[i].nButtonID; b->control = TD_CUSTOM_ID + i; b->custom = 1; b->text = c->pButtons[i].pszButtonText;
    }
    for (i = 0; i < 6; ++i) if (c->dwCommonButtons & common[i].flag) {
        td_button *b = &s->buttons[s->count++];
        b->id = b->control = common[i].id; b->text = common[i].text;
    }
    if (!s->count) { s->count = 1; s->buttons[0].id = s->buttons[0].control = IDOK; s->buttons[0].text = L"OK"; }
    for (i = 0; i < s->count; ++i) {
        if (s->buttons[i].id == c->nDefaultButton) s->default_index = i;
        if (s->buttons[i].id == IDCANCEL) s->allow_cancel = 1;
        for (k = 0; k < i; ++k) if (s->buttons[k].id == s->buttons[i].id) return E_INVALIDARG;
    }
    if (c->dwFlags & TDF_ALLOW_DIALOG_CANCELLATION) s->allow_cancel = 1;
    if (screen_w < 320 || screen_h < 240) return unsupported("display too small or absent");
    if (c->cxWidth > 32767) return E_INVALIDARG;
    s->width = c->cxWidth ? (int)c->cxWidth * 2 : (screen_w > 600 ? 520 : screen_w - 80);
    if (!c->cxWidth && (c->dwFlags & TDF_SIZE_TO_CONTENT)) {
        int widest = line_width(c->pszMainInstruction), n = line_width(c->pszContent);
        if (n > widest) widest = n;
        n = line_width(c->pszVerificationText); if (n > widest) widest = n;
        s->width = widest + (s->icon ? 80 : 32);
        if (s->width < 320) s->width = 320;
        if (s->width > 720) s->width = 720;
        if (s->width > screen_w - 80) s->width = screen_w - 80;
    }
    if (s->width < 240 || s->width > screen_w - 40) return unsupported("dialog width exceeds display bounds");
    /* The existing checkbox renderer draws one line in width - 17 and reads
     * at most 255 characters. Do not report a visible verification label when
     * that renderer would clip or truncate part of it. */
    if (c->pszVerificationText) {
        for (i = 0; c->pszVerificationText[i]; ++i)
            if (c->pszVerificationText[i] == '\n' || c->pszVerificationText[i] == '\r')
                return unsupported("multiline verification label");
        if (i > 255 || i * 8 > s->width - 49) return unsupported("verification label exceeds checkbox bounds");
    }
    s->text_x = s->icon ? 64 : 16; s->text_width = s->width - s->text_x - 16;
    s->instruction_height = text_height(c->pszMainInstruction, s->text_width);
    s->content_height = text_height(c->pszContent, s->text_width);
    if (s->instruction_height < 0 || s->content_height < 0) return E_FAIL;
    y = 16 + s->instruction_height + (s->instruction_height ? 4 : 0) + s->content_height;
    if (s->icon && y < 56) y = 56;
    y += 16; s->buttons_y = y;
    links = c->dwFlags & (TDF_USE_COMMAND_LINKS | TDF_USE_COMMAND_LINKS_NO_ICON);
    for (i = 0; i < s->count; ++i) {
        td_button *b = &s->buttons[i];
        int n = 0;
        while (b->text[n] && b->text[n] != '\n') ++n;
        if (b->text[n]) {
            if (!links || !b->custom) return unsupported("multiline push-button label");
            b->owned_title = HeapAlloc(GetProcessHeap(), 0, (n + 1) * sizeof(WCHAR));
            if (!b->owned_title) return E_OUTOFMEMORY;
            memcpy(b->owned_title, b->text, n * sizeof(WCHAR)); b->owned_title[n] = 0;
            b->note = b->text + n + 1; b->text = b->owned_title;
        }
        if (n * 8 + 24 > s->width - 32) return unsupported("button title exceeds display width");
        if (n * 8 + 24 > button_width) button_width = n * 8 + 24;
        if (links && b->custom) {
            b->x = 16; b->y = y; b->width = s->width - 32;
            b->note_height = text_height(b->note, b->width - 8); y += 36 + b->note_height;
            if (b->note_height < 0) return E_FAIL;
        }
    }
    k = 0; for (i = 0; i < s->count; ++i) if (!links || !s->buttons[i].custom) ++k;
    columns = (s->width - 32 + 8) / (button_width + 8); if (columns < 1) columns = 1;
    rows = (k + columns - 1) / columns; k = 0;
    for (i = 0; i < s->count; ++i) if (!links || !s->buttons[i].custom) {
        td_button *b = &s->buttons[i];
        b->x = 16 + k % columns * (button_width + 8); b->y = y + k / columns * 36; b->width = button_width; ++k;
    }
    s->height = y + rows * 36 + (c->pszVerificationText ? 40 : 16);
    if (s->height > screen_h - 80) return unsupported("dialog content exceeds display height");
    return S_OK;
}

DLLAPI HRESULT WINAPI TaskDialogIndirect(const TASKDIALOGCONFIG *cfg, int *button, int *radio, BOOL *verification)
{
    td_state state;
    WORD template[1040] __attribute__((aligned(4)));
    DLGTEMPLATE *dlg = (DLGTEMPLATE *)template;
    WCHAR module[MAX_PATH], *title;
    WORD *p;
    INT_PTR result;
    HRESULT status;
    int i;
    if (button) *button = 0;
    if (radio) *radio = 0;
    if (verification) *verification = FALSE;
    if (!cfg || cfg->cbSize != sizeof *cfg) return E_INVALIDARG;
    memset(&state, 0, sizeof state); state.cfg = cfg; state.verification_enabled = verification != 0;
    state.verification = cfg->pszVerificationText && !!(cfg->dwFlags & TDF_VERIFICATION_FLAG_CHECKED); state.error = S_OK;
    status = prepare(&state);
    if (FAILED(status)) goto done;
    memset(template, 0, sizeof template);
    dlg->style = WS_POPUP | WS_CAPTION | DS_MODALFRAME | DS_CENTER | (state.allow_cancel ? WS_SYSMENU : 0);
    dlg->cx = (short)((state.width + 1) / 2); dlg->cy = (short)((state.height + 1) / 2);
    p = (WORD *)((char *)dlg + sizeof *dlg); *p++ = 0; *p++ = 0;
    title = (WCHAR *)cfg->pszWindowTitle;
    if (!title) {
        DWORD n = GetModuleFileNameW(0, module, MAX_PATH);
        module[n < MAX_PATH ? n : MAX_PATH - 1] = 0; title = module;
        for (i = 0; module[i]; ++i) if (module[i] == '\\' || module[i] == '/') title = module + i + 1;
    }
    while (*title) *p++ = *title++;
    *p = 0;
    result = DialogBoxIndirectParamW(cfg->hInstance, dlg, cfg->hwndParent, dialog_proc, (LPARAM)&state);
    if (FAILED(state.error)) status = state.error;
    else if (result == -1 || !state.ended) status = E_FAIL;
    else {
        if (button) *button = state.selected;
        if (verification) *verification = state.verification;
        status = S_OK;
    }
done:
    for (i = 0; i < state.count; ++i) if (state.buttons[i].owned_title) HeapFree(GetProcessHeap(), 0, state.buttons[i].owned_title);
    return status;
}

DLLAPI HRESULT WINAPI TaskDialog(HWND parent, HINSTANCE instance, PCWSTR title, PCWSTR instruction, PCWSTR content,
                                 TASKDIALOG_COMMON_BUTTON_FLAGS buttons, PCWSTR icon, int *selected)
{
    TASKDIALOGCONFIG cfg;
    memset(&cfg, 0, sizeof cfg);
    cfg.cbSize = sizeof cfg; cfg.hwndParent = parent; cfg.hInstance = instance;
    cfg.pszWindowTitle = title; cfg.pszMainInstruction = instruction; cfg.pszContent = content;
    cfg.dwCommonButtons = buttons; cfg.pszMainIcon = icon;
    return TaskDialogIndirect(&cfg, selected, 0, 0);
}
