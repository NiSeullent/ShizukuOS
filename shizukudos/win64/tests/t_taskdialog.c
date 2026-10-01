/* SPDX-License-Identifier: GPL-2.0-only
 * Real modal HWND/control/message tests. Callbacks post user-like clicks only
 * in this fixture; the runtime never accepts application dialogs itself. */
#include "k32test.h"
#include <commctrl.h>

typedef HRESULT (WINAPI *indirect_fn)(const TASKDIALOGCONFIG *, int *, int *, BOOL *);
typedef HRESULT (WINAPI *simple_fn)(HWND, HINSTANCE, PCWSTR, PCWSTR, PCWSTR, TASKDIALOG_COMMON_BUTTON_FLAGS, PCWSTR, int *);
typedef struct {
    int mode, constructed, created, destroyed, clicks, verification_notifications, instruction, content, note;
    HWND owner, dialog, checkbox;
} fixture;

static BOOL CALLBACK inspect_child(HWND child, LPARAM parameter)
{
    fixture *f = (fixture *)parameter;
    WCHAR text[1024], cls[32];
    GetWindowTextW(child, text, 1024); GetClassNameW(child, cls, 32);
    if (k32t_weq(cls, L"Static")) {
        if (k32t_weq(text, L"Main instruction")) ++f->instruction;
        if (k32t_weq(text, L"Actual content")) ++f->content;
        if (k32t_weq(text, L"First note")) ++f->note;
    }
    if (k32t_weq(cls, L"Button") && k32t_weq(text, L"Remember")) f->checkbox = child;
    return TRUE;
}

static HRESULT CALLBACK notification(HWND dialog, UINT message, WPARAM value, LPARAM ignored, LONG_PTR parameter)
{
    fixture *f = (fixture *)parameter;
    (void)ignored;
    if (message == TDN_DIALOG_CONSTRUCTED) ++f->constructed;
    if (message == TDN_CREATED) {
        WCHAR cls[32], text[128];
        LRESULT default_id = SendMessageW(dialog, DM_GETDEFID, 0, 0);
        ++f->created; f->dialog = dialog;
        CHECK(IsWindow(dialog) && GetClassNameW(dialog, cls, 32) && k32t_weq(cls, L"#32770"), "created callback receives actual dialog HWND");
        CHECK(f->constructed == 1, "dialog constructed notification precedes creation notification");
        EnumChildWindows(dialog, inspect_child, (LPARAM)f);
        if (f->mode == 1) {
            HWND button = GetDlgItem(dialog, LOWORD(default_id));
            CHECK(HIWORD(default_id) == DC_HASDEFID && button && GetWindowTextW(button, text, 128) && k32t_weq(text, L"Second"),
                  "application default ID selects corresponding real button control");
            CHECK(f->instruction == 1 && f->content == 1 && f->note == 1, "instruction/content/command-link note exist in real STATIC controls");
            CHECK(f->checkbox && IsWindowEnabled(f->checkbox) && SendMessageW(f->checkbox, BM_GETCHECK, 0, 0) == BST_CHECKED,
                  "verification control starts checked and enabled");
            PostMessageW(dialog, TDM_CLICK_VERIFICATION, FALSE, FALSE);
            PostMessageW(dialog, TDM_CLICK_BUTTON, 100, 0);
        } else if (f->mode == 2) {
            CHECK(GetDlgItem(dialog, IDOK) != NULL, "no explicit buttons creates a real default OK button");
            PostMessageW(dialog, WM_CLOSE, 0, 0);
        } else if (f->mode == 3) {
            PostMessageW(dialog, WM_CLOSE, 0, 0);             /* cancellation denied: remains modal */
            PostMessageW(dialog, TDM_CLICK_BUTTON, 42, 0);
        } else if (f->mode == 4) {
            SendMessageW(dialog, TDM_CLICK_BUTTON, 42, 0);    /* legitimate synchronous callback reentry */
        } else if (f->mode == 5) {
            CHECK(f->checkbox && !IsWindowEnabled(f->checkbox), "NULL verification output disables its checkbox");
            PostMessageW(dialog, TDM_CLICK_VERIFICATION, FALSE, FALSE);
            PostMessageW(dialog, TDM_CLICK_BUTTON, 42, 0);
        } else if (f->mode == 6) {
            PostMessageW(dialog, TDM_CLICK_BUTTON, 42, 0);
        } else if (f->mode == 7) {
            CHECK(!f->checkbox, "verification flag without label creates no checkbox");
            CHECK(SendMessageW(dialog, TDM_SET_ELEMENT_TEXT, 0, 0) == E_NOTIMPL,
                  "unsupported dynamic text message reports failure through real dialog result");
            PostMessageW(dialog, TDM_CLICK_BUTTON, 42, 0);
        }
    } else if (message == TDN_BUTTON_CLICKED) {
        ++f->clicks;
        if (f->mode == 1) {
            CHECK(!IsWindowEnabled(f->owner), "owner is disabled while modal input runs");
            if ((int)value == 100) {
                CHECK(IsWindow(dialog), "first real button click reaches callback on live dialog");
                PostMessageW(dialog, TDM_CLICK_BUTTON, 70000, 0);
                return S_FALSE;
            }
            CHECK((int)value == 70000 && f->clicks == 2, "S_FALSE retains dialog and second custom ID is not truncated to WORD");
        } else if (f->mode == 2) {
            CHECK((int)value == IDCANCEL, "WM_CLOSE reports IDCANCEL even without an explicit Cancel button");
        } else if (f->mode == 6) {
            if ((int)value == 42) {
                CHECK(f->clicks == 1, "outer button callback starts synchronous nested selection");
                SendMessageW(dialog, TDM_CLICK_BUTTON, 70000, 0);
            } else {
                CHECK((int)value == 70000 && f->clicks == 2, "inner button callback reports the actual nested custom ID");
            }
        } else {
            CHECK((int)value == 42 && f->clicks == 1, "supported custom button reports its application ID");
            if (f->mode == 5) CHECK(SendMessageW(f->checkbox, BM_GETCHECK, 0, 0) == BST_CHECKED,
                                     "disabled verification ignores programmatic toggle");
        }
    } else if (message == TDN_VERIFICATION_CLICKED) {
        ++f->verification_notifications;
        CHECK(value == FALSE, "verification click callback reports changed checkbox state");
    } else if (message == TDN_DESTROYED) {
        ++f->destroyed;
    }
    return S_OK;
}

static DWORD WINAPI close_simple(LPVOID ignored)
{
    unsigned i;
    (void)ignored;
    for (i = 0; i < 500; ++i) {
        HWND dialog = FindWindowW(L"#32770", L"TaskDialog simple fixture");
        if (dialog) return PostMessageW(dialog, TDM_CLICK_BUTTON, IDCANCEL, 0) ? 0 : 2;
        Sleep(10);
    }
    return 1;
}

int main(void)
{
    HMODULE module = LoadLibraryW(L"comctl32.dll");
    indirect_fn indirect;
    simple_fn simple;
    TASKDIALOGCONFIG cfg;
    TASKDIALOG_BUTTON buttons[] = {{100, L"First\nFirst note"}, {70000, L"Second"}};
    TASKDIALOG_BUTTON nested[] = {{42, L"Actual action"}, {70000, L"Nested action"}};
    TASKDIALOG_BUTTON custom = {42, L"Actual action"};
    fixture f;
    WNDCLASSW wc;
    HWND owner;
    int selected = 999, radio = 999, mode;
    BOOL verified = TRUE;
    HANDLE worker;
    DWORD code, waited;
    CHECK(module != NULL, "comctl32 real DLL loads");
    if (!module) return 1;
    indirect = (indirect_fn)GetProcAddress(module, MAKEINTRESOURCEA(345));
    simple = (simple_fn)GetProcAddress(module, MAKEINTRESOURCEA(344));
    CHECK(indirect && (FARPROC)indirect == GetProcAddress(module, "TaskDialogIndirect"), "ordinal 345 resolves real indirect dialog");
    CHECK(simple && (FARPROC)simple == GetProcAddress(module, "TaskDialog"), "ordinal 344 resolves real simple dialog");
    if (!indirect || !simple) return 1;
    CHECK(indirect(NULL, &selected, &radio, &verified) == E_INVALIDARG && !selected && !radio && !verified,
          "invalid config returns failure and zeroed outputs");
    memset(&cfg, 0, sizeof cfg); cfg.cbSize = sizeof cfg;
    cfg.dwFlags = TDF_SHOW_PROGRESS_BAR;
    CHECK(indirect(&cfg, &selected, NULL, NULL) == E_NOTIMPL && !selected, "unsupported progress dialog fails explicitly");
    cfg.dwFlags = 0; cfg.pszContent = MAKEINTRESOURCEW(123);
    CHECK(indirect(&cfg, &selected, NULL, NULL) == E_NOTIMPL, "unsupported resource string fails explicitly");
    cfg.pszContent = NULL; cfg.cButtons = 1;
    CHECK(indirect(&cfg, &selected, NULL, NULL) == E_INVALIDARG, "nonzero button count requires array");
    cfg.cButtons = 0; cfg.pszVerificationText = L"Two\nlines";
    CHECK(indirect(&cfg, &selected, NULL, NULL) == E_NOTIMPL, "multiline checkbox label fails instead of clipping visible text");

    memset(&wc, 0, sizeof wc); wc.lpfnWndProc = DefWindowProcW;
    wc.hInstance = GetModuleHandleW(NULL); wc.lpszClassName = L"TaskDialog fixture owner";
    CHECK(RegisterClassW(&wc) != 0, "register real owner window class");
    owner = CreateWindowExW(0, wc.lpszClassName, L"Owner", WS_OVERLAPPEDWINDOW | WS_VISIBLE,
                           10, 10, 320, 160, NULL, NULL, wc.hInstance, NULL);
    CHECK(owner != NULL, "create real owner window");
    if (!owner) return 1;
    for (mode = 1; mode <= 7; ++mode) {
        HRESULT result;
        memset(&f, 0, sizeof f); f.mode = mode; f.owner = owner;
        memset(&cfg, 0, sizeof cfg); cfg.cbSize = sizeof cfg; cfg.hwndParent = owner;
        cfg.dwFlags = TDF_SIZE_TO_CONTENT | TDF_POSITION_RELATIVE_TO_WINDOW;
        cfg.pszWindowTitle = L"TaskDialog actual modal fixture";
        cfg.pszMainInstruction = L"Main instruction"; cfg.pszContent = L"Actual content";
        cfg.pfCallback = notification; cfg.lpCallbackData = (LONG_PTR)&f;
        cfg.cButtons = 1; cfg.pButtons = &custom;
        if (mode == 1) {
            cfg.dwFlags |= TDF_USE_COMMAND_LINKS | TDF_VERIFICATION_FLAG_CHECKED;
            cfg.cButtons = 2; cfg.pButtons = buttons; cfg.nDefaultButton = 70000;
            cfg.pszVerificationText = L"Remember";
        } else if (mode == 2) {
            cfg.dwFlags |= TDF_ALLOW_DIALOG_CANCELLATION; cfg.cButtons = 0; cfg.pButtons = NULL;
            cfg.pszMainIcon = TD_ERROR_ICON;
        } else if (mode == 5) {
            cfg.dwFlags |= TDF_VERIFICATION_FLAG_CHECKED; cfg.pszVerificationText = L"Remember";
        } else if (mode == 6) {
            cfg.cButtons = 2; cfg.pButtons = nested;
        } else if (mode == 7) {
            cfg.dwFlags |= TDF_VERIFICATION_FLAG_CHECKED;
        }
        selected = -1; radio = -1; verified = TRUE;
        result = indirect(&cfg, &selected, &radio, mode == 5 ? NULL : &verified);
        CHECK(result == S_OK && selected == ((mode == 1 || mode == 6) ? 70000 : mode == 2 ? IDCANCEL : 42) && radio == 0,
              "real modal dialog returns only the explicitly clicked application result");
        CHECK(f.created == 1 && f.destroyed == 1 && !IsWindow(f.dialog), "created dialog is destroyed exactly once after modal completion");
        CHECK(IsWindowEnabled(owner), "modal manager restores owner after completion");
        if (mode == 1) CHECK(!verified && f.verification_notifications == 1, "returned verification value matches actual control toggle");
        if (mode == 3) CHECK(f.clicks == 1, "disallowed WM_CLOSE does not accept or dismiss the dialog");
        if (mode == 5) CHECK(f.verification_notifications == 0, "disabled checkbox generates no change notification");
        if (mode == 6) CHECK(f.clicks == 2, "nested button callback completes once without outer result overriding inner selection");
        if (mode == 7) CHECK(!verified && !f.verification_notifications, "checked flag is ignored when verification text is absent");
    }
    worker = CreateThread(NULL, 0, close_simple, NULL, 0, NULL);
    CHECK(worker != NULL, "start independent user-like simple-dialog click worker");
    if (worker) {
        CHECK(simple(owner, NULL, L"TaskDialog simple fixture", L"Actual wrapper", L"Actual content", TDCBF_CANCEL_BUTTON,
                     NULL, &selected) == S_OK && selected == IDCANCEL, "ordinal 344 wrapper runs actual modal dialog and real Cancel button");
        waited = WaitForSingleObject(worker, 10000);
        CHECK(waited == WAIT_OBJECT_0 && GetExitCodeThread(worker, &code) && code == 0, "simple dialog was closed by the independent click worker");
        if (waited != WAIT_OBJECT_0) return 1;
        CloseHandle(worker);
    }
    DestroyWindow(owner); FreeLibrary(module);
    return k32t_finish("T_TASKDIALOG");
}
