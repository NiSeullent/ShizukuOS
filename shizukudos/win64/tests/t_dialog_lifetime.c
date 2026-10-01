/* SPDX-License-Identifier: GPL-2.0-only
 * Actual modal owner/show/paint reentry. Reusing the destroyed dialog's real
 * 32-byte state makes the former stale-pointer loop observable as an unwanted
 * dispatch, instead of relying on the contents of a freed heap block. */
#include "k32test.h"

#define PROBE_MESSAGE (WM_APP + 55)
#define REUSE_COUNT 2048
typedef struct {
    int mode, active, shown, painted, destroyed, unexpected_dispatch, queued_probe;
    HWND owner, dialog;
    void *information, *reuse[REUSE_COUNT];
    unsigned reuse_count;
    BOOL reused;
} fixture;
static fixture current;

static void destroy_and_reuse(HWND dialog)
{
    unsigned i;
    CHECK(IsWindow(dialog) && current.information != NULL, "reentry destroys the actual initialized dialog");
    CHECK(DestroyWindow(dialog), "application callback destroys actual modal HWND");
    CHECK(!IsWindow(dialog), "destroyed dialog is no longer a live window");
    for (i = 0; i < REUSE_COUNT; ++i) {
        void *p = HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, 32);
        if (!p) break;
        current.reuse[current.reuse_count++] = p;
        if (p == current.information) { current.reused = TRUE; break; }
    }
    CHECK(current.reused, "freed real dialog state is replaced by a zeroed live allocation");
    CHECK(PostMessageW(current.owner, PROBE_MESSAGE, 0, 0), "queue probe after synchronous HWND destruction");
}

static LRESULT CALLBACK owner_proc(HWND h, UINT msg, WPARAM wp, LPARAM lp)
{
    if (msg == WM_ENABLE && !wp && current.active && current.dialog) {
        if (current.mode == 1) destroy_and_reuse(current.dialog);
        else if (current.mode == 5) CHECK(EndDialog(current.dialog, 73), "owner-disable callback can end real modal dialog");
    }
    if (msg == PROBE_MESSAGE) {
        if (current.active) ++current.unexpected_dispatch;
        else ++current.queued_probe;
        return 0;
    }
    return DefWindowProcW(h, msg, wp, lp);
}

static INT_PTR CALLBACK dialog_proc(HWND h, UINT msg, WPARAM wp, LPARAM lp)
{
    (void)wp; (void)lp;
    if (msg == WM_INITDIALOG) {
        current.dialog = h;
        current.information = GetPropW(h, L"ShzDlgInfo");
        CHECK(current.information != NULL, "modal manager owns real state before initialization notification");
        if (current.mode == 4) {
            CHECK(DestroyWindow(h), "initialization callback can destroy dialog");
        } else if (current.mode == 0) {
            CHECK(PostMessageW(h, WM_COMMAND, IDOK, 0), "queue explicit completion for ordinary modal dialog");
        }
        return FALSE;
    }
    if (msg == WM_COMMAND) {
        CHECK(EndDialog(h, 73), "ordinary modal command ends dialog with explicit result");
        return TRUE;
    }
    if (msg == WM_DESTROY) ++current.destroyed;
    return FALSE;
}

/* A real dialog class with a forwarding window procedure lets application
 * show/paint callbacks run before DefDlgProc dispatches the dialog procedure. */
static LRESULT CALLBACK dialog_window_proc(HWND h, UINT msg, WPARAM wp, LPARAM lp)
{
    if (msg == WM_SHOWWINDOW && wp) {
        ++current.shown;
        if (current.mode == 2 && current.active) { destroy_and_reuse(h); return 0; }
    }
    if (msg == WM_PAINT) {
        ++current.painted;
        if (current.mode == 3 && current.active) { destroy_and_reuse(h); return 0; }
    }
    return DefDlgProcW(h, msg, wp, lp);
}

static LPCDLGTEMPLATEW make_template(WORD *buffer)
{
    DLGTEMPLATE *tpl = (DLGTEMPLATE *)buffer;
    WORD *p;
    const WCHAR *text;
    memset(buffer, 0, 256 * sizeof(WORD));
    tpl->style = WS_POPUP | WS_CAPTION | DS_MODALFRAME;
    tpl->cx = 160; tpl->cy = 80;
    p = (WORD *)((BYTE *)tpl + sizeof *tpl);
    *p++ = 0;                            /* no menu */
    for (text = L"Dialog lifetime actual fixture"; *text; ++text) *p++ = *text;
    *p++ = 0;                           /* custom class */
    for (text = L"Modal lifetime"; *text; ++text) *p++ = *text;
    *p = 0;
    return tpl;
}

int main(void)
{
    WNDCLASSW wc;
    WORD buffer[256] __attribute__((aligned(4)));
    HWND owner;
    int mode;
    memset(&wc, 0, sizeof wc);
    wc.lpfnWndProc = owner_proc; wc.hInstance = GetModuleHandleW(NULL);
    wc.lpszClassName = L"Dialog lifetime owner";
    CHECK(RegisterClassW(&wc) != 0, "register actual modal owner class");
    wc.lpfnWndProc = dialog_window_proc; wc.cbWndExtra = DLGWINDOWEXTRA;
    wc.lpszClassName = L"Dialog lifetime actual fixture";
    CHECK(RegisterClassW(&wc) != 0, "register actual dialog class for show/paint reentry");
    owner = CreateWindowExW(0, L"Dialog lifetime owner", L"Lifetime owner", WS_OVERLAPPEDWINDOW | WS_VISIBLE,
                           10, 10, 320, 160, NULL, NULL, wc.hInstance, NULL);
    CHECK(owner != NULL, "create live modal owner");
    if (!owner) return 1;
    for (mode = 0; mode <= 5; ++mode) {
        INT_PTR result;
        MSG message;
        unsigned i;
        memset(&current, 0, sizeof current);
        current.mode = mode; current.owner = owner; current.active = 1;
        result = DialogBoxIndirectParamW(wc.hInstance, make_template(buffer), owner, dialog_proc, 0);
        current.active = 0;
        CHECK(result == ((mode == 0 || mode == 5) ? 73 : -1), "destroyed modal fails while legitimate EndDialog preserves result");
        CHECK(current.destroyed == 1 && !IsWindow(current.dialog), "modal HWND is destroyed exactly once");
        CHECK(IsWindowEnabled(owner), "owner is re-enabled after callback completion or destruction");
        CHECK(current.unexpected_dispatch == 0, "modal loop does not dispatch queued work after synchronous destruction");
        if (mode == 1 || mode == 5) CHECK(current.shown == 0, "owner callback completion prevents showing ended or destroyed dialog");
        if (mode == 2) CHECK(current.shown == 1 && current.painted == 0, "show destruction prevents later paint");
        if (mode == 3) CHECK(current.shown == 1 && current.painted == 1, "paint callback runs on actual shown dialog before destruction");
        while (PeekMessageW(&message, NULL, 0, 0, PM_REMOVE)) { TranslateMessage(&message); DispatchMessageW(&message); }
        if (mode >= 1 && mode <= 3) CHECK(current.queued_probe == 1, "work remains queued until caller resumes after modal failure");
        for (i = 0; i < current.reuse_count; ++i) HeapFree(GetProcessHeap(), 0, current.reuse[i]);
    }
    DestroyWindow(owner);
    return k32t_finish("T_DIALOG_LIFETIME");
}
