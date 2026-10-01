/* SPDX-License-Identifier: GPL-2.0-only
 * Actual in-guest installer window. Disk writing stays in the portable SHZSETUP
 * core; this frontend only selects, confirms and reports its real results. */
#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include "interactive_ui.h"
#include "interactive_choice.h"
#include "shzcrt.h"

#define UI_DISKS 32
static HWND window;
static HINSTANCE instance;
static const plat_t *platform;
static unsigned choices[UI_DISKS], count, selected, top;
static plat_disk_t reviewed;
static char confirmation[6], last_line[280];
static char progress_line[280];
static size_t progress_used;
static unsigned confirmation_len;
static char *answer_out;
static size_t answer_capacity;
static int stage, approved, done, failed, reserve_win98, installed, power;
/* 0 selection, 1 review, 2 installing, 3 result. */

static void text(HDC dc, int x, int y, const WCHAR *value)
{ int n = 0; while (value[n]) ++n; TextOutW(dc, x, y, value, n); }

static void narrow_text(HDC dc, int x, int y, const char *value)
{
    WCHAR w[300];
    unsigned i;
    for (i = 0; value[i] && i + 1 < sizeof w / sizeof w[0]; ++i) w[i] = (unsigned char)value[i];
    w[i] = 0; text(dc, x, y, w);
}

static void repaint(void)
{ if (window) { InvalidateRect(window, 0, TRUE); UpdateWindow(window); } }

static unsigned visible_rows(HWND hwnd)
{
    RECT rc;
    unsigned rows;
    GetClientRect(hwnd, &rc);
    rows = rc.bottom > 250 ? (unsigned)(rc.bottom - 250) / 25 : 1;
    return rows ? rows : 1;
}

static void paint(HWND hwnd)
{
    PAINTSTRUCT ps;
    RECT rc;
    HDC dc = BeginPaint(hwnd, &ps);
    HBRUSH background = CreateSolidBrush(RGB(244, 246, 251));
    unsigned i, visible;
    char line[220];
    GetClientRect(hwnd, &rc); FillRect(dc, &rc, background); DeleteObject(background);
    visible = visible_rows(hwnd);
    if (selected < top) top = selected;
    if (selected >= top + visible) top = selected - visible + 1;
    SetBkMode(dc, TRANSPARENT); SetTextColor(dc, RGB(24, 34, 56));
    text(dc, 28, 24, L"ShizukuOS Setup");
    text(dc, 28, 52, L"Install with the built-in Shizuku installer");
    if (stage == 0) {
        text(dc, 28, 88, L"Choose a disk. Nothing is changed until you confirm.");
        if (!count) text(dc, 28, 128, L"No writable disk: need 256 MiB and 512-byte sectors.");
        for (i = top; i < count && i < top + visible; ++i) {
            plat_disk_t d;
            platform->disk_info(platform->ctx, choices[i], &d);
            snprintf(line, sizeof line, "%c %s   %llu MiB%s", i == selected ? '>' : ' ', d.name,
                     (unsigned long long)(d.sectors / 2048), d.flags & PLAT_DISK_REMOVABLE ? "   removable" : "");
            narrow_text(dc, 34, 126 + (int)(i - top) * 25, line);
        }
        text(dc, 28, rc.bottom - 64, L"Up/Down or click: select    Enter: review    Esc: cancel");
        text(dc, 28, rc.bottom - 36, L"Confirming installation deletes every file on that disk.");
    } else if (stage == 1) {
        snprintf(line, sizeof line, "Target: %s   %llu MiB", reviewed.name,
                 (unsigned long long)(reviewed.sectors / 2048));
        narrow_text(dc, 28, 100, line);
        text(dc, 28, 144, L"Installation deletes ALL partitions and files on this target.");
        text(dc, 28, 176, L"Other disks are not selected. Esc returns without installing.");
        text(dc, 28, 220, reserve_win98 ? L"Windows 98 data partition: 512 MiB (F2 to change)" :
                                                      L"Windows 98 data partition: none (F2 to change)");
        text(dc, 28, 252, L"Your own Windows 98 files are separate; they are not bundled.");
        text(dc, 28, 302, L"Type ERASE, then press Enter to install:");
        narrow_text(dc, 28, 344, confirmation);
    } else if (stage == 2) {
        text(dc, 28, 112, L"Installing and checking the written system...");
        text(dc, 28, 152, L"Keep the machine on until verification finishes.");
        narrow_text(dc, 28, 216, last_line);
    } else {
        text(dc, 28, 112, installed ? L"Installation and file verification finished." : L"Installation failed.");
        narrow_text(dc, 28, 168, last_line);
        text(dc, 28, 236, installed ? L"Remove the installation medium before starting the installed disk." :
                                              L"The failure is recorded in the console. Review the target before retrying.");
        text(dc, 28, 310, L"R: restart    S: shut down    Esc: close");
    }
    EndPaint(hwnd, &ps);
}

static void review(void)
{
    if (!count || setup_review_target(platform, choices[selected], &reviewed)) return;
    reserve_win98 = reviewed.sectors >= 768ull * 2048;
    confirmation[0] = 0; confirmation_len = 0; stage = 1;
    printf("SHZ-SETUP UI review target=%s sectors=%llu\n", reviewed.name, (unsigned long long)reviewed.sectors);
    repaint();
}

static LRESULT CALLBACK procedure(HWND hwnd, UINT msg, WPARAM wp, LPARAM lp)
{
    if (msg == WM_PAINT) { paint(hwnd); return 0; }
    if (msg == WM_GETMINMAXINFO) {
        MINMAXINFO *limits = (MINMAXINFO *)(uintptr_t)lp;
        limits->ptMinTrackSize.x = 600; limits->ptMinTrackSize.y = 440;
        return 0;
    }
    if (msg == WM_SIZING) {
        RECT *bounds = (RECT *)(uintptr_t)lp;
        if (bounds->right - bounds->left < 600) {
            if (wp == WMSZ_LEFT || wp == WMSZ_TOPLEFT || wp == WMSZ_BOTTOMLEFT)
                bounds->left = bounds->right - 600;
            else bounds->right = bounds->left + 600;
        }
        if (bounds->bottom - bounds->top < 440) {
            if (wp == WMSZ_TOP || wp == WMSZ_TOPLEFT || wp == WMSZ_TOPRIGHT)
                bounds->top = bounds->bottom - 440;
            else bounds->bottom = bounds->top + 440;
        }
        return TRUE;
    }
    if (msg == WM_CLOSE) {
        if (stage != 2) done = 1;
        return 0;
    }
    if (msg == WM_KEYDOWN) {
        if (wp == VK_ESCAPE && stage != 2) {
            if (stage == 1) { stage = 0; confirmation_len = 0; confirmation[0] = 0; repaint(); }
            else done = 1;
        } else if (stage == 0 && count) {
            if (wp == VK_UP) { if (selected) --selected; repaint(); }
            else if (wp == VK_DOWN) { if (selected + 1 < count) ++selected; repaint(); }
            else if (wp == VK_RETURN) review();
        } else if (stage == 1 && wp == VK_RETURN) {
            plat_disk_t current;
            if (!setup_review_target(platform, choices[selected], &current) &&
                !memcmp(&current, &reviewed, sizeof current) &&
                !setup_build_interactive_answer(&current, confirmation, reserve_win98, answer_out, answer_capacity)) {
                approved = 1; stage = 2;
                printf("SHZ-SETUP UI confirmed target=%s\n", current.name);
                repaint();
            }
        } else if (stage == 1 && wp == VK_F2 && confirmation_len == 0) {
            if (reviewed.sectors >= 768ull * 2048) reserve_win98 = !reserve_win98;
            repaint();
        } else if (stage == 3) {
            if (wp == 'R') { power = SETUP_POWER_REBOOT; done = 1; }
            else if (wp == 'S') { power = SETUP_POWER_SHUTDOWN; done = 1; }
        }
        return 0;
    }
    if (msg == WM_CHAR && stage == 1) {
        if (wp == '\b') { if (confirmation_len) confirmation[--confirmation_len] = 0; }
        else if (((wp >= 'A' && wp <= 'Z') || (wp >= 'a' && wp <= 'z')) && confirmation_len < 5) {
            if (wp >= 'a' && wp <= 'z') wp -= 'a' - 'A';
            confirmation[confirmation_len++] = (char)wp; confirmation[confirmation_len] = 0;
        }
        repaint(); return 0;
    }
    if (msg == WM_LBUTTONDOWN && stage == 0) {
        int y = (short)((lp >> 16) & 0xffff);
        int x = (short)(lp & 0xffff);
        RECT rc;
        GetClientRect(hwnd, &rc);
        if (x >= 28 && x < rc.right - 28 && y >= 120 && y < 120 + (int)visible_rows(hwnd) * 25) {
            unsigned row = top + (unsigned)(y - 120) / 25;
            if (row < count) { selected = row; repaint(); }
        }
        return 0;
    }
    return DefWindowProcW(hwnd, msg, wp, lp);
}

static int messages(int selection)
{
    MSG msg;
    int rc;
    while (!done && !(selection && approved)) {
        rc = GetMessageW(&msg, 0, 0, 0);
        if (rc <= 0) { if (rc < 0) failed = 1; done = 1; break; }
        TranslateMessage(&msg); DispatchMessageW(&msg);
    }
    return failed ? -1 : approved ? 0 : 1;
}

static void close_ui(void)
{
    if (window) DestroyWindow(window);
    window = 0; UnregisterClassW(L"ShizukuSetupWindow", instance);
}

int setup_ui_choose(const plat_t *p, char *answer, size_t capacity)
{
    WNDCLASSEXW wc;
    unsigned i;
    int rc, width = GetSystemMetrics(SM_CXSCREEN), height = GetSystemMetrics(SM_CYSCREEN);
    if (!p || !answer || width < 640 || height < 480) return -1;
    platform = p; answer_out = answer; answer_capacity = capacity;
    count = selected = top = confirmation_len = 0; stage = approved = done = failed = installed = power = reserve_win98 = 0;
    progress_used = 0; progress_line[0] = last_line[0] = 0;
    for (i = 0; i < p->disk_count(p->ctx) && count < UI_DISKS; ++i) {
        plat_disk_t target;
        if (!setup_review_target(p, i, &target)) choices[count++] = i;
    }
    instance = GetModuleHandleW(0);
    memset(&wc, 0, sizeof wc); wc.cbSize = sizeof wc; wc.lpfnWndProc = procedure;
    wc.hInstance = instance; wc.lpszClassName = L"ShizukuSetupWindow";
    if (!RegisterClassExW(&wc)) return -1;
    { int w = width < 792 ? width - 32 : 760, h = height < 612 ? height - 32 : 580;
      window = CreateWindowExW(0, wc.lpszClassName, L"ShizukuOS Setup", WS_OVERLAPPEDWINDOW | WS_VISIBLE,
                               (width - w) / 2, (height - h) / 2, w, h, 0, 0, instance, 0); }
    if (!window) { close_ui(); return -1; }
    SetForegroundWindow(window); SetFocus(window); repaint();
    printf("SHZ-SETUP UI ready candidates=%u writes=0\n", count);
    rc = messages(1);
    if (rc) close_ui();
    return rc;
}

void setup_ui_progress(const char *value)
{
    size_t i, j;
    if (!window || !value) return;
    /* The portable writer emits each line in several out() calls. Keep the
     * actual assembled line visible when the final call is just a newline. */
    for (i = 0; value[i]; ++i) {
        if (value[i] == '\r') continue;
        if (value[i] == '\n') {
            progress_used = 0;
            continue;
        }
        if (progress_used + 1 < sizeof progress_line) progress_line[progress_used++] = value[i];
        progress_line[progress_used] = 0;
        for (j = 0; j <= progress_used; ++j) last_line[j] = progress_line[j];
    }
    repaint();
}

void setup_ui_finish(setup_result_t *result)
{
    MSG msg;
    if (!window || !result) return;
    /* Input pressed while the writer was busy must not trigger a restart. */
    while (PeekMessageW(&msg, window, WM_KEYFIRST, WM_KEYLAST, PM_REMOVE)) {}
    installed = result->ok; stage = 3; done = 0;
    progress_used = 0;
    setup_ui_progress(result->ok ? "SETUP-RESULT: OK" : result->reason);
    messages(0); result->power = power; close_ui();
}
