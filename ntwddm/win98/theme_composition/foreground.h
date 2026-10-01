/* SPDX-License-Identifier: GPL-2.0-only
 * One bounded request for our visible probe window. No visibility inference.
 * The caller retains the live CreateWindowExA handle on its GUI thread.
 */
#ifndef COMPOSITION_FOREGROUND_H
#define COMPOSITION_FOREGROUND_H
typedef struct {
    int owned, visible, requested, api_return, matches;
} foreground_report;

static foreground_report acquire_own_foreground(HWND window)
{
    foreground_report result = {0};
    DWORD process = 0;
    if (!window || !GetWindowThreadProcessId(window, &process) ||
        !process || process != GetCurrentProcessId()) return result;
    result.owned = 1;
    result.visible = IsWindowVisible(window) != 0;
    if (!result.visible) return result;
    result.requested = 1;
    result.api_return = SetForegroundWindow(window) != 0;
    result.matches = GetForegroundWindow() == window;
    return result;
}
#endif
