/* SPDX-License-Identifier: GPL-2.0-only
 * Observe one fixed original VLC process. Never send it WM_CLOSE.
 * Playback/UI acceptance comes from original guest evidence, not this log.
 */
#define WIN32_LEAN_AND_MEAN
#define WINVER 0x0410
#define _WIN32_WINNT 0x0400
#include <windows.h>
static HANDLE report = INVALID_HANDLE_VALUE;
static DWORD child_id;
static int io_failed, seen_window;
static unsigned length(const char *s) { unsigned n = 0; while (s[n]) ++n; return n; }
static int same(const char *a, const char *b) {
    while (*a && *a == *b) { ++a; ++b; } return *a == *b;
}
static void text(const char *s) {
    DWORD written, bytes = length(s);
    if (!WriteFile(report, s, bytes, &written, NULL) || written != bytes) io_failed = 1;
}
static void number(const char *key, DWORD n) {
    char data[9]; unsigned i;
    for (i = 0; i < 8; ++i) data[i] = "0123456789ABCDEF"[(n >> (28 - i * 4)) & 15];
    data[8] = 0; text(key); text(data); text("\r\n");
}
static const char *argument(void) {
    const char *s = GetCommandLineA(); BOOL quote = FALSE;
    while (*s) {
        if (*s == '"') quote = !quote;
        else if (!quote && (*s == ' ' || *s == '\t')) break;
        ++s;
    }
    while (*s == ' ' || *s == '\t') ++s;
    return s;
}
static BOOL CALLBACK observe(HWND window, LPARAM unused) {
    DWORD pid = 0; char name[128], title[256]; int count;
    (void)unused;
    if (seen_window || !IsWindowVisible(window)) return TRUE;
    if (!GetWindowThreadProcessId(window, &pid) || pid != child_id) return TRUE;
    count = GetClassNameA(window, name, sizeof(name));
    if (!count) return TRUE;
    name[sizeof(name) - 1] = 0;
    title[0] = 0; GetWindowTextA(window, title, sizeof(title)); title[sizeof(title) - 1] = 0;
    number("OBSERVED_VISIBLE_CHILD_HWND=", (DWORD)(ULONG_PTR)window);
    number("OBSERVED_VISIBLE_CHILD_PID=", pid);
    text("OBSERVED_CHILD_CLASS="); text(name); text("\r\nOBSERVED_CHILD_TITLE="); text(title); text("\r\n");
    seen_window = 1;
    return TRUE;
}
void WINAPI entry(void) {
    char video[] = "C:\\VLCLAB\\VLC\\VLC.EXE --no-plugins-cache --no-media-library --no-one-instance --vout=wingdi --aout=waveout --file-logging --logfile=C:\\VLCLAB\\VIDEO.LOG --verbose=2 C:\\VLCLAB\\MEDIA\\VIDEO.AVI";
    char audio[] = "C:\\VLCLAB\\VLC\\VLC.EXE --no-plugins-cache --no-media-library --no-one-instance --vout=wingdi --aout=waveout --file-logging --logfile=C:\\VLCLAB\\AUDIO.LOG --verbose=2 C:\\VLCLAB\\MEDIA\\TONE.WAV";
    STARTUPINFOA startup = {0}; PROCESS_INFORMATION process = {0};
    const char *mode = argument(); BOOL is_video = same(mode, "video");
    DWORD start, wait_result, target_exit = STILL_ACTIVE, code = 3; int completed = 0;
    if (!is_video && !same(mode, "audio")) ExitProcess(2);
    report = CreateFileA(is_video ? "C:\\VLCLAB\\VIDWATCH.LOG" : "C:\\VLCLAB\\AUDWATCH.LOG",
                         GENERIC_WRITE, 0, NULL, CREATE_NEW, FILE_ATTRIBUTE_NORMAL, NULL);
    if (report == INVALID_HANDLE_VALUE) ExitProcess(20);
    text("SCOPE=ONE_FIXED_OFFICIAL_VLC_CHILD_PROCESS_OBSERVER\r\n");
    text("NO_AUTOMATIC_WM_CLOSE=1\r\nDEADLINE_MS=600000\r\n");
    if (io_failed) goto done;
    startup.cb = sizeof(startup);
    if (!CreateProcessA("C:\\VLCLAB\\VLC\\VLC.EXE", is_video ? video : audio,
                        NULL, NULL, FALSE, 0, NULL, "C:\\VLCLAB\\VLC", &startup, &process)) {
        number("CREATE_PROCESS_FAILED_ERROR=", GetLastError()); goto done;
    }
    child_id = process.dwProcessId;
    number("ACTUAL_CREATED_PID=", child_id);
    number("ACTUAL_CREATED_THREAD_ID=", process.dwThreadId);
    start = GetTickCount();
    for (;;) {
        if (!EnumWindows(observe, 0)) { number("ENUM_WINDOWS_ERROR=", GetLastError()); break; }
        if (io_failed || !FlushFileBuffers(report)) { io_failed = 1; break; }
        wait_result = WaitForSingleObject(process.hProcess, 500);
        if (wait_result == WAIT_OBJECT_0) {
            if (!GetExitCodeProcess(process.hProcess, &target_exit)) {
                number("GET_EXIT_CODE_ERROR=", GetLastError()); break;
            }
            number("ACTUAL_CHILD_EXIT_CODE=", target_exit); completed = 1;
            code = target_exit == 0 ? 0 : 4; break;
        }
        if (wait_result != WAIT_TIMEOUT) { number("WAIT_FAILED_RESULT=", wait_result); break; }
        if (GetTickCount() - start >= 600000U) { text("DEADLINE_EXCEEDED=1\r\n"); break; }
    }
    number("OBSERVATION_ELAPSED_MS=", GetTickCount() - start);
    if (!completed) {
        text("NORMAL_EXIT_NOT_CONFIRMED=1\r\nFORCED_TERMINATION_REQUESTED=1\r\n");
        number("TERMINATE_PROCESS_RETURN=", TerminateProcess(process.hProcess, 119));
        number("POST_TERMINATION_WAIT=", WaitForSingleObject(process.hProcess, 2000));
        if (GetExitCodeProcess(process.hProcess, &target_exit)) number("POST_TERMINATION_ACTUAL_EXIT=", target_exit);
        code = 5;
    }
    number("VISIBLE_CHILD_WINDOW_OBSERVED=", seen_window);
    if (!CloseHandle(process.hThread)) io_failed = 1;
    if (!CloseHandle(process.hProcess)) io_failed = 1;
done:
    number("SELECTED_OBSERVER_EXIT=", code);
    text(code || io_failed ? "STATUS=FAILED_VLC_PROCESS_SCOPE\r\n" : "STATUS=ACTUAL_CHILD_NORMAL_ZERO_EXIT\r\n");
    text("GUI_MEDIA_ACCEPTANCE_REQUIRES_SEPARATE_ORIGINAL_GUEST_EVIDENCE=1\r\n");
    if (!FlushFileBuffers(report)) io_failed = 1;
    if (!CloseHandle(report)) io_failed = 1;
    ExitProcess(io_failed ? 31 : code);
}
