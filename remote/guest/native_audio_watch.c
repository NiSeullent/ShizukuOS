/* SPDX-License-Identifier: GPL-2.0-only
 * Observe one fixed GUI WINMM child; a forced cleanup always fails.
 */
#define WIN32_LEAN_AND_MEAN
#define WINVER 0x0410
#define _WIN32_WINNT 0x0400
#include <windows.h>
static HANDLE report = INVALID_HANDLE_VALUE;
static int io_failed;
static unsigned length(const char *s) { unsigned n = 0; while (s[n]) ++n; return n; }
static void text(const char *s) { DWORD done, n = length(s); if (!WriteFile(report, s, n, &done, NULL) || done != n) io_failed = 1; }
static void number(const char *key, DWORD value) {
    char hex[9]; unsigned i;
    for (i = 0; i < 8; ++i) hex[i] = "0123456789ABCDEF"[(value >> (28 - i * 4)) & 15];
    hex[8] = 0; text(key); text(hex); text("\r\n");
}
static int absent(const char *path) {
    DWORD error;
    if (GetFileAttributesA(path) != INVALID_FILE_ATTRIBUTES) return 0;
    error = GetLastError(); return error == ERROR_FILE_NOT_FOUND || error == ERROR_PATH_NOT_FOUND;
}
void WINAPI entry(void) {
    STARTUPINFOA startup = {0}; PROCESS_INFORMATION child = {0};
    char command[] = "C:\\VXDLAB\\AUDTONE.EXE";
    DWORD result, error = 0, code = 3, actual = STILL_ACTIVE; int completed = 0;
    if (!absent("C:\\VXDLAB\\AUDTONE.LOG")) ExitProcess(21);
    report = CreateFileA("C:\\VXDLAB\\AUDWATCH.LOG", GENERIC_WRITE, FILE_SHARE_READ, NULL,
                         CREATE_NEW, FILE_ATTRIBUTE_NORMAL, NULL);
    if (report == INVALID_HANDLE_VALUE) ExitProcess(20);
    text("SCOPE=ONE_FIXED_NATIVE_AUDIO_CHILD_ACTUAL_OS_EXIT\r\nOWNED_CHILD_MAX_WAIT_MS=30000\r\n");
    if (io_failed || !FlushFileBuffers(report)) { io_failed = 1; goto done; }
    startup.cb = sizeof(startup);
    if (!CreateProcessA(command, command, NULL, NULL, FALSE, 0, NULL, "C:\\VXDLAB", &startup, &child)) {
        number("CREATE_PROCESS_ERROR=", GetLastError()); goto done;
    }
    number("ACTUAL_CREATED_PID=", child.dwProcessId); number("ACTUAL_CREATED_THREAD_ID=", child.dwThreadId);
    if (!FlushFileBuffers(report)) io_failed = 1;
    result = WaitForSingleObject(child.hProcess, 30000);
    if (result == WAIT_FAILED) error = GetLastError();
    number("ACTUAL_CHILD_WAIT=", result); number("ACTUAL_CHILD_WAIT_ERROR=", error);
    if (result == WAIT_OBJECT_0) {
        if (GetExitCodeProcess(child.hProcess, &actual)) {
            number("ACTUAL_CHILD_OS_EXIT=", actual); completed = 1; code = actual == 0 ? 0 : 4;
        } else number("GET_CHILD_EXIT_ERROR=", GetLastError());
    }
    if (!completed) {
        BOOL terminated;
        text("NORMAL_EXIT_NOT_CONFIRMED=1\r\nFORCED_OWNED_CHILD_TERMINATION_REQUESTED=1\r\n");
        terminated = TerminateProcess(child.hProcess, 119);
        error = terminated ? 0 : GetLastError();
        number("TERMINATE_OWNED_CHILD_RETURN=", terminated);
        number("TERMINATE_OWNED_CHILD_ERROR=", error);
        result = WaitForSingleObject(child.hProcess, 2000);
        if (result == WAIT_FAILED) error = GetLastError(); else error = 0;
        number("POST_TERMINATION_WAIT=", result); number("POST_TERMINATION_WAIT_ERROR=", error);
        if (GetExitCodeProcess(child.hProcess, &actual)) number("POST_TERMINATION_ACTUAL_EXIT=", actual);
        code = 5;
    }
    if (!CloseHandle(child.hThread)) io_failed = 1;
    if (!CloseHandle(child.hProcess)) io_failed = 1;
done:
    number("SELECTED_OBSERVER_EXIT=", code);
    text(code || io_failed ? "STATUS=NATIVE_AUDIO_CHILD_SCOPE_FAIL\r\n" : "STATUS=ACTUAL_NATIVE_AUDIO_CHILD_OS_EXIT_ZERO\r\n");
    text("OBSERVER_OWN_OS_EXIT_AND_BACKEND_AUDIO_REQUIRE_SEPARATE_EVIDENCE=1\r\n");
    if (!FlushFileBuffers(report)) io_failed = 1;
    if (!CloseHandle(report)) io_failed = 1;
    ExitProcess(io_failed ? 31 : code);
}
