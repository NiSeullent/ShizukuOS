/* SPDX-License-Identifier: GPL-2.0-only
 * Native OEM Win98 GUI observer for one fixed, frozen W64OBS executable.
 * Captures its real OS exit. This outermost program's own selected exit is
 * an explicit observation limit; no Supervisor or Win64 app claim is made.
 */
#define WIN32_LEAN_AND_MEAN
#define WINVER 0x0410
#define _WIN32_WINNT 0x0400
#include <windows.h>

#ifndef W64_NEGATIVE_NONCE
#error A fresh build-specific W64_NEGATIVE_NONCE is required
#endif
#ifndef W64_NEGATIVE_DIRECTORY
#define W64_NEGATIVE_DIRECTORY "C:\\VXDLAB"
#endif
static HANDLE report = INVALID_HANDLE_VALUE;

static void record(const char *label, DWORD value)
{
    char line[160];
    static const char hex[] = "0123456789abcdef";
    DWORD n = 0, written = 0, i;
    while (*label && n < sizeof line - 16) line[n++] = *label++;
    line[n++] = ' '; line[n++] = '0'; line[n++] = 'x';
    for (i = 0; i < 8; ++i) line[n++] = hex[(value >> (28 - 4 * i)) & 15];
    line[n++] = '\r'; line[n++] = '\n';
    if (!WriteFile(report, line, n, &written, NULL) || written != n) ExitProcess(3);
    if (!FlushFileBuffers(report)) ExitProcess(4);
}
static void fail(const char *stage, DWORD error)
{
    record(stage, error);
    if (!CloseHandle(report)) ExitProcess(4);
    ExitProcess(1);
}
static void absent(const char *name, const char *error_label)
{
    DWORD attributes = GetFileAttributesA(name);
    DWORD error = attributes == INVALID_FILE_ATTRIBUTES ? GetLastError() : 0;
    record(name, attributes); record(error_label, error);
    if (attributes != INVALID_FILE_ATTRIBUTES || error != ERROR_FILE_NOT_FOUND)
        fail("FAIL prior observer or probe log", error);
}
static void close_process(PROCESS_INFORMATION *process)
{
    BOOL ok = CloseHandle(process->hThread);
    DWORD error = ok ? 0 : GetLastError();
    record("OBSERVER_THREAD_CLOSE", ok); record("OBSERVER_THREAD_CLOSE_ERROR", error);
    if (!ok) fail("FAIL observer thread close", error);
    ok = CloseHandle(process->hProcess); error = ok ? 0 : GetLastError();
    record("OBSERVER_PROCESS_CLOSE", ok); record("OBSERVER_PROCESS_CLOSE_ERROR", error);
    if (!ok) fail("FAIL observer process close", error);
}
void mainCRTStartup(void)
{
    STARTUPINFOA startup = {0};
    PROCESS_INFORMATION process = {0};
    const char application[] = W64_NEGATIVE_DIRECTORY "\\W64OBS.EXE";
    char command[] = W64_NEGATIVE_DIRECTORY "\\W64OBS.EXE";
    const char prefix[] = "CASE " W64_NEGATIVE_NONCE " 0x00000000\r\n";
    char text[112];
    HANDLE child_log;
    DWORD result, error, exit_code = 0xffffffffu, bytes = 0;
    unsigned i;
    if (!SetCurrentDirectoryA(W64_NEGATIVE_DIRECTORY)) ExitProcess(5);
    report = CreateFileA("W64OUT.LOG", GENERIC_WRITE, FILE_SHARE_READ, NULL,
                         CREATE_NEW, FILE_ATTRIBUTE_NORMAL, NULL);
    if (report == INVALID_HANDLE_VALUE) ExitProcess(2);
    record("CASE " W64_NEGATIVE_NONCE, 0);
    absent("W64OBS.LOG", "FRESH_OBSERVER_REPORT_ERROR");
    absent("W64NEG.LOG", "FRESH_PROBE_REPORT_ERROR");
    startup.cb = sizeof startup;
    if (!CreateProcessA(application, command, NULL, NULL, FALSE, 0, NULL,
                        W64_NEGATIVE_DIRECTORY, &startup, &process))
        fail("FAIL CreateProcess W64OBS", GetLastError());
    record("OBSERVER_PID", process.dwProcessId);
    result = WaitForSingleObject(process.hProcess, 45000);
    error = result == WAIT_FAILED ? GetLastError() : 0;
    record("OBSERVER_WAIT", result); record("OBSERVER_WAIT_ERROR", error);
    if (result != WAIT_OBJECT_0) {
        BOOL terminated = TerminateProcess(process.hProcess, 1);
        error = terminated ? 0 : GetLastError();
        record("GUARD_TERMINATE_RESULT", terminated); record("GUARD_TERMINATE_ERROR", error);
        result = WaitForSingleObject(process.hProcess, 5000);
        error = result == WAIT_FAILED ? GetLastError() : 0;
        record("GUARD_TERMINATION_WAIT", result); record("GUARD_TERMINATION_WAIT_ERROR", error);
        close_process(&process);
        fail("FAIL observer wait required guard", result);
    }
    if (!GetExitCodeProcess(process.hProcess, &exit_code)) {
        error = GetLastError(); close_process(&process);
        fail("FAIL actual observer OS exit query", error);
    }
    record("OBSERVER_ACTUAL_OS_EXIT", exit_code);
    close_process(&process);
    if (exit_code) fail("FAIL observer actual OS exit", exit_code);
    child_log = CreateFileA("W64OBS.LOG", GENERIC_READ, FILE_SHARE_READ, NULL,
                            OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
    if (child_log == INVALID_HANDLE_VALUE) fail("FAIL fresh observer report", GetLastError());
    if (!ReadFile(child_log, text, sizeof text, &bytes, NULL)) {
        error = GetLastError();
        if (!CloseHandle(child_log)) fail("FAIL failed observer report close", GetLastError());
        fail("FAIL observer report read", error);
    }
    if (!CloseHandle(child_log)) fail("FAIL observer report close", GetLastError());
    if (bytes < sizeof prefix - 1) fail("FAIL observer nonce extent", bytes);
    for (i = 0; i < sizeof prefix - 1; ++i)
        if (text[i] != prefix[i]) fail("FAIL observer nonce", i);
    record("PASS fresh nonce and real observer OS exit", 0);
    record("OUTERMOST_SELECTED_EXIT", 0);
    if (!CloseHandle(report)) ExitProcess(4);
    ExitProcess(0); /* Our own actual OS exit is deliberately not inferred. */
}
