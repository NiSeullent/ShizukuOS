/* SPDX-License-Identifier: GPL-2.0-only
 * Native Win98 evidence supervisor for one owned delay-runtime probe.
 * No compatibility settings, registry keys, or system binaries are changed.
 */
#define WIN32_LEAN_AND_MEAN
#define WINVER 0x0410
#define _WIN32_WINNT 0x0400
#include <windows.h>
static HANDLE report = INVALID_HANDLE_VALUE;
static unsigned failures, completed;
static int io_failed;
static void text(const char *s) {
    DWORD length = 0, written;
    while (s[length]) ++length;
    if (!WriteFile(report, s, length, &written, NULL) || written != length) io_failed = 1;
}
static void value(const char *label, DWORD number) {
    char output[9]; unsigned i;
    for (i = 0; i < 8; ++i) output[i] = "0123456789ABCDEF"[(number >> (28 - i * 4)) & 15];
    output[8] = 0; text(label); text(output); text("\r\n");
}
static void zero(void *p, unsigned length) {
    unsigned i; for (i = 0; i < length; ++i) ((BYTE *)p)[i] = 0;
}
void WINAPI entry(void) {
    static const char *const probes[] = {"CHDLY.EXE"};
    unsigned i;
    int unconfirmed_child = 0;
    report = CreateFileA("C:\\VXDLAB\\CHDSUIT.LOG", GENERIC_WRITE, 0, NULL,
                         CREATE_NEW, FILE_ATTRIBUTE_NORMAL, NULL);
    if (report == INVALID_HANDLE_VALUE) ExitProcess(20);
    text("SCOPE=OWNED_NATIVE_DELAY_PROBE_NOT_APPLICATION_ACCEPTANCE\r\n");
    for (i = 0; i < 1; ++i) {
        STARTUPINFOA startup; PROCESS_INFORMATION process;
        char command[64] = "C:\\VXDLAB\\";
        unsigned n = 10, j = 0;
        DWORD wait, code, error;
        while (probes[i][j]) command[n++] = probes[i][j++];
        command[n] = 0;
        zero(&startup, sizeof(startup)); zero(&process, sizeof(process));
        startup.cb = sizeof(startup);
        text("PROBE="); text(probes[i]); text("\r\n");
        if (!CreateProcessA(NULL, command, NULL, NULL, FALSE, 0, NULL,
                            "C:\\VXDLAB", &startup, &process)) {
            value("CREATE_ERROR=", GetLastError()); ++failures; continue;
        }
        value("OWNED_CHILD_PID=", process.dwProcessId);
        wait = WaitForSingleObject(process.hProcess, 30000);
        error = wait == WAIT_FAILED ? GetLastError() : ERROR_TIMEOUT;
        value("WAIT_RESULT=", wait);
        if (wait != WAIT_OBJECT_0) {
            value("WAIT_ERROR=", error); ++failures;
            text("STATUS_CHILD=FAILED_BOUNDED_WAIT\r\n");
            if (TerminateProcess(process.hProcess, 1460)) {
                DWORD reaped = WaitForSingleObject(process.hProcess, 5000);
                value("OWNED_TERMINATED_REAP=", reaped);
                if (reaped != WAIT_OBJECT_0) { ++failures; unconfirmed_child = 1; }
            } else {
                value("OWNED_TERMINATE_ERROR=", GetLastError()); ++failures;
                unconfirmed_child = WaitForSingleObject(process.hProcess, 5000) != WAIT_OBJECT_0;
            }
        } else if (!GetExitCodeProcess(process.hProcess, &code)) {
            value("EXIT_QUERY_ERROR=", GetLastError()); ++failures;
        } else {
            value("ACTUAL_EXIT=", code);
            if (code) ++failures;
            else ++completed;
        }
        if (!CloseHandle(process.hThread)) { value("THREAD_HANDLE_CLOSE_ERROR=", GetLastError()); ++failures; }
        if (!CloseHandle(process.hProcess)) { value("PROCESS_HANDLE_CLOSE_ERROR=", GetLastError()); ++failures; }
        if (unconfirmed_child) { text("OWNED_CHILD_CLOSURE=UNCONFIRMED\r\n"); break; }
    }
    value("ACTUAL_ZERO_EXIT_PROBES=", completed); value("FAILURES=", failures);
    text(failures || completed != 1 || io_failed ? "STATUS=FAIL\r\n" : "STATUS=SCOPED_NATIVE_DELAY_SUITE_PASS\r\n");
    if (!FlushFileBuffers(report)) io_failed = 1;
    if (!CloseHandle(report)) io_failed = 1;
    ExitProcess(failures || completed != 1 || io_failed ? 31 : 0);
}
