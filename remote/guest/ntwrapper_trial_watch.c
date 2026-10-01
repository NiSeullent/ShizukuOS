/* SPDX-License-Identifier: GPL-2.0-only
 * Original bounded observer for the immutable production VxD query.
 * This is not a WIN64 bridge/application acceptance probe.
 */
#define WIN32_LEAN_AND_MEAN
#define WINVER 0x0410
#define _WIN32_WINNT 0x0400
#include <windows.h>

static HANDLE report;
static int failed;

static void record(const char *name, DWORD value)
{
    static const char digits[] = "0123456789ABCDEF";
    char line[160];
    DWORD length = 0, written = 0, i;
    while (*name && length < sizeof(line) - 12) line[length++] = *name++;
    line[length++] = '=';
    for (i = 0; i < 8; ++i) line[length++] = digits[(value >> (28 - 4*i)) & 15];
    line[length++] = '\r'; line[length++] = '\n';
    if (!WriteFile(report, line, length, &written, NULL) || written != length ||
            !FlushFileBuffers(report)) failed = 1;
}

void WINAPI entry(void)
{
    STARTUPINFOA start = {0};
    PROCESS_INFORMATION process = {0};
    char command[] = "C:\\VXDLAB\\NTWQUERY.EXE";
    DWORD version, wait, code = 0xFFFFFFFF, result = 31, error;
    report = CreateFileA("C:\\VXDLAB\\NTWOBS.LOG", GENERIC_WRITE, 0, NULL,
                         CREATE_NEW, FILE_ATTRIBUTE_NORMAL, NULL);
    if (report == INVALID_HANDLE_VALUE) ExitProcess(21);
    version = GetVersion();
    record("VERSION", version);
    if (!(version & 0x80000000u) || (version & 0xFFFFu) != 0x0A04u) goto finish;
    if (GetFileAttributesA("C:\\VXDLAB\\NTWQUERY.LOG") != INVALID_FILE_ATTRIBUTES)
        goto finish;
    error = GetLastError();
    record("FRESH_QUERY_LOG_ERROR", error);
    if (error != ERROR_FILE_NOT_FOUND || failed) goto finish;
    start.cb = sizeof(start);
    if (!CreateProcessA("C:\\VXDLAB\\NTWQUERY.EXE", command, NULL, NULL, FALSE,
                        0, NULL, "C:\\VXDLAB", &start, &process)) {
        record("CREATE_ERROR", GetLastError()); goto finish;
    }
    record("CHILD_PID", process.dwProcessId);
    if (!CloseHandle(process.hThread)) failed = 1;
    wait = WaitForSingleObject(process.hProcess, 30000);
    error = wait == WAIT_FAILED ? GetLastError() : 0;
    record("CHILD_WAIT", wait);
    if (wait != WAIT_OBJECT_0) {
        record("CHILD_WAIT_ERROR", error);
        /* A guard termination remains a failed trial, even if it later exits0. */
        record("GUARD_TERMINATE", TerminateProcess(process.hProcess, 44));
        record("GUARD_WAIT", WaitForSingleObject(process.hProcess, 5000));
    } else {
        if (!GetExitCodeProcess(process.hProcess, &code)) failed = 1;
        record("CHILD_EXIT", code);
        if (code == 0 && !failed) result = 0;
    }
    if (!CloseHandle(process.hProcess)) failed = 1;
finish:
    if (failed) result = 21;
    record("OBSERVER_RESULT", result);
    if (failed) result = 21;
    if (!CloseHandle(report)) result = 21;
    ExitProcess(result);
}
