/* SPDX-License-Identifier: GPL-2.0-only
 * Inject failures into native child ownership, waits, path pinning and logs.
 * Mock success is not native Windows execution or visible theme evidence.
 */
#define NTTHOBS_HOST_TEST
#include "observer.c"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define LOG_HANDLE ((HANDLE)(uintptr_t)1)
#define PROCESS_HANDLE ((HANDLE)(uintptr_t)2)
#define THREAD_HANDLE ((HANDLE)(uintptr_t)3)
static unsigned assertions;
#define CHECK(condition) do { ++assertions; if (!(condition)) { \
    fprintf(stderr, "FAIL line %d: %s\n", __LINE__, #condition); exit(1); \
} } while (0)

enum faults {
    BAD_OS = 1u << 0, BAD_BUILD = 1u << 1, BAD_VERSION = 1u << 2,
    STALE_CHILD_LOG = 1u << 3, INACCESSIBLE_CHILD_LOG = 1u << 4,
    MISSING_CHILD = 1u << 5, CHILD_DIRECTORY = 1u << 6,
    STALE_PARENT_LOG = 1u << 7, BAD_CREATE = 1u << 8,
    BAD_THREAD_CLOSE = 1u << 9, BAD_PROCESS_CLOSE = 1u << 10,
    CHILD_TIMEOUT = 1u << 11, BAD_WAIT = 1u << 12,
    BAD_QUERY = 1u << 13, BAD_TERMINATE = 1u << 14,
    BAD_REAP = 1u << 15, BAD_PARENT_CLOSE = 1u << 16,
    BAD_WRITE = 1u << 17, SHORT_WRITE = 1u << 18,
    ZERO_WRITE = 1u << 19, OVERSIZE_WRITE = 1u << 20
};
static unsigned fault, creates, waits, queries, terminations;
static unsigned thread_closes, process_closes, log_closes, flushes, fail_flush;
static DWORD last_error, child_exit;
static char log_bytes[8192], command_line[512], module_path[MAX_PATH];
static size_t log_length;

static void reset(unsigned errors)
{
    fault = errors; creates = waits = queries = terminations = 0;
    thread_closes = process_closes = log_closes = flushes = fail_flush = 0;
    last_error = child_exit = 0; log_length = 0; log_bytes[0] = 0;
    strcpy(command_line, "\"C:\\VXDLAB\\NTTHRUN.EXE\" --nonce=0123456789abcdef0123456789abcdef");
    strcpy(module_path, "C:\\VXDLAB\\NTTHRUN.EXE");
}

char *GetCommandLineA(void) { return command_line; }
DWORD GetModuleFileNameA(HANDLE module, char *output, DWORD count)
{
    size_t length = strlen(module_path);
    CHECK(module == NULL); CHECK(count == MAX_PATH);
    if (length >= count) return count;
    memcpy(output, module_path, length + 1u);
    return (DWORD)length;
}
HANDLE CreateFileA(const char *path, DWORD access, DWORD sharing, void *security,
                    DWORD disposition, DWORD flags, HANDLE template_file)
{
    CHECK(strstr(path, "THOBS.LOG") != NULL);
    CHECK(access == GENERIC_WRITE && sharing == FILE_SHARE_READ);
    CHECK(security == NULL && disposition == CREATE_NEW);
    CHECK(flags == FILE_ATTRIBUTE_NORMAL && template_file == NULL);
    if (fault & STALE_PARENT_LOG) { last_error = 80; return INVALID_HANDLE_VALUE; }
    return LOG_HANDLE;
}
BOOL WriteFile(HANDLE handle, const void *bytes, DWORD count, DWORD *written, void *overlapped)
{
    DWORD length = count;
    CHECK(handle == LOG_HANDLE && overlapped == NULL);
    if (fault & BAD_WRITE) { last_error = 5; return FALSE; }
    if (fault & ZERO_WRITE) { *written = 0; return TRUE; }
    if (fault & OVERSIZE_WRITE) { *written = count + 1u; return TRUE; }
    if ((fault & SHORT_WRITE) && length > 1u) length = 1u;
    CHECK(log_length + length < sizeof(log_bytes));
    memcpy(log_bytes + log_length, bytes, length);
    log_length += length; log_bytes[log_length] = 0; *written = length;
    return TRUE;
}
BOOL GetVersionExA(OSVERSIONINFOA *version)
{
    CHECK(version->dwOSVersionInfoSize == sizeof(*version));
    version->dwMajorVersion = 4; version->dwMinorVersion = 10;
    version->dwBuildNumber = (fault & BAD_BUILD) ? 1998u : UINT32_C(0xffff08ae);
    version->dwPlatformId = (fault & BAD_OS) ? 2u : 1u;
    if (fault & BAD_VERSION) { last_error = 5; return FALSE; }
    return TRUE;
}
DWORD GetFileAttributesA(const char *path)
{
    if (strstr(path, "THEME.LOG")) {
        if (fault & STALE_CHILD_LOG) return FILE_ATTRIBUTE_NORMAL;
        last_error = fault & INACCESSIBLE_CHILD_LOG ? 5u : ERROR_FILE_NOT_FOUND;
        return INVALID_FILE_ATTRIBUTES;
    }
    CHECK(strstr(path, "NTTHGUI.EXE") != NULL);
    if (fault & MISSING_CHILD) { last_error = ERROR_FILE_NOT_FOUND; return INVALID_FILE_ATTRIBUTES; }
    return fault & CHILD_DIRECTORY ? FILE_ATTRIBUTE_DIRECTORY : FILE_ATTRIBUTE_NORMAL;
}
DWORD GetLastError(void) { return last_error; }
void SetLastError(DWORD error) { last_error = error; }
BOOL FlushFileBuffers(HANDLE handle)
{
    CHECK(handle == LOG_HANDLE); ++flushes;
    if (flushes == fail_flush) { last_error = 5; return FALSE; }
    return TRUE;
}
BOOL CloseHandle(HANDLE handle)
{
    if (handle == THREAD_HANDLE) {
        ++thread_closes;
        if (fault & BAD_THREAD_CLOSE) { last_error = 6; return FALSE; }
    } else if (handle == PROCESS_HANDLE) {
        ++process_closes;
        if (fault & BAD_PROCESS_CLOSE) { last_error = 6; return FALSE; }
    } else {
        CHECK(handle == LOG_HANDLE); ++log_closes;
        if (fault & BAD_PARENT_CLOSE) { last_error = 6; return FALSE; }
    }
    return TRUE;
}
BOOL CreateProcessA(const char *application, char *command, void *process_security,
                      void *thread_security, BOOL inherit, DWORD flags, void *environment,
                      const char *directory, STARTUPINFOA *startup, PROCESS_INFORMATION *process)
{
    char expected[512], child[MAX_PATH], child_log[MAX_PATH], parent_log[MAX_PATH], root[MAX_PATH];
    CHECK(local_paths(module_path, root, child, child_log, parent_log));
    CHECK(strcmp(application, child) == 0 && strcmp(directory, root) == 0);
    snprintf(expected, sizeof(expected), "\"%s\" --nonce=0123456789abcdef0123456789abcdef", child);
    CHECK(strcmp(command, expected) == 0);
    CHECK(process_security == NULL && thread_security == NULL && inherit == FALSE);
    CHECK(flags == 0 && environment == NULL && startup->cb == sizeof(*startup));
    CHECK(startup->dwFlags == 0 && startup->hStdInput == NULL && startup->hStdOutput == NULL);
    ++creates;
    if (fault & BAD_CREATE) { last_error = 193; return FALSE; }
    process->hProcess = PROCESS_HANDLE; process->hThread = THREAD_HANDLE;
    process->dwProcessId = 12345; process->dwThreadId = 54321;
    return TRUE;
}
DWORD WaitForSingleObject(HANDLE handle, DWORD milliseconds)
{
    CHECK(handle == PROCESS_HANDLE); ++waits;
    if (waits == 1) {
        CHECK(milliseconds == CHILD_TIMEOUT_MS);
        if (fault & CHILD_TIMEOUT) return WAIT_TIMEOUT;
        if (fault & BAD_WAIT) { last_error = 6; return WAIT_FAILED; }
        return WAIT_OBJECT_0;
    }
    CHECK(waits == 2 && milliseconds == REAP_TIMEOUT_MS && terminations == 1);
    return fault & BAD_REAP ? WAIT_TIMEOUT : WAIT_OBJECT_0;
}
BOOL GetExitCodeProcess(HANDLE handle, DWORD *code)
{
    CHECK(handle == PROCESS_HANDLE && waits == 1);
    CHECK(!(fault & (CHILD_TIMEOUT | BAD_WAIT))); ++queries;
    if (fault & BAD_QUERY) { last_error = 5; return FALSE; }
    *code = child_exit; return TRUE;
}
BOOL TerminateProcess(HANDLE handle, DWORD code)
{
    CHECK(handle == PROCESS_HANDLE && creates == 1 && waits == 1 && code == ERROR_TIMEOUT);
    ++terminations;
    if (fault & BAD_TERMINATE) { last_error = 5; return FALSE; }
    return TRUE;
}

static void logged(const char *text) { CHECK(strstr(log_bytes, text) != NULL); }
static void normal_child(void)
{
    CHECK(creates == 1 && waits == 1 && queries == 1 && terminations == 0);
    CHECK(thread_closes == 1 && process_closes == 1 && log_closes == 1);
    logged("CHILD_CREATED=1\r\nCHILD_CREATE_ERROR=0\r\n");
    logged("CHILD_WAIT=0\r\nCHILD_WAIT_ERROR=0\r\n");
    logged("CHILD_EXIT_QUERY=1\r\nCHILD_EXIT_QUERY_ERROR=0\r\nCHILD_EXIT_CODE=0\r\n");
    logged("CHILD_REAPED=1\r\nTHREAD_CLOSED=1\r\nPROCESS_CLOSED=1\r\n");
}

int main(void)
{
    unsigned index;
    static const unsigned blocked[] = {BAD_OS, BAD_BUILD, BAD_VERSION, STALE_CHILD_LOG,
        INACCESSIBLE_CHILD_LOG, MISSING_CHILD, CHILD_DIRECTORY};
    static const char *const bad_commands[] = {
        "NTTHRUN.EXE", "NTTHRUN.EXE --nonce=0123", "NTTHRUN.EXE --nonce=0123456789abcdef0123456789abcdeF",
        "NTTHRUN.EXE --nonce=0123456789abcdef0123456789abcdef extra",
        "\"NTTHRUN.EXE --nonce=0123456789abcdef0123456789abcdef",
        "NTTHRUN.EXE --nonce=0123456789abcdef0123456789abcdef --nonce=0123456789abcdef0123456789abcdef"
    };
    reset(0); CHECK(observe() == 0); normal_child();
    logged("OS_BUILD_LOW=2222\r\nWIN98_IDENTIFIED=1\r\n");
    logged("RUN_NONCE=0123456789abcdef0123456789abcdef\r\nCLEANUP=PASS\r\nRESULT=PASS\r\n");
    CHECK(log_length >= 13u && strcmp(log_bytes + log_length - 13u, "RESULT=PASS\r\n") == 0);
    reset(SHORT_WRITE); CHECK(observe() == 0); normal_child();
    for (index = 0; index < sizeof(blocked) / sizeof(blocked[0]); ++index) {
        reset(blocked[index]); CHECK(observe() == 1);
        CHECK(creates == 0 && waits == 0 && queries == 0 && terminations == 0);
        CHECK(thread_closes == 0 && process_closes == 0 && log_closes == 1);
        logged("RESULT=FAIL\r\n");
    }
    for (index = 0; index < sizeof(bad_commands) / sizeof(bad_commands[0]); ++index) {
        reset(0); strcpy(command_line, bad_commands[index]);
        CHECK(observe() == 2 && log_length == 0 && creates == 0 && log_closes == 0);
    }
    reset(STALE_PARENT_LOG); CHECK(observe() == 2 && creates == 0 && log_length == 0 && log_closes == 0);
    reset(BAD_CREATE); CHECK(observe() == 1);
    CHECK(creates == 1 && waits == 0 && queries == 0 && terminations == 0);
    CHECK(thread_closes == 0 && process_closes == 0); logged("CHILD_CREATE_ERROR=193\r\n");
    reset(BAD_QUERY); CHECK(observe() == 1);
    CHECK(queries == 1 && waits == 1 && terminations == 0);
    CHECK(strstr(log_bytes, "CHILD_EXIT_CODE=") == NULL);
    logged("CHILD_EXIT_QUERY=0\r\nCHILD_EXIT_QUERY_ERROR=5\r\n");
    logged("CHILD_REAPED=1\r\n"); logged("RESULT=FAIL\r\n");
    reset(0); child_exit = UINT32_C(0x80000001); CHECK(observe() == 1);
    logged("CHILD_EXIT_CODE=2147483649\r\n"); logged("RESULT=FAIL\r\n");
    reset(0); child_exit = 259u; CHECK(observe() == 1);
    logged("CHILD_EXIT_CODE=259\r\n"); CHECK(queries == 1 && terminations == 0);
    for (index = 0; index < 4u; ++index) {
        reset((index & 1u ? BAD_WAIT : CHILD_TIMEOUT) | (index & 2u ? BAD_REAP : 0));
        CHECK(observe() == 1);
        CHECK(creates == 1 && waits == 2 && queries == 0 && terminations == 1);
        CHECK(thread_closes == 1 && process_closes == 1);
        logged("TERMINATION_ATTEMPTED=1\r\n"); logged("RESULT=FAIL\r\n");
        logged(index & 2u ? "CLEANUP=FAIL\r\n" : "CLEANUP=PASS\r\n");
    }
    reset(CHILD_TIMEOUT | BAD_TERMINATE); CHECK(observe() == 1);
    CHECK(waits == 2 && terminations == 1); logged("CHILD_TERMINATE_ERROR=5\r\n");
    reset(BAD_THREAD_CLOSE); CHECK(observe() == 1);
    CHECK(thread_closes == 1 && process_closes == 1); logged("THREAD_CLOSED=0\r\n");
    reset(BAD_PROCESS_CLOSE); CHECK(observe() == 1);
    CHECK(process_closes == 1); logged("PROCESS_CLOSED=0\r\n");
    reset(0); fail_flush = 1; CHECK(observe() == 2 && creates == 0); logged("RESULT=FAIL\r\n");
    reset(0); fail_flush = 2; CHECK(observe() == 2); normal_child(); logged("RESULT=PASS\r\n");
    reset(BAD_PARENT_CLOSE); CHECK(observe() == 2); normal_child(); logged("RESULT=PASS\r\n");
    for (index = 0; index < 3u; ++index) {
        reset(index == 0 ? BAD_WRITE : index == 1 ? ZERO_WRITE : OVERSIZE_WRITE);
        CHECK(observe() == 2 && creates == 0 && log_closes == 1);
    }
    reset(0); strcpy(module_path, "C:\\directory with spaces\\NTTHRUN.EXE");
    CHECK(observe() == 0); normal_child();
    reset(0); memset(module_path, 'x', sizeof(module_path)); module_path[MAX_PATH - 1u] = 0;
    module_path[0] = 'C'; module_path[1] = ':'; module_path[2] = '\\'; module_path[MAX_PATH - 2u] = '\\';
    CHECK(observe() == 2 && creates == 0 && log_length == 0);
    reset(0); strcpy(module_path, "relative\\NTTHRUN.EXE"); CHECK(observe() == 2 && creates == 0);
    reset(0); strcpy(module_path, "C:\\quote\"directory\\NTTHRUN.EXE"); CHECK(observe() == 2 && creates == 0);
    printf("PASS: %u observer ownership, lifecycle, exit and log assertions\n", assertions);
    return 0;
}
