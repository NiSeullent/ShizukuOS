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
#define ENTRY_HANDLE ((HANDLE)(uintptr_t)4)
#define PIN_HANDLE ((HANDLE)(uintptr_t)5)
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
enum entry_faults {
    ENTRY_CREATE_FAIL = 1u << 0, ENTRY_WRITE_FAIL = 1u << 1,
    ENTRY_SHORT_WRITE = 1u << 2, ENTRY_ZERO_WRITE = 1u << 3,
    ENTRY_OVERSIZE_WRITE = 1u << 4, ENTRY_FLUSH_FAIL = 1u << 5,
    ENTRY_CLOSE_FAIL = 1u << 6, PIN_OPEN_FAIL = 1u << 7,
    PIN_SHORT_READ = 1u << 8, PIN_READ_FAIL = 1u << 9,
    PIN_TRAILING_BYTE = 1u << 10, PIN_CLOSE_FAIL = 1u << 11,
    PIN_INVALID_BYTE = 1u << 12, NULL_COMMAND = 1u << 13,
    MODULE_API_FAIL = 1u << 14
};
static unsigned entry_fault, entry_closes, entry_flushes, pin_closes, pin_reads, message_boxes;
static char entry_bytes[8192];
static size_t entry_length;

static void reset(unsigned errors)
{
    fault = errors; creates = waits = queries = terminations = 0;
    thread_closes = process_closes = log_closes = flushes = fail_flush = 0;
    last_error = child_exit = 0; log_length = 0; log_bytes[0] = 0;
    strcpy(command_line, "\"C:\\VXDLAB\\NTTHRUN.EXE\" --nonce=0123456789abcdef0123456789abcdef");
    strcpy(module_path, "C:\\VXDLAB\\NTTHRUN.EXE");
    entry_fault = entry_closes = entry_flushes = pin_closes = pin_reads = message_boxes = 0;
    entry_length = 0; entry_bytes[0] = 0;
}

char *GetCommandLineA(void) { return entry_fault & NULL_COMMAND ? NULL : command_line; }
DWORD GetModuleFileNameA(HANDLE module, char *output, DWORD count)
{
    size_t length = strlen(module_path);
    CHECK(module == NULL); CHECK(count == MAX_PATH);
    if (entry_fault & MODULE_API_FAIL) { last_error = 126u; return 0; }
    if (length >= count) return count;
    memcpy(output, module_path, length + 1u);
    return (DWORD)length;
}
HANDLE CreateFileA(const char *path, DWORD access, DWORD sharing, void *security,
                    DWORD disposition, DWORD flags, HANDLE template_file)
{
    CHECK(sharing == FILE_SHARE_READ);
    CHECK(security == NULL);
    CHECK(flags == FILE_ATTRIBUTE_NORMAL && template_file == NULL);
    if (strcmp(path, "C:\\VXDLAB\\THENTRY.LOG") == 0) {
        CHECK(access == GENERIC_WRITE && disposition == CREATE_NEW);
        if (entry_fault & ENTRY_CREATE_FAIL) { last_error = 80u; return INVALID_HANDLE_VALUE; }
        return ENTRY_HANDLE;
    }
    if (strcmp(path, "C:\\VXDLAB\\THNONCE.TXT") == 0) {
        CHECK(access == GENERIC_READ && disposition == OPEN_EXISTING);
        if (entry_fault & PIN_OPEN_FAIL) { last_error = 2u; return INVALID_HANDLE_VALUE; }
        return PIN_HANDLE;
    }
    CHECK(strstr(path, "THOBS.LOG") != NULL);
    CHECK(access == GENERIC_WRITE && disposition == CREATE_NEW);
    if (fault & STALE_PARENT_LOG) { last_error = 80; return INVALID_HANDLE_VALUE; }
    return LOG_HANDLE;
}
BOOL WriteFile(HANDLE handle, const void *bytes, DWORD count, DWORD *written, void *overlapped)
{
    DWORD length = count;
    if (handle == ENTRY_HANDLE) {
        CHECK(overlapped == NULL);
        if (entry_fault & ENTRY_WRITE_FAIL) { last_error = 5u; return FALSE; }
        if (entry_fault & ENTRY_ZERO_WRITE) { *written = 0; return TRUE; }
        if (entry_fault & ENTRY_OVERSIZE_WRITE) { *written = count + 1u; return TRUE; }
        if ((entry_fault & ENTRY_SHORT_WRITE) && length > 1u) length = 1u;
        CHECK(entry_length + length < sizeof(entry_bytes));
        memcpy(entry_bytes + entry_length, bytes, length);
        entry_length += length; entry_bytes[entry_length] = 0; *written = length;
        return TRUE;
    }
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
BOOL ReadFile(HANDLE handle, void *bytes, DWORD count, DWORD *read, void *overlapped)
{
    CHECK(handle == PIN_HANDLE && overlapped == NULL); ++pin_reads;
    CHECK((pin_reads == 1u && count == 32u) || (pin_reads == 2u && count == 1u));
    if (entry_fault & PIN_READ_FAIL) { last_error = 5u; return FALSE; }
    if (pin_reads == 1u) {
        *read = entry_fault & PIN_SHORT_READ ? 31u : 32u;
        memcpy(bytes, "0123456789abcdef0123456789abcdef", *read);
        if (entry_fault & PIN_INVALID_BYTE) ((char *)bytes)[0] = 'G';
    } else {
        *read = entry_fault & PIN_TRAILING_BYTE ? 1u : 0u;
        if (*read) *(char *)bytes = '\n';
    }
    return TRUE;
}
int MessageBoxA(HANDLE owner, const char *message, const char *title, unsigned flags)
{
    CHECK(owner == NULL && flags == (MB_OK | MB_ICONERROR));
    CHECK(strcmp(title, "NTTHRUN startup diagnostic") == 0);
    CHECK(message != NULL && strstr(message, "0123456789abcdef") == NULL);
    ++message_boxes; return 1;
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
    if (handle == ENTRY_HANDLE) {
        ++entry_flushes;
        if (entry_fault & ENTRY_FLUSH_FAIL) { last_error = 5u; return FALSE; }
        return TRUE;
    }
    CHECK(handle == LOG_HANDLE); ++flushes;
    if (flushes == fail_flush) { last_error = 5; return FALSE; }
    return TRUE;
}
BOOL CloseHandle(HANDLE handle)
{
    if (handle == ENTRY_HANDLE) {
        ++entry_closes;
        if (entry_fault & ENTRY_CLOSE_FAIL) { last_error = 6u; return FALSE; }
    } else if (handle == PIN_HANDLE) {
        ++pin_closes;
        if (entry_fault & PIN_CLOSE_FAIL) { last_error = 6u; return FALSE; }
    } else if (handle == THREAD_HANDLE) {
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
static void entry_logged(const char *text) { CHECK(strstr(entry_bytes, text) != NULL); }
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
    CHECK(entry_closes == 1 && pin_closes == 1 && pin_reads == 2 && message_boxes == 0);
    entry_logged("STAGE=observer-entry-reached\r\n");
    entry_logged("PIN_VALID=1\r\n");
    entry_logged("COMMAND_MATCHES_STAGED_CHALLENGE=1\r\n");
    entry_logged("RAW_MODULE=C:\\VXDLAB\\NTTHRUN.EXE\r\n");
    entry_logged("STAGE=fresh-THOBS-created\r\n");
    entry_logged("REQUESTED_OBSERVER_EXIT_CODE=0\r\nEXTERNAL_OBSERVER_EXIT=NOT-OBSERVED\r\n");
    CHECK(strstr(entry_bytes, "RESULT=PASS") == NULL);
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
    /* Diagnostic failures remain independent of logical child acceptance. */
    for (index = 0; index < 7u; ++index) {
        static const unsigned diagnostic_errors[] = {ENTRY_CREATE_FAIL, ENTRY_WRITE_FAIL,
            ENTRY_ZERO_WRITE, ENTRY_OVERSIZE_WRITE, ENTRY_FLUSH_FAIL, ENTRY_CLOSE_FAIL, ENTRY_SHORT_WRITE};
        reset(0); entry_fault = diagnostic_errors[index];
        CHECK(observe() == 0); normal_child();
        CHECK(entry_closes == (entry_fault & ENTRY_CREATE_FAIL ? 0u : 1u));
        CHECK(message_boxes == (entry_fault & ENTRY_SHORT_WRITE ? 0u : 1u));
    }
    for (index = 0; index < 6u; ++index) {
        static const unsigned pin_errors[] = {PIN_OPEN_FAIL, PIN_SHORT_READ, PIN_READ_FAIL,
            PIN_TRAILING_BYTE, PIN_CLOSE_FAIL, PIN_INVALID_BYTE};
        reset(0); entry_fault = pin_errors[index];
        CHECK(observe() == 0); normal_child();
        CHECK(pin_closes == (entry_fault & PIN_OPEN_FAIL ? 0u : 1u));
        entry_logged("PIN_VALID=0\r\n"); entry_logged("RAW_COMMAND=<redacted-or-unavailable>\r\n");
    }
    reset(0); strcpy(command_line, "--nonce=0123456789abcdef0123456789abcdef");
    CHECK(observe() == 2 && creates == 0 && log_length == 0);
    entry_logged("RAW_COMMAND=--nonce=0123456789abcdef0123456789abcdef\r\n");
    entry_logged("STAGE=strict-nonce-parser-rejected\r\n");
    CHECK(message_boxes == 1 && entry_closes == 1 && pin_closes == 1);
    reset(0); strcpy(command_line, " NTTHRUN.EXE --nonce=0123456789abcdef0123456789abcdef");
    CHECK(observe() == 2 && creates == 0); entry_logged("COMMAND_MATCHES_STAGED_CHALLENGE=1\r\n");
    reset(0); strcpy(command_line, "NTTHRUN.EXE --nonce=0123456789abcdef0123456789abcdef --token=private");
    CHECK(observe() == 2); entry_logged("RAW_COMMAND=<redacted-or-unavailable>\r\n");
    CHECK(strstr(entry_bytes, "private") == NULL);
    reset(0); memset(command_line, 'x', sizeof(command_line)); command_line[sizeof(command_line) - 1u] = 0;
    CHECK(observe() == 2); entry_logged("COMMAND_BOUND_REACHED=1\r\n");
    CHECK(strstr(entry_bytes, "xxxx") == NULL);
    reset(0); entry_fault = NULL_COMMAND; CHECK(observe() == 2 && creates == 0);
    entry_logged("COMMAND_POINTER_PRESENT=0\r\n");
    reset(0); entry_fault = MODULE_API_FAIL; CHECK(observe() == 2 && creates == 0);
    entry_logged("MODULE_RETURN=0\r\nMODULE_ERROR=126\r\n");
    entry_logged("STAGE=module-or-local-paths-rejected\r\nSTAGE_ERROR=126\r\n");
    reset(STALE_PARENT_LOG); CHECK(observe() == 2 && creates == 0);
    entry_logged("STAGE=fresh-THOBS-create-failed\r\nSTAGE_ERROR=80\r\n");
    CHECK(message_boxes == 1 && entry_closes == 1);
    printf("PASS: %u observer ownership, lifecycle, exit and log assertions\n", assertions);
    return 0;
}
