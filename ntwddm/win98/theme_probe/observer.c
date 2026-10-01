/* SPDX-License-Identifier: GPL-2.0-only
 * Observe one exclusively owned native theme child. This log records the
 * child's actual full exit code; it does not observe this parent's own exit.
 * No CRT, inherited handles, installation, registry changes, or networking.
 */
#ifdef NTTHOBS_HOST_TEST
#include "observer_mock.h"
#else
#define WIN32_LEAN_AND_MEAN
#define WINVER 0x0400
#define _WIN32_WINNT 0x0400
#include <windows.h>
#endif

#define CHILD_TIMEOUT_MS 60000u
#define REAP_TIMEOUT_MS 5000u

static HANDLE observer_log = INVALID_HANDLE_VALUE;
static int observer_io_failed;

static void zero_bytes(void *object, DWORD length)
{
    unsigned char *cursor = (unsigned char *)object;
    while (length--) *cursor++ = 0;
}

static void say(const char *text)
{
    DWORD length = 0;
    while (text[length]) ++length;
    while (length) {
        DWORD written = 0;
        if (!WriteFile(observer_log, text, length, &written, NULL) ||
            !written || written > length) {
            observer_io_failed = 1;
            return;
        }
        text += written;
        length -= written;
    }
}

static void number(const char *name, DWORD value)
{
    char digits[11];
    DWORD position = 10;
    digits[position] = 0;
    do {
        digits[--position] = (char)('0' + value % 10u);
        value /= 10u;
    } while (value);
    say(name); say(digits + position); say("\r\n");
}

static void failure(const char *stage, DWORD error)
{
    say("FAIL_STAGE="); say(stage); say("\r\n");
    number("ERROR=", error);
}

static int read_nonce(char nonce[33])
{
    static const char option[] = "--nonce=";
    const char *cursor = GetCommandLineA();
    unsigned index;
    if (!cursor || !*cursor) return 0;
    if (*cursor == '"') {
        ++cursor;
        while (*cursor && *cursor != '"') ++cursor;
        if (!*cursor) return 0;
        ++cursor;
    } else {
        while (*cursor && *cursor != ' ' && *cursor != '\t') ++cursor;
    }
    while (*cursor == ' ' || *cursor == '\t') ++cursor;
    for (index = 0; option[index]; ++index) {
        if (*cursor != option[index]) return 0;
        ++cursor;
    }
    for (index = 0; index < 32u; ++index) {
        char character = *cursor;
        if (!((character >= '0' && character <= '9') ||
              (character >= 'a' && character <= 'f'))) return 0;
        nonce[index] = character;
        ++cursor;
    }
    nonce[32] = 0;
    while (*cursor == ' ' || *cursor == '\t') ++cursor;
    return !*cursor;
}

static int local_paths(const char *module, char directory[MAX_PATH],
                       char child[MAX_PATH], char child_log[MAX_PATH],
                       char parent_log[MAX_PATH])
{
    static const char *const names[3] = {"NTTHGUI.EXE", "THEME.LOG", "THOBS.LOG"};
    char *outputs[3];
    unsigned length = 0, slash = 0, index, item;
    outputs[0] = child; outputs[1] = child_log; outputs[2] = parent_log;
    /* An absolute drive path avoids process-current-directory resolution.
     * Quotes and control bytes would make the quoted command line ambiguous. */
    if (!((module[0] >= 'A' && module[0] <= 'Z') ||
          (module[0] >= 'a' && module[0] <= 'z')) ||
        module[1] != ':' || (module[2] != '\\' && module[2] != '/')) return 0;
    while (module[length]) {
        unsigned char character = (unsigned char)module[length];
        if (character < 32u || character == '"' || length >= MAX_PATH - 1u) return 0;
        if (character == '\\' || character == '/') slash = length + 1u;
        ++length;
    }
    if (!slash || slash == length) return 0;
    for (index = 0; index < slash; ++index) directory[index] = module[index];
    directory[slash] = 0;
    for (item = 0; item < 3u; ++item) {
        for (index = 0; index < slash; ++index) outputs[item][index] = module[index];
        for (index = 0; names[item][index]; ++index) {
            if (slash + index >= MAX_PATH - 1u) return 0;
            outputs[item][slash + index] = names[item][index];
        }
        outputs[item][slash + index] = 0;
    }
    return 1;
}

static int absent(const char *path)
{
    DWORD attributes = GetFileAttributesA(path);
    return attributes == INVALID_FILE_ATTRIBUTES && GetLastError() == ERROR_FILE_NOT_FOUND;
}

static int close_checked(HANDLE *handle)
{
    BOOL closed;
    if (!*handle || *handle == INVALID_HANDLE_VALUE) return 1;
    closed = CloseHandle(*handle);
    /* Never reuse a handle after an attempted close, even when close failed. */
    *handle = NULL;
    return closed != FALSE;
}

static DWORD observe(void)
{
    char nonce[33], module[MAX_PATH], directory[MAX_PATH];
    char child[MAX_PATH], child_log[MAX_PATH], parent_log[MAX_PATH];
    /* MAX_PATH includes NUL; two quotes + space + --nonce= + 32 hex + NUL. */
    char command[MAX_PATH + 44];
    OSVERSIONINFOA version;
    STARTUPINFOA startup;
    PROCESS_INFORMATION process;
    DWORD length, index, position, attributes, actual_exit = 0;
    DWORD create_error = 0, waited = WAIT_FAILED, wait_error = 0;
    DWORD exit_error = 0, reaped = WAIT_FAILED, terminate_error = 0;
    BOOL exact_os, created = FALSE, queried = FALSE, terminated = FALSE;
    int child_reaped = 0, thread_closed = 1, process_closed = 1;
    int cleanup = 1, success = 0, termination_attempted = 0;

    observer_log = INVALID_HANDLE_VALUE; observer_io_failed = 0;
    if (!read_nonce(nonce)) return 2;
    length = GetModuleFileNameA(NULL, module, MAX_PATH);
    if (!length || length >= MAX_PATH ||
        !local_paths(module, directory, child, child_log, parent_log)) return 2;
    observer_log = CreateFileA(parent_log, GENERIC_WRITE, FILE_SHARE_READ, NULL,
                               CREATE_NEW, FILE_ATTRIBUTE_NORMAL, NULL);
    if (observer_log == INVALID_HANDLE_VALUE) return 2;
    say("NTTHOBS_LOG_VERSION=1\r\nBEGIN_NONCE="); say(nonce); say("\r\n");
    zero_bytes(&version, sizeof(version));
    zero_bytes(&startup, sizeof(startup)); zero_bytes(&process, sizeof(process));
    version.dwOSVersionInfoSize = sizeof(version);
    exact_os = GetVersionExA(&version) &&
               version.dwPlatformId == VER_PLATFORM_WIN32_WINDOWS &&
               version.dwMajorVersion == 4u && version.dwMinorVersion == 10u &&
               LOWORD(version.dwBuildNumber) == 2222u;
    number("OS_PLATFORM=", version.dwPlatformId);
    number("OS_MAJOR=", version.dwMajorVersion); number("OS_MINOR=", version.dwMinorVersion);
    number("OS_BUILD_LOW=", LOWORD(version.dwBuildNumber));
    number("WIN98_IDENTIFIED=", exact_os != FALSE);
    say("CHILD_PATH="); say(child); say("\r\n");
    if (!exact_os) { failure("native-Windows-98-SE-required", 0); goto done; }
    if (!absent(child_log)) { failure("child-log-not-absent", GetLastError()); goto done; }
    attributes = GetFileAttributesA(child);
    if (attributes == INVALID_FILE_ATTRIBUTES || (attributes & FILE_ATTRIBUTE_DIRECTORY)) {
        failure("child-file-unavailable", GetLastError()); goto done;
    }
    if (observer_io_failed || !FlushFileBuffers(observer_log)) {
        observer_io_failed = 1; goto done;
    }
    position = 0; command[position++] = '"';
    for (index = 0; child[index]; ++index) command[position++] = child[index];
    command[position++] = '"'; command[position++] = ' ';
    {
        static const char option[] = "--nonce=";
        for (index = 0; option[index]; ++index) command[position++] = option[index];
    }
    for (index = 0; nonce[index]; ++index) command[position++] = nonce[index];
    command[position] = 0;
    startup.cb = sizeof(startup);
    SetLastError(0);
    created = CreateProcessA(child, command, NULL, NULL, FALSE, 0, NULL,
                             directory, &startup, &process);
    create_error = created ? 0u : GetLastError();
    if (!created) { failure("CreateProcessA", create_error); goto done; }
    number("CHILD_PID=", process.dwProcessId);
    thread_closed = close_checked(&process.hThread);
    if (!thread_closed) failure("CloseHandle(thread)", GetLastError());
    waited = WaitForSingleObject(process.hProcess, CHILD_TIMEOUT_MS);
    wait_error = waited == WAIT_FAILED ? GetLastError() : 0u;
    if (waited == WAIT_OBJECT_0) {
        child_reaped = 1;
        queried = GetExitCodeProcess(process.hProcess, &actual_exit);
        exit_error = queried ? 0u : GetLastError();
        if (!queried) failure("GetExitCodeProcess", exit_error);
        /* STILL_ACTIVE is legal as an application's exit value; the normal
         * wait establishes termination, and only the exact value zero passes. */
        success = queried && actual_exit == 0u;
    } else {
        failure("WaitForSingleObject(child)", wait_error);
        termination_attempted = 1;
        terminated = TerminateProcess(process.hProcess, ERROR_TIMEOUT);
        terminate_error = terminated ? 0u : GetLastError();
        if (!terminated) failure("TerminateProcess(owned-child)", terminate_error);
        reaped = WaitForSingleObject(process.hProcess, REAP_TIMEOUT_MS);
        child_reaped = reaped == WAIT_OBJECT_0;
        if (!child_reaped) failure("WaitForSingleObject(reap)",
                                  reaped == WAIT_FAILED ? GetLastError() : 0u);
    }
done:
    /* Failures before CreateProcess own no child handles. Failed waits never
     * discover, reopen, or target another process; all stopping uses this handle. */
    if (process.hThread) {
        int closed = close_checked(&process.hThread);
        thread_closed = closed && thread_closed;
        if (!closed) failure("CloseHandle(thread-cleanup)", GetLastError());
    }
    if (process.hProcess) {
        process_closed = close_checked(&process.hProcess);
        if (!process_closed) failure("CloseHandle(process)", GetLastError());
    }
    cleanup = thread_closed && process_closed && (!created || child_reaped);
    number("CHILD_CREATED=", created != FALSE); number("CHILD_CREATE_ERROR=", create_error);
    number("CHILD_WAIT=", waited); number("CHILD_WAIT_ERROR=", wait_error);
    number("CHILD_EXIT_QUERY=", queried != FALSE); number("CHILD_EXIT_QUERY_ERROR=", exit_error);
    /* Do not label a requested or fabricated exit as an actual process code. */
    if (queried) number("CHILD_EXIT_CODE=", actual_exit);
    number("TERMINATION_ATTEMPTED=", (DWORD)termination_attempted);
    if (termination_attempted) {
        number("CHILD_TERMINATED=", terminated != FALSE);
        number("CHILD_TERMINATE_ERROR=", terminate_error);
        number("CHILD_REAP_WAIT=", reaped);
    }
    number("CHILD_REAPED=", (DWORD)child_reaped);
    number("THREAD_CLOSED=", (DWORD)thread_closed); number("PROCESS_CLOSED=", (DWORD)process_closed);
    say("RUN_NONCE="); say(nonce); say("\r\n");
    say(cleanup ? "CLEANUP=PASS\r\n" : "CLEANUP=FAIL\r\n");
    say(success && cleanup && !observer_io_failed ? "RESULT=PASS\r\n" : "RESULT=FAIL\r\n");
    /* An external observer may see RESULT=PASS before these operations fail.
     * This parent returns nonzero then; its log proves only the child's exit. */
    if (!FlushFileBuffers(observer_log)) observer_io_failed = 1;
    if (!close_checked(&observer_log)) observer_io_failed = 1;
    return observer_io_failed ? 2u : success && cleanup ? 0u : 1u;
}

#ifndef NTTHOBS_HOST_TEST
void mainCRTStartup(void) { ExitProcess(observe()); }
#endif
