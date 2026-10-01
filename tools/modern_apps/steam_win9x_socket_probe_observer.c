/* SPDX-License-Identifier: GPL-2.0-only
 * Observe only this invocation's actual native Winsock probe child. No Steam
 * payload, remote endpoint, process enumeration or provider substitution.
 */
#include <windows.h>
#include <stdio.h>
#include <stdarg.h>
#include <string.h>

#define SELF "C:\\GOPLAB\\SPWAIT.EXE"
#define CHILD "C:\\GOPLAB\\SPROB.EXE"
#define LOG "C:\\GOPLAB\\SPWAIT.LOG"
#define CHILD_DEADLINE_MS 90000UL
#define REAP_DEADLINE_MS 5000UL

static BOOL log_ok = TRUE;

static BOOL checkpoint(BOOL first, const char *format, ...)
{
    char text[1024];
    va_list args;
    HANDLE file;
    DWORD count;
    int length;
    BOOL ok;
    va_start(args, format);
    length = vsnprintf(text, sizeof(text), format, args);
    va_end(args);
    if (!log_ok || length <= 0 || (size_t)length >= sizeof(text)) {
        log_ok = FALSE;
        return FALSE;
    }
    file = CreateFileA(LOG, GENERIC_WRITE, FILE_SHARE_READ, NULL,
        first ? CREATE_NEW : OPEN_EXISTING,
        FILE_ATTRIBUTE_NORMAL | FILE_FLAG_WRITE_THROUGH, NULL);
    if (file == INVALID_HANDLE_VALUE) {
        log_ok = FALSE;
        return FALSE;
    }
    SetLastError(NO_ERROR);
    ok = first || SetFilePointer(file, 0, NULL, FILE_END) != INVALID_SET_FILE_POINTER ||
        GetLastError() == NO_ERROR;
    ok = ok && WriteFile(file, text, (DWORD)length, &count, NULL) &&
        count == (DWORD)length && FlushFileBuffers(file);
    if (!CloseHandle(file))
        ok = FALSE;
    log_ok = ok;
    return ok;
}

/* Never use a PID lookup: only the live handle returned by our CreateProcessA.
 * Reap even if TerminateProcess fails, as normal exit can race termination. */
static BOOL stop_owned_child(HANDLE process, DWORD reason)
{
    DWORD initial = WaitForSingleObject(process, 0);
    DWORD waited, error = 0, code = STILL_ACTIVE;
    BOOL needed = initial != WAIT_OBJECT_0;
    BOOL terminated = FALSE, queried = FALSE;
    if (needed) {
        terminated = TerminateProcess(process, reason);
        if (!terminated)
            error = GetLastError();
    }
    waited = WaitForSingleObject(process, REAP_DEADLINE_MS);
    if (waited == WAIT_OBJECT_0)
        queried = GetExitCodeProcess(process, &code);
    checkpoint(FALSE, "cleanup.termination-needed=%u\r\ncleanup.terminated=%u\r\n"
        "cleanup.terminate-error=%lu\r\ncleanup.reap-wait=%lu\r\n"
        "cleanup.exit-query=%u\r\ncleanup.exit-code=%lu\r\n",
        !!needed, !!terminated, error, waited, !!queried, code);
    return waited == WAIT_OBJECT_0 && queried && code != STILL_ACTIVE;
}

int main(int argc, char **argv)
{
    char module[MAX_PATH], command[256];
    OSVERSIONINFOA version;
    STARTUPINFOA startup;
    PROCESS_INFORMATION process;
    DWORD module_length, waited, error, code = STILL_ACTIVE;
    BOOL created, thread_closed, query = FALSE, process_closed, passed;
    int length;
    if (argc != 2 || strlen(argv[1]) < 16 || strlen(argv[1]) > 80 ||
        strspn(argv[1], "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789-_") != strlen(argv[1]))
        return 10;
    module_length = GetModuleFileNameA(NULL, module, sizeof(module));
    if (!module_length || module_length >= sizeof(module) || lstrcmpiA(module, SELF))
        return 11;
    if (!checkpoint(TRUE, "scope=steam-native-win98-loopback-owned-child-exit\r\nnonce=%s\r\n"
        "source.version=1\r\nsteam.application-executed=0\r\n", argv[1]))
        return 2;
    memset(&version, 0, sizeof(version));
    version.dwOSVersionInfoSize = sizeof(version);
    passed = GetVersionExA(&version) && version.dwPlatformId == VER_PLATFORM_WIN32_WINDOWS &&
        version.dwMajorVersion == 4 && version.dwMinorVersion == 10 &&
        LOWORD(version.dwBuildNumber) == 2222;
    if (!checkpoint(FALSE, "os.platform=%lu\r\nos.major=%lu\r\nos.minor=%lu\r\n"
        "os.build-low=%lu\r\nos.exact-target=%u\r\n", version.dwPlatformId,
        version.dwMajorVersion, version.dwMinorVersion, (DWORD)LOWORD(version.dwBuildNumber), !!passed))
        return 2;
    if (!passed) {
        checkpoint(FALSE, "exit=3\r\n");
        return 3;
    }
    length = snprintf(command, sizeof(command), "\"%s\" %s", CHILD, argv[1]);
    if (length <= 0 || (size_t)length >= sizeof(command))
        return 10;
    memset(&startup, 0, sizeof(startup));
    memset(&process, 0, sizeof(process));
    startup.cb = sizeof(startup);
    created = CreateProcessA(CHILD, command, NULL, NULL, FALSE, 0, NULL,
        "C:\\GOPLAB", &startup, &process);
    error = created ? 0 : GetLastError();
    if (!checkpoint(FALSE, "child.created=%u\r\nchild.create-error=%lu\r\n", !!created, error)) {
        if (created) {
            stop_owned_child(process.hProcess, 7);
            CloseHandle(process.hThread);
            CloseHandle(process.hProcess);
        }
        return 2;
    }
    if (!created) {
        checkpoint(FALSE, "exit=4\r\n");
        return 4;
    }
    thread_closed = CloseHandle(process.hThread);
    if (!checkpoint(FALSE, "child.pid=%lu\r\nchild.thread-handle-closed=%u\r\n"
        "child.deadline-ms=%lu\r\n", process.dwProcessId, !!thread_closed, CHILD_DEADLINE_MS) ||
        !thread_closed) {
        stop_owned_child(process.hProcess, 7);
        if (!thread_closed)
            CloseHandle(process.hThread);
        CloseHandle(process.hProcess);
        return log_ok ? 6 : 2;
    }
    waited = WaitForSingleObject(process.hProcess, CHILD_DEADLINE_MS);
    error = waited == WAIT_FAILED ? GetLastError() : 0;
    if (waited == WAIT_OBJECT_0)
        query = GetExitCodeProcess(process.hProcess, &code);
    if (!checkpoint(FALSE, "child.wait=%lu\r\nchild.wait-error=%lu\r\n"
        "child.exit-query=%u\r\nchild.exit-code=%lu\r\n", waited, error, !!query, code)) {
        stop_owned_child(process.hProcess, 7);
        CloseHandle(process.hProcess);
        return 2;
    }
    passed = waited == WAIT_OBJECT_0 && query && code == 0;
    if (waited != WAIT_OBJECT_0)
        stop_owned_child(process.hProcess, 6);
    process_closed = CloseHandle(process.hProcess);
    passed = passed && process_closed;
    if (!checkpoint(FALSE, "child.process-handle-closed=%u\r\n"
        "child.post-CRT-exit-verified=%u\r\nsteam.application-passed=0\r\nexit=%u\r\n",
        !!process_closed, !!passed, passed ? 0 : 5))
        return 2;
    return passed ? 0 : 5;
}
