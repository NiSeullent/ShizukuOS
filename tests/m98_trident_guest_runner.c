/* SPDX-License-Identifier: GPL-2.0-only
 * Native single-child observer for real script or genuine MSHTML fixtures.
 * Derived from m98_tls13_guest_runner.c in this project (GPL-2.0-only); the
 * independent source file and fixtures avoid overlapping theme ownership.
 * No console, CRT, installation, registry changes, or unrelated processes. */
#ifdef M98_RUNNER_HOST_TEST
#include "m98_tls13_guest_runner_mock.h"
#else
#define WIN32_LEAN_AND_MEAN
#define _WIN32_WINNT 0x0400
#include <windows.h>
#endif

#ifndef M98_RUN_NONCE
#error Build with a frozen M98_RUN_NONCE
#endif

#if !defined(M98_TRIDENT_AUTOMATION) || (M98_TRIDENT_AUTOMATION != 0 && M98_TRIDENT_AUTOMATION != 1)
#error Select explicit runtime-only or genuine MSHTML observer profile
#endif
#define ROOT_DIR "C:\\GOPLAB"
#if M98_TRIDENT_AUTOMATION
#define SELF_PATH ROOT_DIR "\\M98AURUN.EXE"
#define RUN_LOG ROOT_DIR "\\AURUN.LOG"
#define FIRST_LOG ROOT_DIR "\\AUOUT.LOG"
#define CHILD_LOG ROOT_DIR "\\AUT13.LOG"
#define CHILD_PATH ROOT_DIR "\\M98AUTPR.EXE"
#define CHILD_TIMEOUT_MS 240000u
#else
#define SELF_PATH ROOT_DIR "\\M98JSRUN.EXE"
#define RUN_LOG ROOT_DIR "\\JSRUN.LOG"
#define FIRST_LOG ROOT_DIR "\\JSOUT.LOG"
#define CHILD_LOG ROOT_DIR "\\QJS13.LOG"
#define CHILD_PATH ROOT_DIR "\\QJS13PR.EXE"
#define CHILD_TIMEOUT_MS 60000u
#endif
#define REAP_TIMEOUT_MS 5000u

static HANDLE run_log = INVALID_HANDLE_VALUE;
static BOOL log_ok = TRUE;

static void zero_bytes(void *p, DWORD n)
{
    unsigned char *s = (unsigned char *)p;
    while (n--) *s++ = 0;
}

static BOOL write_all(HANDLE file, const char *text)
{
    DWORD length = 0, written;
    while (text[length]) ++length;
    while (length) {
        if (!WriteFile(file, text, length, &written, NULL) || !written || written > length)
            return FALSE;
        text += written;
        length -= written;
    }
    return TRUE;
}

static void say(const char *text)
{
    if (!write_all(run_log, text)) log_ok = FALSE;
}

static void number(const char *name, DWORD value)
{
    char digits[11];
    DWORD n = 10;
    digits[n] = 0;
    do { digits[--n] = (char)('0' + value % 10u); value /= 10u; } while (value);
    say(name); say(digits + n); say("\r\n");
}

static BOOL absent(const char *path)
{
    DWORD error;
    if (GetFileAttributesA(path) != INVALID_FILE_ATTRIBUTES) return FALSE;
    error = GetLastError();
    return error == ERROR_FILE_NOT_FOUND;
}

static BOOL close_checked(HANDLE *handle)
{
    BOOL result = TRUE;
    if (*handle != INVALID_HANDLE_VALUE && *handle != NULL) result = CloseHandle(*handle);
    *handle = INVALID_HANDLE_VALUE;
    return result;
}

/* safe_to_continue is false if the exclusively owned child was not reaped. */
static BOOL child_probe(const char *application, const char *log_path, BOOL *safe_to_continue)
{
    SECURITY_ATTRIBUTES inherit;
    STARTUPINFOA startup;
    PROCESS_INFORMATION process;
    HANDLE output = INVALID_HANDLE_VALUE, input = INVALID_HANDLE_VALUE;
    char command[MAX_PATH];
    DWORD i = 0, waited, actual_exit = 0, error, reaped, wait_error;
    BOOL created = FALSE, exited = FALSE, success = FALSE, flushed, cleanup = TRUE;

    *safe_to_continue = TRUE;
    say("child.path="); say(application); say("\r\nchild.stdout="); say(log_path); say("\r\n");
    zero_bytes(&inherit, sizeof(inherit));
    inherit.nLength = sizeof(inherit); inherit.bInheritHandle = TRUE;
    output = CreateFileA(log_path, GENERIC_WRITE, FILE_SHARE_READ, &inherit,
                         CREATE_NEW, FILE_ATTRIBUTE_NORMAL, NULL);
    if (output == INVALID_HANDLE_VALUE) {
        number("child.output-create-error=", GetLastError());
        /* A raced or stale log prevents any further child execution. */
        *safe_to_continue = FALSE;
        goto done;
    }
    input = CreateFileA("NUL", GENERIC_READ, FILE_SHARE_READ | FILE_SHARE_WRITE,
                        &inherit, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
    if (input == INVALID_HANDLE_VALUE) {
        number("child.input-create-error=", GetLastError()); goto done;
    }
    while (application[i]) { command[i] = application[i]; ++i; }
    command[i] = 0;
    zero_bytes(&startup, sizeof(startup)); zero_bytes(&process, sizeof(process));
    startup.cb = sizeof(startup); startup.dwFlags = STARTF_USESTDHANDLES;
    startup.hStdInput = input; startup.hStdOutput = output; startup.hStdError = output;
    SetLastError(0);
    created = CreateProcessA(application, command, NULL, NULL, TRUE, 0, NULL,
                             ROOT_DIR, &startup, &process);
    error = GetLastError();
    number("child.created=", created != FALSE); number("child.create-error=", created ? 0u : error);
    if (!created) goto done;
    number("child.pid=", process.dwProcessId);
    cleanup = close_checked(&process.hThread) && cleanup;
    cleanup = close_checked(&input) && cleanup;
    waited = WaitForSingleObject(process.hProcess, CHILD_TIMEOUT_MS);
    wait_error = waited == WAIT_FAILED ? GetLastError() : 0u;
    number("child.wait=", waited);
    if (waited == WAIT_OBJECT_0) {
        exited = GetExitCodeProcess(process.hProcess, &actual_exit);
        error = exited ? 0u : GetLastError();
        number("child.exit-query=", exited != FALSE); number("child.exit-query-error=", error);
        if (exited) number("child.exit-code=", actual_exit);
        success = exited && actual_exit == 0;
    } else {
        BOOL terminated;
        number("child.wait-error=", wait_error);
        /* Termination is limited to this exact CreateProcess-owned handle. */
        terminated = TerminateProcess(process.hProcess, ERROR_TIMEOUT);
        error = terminated ? 0u : GetLastError();
        number("child.terminated=", terminated != FALSE);
        if (!terminated) number("child.terminate-error=", error);
        reaped = WaitForSingleObject(process.hProcess, REAP_TIMEOUT_MS);
        number("child.reap-wait=", reaped);
        *safe_to_continue = reaped == WAIT_OBJECT_0;
        if (*safe_to_continue && GetExitCodeProcess(process.hProcess, &actual_exit))
            number("child.exit-code-after-stop=", actual_exit);
    }
    cleanup = close_checked(&process.hProcess) && cleanup;
done:
    if (output != INVALID_HANDLE_VALUE) {
        flushed = FlushFileBuffers(output);
        number("child.stdout-flushed=", flushed != FALSE);
        cleanup = flushed && cleanup;
    }
    cleanup = close_checked(&input) && cleanup;
    cleanup = close_checked(&output) && cleanup;
    number("child.handles-closed=", cleanup != FALSE);
    number("child.success=", success && cleanup);
    if (!FlushFileBuffers(run_log)) log_ok = FALSE;
    return success && cleanup && log_ok;
}

static DWORD supervise(void)
{
    OSVERSIONINFOA version;
    char module[MAX_PATH];
    DWORD length, result = 1;
    BOOL child = FALSE, safe = TRUE, exact_os;

    run_log = CreateFileA(RUN_LOG, GENERIC_WRITE, FILE_SHARE_READ, NULL,
                          CREATE_NEW, FILE_ATTRIBUTE_NORMAL, NULL);
    if (run_log == INVALID_HANDLE_VALUE) return 10;
    say("scope=actual-win98-trident-owned-child-observer\r\nnonce=" M98_RUN_NONCE "\r\n");
#if M98_TRIDENT_AUTOMATION
    say("profile=genuine-mshtml-direct-host\r\n");
#else
    say("profile=runtime-only\r\n");
#endif
    zero_bytes(&version, sizeof(version)); version.dwOSVersionInfoSize = sizeof(version);
    exact_os = GetVersionExA(&version) && version.dwPlatformId == VER_PLATFORM_WIN32_WINDOWS &&
               version.dwMajorVersion == 4 && version.dwMinorVersion == 10 &&
               LOWORD(version.dwBuildNumber) == 2222;
    number("WIN98_IDENTIFIED=", exact_os != FALSE);
    number("os.major=", version.dwMajorVersion); number("os.minor=", version.dwMinorVersion);
    number("os.build-low=", LOWORD(version.dwBuildNumber)); number("os.platform=", version.dwPlatformId);
    length = GetModuleFileNameA(NULL, module, sizeof(module));
    if (!exact_os) { result = 11; goto done; }
    if (!length || length >= sizeof(module) || lstrcmpiA(module, SELF_PATH)) {
        say("FAIL: supervisor path mismatch\r\n"); result = 12; goto done;
    }
    if (!absent(FIRST_LOG) || !absent(CHILD_LOG)) {
        say("FAIL: child log exists or absence could not be established\r\n"); result = 13; goto done;
    }
    if (!log_ok || !FlushFileBuffers(run_log)) { result = 14; goto done; }
    child = child_probe(CHILD_PATH, FIRST_LOG, &safe);
    result = child && safe && log_ok ? 0u : 15u;
done:
    /* This is the result requested before final flush/close/ExitProcess.
     * An outer observer must obtain the actual supervisor exit separately. */
    number("supervisor.requested-exit-code=", result);
    if (!FlushFileBuffers(run_log) || !log_ok) result = 14;
    if (!close_checked(&run_log)) result = 14;
    return result;
}

#ifndef M98_RUNNER_HOST_TEST
void mainCRTStartup(void) { ExitProcess(supervise()); }
#endif
