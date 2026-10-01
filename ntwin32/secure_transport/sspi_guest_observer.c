/* SPDX-License-Identifier: GPL-2.0-only
 * Original bounded observer for the explicit-loading native ANSI SSPI fixture.
 * No CRT, arbitrary executable, shell, network, or global configuration use.
 * The child handle belongs exclusively to CreateProcessA below. Its actual
 * OS exit, after its own CRT teardown, is independent of its fixture log.
 */
#define WIN32_LEAN_AND_MEAN
#define WINVER 0x0410
#define _WIN32_WINNT 0x0400
#include <windows.h>

#define CHILD_TIMEOUT_MS 90000u
#define REAP_TIMEOUT_MS 5000u
#define GUARD_EXIT_CODE 0x77070001u

static const char self_path[] = "C:\\GOPLAB\\SSPWATCH.EXE";
static const char child_path[] = "C:\\GOPLAB\\TLS13PRB.EXE";
static const char child_log[] = "C:\\GOPLAB\\SSPI13.LOG";
static const char observer_log[] = "C:\\GOPLAB\\SSPIOBS.LOG";
static const char working_directory[] = "C:\\GOPLAB";
static const char child_arguments[] =
    "C:\\GOPLAB\\TLS13PRB.EXE --nonce ";

static HANDLE report;
static int io_failed;

static unsigned length(const char *value)
{
    unsigned n = 0;
    while (value[n]) ++n;
    return n;
}

static int equal(const char *left, const char *right)
{
    while (*left && *left == *right) { ++left; ++right; }
    return *left == *right;
}

static int equal_path(const char *left, const char *right)
{
    unsigned char a, b;
    do {
        a = (unsigned char)*left++; b = (unsigned char)*right++;
        if (a >= 'a' && a <= 'z') a -= 'a' - 'A';
        if (b >= 'a' && b <= 'z') b -= 'a' - 'A';
        if (a != b) return 0;
    } while (a);
    return 1;
}

/* Quotes are accepted only as a whole token, never as escapes or fragments. */
static int token(const char **cursor, char *out, unsigned capacity)
{
    const char *p = *cursor;
    unsigned n = 0;
    int quoted;
    while (*p == ' ' || *p == '\t') ++p;
    if (!*p) return 0;
    quoted = *p == '"';
    if (quoted) ++p;
    while (*p && (quoted ? *p != '"' : *p != ' ' && *p != '\t')) {
        if (*p == '"' || (unsigned char)*p < 32 || (unsigned char)*p > 126 ||
                n + 1 >= capacity) return 0;
        out[n++] = *p++;
    }
    if (quoted) {
        if (*p++ != '"') return 0;
        if (*p && *p != ' ' && *p != '\t') return 0;
    }
    out[n] = 0;
    *cursor = p;
    return n != 0;
}

static int arguments(char nonce[65])
{
    char executable[MAX_PATH], option[16], actual[MAX_PATH];
    const char *cursor = GetCommandLineA();
    unsigned i, n;
    DWORD got = GetModuleFileNameA(NULL, actual, sizeof actual);
    if (!got || got >= sizeof actual || actual[got] ||
            !equal_path(actual, self_path) || !cursor) return 0;
    /* Bound the read before tokenization; the valid command is under 128 bytes. */
    for (i = 0; i < 256 && cursor[i]; ++i) {}
    if (i == 256 || !token(&cursor, executable, sizeof executable) ||
            !equal_path(executable, self_path) ||
            !token(&cursor, option, sizeof option) || !equal(option, "--nonce") ||
            !token(&cursor, nonce, 65)) return 0;
    while (*cursor == ' ' || *cursor == '\t') ++cursor;
    if (*cursor) return 0;
    n = length(nonce);
    if (n < 16 || n > 64) return 0;
    for (i = 0; i < n; ++i) {
        char c = nonce[i];
        if (!((c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') ||
                (c >= '0' && c <= '9') || c == '-')) return 0;
    }
    return 1;
}

static int absent(const char *path)
{
    DWORD error;
    SetLastError(0);
    if (GetFileAttributesA(path) != INVALID_FILE_ATTRIBUTES) return 0;
    error = GetLastError();
    return error == ERROR_FILE_NOT_FOUND;
}

static void bytes(const char *data, unsigned size)
{
    DWORD written;
    while (size && !io_failed) {
        written = 0;
        if (!WriteFile(report, data, size, &written, NULL) ||
                !written || written > size) {
            io_failed = 1;
            return;
        }
        data += written; size -= written;
    }
}

static void text(const char *name, const char *value)
{
    bytes(name, length(name)); bytes("=", 1); bytes(value, length(value));
    bytes("\r\n", 2);
    if (!io_failed && !FlushFileBuffers(report)) io_failed = 1;
}

static void number(const char *name, DWORD value)
{
    char reverse[10], digits[11];
    unsigned n = 0, i;
    do { reverse[n++] = (char)('0' + value % 10); value /= 10; } while (value);
    for (i = 0; i < n; ++i) digits[i] = reverse[n - i - 1];
    digits[n] = 0; text(name, digits);
}

static int close_recorded(HANDLE handle, const char *field, const char *error_field)
{
    BOOL closed;
    DWORD error;
    SetLastError(0);
    closed = CloseHandle(handle);
    error = closed ? 0 : GetLastError();
    number(field, closed != FALSE); number(error_field, error);
    return closed != FALSE;
}

void mainCRTStartup(void)
{
    char nonce[65], command[384];
    OSVERSIONINFOA version = {0};
    STARTUPINFOA start = {0};
    PROCESS_INFORMATION child = {0};
    unsigned prefix, i;
    DWORD error, waited, code = 0xFFFFFFFFu, result = 23;
    BOOL ok, terminated, queried = FALSE;
    int native, thread_closed, process_closed, ended = 0;

    if (!arguments(nonce)) { ExitProcess(20); return; }
    if (!absent(child_log) || !absent(observer_log)) { ExitProcess(22); return; }
    report = CreateFileA(observer_log, GENERIC_WRITE, 0, NULL, CREATE_NEW,
                         FILE_ATTRIBUTE_NORMAL, NULL);
    if (report == INVALID_HANDLE_VALUE) { ExitProcess(21); return; }
    text("schema", "win98modern.sspi-owned-child-observer.v1");
    text("scope", "fixed-explicit-SSPI-fixture-actual-post-CRT-child-exit");
    text("nonce", nonce);
    text("observer.application", self_path);
    number("observer.pid", GetCurrentProcessId());
    number("observer.tid", GetCurrentThreadId());
    version.dwOSVersionInfoSize = sizeof version;
    SetLastError(0);
    ok = GetVersionExA(&version);
    error = ok ? 0 : GetLastError();
    native = ok && version.dwPlatformId == VER_PLATFORM_WIN32_WINDOWS &&
        version.dwMajorVersion == 4 && version.dwMinorVersion == 10 &&
        (version.dwBuildNumber & 0xFFFFu) == 2222;
    number("os.query-ok", ok != FALSE); number("os.query-error", error);
    number("os.platform", version.dwPlatformId); number("os.major", version.dwMajorVersion);
    number("os.minor", version.dwMinorVersion); number("os.build", version.dwBuildNumber);
    number("os.build-low", version.dwBuildNumber & 0xFFFFu);
    number("os.exact-win98se", native);
    if (!native || io_failed) goto finish;
    prefix = length(child_arguments);
    for (i = 0; i < prefix; ++i) command[i] = child_arguments[i];
    for (i = 0; nonce[i]; ++i) command[prefix + i] = nonce[i];
    command[prefix + i] = 0;
    text("child.application", child_path); text("child.command", command);
    text("child.directory", working_directory);
    number("child.timeout-ms", CHILD_TIMEOUT_MS);
    /* Recheck freshness immediately before starting the exclusively owned child. */
    ok = absent(child_log);
    number("child.output-absent-before-create", ok != FALSE);
    result = 22;
    if (!ok || io_failed) goto finish;
    start.cb = sizeof start;
    SetLastError(0);
    ok = CreateProcessA(child_path, command, NULL, NULL, FALSE, 0, NULL,
                        working_directory, &start, &child);
    error = ok ? 0 : GetLastError();
    number("child.created", ok != FALSE); number("child.create-error", error);
    result = 24;
    if (!ok) goto finish;
    number("child.pid", child.dwProcessId); number("child.tid", child.dwThreadId);
    thread_closed = close_recorded(child.hThread, "child.thread-handle-closed",
                                   "child.thread-handle-close-error");
    SetLastError(0);
    waited = WaitForSingleObject(child.hProcess, CHILD_TIMEOUT_MS);
    error = waited == WAIT_FAILED ? GetLastError() : 0;
    number("child.wait", waited); number("child.wait-error", error);
    if (waited == WAIT_OBJECT_0) {
        ended = 1;
        SetLastError(0);
        queried = GetExitCodeProcess(child.hProcess, &code);
        error = queried ? 0 : GetLastError();
        number("child.exit-query", queried != FALSE); number("child.exit-query-error", error);
        number("child.exit-code", code);
        result = !queried ? 26 : code ? 27 : 0;
    } else {
        /* Timeout and wait failures remain failures even if guard reaping succeeds. */
        result = 25;
        SetLastError(0);
        terminated = TerminateProcess(child.hProcess, GUARD_EXIT_CODE);
        error = terminated ? 0 : GetLastError();
        number("child.guard-terminate", terminated != FALSE);
        number("child.guard-terminate-error", error); number("child.guard-exit-request", GUARD_EXIT_CODE);
        SetLastError(0);
        waited = WaitForSingleObject(child.hProcess, REAP_TIMEOUT_MS);
        error = waited == WAIT_FAILED ? GetLastError() : 0;
        number("child.guard-wait", waited); number("child.guard-wait-error", error);
        ended = waited == WAIT_OBJECT_0;
        if (ended) {
            SetLastError(0);
            queried = GetExitCodeProcess(child.hProcess, &code);
            error = queried ? 0 : GetLastError();
            number("child.guard-exit-query", queried != FALSE);
            number("child.guard-exit-query-error", error); number("child.guard-exit-code", code);
        }
    }
    process_closed = close_recorded(child.hProcess, "child.process-handle-closed",
                                    "child.process-handle-close-error");
    number("child.terminated", ended);
    number("child.post-crt-zero-exit-observed", ended && queried && !code && !result);
    if (!thread_closed || !process_closed) result = 28;
finish:
    if (io_failed) result = 29;
    number("observer.exit-candidate", result);
    /* This is provisional: only the real observer OS exit includes close success. */
    text("observer.success-requires-report-close", "1");
    if (io_failed) result = 29;
    if (!CloseHandle(report)) result = 29;
    ExitProcess(result);
}
