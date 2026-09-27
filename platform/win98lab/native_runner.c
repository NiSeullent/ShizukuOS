/* SPDX-License-Identifier: GPL-2.0-only
 * Original Win98 probe supervisor. No CRT or implementation from an SDK.
 * Public API contracts: Microsoft CreateProcessA, WaitForSingleObject,
 * GetExitCodeProcess, TerminateProcess, GetVersionExA and file API reference.
 * https://learn.microsoft.com/en-us/windows/win32/api/processthreadsapi/nf-processthreadsapi-createprocessa
 * https://learn.microsoft.com/en-us/windows/win32/api/synchapi/nf-synchapi-waitforsingleobject
 * https://learn.microsoft.com/en-us/windows/win32/api/processthreadsapi/nf-processthreadsapi-getexitcodeprocess
 * https://learn.microsoft.com/en-us/windows/win32/api/processthreadsapi/nf-processthreadsapi-terminateprocess
 * Current Learn support tables do not prove Win98 execution: the native
 * artifact must be tested in the actual disposable guest before acceptance.
 *
 * Install all original binaries in the exclusively owned C:\NTWLAB directory.
 * Existing logs are preserved and cause refusal. This program neither hashes
 * files nor validates child log contents; a host collector must bind the media,
 * executable hashes, complete logs, stopped guest and screenshot separately.
 * OS-reported process waits are bounded. A hung native API or VMM still needs
 * the external guest watchdog. Failed termination means guest state is unknown.
 */
#define WIN32_LEAN_AND_MEAN
#define WINVER 0x0410
#define _WIN32_WINNT 0x0400
#ifdef NTWRUN_TEST
#include "native_runner_mock.h"
#else
#include <windows.h>
#endif

#define PROBE_WAIT_MS 120000u
#define STOP_WAIT_MS 5000u
#define STOP_EXIT_CODE 0x4e545701u
static const char directory[] = "C:\\NTWLAB";
static const char self_path[] = "C:\\NTWLAB\\NTWRUN.EXE";
static const char runner_log[] = "C:\\NTWLAB\\NTWRUN.LOG";
static const char *const probes[] = { "NTWPROBE.EXE", "NTWQUERY.EXE", "NTWGPROB.EXE" };
static const char *const logs[] = { "NTWPROBE.LOG", "NTWQUERY.LOG", "NTWGPROB.LOG" };

typedef struct runner { HANDLE log; int io_failed; } runner;

static DWORD length(const char *text)
{
    DWORD n = 0;
    while (text[n]) ++n;
    return n;
}

static void bytes(runner *r, const char *text, DWORD n)
{
    DWORD written = 0;
    if (r->io_failed) return;
    if (!WriteFile(r->log, text, n, &written, NULL) || written != n)
        r->io_failed = 1;
}

static void field(runner *r, const char *key, const char *value)
{
    bytes(r, key, length(key));
    bytes(r, "=", 1);
    bytes(r, value, length(value));
    bytes(r, "\r\n", 2);
    if (!r->io_failed && !FlushFileBuffers(r->log)) r->io_failed = 1;
}

static void number(runner *r, const char *key, DWORD n)
{
    char reversed[10], text[11];
    DWORD count = 0, i;
    do { reversed[count++] = (char)('0' + n % 10u); n /= 10u; } while (n);
    for (i = 0; i < count; ++i) text[i] = reversed[count - i - 1u];
    text[count] = 0;
    field(r, key, text);
}

static int error(runner *r, const char *stage, DWORD code)
{
    field(r, "FAIL_STAGE", stage);
    number(r, "WIN32_ERROR", code);
    return 0;
}

static void path_for(char path[64], const char *name)
{
    DWORD n = 0, i = 0;
    while (directory[n]) { path[n] = directory[n]; ++n; }
    path[n++] = '\\';
    do { path[n++] = name[i]; } while (name[i++]);
}

static int correct_location(void)
{
    char path[MAX_PATH] = {0};
    DWORD i, n = GetModuleFileNameA(NULL, path, MAX_PATH);
    if (!n || n >= MAX_PATH || n != sizeof(self_path) - 1u || path[n] != 0) return 0;
    for (i = 0; i < n; ++i) {
        char ch = path[i];
        if (ch >= 'a' && ch <= 'z') ch = (char)(ch - 'a' + 'A');
        if (ch != self_path[i]) return 0;
    }
    return 1;
}

static int close_owned(runner *r, HANDLE handle, const char *stage)
{
    if (!CloseHandle(handle)) {
        DWORD code = GetLastError();
        return error(r, stage, code);
    }
    field(r, stage, "PASS");
    return !r->io_failed;
}

static void stop_child(runner *r, HANDLE process)
{
    DWORD state, code;
    if (!TerminateProcess(process, STOP_EXIT_CODE)) {
        code = GetLastError();
        (void)error(r, "TerminateProcess", code);
    } else field(r, "TERMINATE_REQUESTED", "1");
    /* TerminateProcess is asynchronous. A request is never a stopped proof. */
    state = WaitForSingleObject(process, STOP_WAIT_MS);
    code = state == WAIT_FAILED ? GetLastError() : 0;
    number(r, "STOP_WAIT_RESULT", state);
    if (state != WAIT_OBJECT_0) {
        if (state == WAIT_FAILED) (void)error(r, "StopWait", code);
        field(r, "CHILD_STOPPED", "UNKNOWN");
        return;
    }
    field(r, "CHILD_STOPPED", "1");
    if (!GetExitCodeProcess(process, &code)) {
        code = GetLastError();
        (void)error(r, "StopGetExitCodeProcess", code);
    } else number(r, "STOP_EXIT_CODE", code);
}

static int child(runner *r, const char *name)
{
    STARTUPINFOA startup = {0};
    PROCESS_INFORMATION process = {0};
    char path[64], command[68];
    DWORD n, i, state, code;
    int success = 0, known_stopped = 0;
    path_for(path, name);
    n = length(path);
    command[0] = '"';
    for (i = 0; i < n; ++i) command[i + 1u] = path[i];
    command[n + 1u] = '"'; command[n + 2u] = 0;
    startup.cb = sizeof(startup);
    field(r, "BEGIN", name);
    if (r->io_failed) return 0;
    if (!CreateProcessA(path, command, NULL, NULL, FALSE, 0, NULL,
                        directory, &startup, &process)) {
        code = GetLastError();
        return error(r, "CreateProcessA", code);
    }
    field(r, "PROCESS_CREATED", "1");
    if (r->io_failed) goto cleanup;
    state = WaitForSingleObject(process.hProcess, PROBE_WAIT_MS);
    code = state == WAIT_FAILED ? GetLastError() : 0;
    number(r, "WAIT_RESULT", state);
    if (state != WAIT_OBJECT_0) {
        (void)error(r, state == WAIT_TIMEOUT ? "ProbeTimeout" : "ProbeWait", code);
        goto cleanup;
    }
    known_stopped = 1;
    if (!GetExitCodeProcess(process.hProcess, &code)) {
        code = GetLastError();
        (void)error(r, "GetExitCodeProcess", code);
        goto cleanup;
    }
    /* Do not truncate DWORD exit codes or infer success from a child log. */
    number(r, "EXIT_CODE", code);
    success = code == 0 && !r->io_failed;
cleanup:
    if (!known_stopped) stop_child(r, process.hProcess);
    /* Always attempt BOTH closes, including on log failure and close failure. */
    if (!close_owned(r, process.hThread, "CLOSE_THREAD")) success = 0;
    if (!close_owned(r, process.hProcess, "CLOSE_PROCESS")) success = 0;
    if (success && !r->io_failed) field(r, "END", name);
    return success && !r->io_failed;
}

void mainCRTStartup(void)
{
    runner r;
    OSVERSIONINFOA version = {0};
    DWORD i, attributes, code;
    char path[64];
    int success = 0;
    if (!correct_location()) ExitProcess(2);
    r.io_failed = 0;
    r.log = CreateFileA(runner_log, GENERIC_WRITE, FILE_SHARE_READ, NULL,
                        CREATE_NEW, FILE_ATTRIBUTE_NORMAL, NULL);
    if (r.log == INVALID_HANDLE_VALUE) ExitProcess(2);
    field(&r, "NTWRUN_VERSION", "1");
    field(&r, "DIRECTORY", directory);
    if (r.io_failed) goto done;
    version.dwOSVersionInfoSize = sizeof(version);
    if (!GetVersionExA(&version)) {
        code = GetLastError(); (void)error(&r, "GetVersionExA", code); goto done;
    }
    number(&r, "OS_PLATFORM", version.dwPlatformId);
    number(&r, "OS_MAJOR", version.dwMajorVersion);
    number(&r, "OS_MINOR", version.dwMinorVersion);
    number(&r, "OS_BUILD_RAW", version.dwBuildNumber);
    number(&r, "OS_BUILD_LOW", version.dwBuildNumber & 0xffffu);
    if (version.dwPlatformId != VER_PLATFORM_WIN32_WINDOWS ||
        version.dwMajorVersion != 4 || version.dwMinorVersion != 10) {
        field(&r, "WIN98_IDENTIFIED", "0"); goto done;
    }
    field(&r, "WIN98_IDENTIFIED", "1");
    if (r.io_failed) goto done;
    for (i = 0; i < 3; ++i) {
        path_for(path, logs[i]);
        attributes = GetFileAttributesA(path);
        if (attributes != INVALID_FILE_ATTRIBUTES) {
            field(&r, "EXISTING_LOG", logs[i]); goto done;
        }
        code = GetLastError();
        if (code != ERROR_FILE_NOT_FOUND) {
            (void)error(&r, "LogPreflight", code); goto done;
        }
    }
    field(&r, "PREFLIGHT", "PASS");
    for (i = 0; i < 3; ++i) {
        if (r.io_failed || !child(&r, probes[i])) goto done;
    }
    success = 1;
done:
    field(&r, "RESULT", success ? "PASS" : "FAIL");
    /* RESULT=PASS without this process's separately captured zero exit is not
     * acceptance: a final close failure cannot be appended to a closed log. */
    if (!CloseHandle(r.log)) r.io_failed = 1;
    ExitProcess(r.io_failed ? 3u : success ? 0u : 1u);
}
