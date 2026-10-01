/* SPDX-License-Identifier: GPL-2.0-only
 * Original native Win98 diagnostic. Real QUERY plus the absent-Supervisor
 * W64_OPEN failure boundary; no Win64 execution or graphics bridge claim.
 * Build both modes as GUI i486 PE32 programs. Run only in an owned Win98 clone.
 */
#define WIN32_LEAN_AND_MEAN
#define WINVER 0x0410
#define _WIN32_WINNT 0x0400
#include <windows.h>
#include <cpuid.h>
#include "bridge.h"

#ifndef W64_NEGATIVE_NONCE
#error A fresh build-specific W64_NEGATIVE_NONCE is required
#endif
#ifndef W64_NEGATIVE_DIRECTORY
#define W64_NEGATIVE_DIRECTORY "C:\\W64LAB"
#endif
_Static_assert(sizeof(struct ntwv_query) == 32, "production QUERY ABI");
_Static_assert(sizeof(struct ntwv_w64_open) == 64, "production W64_OPEN ABI");
static HANDLE log_file = INVALID_HANDLE_VALUE;

static void record(const char *message, DWORD value)
{
    char line[160];
    static const char hex[] = "0123456789abcdef";
    DWORD length = 0, written, i;
    while (*message && length < sizeof line - 16) line[length++] = *message++;
    line[length++] = ' '; line[length++] = '0'; line[length++] = 'x';
    for (i = 0; i < 8; ++i) line[length++] = hex[(value >> (28 - 4 * i)) & 15];
    line[length++] = '\r'; line[length++] = '\n';
    if (!WriteFile(log_file, line, length, &written, NULL) || written != length) ExitProcess(3);
    if (!FlushFileBuffers(log_file)) ExitProcess(4);
}

#ifdef W64_NEGATIVE_OBSERVER
static void fail(const char *stage, DWORD error)
{
    record(stage, error);
    if (!CloseHandle(log_file)) ExitProcess(4);
    ExitProcess(1);
}
void mainCRTStartup(void)
{
    STARTUPINFOA startup = {0};
    PROCESS_INFORMATION process = {0};
    DWORD result, error, exit_code, attributes, bytes = 0;
    HANDLE child_log;
    char command[] = "W64NEG.EXE", text[112];
    const char prefix[] = "CASE " W64_NEGATIVE_NONCE " 0x00000000\r\n";
    unsigned i;
    if (!SetCurrentDirectoryA(W64_NEGATIVE_DIRECTORY)) ExitProcess(5);
    log_file = CreateFileA("W64OBS.LOG", GENERIC_WRITE, FILE_SHARE_READ, NULL,
                           CREATE_NEW, FILE_ATTRIBUTE_NORMAL, NULL);
    if (log_file == INVALID_HANDLE_VALUE) ExitProcess(2);
    record("CASE " W64_NEGATIVE_NONCE, 0);
    attributes = GetFileAttributesA("W64NEG.LOG"); error = GetLastError();
    record("PREEXISTING_PROBE_LOG_ATTRIBUTES", attributes);
    record("PREEXISTING_PROBE_LOG_ERROR", error);
    if (attributes != INVALID_FILE_ATTRIBUTES || error != ERROR_FILE_NOT_FOUND)
        fail("FAIL probe output must be absent", error);
    startup.cb = sizeof startup;
    if (!CreateProcessA(NULL, command, NULL, NULL, FALSE, 0, NULL, NULL, &startup, &process))
        fail("FAIL CreateProcess W64NEG", GetLastError());
    record("CHILD_PID", process.dwProcessId);
    result = WaitForSingleObject(process.hProcess, 30000); error = GetLastError();
    record("CHILD_WAIT", result); record("CHILD_WAIT_ERROR", error);
    if (result != WAIT_OBJECT_0) {
        BOOL terminated = TerminateProcess(process.hProcess, 1);
        DWORD termination_error = GetLastError();
        record("TIMEOUT_TERMINATE_RESULT", terminated);
        record("TIMEOUT_TERMINATE_ERROR", termination_error);
        record("TIMEOUT_TERMINATION_WAIT", WaitForSingleObject(process.hProcess, 5000));
        CloseHandle(process.hThread); CloseHandle(process.hProcess);
        fail("FAIL child wait", result);
    }
    if (!GetExitCodeProcess(process.hProcess, &exit_code)) fail("FAIL actual child OS exit query", GetLastError());
    record("CHILD_ACTUAL_OS_EXIT", exit_code);
    if (!CloseHandle(process.hThread)) fail("FAIL child thread close", GetLastError());
    if (!CloseHandle(process.hProcess)) fail("FAIL child process close", GetLastError());
    if (exit_code) fail("FAIL child OS exit", exit_code);
    child_log = CreateFileA("W64NEG.LOG", GENERIC_READ, FILE_SHARE_READ, NULL,
                            OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
    if (child_log == INVALID_HANDLE_VALUE) fail("FAIL fresh child report", GetLastError());
    if (!ReadFile(child_log, text, sizeof text, &bytes, NULL)) fail("FAIL child report read", GetLastError());
    if (!CloseHandle(child_log)) fail("FAIL child report close", GetLastError());
    if (bytes < sizeof prefix - 1) fail("FAIL child nonce extent", bytes);
    for (i = 0; i < sizeof prefix - 1; ++i)
        if (text[i] != prefix[i]) fail("FAIL child nonce", i);
    record("PASS fresh nonce and real child OS exit", 0);
    record("OBSERVER_SELECTED_EXIT", 0);
    if (!CloseHandle(log_file)) ExitProcess(4);
    ExitProcess(0); /* The outer owner's observer must establish our own exit. */
}
#else
static HANDLE device = INVALID_HANDLE_VALUE;
static void fail(const char *stage, DWORD error)
{
    record(stage, error);
    if (device != INVALID_HANDLE_VALUE) {
        BOOL closed = CloseHandle(device); DWORD close_error = GetLastError();
        record("FAILED_PATH_DEVICE_CLOSE", closed); record("FAILED_PATH_DEVICE_CLOSE_ERROR", close_error);
    }
    if (!CloseHandle(log_file)) ExitProcess(4);
    ExitProcess(1);
}
static void query(const char *stage)
{
    struct ntwv_query reply;
    DWORD returned = 0;
    if (!DeviceIoControl(device, NTWV_IOCTL_QUERY, NULL, 0, &reply, sizeof reply, &returned, NULL))
        fail("FAIL real production QUERY", GetLastError());
    if (returned != sizeof reply || reply.magic != NTWV_QUERY_MAGIC || reply.size != sizeof reply ||
        reply.abi != 1 || reply.core_abi != NTW_ABI_VERSION || reply.max_objects != NTW_MAX_OBJECTS ||
        reply.features != 1 || reply.initialized != 1 || reply.selftest != 1)
        fail("FAIL production QUERY payload", returned);
    record(stage, reply.core_abi);
}
void mainCRTStartup(void)
{
    struct ntwv_w64_open reply;
    unsigned eax = 0, ebx = 0, ecx = 0, edx = 0, sigb = 0, sigc = 0, sigd = 0;
    DWORD returned, error, cycle;
    BOOL success;
    unsigned i, changed;
    if (!SetCurrentDirectoryA(W64_NEGATIVE_DIRECTORY)) ExitProcess(5);
    log_file = CreateFileA("W64NEG.LOG", GENERIC_WRITE, FILE_SHARE_READ, NULL,
                           CREATE_NEW, FILE_ATTRIBUTE_NORMAL, NULL);
    if (log_file == INVALID_HANDLE_VALUE) ExitProcess(2);
    record("CASE " W64_NEGATIVE_NONCE, 0);
    /* Read the real CPU advertisement. cpuid.h checks EFLAGS.ID before CPUID
     * on an i486. Never override a signature or call VMCALL from this probe. */
    if (__get_cpuid(1, &eax, &ebx, &ecx, &edx) && (ecx & 0x80000000u)) {
        unsigned unused;
        __cpuid(0x40000000u, unused, sigb, sigc, sigd);
        (void)unused;
    }
    record("REAL_CPUID1_ECX", ecx);
    record("REAL_HYPERVISOR_EBX", sigb); record("REAL_HYPERVISOR_ECX", sigc); record("REAL_HYPERVISOR_EDX", sigd);
    if ((ecx & 0x80000000u) && sigb == 0x5a485353u && sigc == 0x4d4d5675u && sigd == 0x30312d76u)
        fail("FAIL negative fixture requires absent Shizuku Supervisor", 1);
    for (cycle = 0; cycle < 2; ++cycle) {
        record("BEGIN_REAL_LOAD_CYCLE", cycle + 1);
        device = CreateFileA("\\\\.\\NTWRAP9X.VXD", 0, 0, NULL, OPEN_EXISTING,
                             FILE_FLAG_DELETE_ON_CLOSE, NULL);
        if (device == INVALID_HANDLE_VALUE) fail("FAIL real production VXD open", GetLastError());
        query("PASS_REAL_QUERY_BEFORE_OPEN");
        for (i = 0; i < sizeof reply; ++i) ((unsigned char *)&reply)[i] = 0xa5;
        returned = 0xa5a5a5a5u;
        success = DeviceIoControl(device, NTWV_IOCTL_W64_OPEN, NULL, 0,
                                  &reply, sizeof reply, &returned, NULL);
        error = GetLastError(); /* Capture before any diagnostic WriteFile. */
        record("ACTUAL_W64_OPEN_IOCTL", NTWV_IOCTL_W64_OPEN);
        record("ACTUAL_W64_OPEN_RESULT", success);
        record("ACTUAL_W64_OPEN_ERROR", error);
        /* VWIN32 may normalize returned count on failure. Record it without
         * inventing a requirement on the native dispatcher's normalization. */
        record("ACTUAL_W64_OPEN_RETURNED_BYTES", returned);
        if (success || error != NTWV_ERROR_NOT_SUPPORTED) fail("FAIL absent Supervisor gate", error);
        changed = 0;
        for (i = 0; i < sizeof reply; ++i)
            if (((unsigned char *)&reply)[i] != 0xa5) ++changed;
        record("FAILED_OUTPUT_CHANGED_BYTES", changed);
        /* A failed Win32 call does not publish a valid channel. Native VWIN32
         * output-buffer behavior is diagnostic; do not interpret reply fields. */
        record("PASS_ABSENT_SUPERVISOR_GATE_50", 50);
        query("PASS_REAL_QUERY_AFTER_REJECTION");
        if (!CloseHandle(device)) fail("FAIL checked real VXD close", GetLastError());
        device = INVALID_HANDLE_VALUE;
        record("PASS_REAL_DEVICE_CLOSE_REQUEST", cycle + 1);
    }
    record("PASS_NATIVE_W64_NEGATIVE_GATE", 0);
    if (!CloseHandle(log_file)) ExitProcess(4);
    ExitProcess(0); /* W64OBS records the actual process exit, not this intent. */
}
#endif
