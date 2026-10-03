/* SPDX-License-Identifier: GPL-2.0-only
 * Literal production frontend; native Win32 and NTW32 callbacks are modeled.
 * No Windows, VxD, Kernel64 or application executes in these host controls. */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "mock/windows.h"
typedef uint16_t WCHAR;
#define CP_ACP 0u
#define STD_INPUT_HANDLE ((DWORD)-10)
#define STD_OUTPUT_HANDLE ((DWORD)-11)
#define STD_ERROR_HANDLE ((DWORD)-12)
#define ERROR_WRITE_FAULT 29u
#define ERROR_INVALID_DATA 13u
const char *GetCommandLineA(void);
HANDLE GetStdHandle(DWORD);
BOOL WriteFile(HANDLE, const void *, DWORD, DWORD *, void *);
BOOL ReadFile(HANDLE, void *, DWORD, DWORD *, void *);
int MultiByteToWideChar(unsigned, DWORD, const char *, int, WCHAR *, int);
void ExitProcess(DWORD);
#ifndef NTW64RUN_SOURCE
#define NTW64RUN_SOURCE "../ntw64run.c"
#endif
#include NTW64RUN_SOURCE

static unsigned checks, reads, input_reads, writes, input_writes, eof_closes, waits, closes, kills;
static DWORD error_value, remote_exit;
static const char *scenario;
static unsigned char captured[8192];
static size_t captured_bytes;
static char diagnostics[8192];
static size_t diagnostic_bytes;
static const unsigned char payload[] = {'A', 0, 'B', 0xff, '\r', '\n', 'Z'};
#define CHECK(x) do { ++checks; if (!(x)) { fprintf(stderr, "FAIL %s line %d: %s\n", scenario, __LINE__, #x); exit(1); } } while (0)
static int is(const char *name) { return strcmp(scenario, name) == 0; }
void SetLastError(DWORD e) { error_value = e; }
DWORD GetLastError(void) { return error_value; }
void ExitProcess(DWORD code) { CHECK(code == remote_exit); }
const char *GetCommandLineA(void)
{
    if (is("query") || is("query-output-fail")) return "NTW64RUN /q";
    if (is("usage")) return "NTW64RUN";
    if (strncmp(scenario, "stdin-", 6) == 0 || is("early-child") || is("native-input-eof"))
        return "NTW64RUN /i T_HELLO.EXE";
    return "NTW64RUN T_HELLO.EXE";
}
HANDLE GetStdHandle(DWORD id)
{
    CHECK(id == STD_INPUT_HANDLE || id == STD_OUTPUT_HANDLE || id == STD_ERROR_HANDLE);
    return (HANDLE)(uintptr_t)(id == STD_INPUT_HANDLE ? 1 : id == STD_OUTPUT_HANDLE ? 2 : 3);
}
int MultiByteToWideChar(unsigned cp, DWORD flags, const char *src, int bytes, WCHAR *dest, int capacity)
{
    CHECK(cp == CP_ACP && !flags && bytes > 0 && bytes <= capacity);
    for (int i = 0; i < bytes; ++i) dest[i] = (unsigned char)src[i];
    return bytes;
}
BOOL WriteFile(HANDLE h, const void *buf, DWORD bytes, DWORD *written, void *overlapped)
{
    CHECK((h == (HANDLE)(uintptr_t)2 || h == (HANDLE)(uintptr_t)3) && buf && written && !overlapped && bytes);
    *written = 0;
    if (h == (HANDLE)(uintptr_t)3) {
        if (is("stderr-fail")) { SetLastError(ERROR_WRITE_FAULT); return FALSE; }
        CHECK(bytes <= sizeof diagnostics - diagnostic_bytes - 1);
        memcpy(diagnostics + diagnostic_bytes, buf, bytes); diagnostic_bytes += bytes;
        diagnostics[diagnostic_bytes] = 0; *written = bytes; return TRUE;
    }
    ++writes;
    if (is("stdout-fail") || is("query-output-fail")) { SetLastError(ERROR_WRITE_FAULT); return FALSE; }
    if (is("stdout-zero")) return TRUE;
    if (is("stdout-overreported")) { *written = bytes + 1; return TRUE; }
    *written = is("stdout-short") && bytes > 2 ? 2 : bytes;
    CHECK(*written <= sizeof captured - captured_bytes);
    memcpy(captured + captured_bytes, buf, *written); captured_bytes += *written;
    return TRUE;
}
BOOL ReadFile(HANDLE h, void *buf, DWORD cap, DWORD *got, void *overlapped)
{
    CHECK(h == (HANDLE)(uintptr_t)1 && buf && cap >= 3 && got && !overlapped);
    ++input_reads; *got = 0;
    if (is("stdin-read-fail")) { SetLastError(ERROR_GEN_FAILURE); return FALSE; }
    if (is("native-input-eof")) { SetLastError(ERROR_BROKEN_PIPE); return FALSE; }
    if (input_reads == 1) { memcpy(buf, "inp", 3); *got = 3; }
    return TRUE;
}
BOOL NtwQuerySubsystem64(ntw64_info_t *info)
{
    CHECK(info); memset(info, 0, sizeof *info); info->size = sizeof *info;
    info->abi_major = 1; info->abi_minor = 1; info->max_processes = 4; return TRUE;
}
BOOL NtwCreateProcess64W(LPCWSTR path, LPCWSTR cmd, LPCWSTR cwd, HANDLE *handle)
{
    CHECK(path && cmd && !cwd && handle && path[0] == 'T');
    if (is("create-fail") || is("stderr-fail")) { SetLastError(ERROR_FILE_NOT_FOUND); return FALSE; }
    *handle = (HANDLE)(uintptr_t)4; return TRUE;
}
BOOL NtwReadConsole64(HANDLE h, void *buf, DWORD cap, DWORD *got)
{
    CHECK(h == (HANDLE)(uintptr_t)4 && buf && cap >= sizeof payload && got);
    ++reads; *got = 0;
    if (is("receive-fail") || is("kill-fail")) { SetLastError(ERROR_GEN_FAILURE); return FALSE; }
    if (is("receive-zero") && reads == 1) return TRUE;
    if (is("receive-overreported") && reads == 1) { *got = cap + 1; return TRUE; }
    if (reads <= 2) {
        const size_t start = reads == 1 ? 0 : 3, n = reads == 1 ? 3 : sizeof payload - 3;
        memcpy(buf, payload + start, n); *got = (DWORD)n; return TRUE;
    }
    SetLastError(NTW64_ERROR_HANDLE_EOF); return FALSE;
}
BOOL NtwWriteConsole64(HANDLE h, const void *buf, DWORD bytes, DWORD *written)
{
    CHECK(h == (HANDLE)(uintptr_t)4 && bytes == 3 && !memcmp(buf, "inp", 3) && written);
    ++input_writes; *written = 0;
    if (is("stdin-send-fail")) { SetLastError(ERROR_GEN_FAILURE); return FALSE; }
    if (is("early-child")) { SetLastError(ERROR_BROKEN_PIPE); return FALSE; }
    *written = is("stdin-short") ? 2 : bytes; return TRUE;
}
BOOL NtwCloseConsole64(HANDLE h)
{
    CHECK(h == (HANDLE)(uintptr_t)4); ++eof_closes;
    if (is("stdin-close-fail")) { SetLastError(ERROR_GEN_FAILURE); return FALSE; }
    if (is("close-input-eof")) { SetLastError(ERROR_BROKEN_PIPE); return FALSE; }
    return TRUE;
}
BOOL NtwKillProcess64(HANDLE h, DWORD code)
{
    CHECK(h == (HANDLE)(uintptr_t)4 && code == RUN_FAILED); ++kills;
    if (is("kill-fail")) { SetLastError(ERROR_GEN_FAILURE); return FALSE; }
    return TRUE;
}
BOOL NtwWaitProcess64(HANDLE h, DWORD timeout, DWORD *code)
{
    CHECK(h == (HANDLE)(uintptr_t)4 && timeout == INFINITE && code); ++waits;
    if (is("wait-fail")) { SetLastError(NTW64_ERROR_TIMEOUT); return FALSE; }
    *code = remote_exit; return TRUE;
}
BOOL NtwCloseProcess64(HANDLE h)
{
    CHECK(h == (HANDLE)(uintptr_t)4); ++closes;
    if (is("release-fail")) { SetLastError(ERROR_BUSY); return FALSE; }
    return TRUE;
}
int main(int argc, char **argv)
{
    CHECK(argc == 2); scenario = argv[1];
    if (is("remote7")) remote_exit = 7;
    else if (is("remote-fault")) remote_exit = 0xc0000005u;
    else if (is("remote255")) remote_exit = 255;
    const int failure = is("receive-fail") || is("stdin-read-fail") || is("stdin-send-fail") ||
        is("stdin-short") || is("stdin-close-fail") || is("stdout-fail") || is("stdout-zero") ||
        is("wait-fail") || is("release-fail") || is("query-output-fail") || is("create-fail") ||
        is("stderr-fail") || is("usage") || is("kill-fail") || is("receive-zero") ||
        is("receive-overreported") || is("stdout-overreported");
    const DWORD result = run();
    CHECK(result == (failure ? RUN_FAILED : remote_exit));
    if (is("query") || is("query-output-fail") || is("usage") || is("create-fail") || is("stderr-fail")) {
        CHECK(!waits && !closes && !reads && !kills);
    } else {
        CHECK(waits == 1 && closes == 1 && eof_closes == 1);
        if (!failure) CHECK(captured_bytes == sizeof payload && !memcmp(captured, payload, sizeof payload));
        if (is("receive-fail") || is("kill-fail") || is("stdout-fail") || is("stdout-zero") ||
            is("receive-zero") || is("receive-overreported") || is("stdout-overreported")) CHECK(kills == 1);
        else CHECK(kills == 0);
    }
    if (failure && !is("stderr-fail") && !is("query-output-fail")) CHECK(diagnostic_bytes > 0);
    if (is("stdout-short")) CHECK(writes > 2);
    printf("PASS %s: %u checks; frontend=%u remote=%u\n", scenario, checks, result, remote_exit);
    return 0;
}
