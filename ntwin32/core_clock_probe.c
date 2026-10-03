/* SPDX-License-Identifier: GPL-2.0-only -- explicit-provider guest probe.
 * Owner may run this with the licensed Windows98 source cohort. Build is not run.
 */
#define WIN32_LEAN_AND_MEAN
#define WINVER 0x0410
#define _WIN32_WINNT 0x0400
#include <windows.h>

typedef BOOL (WINAPI *paired_fn)(PLARGE_INTEGER, PLARGE_INTEGER);
typedef LONG (WINAPI *nt_fn)(PLARGE_INTEGER, PLARGE_INTEGER);
typedef BOOL (WINAPI *shutdown_fn)(void);
static HANDLE log_file = INVALID_HANDLE_VALUE;
static HMODULE provider;
static shutdown_fn shutdown_clock;
static void record(const char *label, ULONGLONG value)
{
    char line[160];
    static const char hex[] = "0123456789abcdef";
    DWORD length = 0, written, at;
    while (*label && length < sizeof(line) - 22) line[length++] = *label++;
    line[length++] = ' '; line[length++] = '0'; line[length++] = 'x';
    for (at = 0; at < 16; ++at) line[length++] = hex[(value >> (60 - at * 4)) & 15];
    line[length++] = '\r'; line[length++] = '\n';
    if (!WriteFile(log_file, line, length, &written, NULL) || written != length ||
        !FlushFileBuffers(log_file)) ExitProcess(3);
}
static void finish(DWORD code)
{
    /* Refuse to unload code/data while the provider still owns a failed-close
     * handle or an admitted call. Process exit then leaves cleanup to the OS. */
    if (provider) {
        if (!shutdown_clock || !shutdown_clock()) {
            record("FAIL explicit shutdown; no FreeLibrary, process exit", GetLastError());
            code = 4;
        } else if (!FreeLibrary(provider)) code = 4;
    }
    if (log_file != INVALID_HANDLE_VALUE && !CloseHandle(log_file)) code = 5;
    ExitProcess(code);
}
static void failed(const char *label, DWORD error)
{ record(label, error); finish(1); }
void mainCRTStartup(void)
{
    OSVERSIONINFOA os = { 0 };
    LARGE_INTEGER count, frequency, previous, initial, sentinel;
    paired_fn query;
    nt_fn ntquery;
    DWORD i, start, saved;
    BOOL crossed = FALSE;
    LONG status;
    log_file = CreateFileA("CORECLK.LOG", GENERIC_WRITE, FILE_SHARE_READ, NULL,
                          CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
    if (log_file == INVALID_HANDLE_VALUE) ExitProcess(2);
    record("START explicit Core clock; not native KERNEL32 routing", 1);
    os.dwOSVersionInfoSize = sizeof(os);
    if (!GetVersionExA(&os) || os.dwPlatformId != 1 || os.dwMajorVersion != 4 ||
        os.dwMinorVersion != 10 || (os.dwBuildNumber & 0xffffu) != 2222)
        failed("FAIL reported Windows98 SE version/profile", os.dwBuildNumber);
    provider = LoadLibraryA("NTW32.DLL");
    if (!provider) failed("FAIL LoadLibrary NTW32", GetLastError());
    query = (paired_fn)GetProcAddress(provider, "NtwQueryCoreClock");
    ntquery = (nt_fn)GetProcAddress(provider, "NtQueryPerformanceCounter");
    shutdown_clock = (shutdown_fn)GetProcAddress(provider, "NtwShutdownCoreClock");
    if (!query || !ntquery || !shutdown_clock) failed("FAIL explicit provider exports", GetLastError());
    count.QuadPart = frequency.QuadPart = sentinel.QuadPart = 0x123456789abcdefLL;
    if (query(NULL, &frequency) || GetLastError() != ERROR_INVALID_PARAMETER ||
        frequency.QuadPart != sentinel.QuadPart) failed("FAIL null counter", GetLastError());
    if (query(&count, &count) || GetLastError() != ERROR_INVALID_PARAMETER ||
        count.QuadPart != sentinel.QuadPart) failed("FAIL overlapping pair", GetLastError());
    SetLastError(0x1233u);
    status = ntquery(NULL, &frequency);
    if ((ULONG)status != 0xc000000du || frequency.QuadPart != sentinel.QuadPart ||
        GetLastError() != 0x1233u)
        failed("FAIL NT invalid parameter", (DWORD)status);
    record("PASS required counter/rejected BOOL overlap/NT error", 3);
    SetLastError(0x1234u);
    if (!query(&count, &frequency)) {
        saved = GetLastError();
        if (count.QuadPart != sentinel.QuadPart || frequency.QuadPart != sentinel.QuadPart)
            failed("FAIL error changed caller outputs", saved);
        failed("FAIL real Core/VxD unavailable", saved);
    }
    if (frequency.QuadPart != 1000000000LL || count.QuadPart < 0)
        failed("FAIL normalized counter/frequency", (DWORD)frequency.LowPart);
    if (GetLastError() != 0x1234u) failed("FAIL BOOL success LastError", GetLastError());
    initial = count;
    SetLastError(0x1235u);
    if (!query(&count, NULL) || count.QuadPart < initial.QuadPart || GetLastError() != 0x1235u)
        failed("FAIL BOOL optional frequency/LastError", GetLastError());
    SetLastError(0x1236u);
    status = ntquery(&frequency, &frequency);
    if (status || frequency.QuadPart != 1000000000LL || GetLastError() != 0x1236u)
        failed("FAIL NT overlap/order/LastError", (DWORD)status);
    previous = count;
    record("SAMPLE initial normalized count", (ULONGLONG)count.QuadPart);
    start = GetTickCount();
    for (i = 0; i < 100 && GetTickCount() - start < 12000; ++i) {
        Sleep(100);
        if (!query(&count, &frequency)) failed("FAIL clock sample", GetLastError());
        if (count.QuadPart < previous.QuadPart || frequency.QuadPart != 1000000000LL)
            failed("FAIL count regressed or units changed", (DWORD)i);
        if (count.QuadPart - initial.QuadPart > 4294967296LL) crossed = TRUE;
        previous = count;
    }
    if (!crossed) failed("FAIL no observed interval beyond 32bit wrap", i);
    SetLastError(0x1237u);
    status = ntquery(&count, NULL);
    if (status || count.QuadPart < previous.QuadPart || GetLastError() != 0x1237u)
        failed("FAIL direct NtQueryPerformanceCounter", (DWORD)status);
    record("SAMPLE final normalized count", (ULONGLONG)count.QuadPart);
    record("PASS real explicit Core paired/NT count beyond 32bits", i);
    SetLastError(0x1238u);
    if (!shutdown_clock() || GetLastError() != 0x1238u) failed("FAIL explicit shutdown", GetLastError());
    count = frequency = sentinel;
    if (query(&count, &frequency) || GetLastError() != ERROR_NOT_READY ||
        count.QuadPart != sentinel.QuadPart || frequency.QuadPart != sentinel.QuadPart)
        failed("FAIL stopped query/outputs", GetLastError());
    record("PASS stopped admission/unchanged outputs", 1);
    finish(0);
}
