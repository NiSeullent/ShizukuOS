/* SPDX-License-Identifier: GPL-2.0-only
 * Deliberately imports modern names from KERNEL32 before preparation. */
#define WIN32_LEAN_AND_MEAN
#define _WIN32_WINNT 0x0601
#include <windows.h>
static DWORD once_calls;
static BOOL WINAPI initialize_once(PINIT_ONCE once, PVOID parameter, PVOID *context) {
    (void)once;
    if (parameter != &once_calls || !context) return FALSE;
    ++once_calls;
    *context = &once_calls;
    return TRUE;
}
static void finish(const char *text, DWORD length, DWORD code) {
    DWORD written;
    HANDLE log = CreateFileA("NTWPROBE.LOG", GENERIC_WRITE, 0, NULL,
                             CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
    if (log == INVALID_HANDLE_VALUE) ExitProcess(2);
    if (!WriteFile(log, text, length, &written, NULL) || written != length) code = 3;
    CloseHandle(log);
    ExitProcess(code);
}
void mainCRTStartup(void) {
    SRWLOCK lock;
    INIT_ONCE once = INIT_ONCE_STATIC_INIT;
    BOOL pending;
    PVOID context = NULL;
    ULONGLONG before, after;
    HMODULE kernel32 = GetModuleHandleA("KERNEL32.DLL");
    typedef ULONGLONG (WINAPI *tick_function)(void);
    tick_function dynamic_tick = (tick_function)(void (*)(void))
        GetProcAddress(kernel32, "GetTickCount64");
    if (!dynamic_tick) goto fail;
    if (GetProcAddress(kernel32, "NTW_FUNCTION_DOES_NOT_EXIST")) goto fail;
    if (!GetProcAddress(kernel32, "Sleep")) goto fail;
    if (!InitOnceExecuteOnce(&once, initialize_once, &once_calls, &context)) goto fail;
    if (context != &once_calls || once_calls != 1) goto fail;
    context = NULL;
    if (!InitOnceExecuteOnce(&once, initialize_once, &once_calls, &context)) goto fail;
    if (context != &once_calls || once_calls != 1) goto fail;
    InitOnceInitialize(&once);
    if (!InitOnceBeginInitialize(&once, 0, &pending, &context) || !pending) goto fail;
    if (!InitOnceComplete(&once, 0, &once_calls)) goto fail;
    context = NULL;
    if (!InitOnceBeginInitialize(&once, INIT_ONCE_CHECK_ONLY, &pending, &context) || pending) goto fail;
    if (context != &once_calls) goto fail;
    InitializeSRWLock(&lock);
    if (!TryAcquireSRWLockShared(&lock)) goto fail;
    if (TryAcquireSRWLockExclusive(&lock)) goto fail;
    ReleaseSRWLockShared(&lock);
    AcquireSRWLockExclusive(&lock);
    if (TryAcquireSRWLockShared(&lock)) goto fail;
    ReleaseSRWLockExclusive(&lock);
    AcquireSRWLockShared(&lock);
    ReleaseSRWLockShared(&lock);
    before = GetTickCount64();
    Sleep(20);
    after = dynamic_tick();
    if (after < before) goto fail;
    finish("PASS: NTWin32Wrapper9x static imports\r\n",
           sizeof("PASS: NTWin32Wrapper9x static imports\r\n") - 1, 0);
    return;
fail:
    finish("FAIL: NTWin32Wrapper9x static imports\r\n",
           sizeof("FAIL: NTWin32Wrapper9x static imports\r\n") - 1, 1);
}
