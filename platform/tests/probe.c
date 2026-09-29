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
static BOOL test_utf(HMODULE kernel32) {
    static const char text[] = { 'A', 0, (char)0xed, (char)0x95, (char)0x9c,
                                (char)0xf0, (char)0x9f, (char)0x98, (char)0x80 };
    static const WCHAR expected[] = { 'A', 0, 0xd55c, 0xd83d, 0xde00 };
    static const char bad[] = { (char)0xe1, (char)0x80, 'A' };
    static const WCHAR lone[] = { 0xd800, 'A' };
    WCHAR wide[8];
    char bytes[16];
    unsigned i;
    BOOL used = TRUE;
    typedef int (WINAPI *from_utf8)(UINT, DWORD, LPCCH, int, LPWSTR, int);
    typedef int (WINAPI *to_utf8)(UINT, DWORD, LPCWCH, int, LPSTR, int, LPCCH, LPBOOL);
    from_utf8 dynamic_from = (from_utf8)(void (*)(void))
        GetProcAddress(kernel32, "MultiByteToWideChar");
    to_utf8 dynamic_to = (to_utf8)(void (*)(void))
        GetProcAddress(kernel32, "WideCharToMultiByte");
    if (!dynamic_from || !dynamic_to) return FALSE;
    SetLastError(0x1234);
    if (MultiByteToWideChar(CP_UTF8, MB_ERR_INVALID_CHARS, text, sizeof(text), NULL, 0) != 5 ||
        GetLastError() != 0x1234) return FALSE;
    if (dynamic_from(CP_UTF8, 0, text, sizeof(text), wide, 8) != 5) return FALSE;
    for (i = 0; i < 5; ++i) if (wide[i] != expected[i]) return FALSE;
    if (WideCharToMultiByte(CP_UTF8, WC_ERR_INVALID_CHARS, wide, 5, NULL, 0, NULL, NULL) != 9)
        return FALSE;
    if (dynamic_to(CP_UTF8, 0, wide, 5, bytes, sizeof(bytes), NULL, NULL) != 9) return FALSE;
    for (i = 0; i < sizeof(text); ++i) if (bytes[i] != text[i]) return FALSE;
    if (MultiByteToWideChar(CP_UTF8, 0, "A", -1, wide, 8) != 2 || wide[1] != 0) return FALSE;
    if (WideCharToMultiByte(CP_UTF8, 0, wide, -1, bytes, 16, NULL, NULL) != 2 || bytes[1] != 0)
        return FALSE;
    for (i = 0; i < 8; ++i) wide[i] = 0x5555;
    if (MultiByteToWideChar(CP_UTF8, MB_ERR_INVALID_CHARS, bad, 3, wide, 8) != 0 ||
        GetLastError() != ERROR_NO_UNICODE_TRANSLATION) return FALSE;
    for (i = 0; i < 8; ++i) if (wide[i] != 0x5555) return FALSE;
    if (MultiByteToWideChar(CP_UTF8, 0, bad, 3, wide, 8) != 2 ||
        wide[0] != 0xfffd || wide[1] != 'A') return FALSE;
    for (i = 0; i < sizeof(bytes); ++i) bytes[i] = 'x';
    if (WideCharToMultiByte(CP_UTF8, WC_ERR_INVALID_CHARS, lone, 2, bytes, 16, NULL, NULL) != 0 ||
        GetLastError() != ERROR_NO_UNICODE_TRANSLATION) return FALSE;
    for (i = 0; i < sizeof(bytes); ++i) if (bytes[i] != 'x') return FALSE;
    if (WideCharToMultiByte(CP_UTF8, 0, expected, 5, bytes, 1, NULL, NULL) != 0 ||
        GetLastError() != ERROR_INSUFFICIENT_BUFFER || bytes[0] != 'x') return FALSE;
    if (MultiByteToWideChar(CP_UTF8, MB_PRECOMPOSED, text, 9, wide, 8) != 0 ||
        GetLastError() != ERROR_INVALID_FLAGS) return FALSE;
    if (WideCharToMultiByte(CP_UTF8, 0, expected, 5, bytes, 16, NULL, &used) != 0 ||
        GetLastError() != ERROR_INVALID_PARAMETER || !used) return FALSE;
    /* ASCII exercises the native ACP route without assuming a locale. */
    if (MultiByteToWideChar(CP_ACP, 0, "A", -1, wide, 8) != 2 || wide[0] != 'A' || wide[1])
        return FALSE;
    if (WideCharToMultiByte(CP_ACP, 0, wide, -1, bytes, 16, NULL, &used) != 2 ||
        bytes[0] != 'A' || bytes[1] || used) return FALSE;
    return TRUE;
}
static LONG WINAPI ignore_exception(EXCEPTION_POINTERS *info) {
    (void)info;
    return EXCEPTION_CONTINUE_SEARCH;
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
    if (!test_utf(kernel32)) goto fail;
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
    {
        PVOID registered = AddVectoredExceptionHandler(1, ignore_exception);
        if (!registered || !RemoveVectoredExceptionHandler(registered)) goto fail;
        if (RemoveVectoredExceptionHandler(registered)) goto fail;
    }
    finish("PASS: NTWin32Wrapper9x static imports\r\n",
           sizeof("PASS: NTWin32Wrapper9x static imports\r\n") - 1, 0);
    return;
fail:
    finish("FAIL: NTWin32Wrapper9x static imports\r\n",
           sizeof("FAIL: NTWin32Wrapper9x static imports\r\n") - 1, 1);
}
