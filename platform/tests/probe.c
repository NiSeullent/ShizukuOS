/* SPDX-License-Identifier: GPL-2.0-only
 * Deliberately imports modern names from KERNEL32 before preparation. */
#define WIN32_LEAN_AND_MEAN
#define _WIN32_WINNT 0x0601
#include <windows.h>
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
    ULONGLONG before, after;
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
    after = GetTickCount64();
    if (after < before) goto fail;
    finish("PASS: NTWin32Wrapper9x static imports\r\n",
           sizeof("PASS: NTWin32Wrapper9x static imports\r\n") - 1, 0);
    return;
fail:
    finish("FAIL: NTWin32Wrapper9x static imports\r\n",
           sizeof("FAIL: NTWin32Wrapper9x static imports\r\n") - 1, 1);
}
