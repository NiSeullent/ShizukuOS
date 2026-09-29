/* SPDX-License-Identifier: GPL-2.0-only
 * Chromium probe (tests/run_k64_disk.py --chromium): a Chromium chrome-win tree copied onto a FAT32 disk image is D:\.
 * 1. LoadLibraryW(D:\chrome-win\chrome.dll): the 334 MB DLL is mapped lazily; the kernel logs how far the import
 *    resolution got ("K64 ldr: ..." lines) and the first failure.
 * 2. CreateProcessW(D:\chrome-win\chrome.exe --no-sandbox): the same for the executable; if a process starts, its
 *    exit code is reported after at most 20 s.
 * The outcome lines are "CHROME-..." for the runner; failures here are the expected state of the Win64 personality
 * (missing kernel32 exports), so this probe never fails the test run: it exits 0 whatever the results.
 * Without D:\chrome-win it prints SKIP. */
#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include "u_check.h"

int main(void)
{
    HMODULE h;
    STARTUPINFOW si;
    PROCESS_INFORMATION pi;
    wchar_t cmd[] = L"D:\\chrome-win\\chrome.exe --no-sandbox --headless about:blank";
    MEMORYSTATUSEX m0, m1;
    if (GetFileAttributesA("D:\\chrome-win\\chrome.dll") == INVALID_FILE_ATTRIBUTES) {
        printf("SKIP: no D:\\chrome-win\\chrome.dll (not the Chromium probe image)\n");
        return 0;
    }
    m0.dwLength = m1.dwLength = sizeof m0;
    GlobalMemoryStatusEx(&m0);
    h = LoadLibraryW(L"D:\\chrome-win\\chrome.dll");
    GlobalMemoryStatusEx(&m1);
    printf("CHROME-DLL %s error %u avail_delta_kib %lld\n", h ? "loaded" : "failed", h ? 0u : (unsigned)GetLastError(),
           (long long)(m0.ullAvailPhys - m1.ullAvailPhys) / 1024);
    memset(&si, 0, sizeof si);
    si.cb = sizeof si;
    memset(&pi, 0, sizeof pi);
    if (CreateProcessW(L"D:\\chrome-win\\chrome.exe", cmd, 0, 0, FALSE, 0, 0, L"D:\\chrome-win", &si, &pi)) {
        DWORD code = 0, w = WaitForSingleObject(pi.hProcess, 20000);
        GetExitCodeProcess(pi.hProcess, &code);
        printf("CHROME-EXE started pid %u wait %u exit %x\n", (unsigned)pi.dwProcessId, (unsigned)w, (unsigned)code);
    } else {
        printf("CHROME-EXE failed error %u\n", (unsigned)GetLastError());
    }
    return 0;
}
