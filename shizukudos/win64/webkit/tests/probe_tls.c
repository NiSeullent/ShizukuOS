/* SPDX-License-Identifier: GPL-2.0-only
 * Toolchain probe: native (clang) __thread variables in the main thread and in a CreateThread thread. */
#include <windows.h>
#include <stdio.h>
static __thread int tv = 5;
static __thread char big[100];
static DWORD WINAPI th(LPVOID a) {
    printf("thread: read tv=%d\n", tv); fflush(stdout);
    big[3] = 1;
    printf("thread: wrote big\n"); fflush(stdout);
    tv += (int)(INT_PTR)a;
    printf("thread: wrote tv=%d\n", tv); fflush(stdout);
    return 0;
}
int main(void) {
    printf("main: tv=%d\n", tv); fflush(stdout);
    tv = 7;
    printf("main: wrote tv=%d\n", tv); fflush(stdout);
    HANDLE h = CreateThread(0, 0, th, (LPVOID)3, 0, 0);
    WaitForSingleObject(h, 20000);
    printf("TLSPROBE done tv=%d\n", tv); fflush(stdout);
    return 0;
}
