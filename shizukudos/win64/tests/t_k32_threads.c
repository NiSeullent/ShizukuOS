/* SPDX-License-Identifier: GPL-2.0-only
 * Many threads at once. A multi-process Chromium run holds a few hundred threads in the machine (the browser alone starts ~40);
 * Kernel64's scheduler table held 96 until run 20 of docs/shizukudos10/reports/K4.md stopped at "thread table full". 300 parked
 * threads must all start, each must report its own index as the exit code, and thread slots and kernel stacks must be reusable:
 * 600 short-lived threads created and joined one after another afterwards. */
#include "k32test.h"

#define PARKED 300
#define CHURN 600

static volatile LONG started;
static HANDLE gate;

static DWORD WINAPI parked(LPVOID arg)
{
    InterlockedIncrement(&started);
    WaitForSingleObject(gate, 30000);
    return (DWORD)(ULONG_PTR)arg;
}

static DWORD WINAPI quick(LPVOID arg) { return (DWORD)(ULONG_PTR)arg * 3u + 1u; }

int main(void)
{
    static HANDLE th[PARKED];
    unsigned i, made = 0, chunk, bad = 0, waited = 0;
    DWORD code;
    gate = CreateEventW(0, TRUE, FALSE, 0);
    CHECK(gate != NULL, "CreateEvent(manual reset) for the start gate");
    for (i = 0; i < PARKED; ++i) {
        th[i] = CreateThread(0, 256 * 1024, parked, (LPVOID)(ULONG_PTR)i, 0, 0);
        if (th[i]) ++made;
    }
    CHECKV(made == PARKED, "300 threads are created while each of the earlier ones is still alive", "made %u, last error %u", made, (unsigned)GetLastError());
    while (started < (LONG)made && waited < 60000) { Sleep(10); waited += 10; }
    CHECKV(started == (LONG)made, "every one of them starts running", "%ld of %u started", (long)started, made);
    SetEvent(gate);
    for (chunk = 0; chunk < made; chunk += MAXIMUM_WAIT_OBJECTS) {
        const DWORD n = made - chunk < MAXIMUM_WAIT_OBJECTS ? made - chunk : MAXIMUM_WAIT_OBJECTS;
        if (WaitForMultipleObjects(n, th + chunk, TRUE, 60000) != WAIT_OBJECT_0) ++bad;
    }
    CHECK(bad == 0, "all 300 threads finish once the gate opens");
    bad = 0;
    for (i = 0; i < made; ++i) {
        if (!GetExitCodeThread(th[i], &code) || code != i) ++bad;
        CloseHandle(th[i]);
    }
    CHECKV(bad == 0, "each thread's exit code is its own index", "%u wrong", bad);
    bad = 0;
    for (i = 0; i < CHURN; ++i) {
        HANDLE q = CreateThread(0, 0, quick, (LPVOID)(ULONG_PTR)i, 0, 0);
        if (!q) { ++bad; continue; }
        if (WaitForSingleObject(q, 30000) != WAIT_OBJECT_0 || !GetExitCodeThread(q, &code) || code != i * 3u + 1u) ++bad;
        CloseHandle(q);
    }
    CHECKV(bad == 0, "600 short-lived threads created and joined in a row reuse the slots", "%u failed", bad);
    CloseHandle(gate);
    return k32t_finish("t_k32_threads");
}
