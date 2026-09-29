/* SPDX-License-Identifier: GPL-2.0-only
 * Test module for process-exit ordering (win64/tests/t_ipc_exit.c). A process registers the handles of its worker threads
 * and the counter its spinning workers increment; at process exit this module's DllMain(DLL_PROCESS_DETACH) asserts that
 * no other thread of the process is still running - Windows ends every other thread (NtTerminateProcess(NULL)) before the
 * loader runs the detach routines. A violated assertion prints FAIL and replaces the exit code with 0xDEAD0000 + reason, so
 * the process visibly fails; success prints PASS and keeps the exit code the process chose.
 */
#include "nt.h"

#define MAX_REG 16
static HANDLE g_threads[MAX_REG];
static int g_count;
static volatile LONG *g_spin;
static volatile LONG g_detached;

static void say(const char *s)
{
    DWORD n = 0, w;
    while (s[n]) ++n;
    WriteFile(GetStdHandle(STD_OUTPUT_HANDLE), s, n, &w, 0);
}

/* Registers worker thread handles (duplicated, so the caller may close its own) and an optional spin counter. */
DLLAPI BOOL WINAPI IpcExitRegister(const HANDLE *threads, int n, volatile LONG *spin)
{
    int i;
    for (i = 0; i < n && g_count < MAX_REG; ++i)
        if (!DuplicateHandle(GetCurrentProcess(), threads[i], GetCurrentProcess(), &g_threads[g_count++], 0, FALSE,
                             DUPLICATE_SAME_ACCESS))
            return FALSE;
    if (spin) g_spin = spin;
    return TRUE;
}

DLLAPI LONG WINAPI IpcExitDetached(void) { return g_detached; }

static void fail(const char *why, DWORD code)
{
    say("FAIL: ipcexit DllMain(DLL_PROCESS_DETACH): ");
    say(why);
    say("\n");
    TerminateProcess(GetCurrentProcess(), 0xDEAD0000u + code);
}

BOOL WINAPI DllMain(HINSTANCE h, DWORD reason, LPVOID reserved)
{
    (void)h;
    if (reason != DLL_PROCESS_DETACH) return TRUE;
    g_detached = 1;
    if (!reserved) return TRUE;                              /* FreeLibrary: not the exit path under test */
    if (g_count || g_spin) {
        int i;
        LONG before;
        for (i = 0; i < g_count; ++i) {
            DWORD code = 0;
            if (WaitForSingleObject(g_threads[i], 0) != WAIT_OBJECT_0) { fail("a worker thread is still alive", 1); return TRUE; }
            if (!GetExitCodeThread(g_threads[i], &code) || code == STILL_ACTIVE) { fail("a worker reports STILL_ACTIVE", 2); return TRUE; }
        }
        if (g_spin) {
            before = *g_spin;
            Sleep(40);                                       /* a spinning worker would advance the counter meanwhile */
            if (*g_spin != before) { fail("the spin counter still advances", 3); return TRUE; }
        }
        {
            HANDLE t = CreateThread(0, 0, (LPTHREAD_START_ROUTINE)(void *)Sleep, (LPVOID)(ULONG_PTR)10, 0, 0);
            if (t) { fail("CreateThread succeeded in an exiting process", 4); return TRUE; }
        }
        say("PASS: ipcexit DllMain(DLL_PROCESS_DETACH) ran with every other thread gone\n");
    }
    return TRUE;
}
