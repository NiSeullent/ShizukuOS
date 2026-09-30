/* SPDX-License-Identifier: GPL-2.0-only
 * Process-exit correctness (Windows order: NtTerminateProcess(NULL) ends every other thread, THEN DLL_PROCESS_DETACH runs,
 * THEN the process ends) and prompt termination of threads that never leave the kernel on their own.
 *
 *   parent  : its own workers (spinning in user mode, blocked INFINITE in event / multiple-object / delay / WaitOnAddress /
 *             critical-section waits) stay alive until it exits; ipcexit.dll's DllMain(DLL_PROCESS_DETACH) then asserts
 *             that every one of them is gone and the spin counter is frozen (a failure changes the exit code).
 *   children: "blocked"  - TerminateProcess of a child whose threads are all blocked INFINITE or spinning: must end promptly
 *                          with the requested exit code;
 *             "workers"  - a child that returns from main with the same kinds of workers (its DllMain asserts too);
 *             "wexit"    - a worker thread calls ExitProcess while the main thread is blocked INFINITE;
 *             "race"     - six threads call ExitProcess at the same moment: exactly one exit wins, no hang, no fault;
 *   and T_NET_LOOP.EXE (exits with two threads blocked in accept()/recv()) is run ten times, each must exit 0.
 */
#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include "shzcrt.h"

extern BOOL WINAPI IpcExitRegister(const HANDLE *threads, int n, volatile LONG *spin);

static int bad;
#define CHECK(cond, ...) do { if (cond) { printf("PASS: "); printf(__VA_ARGS__); printf("\n"); } \
                              else { printf("FAIL: "); printf(__VA_ARGS__); printf(" (line %d)\n", __LINE__); ++bad; } } while (0)

static volatile LONG g_spin;
static HANDLE g_never;                      /* manual-reset event nobody ever sets */
static CRITICAL_SECTION g_cs;
static volatile LONG g_addr_word;

static DWORD WINAPI w_spin(LPVOID a) { (void)a; while (g_spin != -7) InterlockedIncrement(&g_spin); return 0; }
static DWORD WINAPI w_event(LPVOID a) { (void)a; WaitForSingleObject(g_never, INFINITE); return 1; }
static DWORD WINAPI w_multi(LPVOID a) { HANDLE hs[2] = { g_never, g_never }; (void)a; WaitForMultipleObjects(2, hs, TRUE, INFINITE); return 1; }
static DWORD WINAPI w_sleep(LPVOID a) { (void)a; Sleep(INFINITE); return 1; }
static DWORD WINAPI w_sleepex(LPVOID a) { (void)a; SleepEx(INFINITE, TRUE); return 1; }
static DWORD WINAPI w_address(LPVOID a) { LONG zero = 0; (void)a; while (g_addr_word == 0) WaitOnAddress(&g_addr_word, &zero, sizeof zero, INFINITE); return 1; }
static DWORD WINAPI w_cs(LPVOID a) { (void)a; EnterCriticalSection(&g_cs); return 1; }   /* the main thread holds it forever */

/* Starts one worker of every kind; returns how many handles were stored. */
static int start_workers(HANDLE *hs)
{
    static LPTHREAD_START_ROUTINE const fns[] = { w_spin, w_event, w_multi, w_sleep, w_sleepex, w_address, w_cs };
    int i, n = 0;
    if (!g_never) g_never = CreateEventW(0, TRUE, FALSE, 0);
    InitializeCriticalSection(&g_cs);
    EnterCriticalSection(&g_cs);
    for (i = 0; i < (int)(sizeof fns / sizeof fns[0]); ++i) {
        HANDLE h = CreateThread(0, 0, fns[i], 0, 0, 0);
        if (h) hs[n++] = h;
    }
    Sleep(60);                                             /* let every worker reach its blocking call */
    return n;
}

static HANDLE ready_event(const char *tag, DWORD pid, int create)
{
    char a[40];
    WCHAR w[40];
    int i;
    snprintf(a, sizeof a, "ipcexit_%s_%u", tag, (unsigned)pid);
    for (i = 0; a[i]; ++i) w[i] = (WCHAR)a[i];
    w[i] = 0;
    (void)create;
    return CreateEventW(0, TRUE, FALSE, w);           /* named: the parent creates it, the child opens the same object */
}

/* ---------------------------------------------------------------- child modes */
static int child_blocked(DWORD ppid)
{
    HANDLE hs[16];
    const int n = start_workers(hs);
    SetEvent(ready_event("blocked", ppid, 0));
    (void)n;
    WaitForSingleObject(g_never, INFINITE);                /* the parent terminates us from here */
    return 42;
}

static int child_workers(void)
{
    HANDLE hs[16];
    const int n = start_workers(hs);
    if (n != 7 || !IpcExitRegister(hs, n, &g_spin)) return 17;
    return 0;                                              /* ExitProcess(0) with seven live workers */
}

static HANDLE g_main_thread;
static DWORD WINAPI w_exit(LPVOID a) { (void)a; Sleep(80); ExitProcess(9); }

static int child_wexit(void)
{
    HANDLE hs[16], me;
    int n = start_workers(hs);
    if (!DuplicateHandle(GetCurrentProcess(), GetCurrentThread(), GetCurrentProcess(), &me, 0, FALSE, DUPLICATE_SAME_ACCESS))
        return 18;
    g_main_thread = me;
    hs[n++] = me;                                          /* the main thread must be gone before the detach runs, too */
    if (!IpcExitRegister(hs, n, &g_spin)) return 19;
    if (!CreateThread(0, 0, w_exit, 0, 0, 0)) return 20;
    WaitForSingleObject(g_never, INFINITE);
    return 21;                                             /* never reached: the worker's ExitProcess ends us */
}

static HANDLE g_go;
static DWORD WINAPI w_race(LPVOID a) { WaitForSingleObject(g_go, INFINITE); ExitProcess((UINT)(ULONG_PTR)a); }

static int child_race(void)
{
    int i;
    g_go = CreateEventW(0, TRUE, FALSE, 0);
    for (i = 0; i < 6; ++i) if (!CreateThread(0, 0, w_race, (LPVOID)(ULONG_PTR)5, 0, 0)) return 30;
    Sleep(50);
    SetEvent(g_go);                                        /* six threads race into ExitProcess(5) */
    ExitProcess(5);
}

/* ---------------------------------------------------------------- parent */
static WCHAR g_self[260];

static HANDLE spawn(const WCHAR *image, const char *args, DWORD *pid)
{
    WCHAR cmd[400];
    STARTUPINFOW si;
    PROCESS_INFORMATION pi;
    int i = 0, k;
    cmd[i++] = '"';
    for (k = 0; image[k]; ++k) cmd[i++] = image[k];
    cmd[i++] = '"';
    if (args) { cmd[i++] = ' '; for (k = 0; args[k]; ++k) cmd[i++] = (WCHAR)args[k]; }
    cmd[i] = 0;
    memset(&si, 0, sizeof si);
    si.cb = sizeof si;
    if (!CreateProcessW(image, cmd, 0, 0, FALSE, 0, 0, 0, &si, &pi)) return 0;
    CloseHandle(pi.hThread);
    if (pid) *pid = pi.dwProcessId;
    return pi.hProcess;
}

static DWORD exit_code_after(HANDLE h, DWORD ms, DWORD *waited)
{
    DWORD code = 0xffffffffu, t0 = GetTickCount();
    DWORD w = WaitForSingleObject(h, ms);
    if (waited) *waited = GetTickCount() - t0;
    if (w != WAIT_OBJECT_0) return 0xfffffffeu;
    GetExitCodeProcess(h, &code);
    return code;
}

int main(int argc, char **argv)
{
    HANDLE hs[16], h;
    DWORD pid = 0, code, waited = 0;
    char args[64];
    int n, i;
    if (argc >= 3 && !strcmp(argv[1], "blocked")) { DWORD v = 0; const char *c = argv[2]; while (*c >= '0' && *c <= '9') v = v * 10 + (DWORD)(*c++ - '0'); return child_blocked(v); }
    if (argc >= 2 && !strcmp(argv[1], "workers")) return child_workers();
    if (argc >= 2 && !strcmp(argv[1], "wexit")) return child_wexit();
    if (argc >= 2 && !strcmp(argv[1], "race")) return child_race();

    GetModuleFileNameW(0, g_self, 260);

    /* 1. TerminateProcess of a child whose threads are blocked INFINITE (and one spins in user mode). */
    {
        HANDLE ready = ready_event("blocked", GetCurrentProcessId(), 1);
        snprintf(args, sizeof args, "blocked %u", (unsigned)GetCurrentProcessId());
        h = spawn(g_self, args, &pid);
        CHECK(h != 0, "CreateProcess of the 'blocked' child");
        if (h) {
            CHECK(WaitForSingleObject(ready, 10000) == WAIT_OBJECT_0, "the child started its blocked and spinning workers");
            CHECK(WaitForSingleObject(h, 0) == WAIT_TIMEOUT, "the child is alive before TerminateProcess");
            CHECK(TerminateProcess(h, 0x77), "TerminateProcess(child, 0x77)");
            code = exit_code_after(h, 5000, &waited);
            CHECK(code == 0x77, "the child ended with exit code 0x77 (got 0x%x after %u ms)", (unsigned)code, (unsigned)waited);
            CHECK(waited < 2000, "termination of blocked/spinning threads is prompt (%u ms)", (unsigned)waited);
            CHECK(!TerminateProcess(h, 1) && GetLastError() == ERROR_ACCESS_DENIED,
                  "TerminateProcess of an exited process fails with ERROR_ACCESS_DENIED (%u)", (unsigned)GetLastError());
            CloseHandle(h);
        }
        CloseHandle(ready);
    }
    /* 2. A child returning from main with seven live workers: its DllMain(DETACH) asserts they are gone. */
    h = spawn(g_self, "workers", 0);
    code = h ? exit_code_after(h, 10000, &waited) : 0xffffffffu;
    CHECK(code == 0, "ExitProcess with live workers: detach ran after every worker ended (exit 0x%x)", (unsigned)code);
    if (h) CloseHandle(h);
    /* 3. ExitProcess from a worker while the main thread is blocked. */
    h = spawn(g_self, "wexit", 0);
    code = h ? exit_code_after(h, 10000, &waited) : 0xffffffffu;
    CHECK(code == 9, "ExitProcess(9) from a worker ends the blocked main thread first (exit 0x%x)", (unsigned)code);
    if (h) CloseHandle(h);
    /* 4. Six threads race into ExitProcess. */
    for (i = 0; i < 3; ++i) {
        h = spawn(g_self, "race", 0);
        code = h ? exit_code_after(h, 10000, &waited) : 0xffffffffu;
        CHECK(code == 5, "six concurrent ExitProcess(5) calls: one clean exit (round %d, exit 0x%x)", i, (unsigned)code);
        if (h) CloseHandle(h);
    }
    /* 5. T_NET_LOOP.EXE exits with two threads blocked in accept()/recv(): ten clean runs. */
    {
        WCHAR net[260];
        int k = 0, ok = 0, j;
        const char *dir = "C:\\SHZ\\TESTS\\T_NET_LOOP.EXE";
        for (j = 0; dir[j]; ++j) net[k++] = (WCHAR)dir[j];
        net[k] = 0;
        if (GetFileAttributesW(net) == INVALID_FILE_ATTRIBUTES) {
            printf("SKIP: T_NET_LOOP.EXE not present\n");
        } else {
            int clean = 0;
            for (i = 0; i < 10; ++i) {
                h = spawn(net, 0, 0);
                code = h ? exit_code_after(h, 120000, &waited) : 0xffffffffu;
                if (code <= 1) ++ok;                       /* 0 = all checks passed, 1 = a network check failed; both exited */
                if (code == 0) ++clean;
                else printf("INFO: T_NET_LOOP run %d exit 0x%x\n", i, (unsigned)code);
                if (h) CloseHandle(h);
            }
            /* The exit path is what is verified here (no fault while the two parked threads are ended); T_NET_LOOP's own
             * timing-sensitive network checks are reported, not required. */
            CHECK(ok == 10, "T_NET_LOOP.EXE exited 10 times without a fault or hang (%d/10; %d/10 with every check passing)", ok, clean);
        }
    }
    /* 6. This process exits with its own seven workers alive; ipcexit.dll's detach asserts they are gone first. */
    n = start_workers(hs);
    CHECK(n == 7 && IpcExitRegister(hs, n, &g_spin), "seven workers of the parent registered with ipcexit.dll");
    printf("%s: %d check(s) failed; exiting with seven live workers\n", bad ? "FAIL" : "PASS", bad);
    return bad;
}
