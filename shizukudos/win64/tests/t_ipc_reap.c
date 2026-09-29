/* SPDX-License-Identifier: GPL-2.0-only
 * T_IPC_REAP: dead processes give their process-table slots back. More children than the kernel has process slots are
 * created and closed in a row - through CreateProcessW (NtShzCreateUserProcess) and through the native NtCreateProcessEx
 * - some exiting on their own with threads still running, some killed with TerminateProcess while blocked. A process object
 * that is still referenced by a handle keeps answering (exit code, pid, signaled state) however many processes come after
 * it, and once the last handle is gone the pid no longer opens. At the end the kernel's thread slots, heap and physical
 * pages are back where they started.
 *
 * Expected values follow the documented Win32 behaviour: GetExitCodeProcess returns the ExitProcess / TerminateProcess code,
 * a process handle is signaled once the process has ended, OpenProcess of a pid that names no process fails with
 * ERROR_INVALID_PARAMETER. */
#include "ipc_test.h"

typedef struct { USHORT Length, MaximumLength; PWSTR Buffer; } reap_ustr_t;
extern LONG WINAPI NtCreateProcessEx(HANDLE *, HANDLE *, reap_ustr_t *, reap_ustr_t *, reap_ustr_t *);

#define ROUNDS 70           /* each loop alone needs more processes than the kernel's 64 slots */
#define KILL_ROUNDS 40
#define KEEP 6              /* exited children whose process handles stay open throughout */

static DWORD WINAPI parked(LPVOID p) { (void)p; Sleep(INFINITE); return 0; }
static DWORD WINAPI spinner(LPVOID p) { volatile LONG *stop = p; while (!*stop) YieldProcessor(); return 0; }

static int child_threads(unsigned code)
{
    static volatile LONG never;
    CreateThread(0, 0, parked, 0, 0, 0);
    CreateThread(0, 0, parked, 0, 0, 0);
    CreateThread(0, 0, spinner, (LPVOID)&never, 0, 0);
    Sleep(5);
    return (int)code;               /* returning from main is ExitProcess: the other threads are ended with it */
}

static void u_set(reap_ustr_t *u, WCHAR *s)
{
    USHORT n = 0;
    while (s[n]) ++n;
    u->Buffer = s; u->Length = (USHORT)(n * 2); u->MaximumLength = (USHORT)(n * 2 + 2);
}

/* NtCreateProcessEx(&process, &thread, image path, command line, current directory) of this executable. */
static HANDLE native_spawn(const char *args, HANDLE *thread)
{
    WCHAR self[260], cmd[400];
    reap_ustr_t path, cl;
    HANDLE hp = 0, ht = 0;
    int i = 0, k;
    GetModuleFileNameW(0, self, 260);
    cmd[i++] = '"';
    for (k = 0; self[k]; ++k) cmd[i++] = self[k];
    cmd[i++] = '"';
    cmd[i++] = ' ';
    for (k = 0; args[k]; ++k) cmd[i++] = (WCHAR)args[k];
    cmd[i] = 0;
    u_set(&path, self);
    u_set(&cl, cmd);
    if (NtCreateProcessEx(&hp, &ht, &path, &cl, 0) != 0) return 0;
    *thread = ht;
    return hp;
}

static void fmt_args(char *out, const char *mode, unsigned code)
{
    char num[12];
    int n = 0, i = 0;
    do { num[n++] = (char)('0' + code % 10); code /= 10; } while (code);
    while (*mode) out[i++] = *mode++;
    out[i++] = ' ';
    while (n) out[i++] = num[--n];
    out[i] = 0;
}

int main(int argc, char **argv)
{
    kstats_t k0, k1;
    HANDLE kept[KEEP];
    DWORD kept_pid[KEEP], last_pid = 0;
    unsigned i, ok, spawned, waited, codes, ids, killed_ok;
    int have0, have1;
    char args[32];
    DWORD t_start;
    if (argc >= 3 && !strcmp(argv[1], "child")) return (int)ipc_atou(argv[2]);
    if (argc >= 3 && !strcmp(argv[1], "threads")) return child_threads(ipc_atou(argv[2]));
    if (argc >= 2 && !strcmp(argv[1], "block")) {
        CreateThread(0, 0, parked, 0, 0, 0);
        Sleep(INFINITE);
        return 1;
    }
    printf("T_IPC_REAP: %d + %d + %d child processes (the kernel has 64 process slots)\n", ROUNDS, ROUNDS, KILL_ROUNDS);
    t_start = GetTickCount();

    /* warm-up child: first-use allocations (loader caches, kernel32 state) are not counted as leaks */
    {
        HANDLE h = ipc_spawn_self("child 3", 0, FALSE, 0, 0);
        CHECK(h && ipc_wait_exit(h, 20000) == 3, "warm-up child exits with 3");
        if (h) CloseHandle(h);
    }
    have0 = kstats(&k0);

    /* 1. CreateProcessW: each child exits with its own code; the first KEEP handles stay open */
    spawned = waited = codes = ids = 0;
    for (i = 0; i < ROUNDS; ++i) {
        PROCESS_INFORMATION pi;
        HANDLE h;
        DWORD code;
        fmt_args(args, (i & 1) ? "threads" : "child", 100 + i);
        h = ipc_spawn_self(args, 0, FALSE, 0, &pi);
        if (!h) { printf("  CreateProcessW #%u failed, error %u\n", i, (unsigned)GetLastError()); break; }
        ++spawned;
        CloseHandle(pi.hThread);
        if (GetProcessId(h) == pi.dwProcessId) ++ids;
        code = ipc_wait_exit(h, 20000);
        if (code != 0xfffffffeu) ++waited;
        if (code == 100 + i) ++codes;
        if (i < KEEP) { kept[i] = h; kept_pid[i] = pi.dwProcessId; } else CloseHandle(h);
    }
    CHECK(spawned == ROUNDS, "CreateProcessW started %u of %u children in a row", spawned, ROUNDS);
    CHECK(waited == spawned, "all %u CreateProcessW children ended (handle signaled)", waited);
    CHECK(codes == spawned, "%u of %u exit codes are the children's own (half exited with threads still running)", codes, spawned);
    CHECK(ids == spawned, "GetProcessId matches PROCESS_INFORMATION.dwProcessId for %u children", ids);

    /* 2. native NtCreateProcessEx, the path that used to keep every slot */
    spawned = waited = codes = 0;
    for (i = 0; i < ROUNDS; ++i) {
        HANDLE ht = 0, h;
        DWORD code;
        fmt_args(args, (i % 3) ? "child" : "threads", 1000 + i);
        h = native_spawn(args, &ht);
        if (!h) { printf("  NtCreateProcessEx #%u failed\n", i); break; }
        ++spawned;
        code = ipc_wait_exit(h, 20000);
        if (code != 0xfffffffeu) ++waited;
        if (code == 1000 + i) ++codes;
        if (i == ROUNDS - 1) last_pid = GetProcessId(h);
        CloseHandle(ht);
        CloseHandle(h);
    }
    CHECK(spawned == ROUNDS, "NtCreateProcessEx started %u of %u children in a row", spawned, ROUNDS);
    CHECK(waited == spawned && codes == spawned, "NtCreateProcessEx children: %u ended, %u with their own exit code", waited, codes);

    /* 3. TerminateProcess of children blocked in a wait with a second thread parked */
    killed_ok = 0;
    for (i = 0; i < KILL_ROUNDS; ++i) {
        HANDLE h = ipc_spawn_self("block", 0, FALSE, 0, 0);
        DWORD code = 0;
        if (!h) { printf("  kill round %u: CreateProcessW failed, error %u\n", i, (unsigned)GetLastError()); break; }
        Sleep(i % 6);                                   /* during start-up, while entering the waits, or after */
        {
            const BOOL term = TerminateProcess(h, 77 + i);
            const DWORD w = term ? WaitForSingleObject(h, 20000) : WAIT_FAILED;
            if (w == WAIT_OBJECT_0 && GetExitCodeProcess(h, &code) && code == 77 + i) ++killed_ok;
            else printf("  kill round %u: TerminateProcess %d, wait %u, exit code 0x%x\n", i, term, (unsigned)w, (unsigned)code);
        }
        CloseHandle(h);
    }
    CHECK(killed_ok == KILL_ROUNDS, "%u of %u blocked children killed with TerminateProcess report the given code", killed_ok,
          KILL_ROUNDS);

    /* 4. the handles kept since step 1 still answer after more than 64 later processes */
    ok = 0;
    for (i = 0; i < KEEP; ++i) {
        DWORD code = 0;
        if (WaitForSingleObject(kept[i], 0) == WAIT_OBJECT_0 && GetExitCodeProcess(kept[i], &code) && code == 100 + i &&
            GetProcessId(kept[i]) == kept_pid[i])
            ++ok;
    }
    CHECK(ok == KEEP, "%u of %u kept handles of exited children still report signaled, exit code and pid", ok, KEEP);
    {
        HANDLE o = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, kept_pid[0]);
        DWORD code = 0;
        CHECK(o && GetExitCodeProcess(o, &code) && code == 100, "OpenProcess of an exited child that still has a handle works");
        if (o) CloseHandle(o);
    }
    for (i = 0; i < KEEP; ++i) CloseHandle(kept[i]);
    {
        HANDLE o = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, kept_pid[0]);
        const DWORD e = GetLastError();
        CHECK(!o && e == ERROR_INVALID_PARAMETER, "OpenProcess of that pid fails with ERROR_INVALID_PARAMETER once the last handle is closed");
        if (o) CloseHandle(o);
        o = last_pid ? OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, last_pid) : 0;
        CHECK(last_pid && !o, "a closed NtCreateProcessEx child's pid no longer opens");
        if (o) CloseHandle(o);
    }

    /* 5. nothing kept: thread slots, kernel heap and physical pages are back */
    have1 = kstats(&k1);
    CHECK(have0 && have1, "kernel statistics available");
    if (have0 && have1) {
        const long long dheap = (long long)k1.kheap_used - (long long)k0.kheap_used;
        const long long dpages = (long long)k0.pmm_free - (long long)k1.pmm_free;
        printf("  kernel: threads %llu -> %llu, zombies %llu -> %llu, heap %lld bytes, pages %lld\n", k0.threads, k1.threads,
               k0.zombies, k1.zombies, dheap, dpages);
        CHECK(k1.threads <= k0.threads, "no thread slot kept by the %u children (%llu -> %llu)", 2 * ROUNDS + KILL_ROUNDS,
              k0.threads, k1.threads);
        CHECK(dheap < 16384, "kernel heap back within 16 KiB (%lld bytes)", dheap);
        CHECK(dpages < 8, "physical pages back within 8 (%lld)", dpages);
    }
    printf("T_IPC_REAP: %d failure(s), %u ms\n", g_bad, (unsigned)(GetTickCount() - t_start));
    return g_bad;
}
