/* SPDX-License-Identifier: GPL-2.0-only
 * Shared helpers of the t_ipc_*.c tests (IPC and process model). Every check prints PASS:/FAIL:; the program's exit code
 * is the number of failed checks. Expected values come from documented Windows behaviour, never from this implementation's
 * own output. */
#ifndef IPC_TEST_H
#define IPC_TEST_H
#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include "shzcrt.h"

static int g_bad;
#define CHECK(cond, ...) do { if (cond) { printf("PASS: "); printf(__VA_ARGS__); printf("\n"); } \
                              else { printf("FAIL: "); printf(__VA_ARGS__); printf(" (line %d, error %u)\n", __LINE__, (unsigned)GetLastError()); ++g_bad; } } while (0)

typedef struct {
    unsigned long long pmm_free, kheap_used, threads, zombies, sections, views, pipes, irps, packets, jobs, reserved[6];
} kstats_t;
extern LONG WINAPI NtShzQueryKernelStats(void *, ULONG);
static inline int kstats(kstats_t *k) { return NtShzQueryKernelStats(k, sizeof *k) == 0; }

static inline void wcopy(WCHAR *d, const char *s) { while ((*d++ = (WCHAR)(unsigned char)*s++)) { } }
static inline unsigned ipc_atou(const char *s) { unsigned v = 0; while (*s >= '0' && *s <= '9') v = v * 10 + (unsigned)(*s++ - '0'); return v; }
static inline unsigned long long ipc_atoull(const char *s)
{
    unsigned long long v = 0;
    if (s[0] == '0' && (s[1] == 'x' || s[1] == 'X')) {
        for (s += 2; ; ++s) {
            const char c = *s;
            if (c >= '0' && c <= '9') v = v * 16 + (unsigned)(c - '0');
            else if (c >= 'a' && c <= 'f') v = v * 16 + (unsigned)(c - 'a' + 10);
            else if (c >= 'A' && c <= 'F') v = v * 16 + (unsigned)(c - 'A' + 10);
            else break;
        }
        return v;
    }
    while (*s >= '0' && *s <= '9') v = v * 10 + (unsigned)(*s++ - '0');
    return v;
}

/* Starts this same executable with `args` appended; returns the process handle (thread handle closed unless wanted). */
static inline HANDLE ipc_spawn_self(const char *args, DWORD flags, BOOL inherit, STARTUPINFOW *si_in, PROCESS_INFORMATION *pi_out)
{
    WCHAR self[260], cmd[600];
    STARTUPINFOW si;
    PROCESS_INFORMATION pi;
    int i = 0, k;
    GetModuleFileNameW(0, self, 260);
    cmd[i++] = '"';
    for (k = 0; self[k]; ++k) cmd[i++] = self[k];
    cmd[i++] = '"';
    if (args) { cmd[i++] = ' '; for (k = 0; args[k]; ++k) cmd[i++] = (WCHAR)args[k]; }
    cmd[i] = 0;
    memset(&si, 0, sizeof si);
    si.cb = sizeof si;
    if (!CreateProcessW(self, cmd, 0, 0, inherit, flags, 0, 0, si_in ? si_in : &si, &pi)) return 0;
    if (pi_out) *pi_out = pi; else CloseHandle(pi.hThread);
    return pi.hProcess;
}

static inline DWORD ipc_wait_exit(HANDLE h, DWORD ms)
{
    DWORD code = 0xffffffffu;
    if (WaitForSingleObject(h, ms) != WAIT_OBJECT_0) return 0xfffffffeu;
    GetExitCodeProcess(h, &code);
    return code;
}
#endif
