/* SPDX-License-Identifier: GPL-2.0-only
 * Address-space descriptor serialisation. Four threads reserve, commit, touch and release memory as fast as they can
 * while the main thread keeps checking, with VirtualQuery, that its own stack is still a committed region and that a
 * guard allocation keeps its exact layout. Before the kernel serialised its descriptor set, concurrent
 * NtAllocateVirtualMemory / NtFreeVirtualMemory calls corrupted it: a live stack's descriptor vanished and its thread
 * faulted on its own stack (the intermittent T_NET_LOOP crash inside ntdll's unwinder).
 */
#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include "shzcrt.h"

static int bad;
#define CHECK(cond, ...) do { if (cond) { printf("PASS: "); printf(__VA_ARGS__); printf("\n"); } \
                              else { printf("FAIL: "); printf(__VA_ARGS__); printf(" (line %d)\n", __LINE__); ++bad; } } while (0)

static volatile LONG g_stop, g_errors, g_ops;

static DWORD WINAPI churn(LPVOID a)
{
    unsigned seed = (unsigned)(ULONG_PTR)a * 2654435761u;
    unsigned char *keep[8] = {0};
    SIZE_T sizes[8] = {0};
    unsigned k;
    while (!g_stop) {
        seed = seed * 1103515245u + 12345u;
        k = (seed >> 16) & 7;
        if (keep[k]) {
            SIZE_T i;
            for (i = 0; i < sizes[k]; i += 4096)                 /* our own pattern must still be there */
                if (keep[k][i] != (unsigned char)(k + 1)) { InterlockedIncrement(&g_errors); break; }
            if (!VirtualFree(keep[k], 0, MEM_RELEASE)) InterlockedIncrement(&g_errors);
            keep[k] = 0;
        } else {
            SIZE_T i;
            sizes[k] = 4096 * (1 + ((seed >> 8) & 31));
            keep[k] = VirtualAlloc(0, sizes[k], MEM_COMMIT | MEM_RESERVE, (seed & 1) ? PAGE_READWRITE : PAGE_EXECUTE_READWRITE);
            if (!keep[k]) { InterlockedIncrement(&g_errors); continue; }
            for (i = 0; i < sizes[k]; i += 4096) keep[k][i] = (unsigned char)(k + 1);
            if ((seed >> 4) & 1) {                                /* split the region's protection now and then */
                DWORD old;
                if (!VirtualProtect(keep[k], 4096, PAGE_READONLY, &old)) InterlockedIncrement(&g_errors);
                else VirtualProtect(keep[k], 4096, PAGE_READWRITE, &old);
            }
        }
        InterlockedIncrement(&g_ops);
    }
    for (k = 0; k < 8; ++k) if (keep[k]) VirtualFree(keep[k], 0, MEM_RELEASE);
    return 0;
}

int main(void)
{
    HANDLE t[4];
    int i, lost = 0, guard_bad = 0;
    DWORD t0 = GetTickCount();
    MEMORY_BASIC_INFORMATION m;
    char probe = 1;
    unsigned char *guard = VirtualAlloc(0, 3 * 65536, MEM_RESERVE, PAGE_NOACCESS);
    CHECK(guard && VirtualAlloc(guard + 65536, 65536, MEM_COMMIT, PAGE_READWRITE) == guard + 65536, "guard reservation");
    for (i = 0; i < 4; ++i) t[i] = CreateThread(0, 0, churn, (LPVOID)(ULONG_PTR)(i + 1), 0, 0);
    while (GetTickCount() - t0 < 3000) {
        if (!VirtualQuery(&probe, &m, sizeof m) || m.State != MEM_COMMIT || m.Protect != PAGE_READWRITE) ++lost;
        if (!VirtualQuery(guard + 65536, &m, sizeof m) || m.State != MEM_COMMIT || m.BaseAddress != guard + 65536 ||
            m.RegionSize != 65536 || m.AllocationBase != guard)
            ++guard_bad;
        if (!VirtualQuery(guard, &m, sizeof m) || m.State != MEM_RESERVE || m.RegionSize != 65536) ++guard_bad;
        guard[65536 + (GetTickCount() & 0xffff)] = (char)probe;
        Sleep(0);
    }
    g_stop = 1;
    WaitForMultipleObjects(4, t, TRUE, INFINITE);
    CHECK(lost == 0, "the main thread's stack stayed one committed read-write region (%d bad queries)", lost);
    CHECK(guard_bad == 0, "an unrelated reservation kept its exact layout (%d bad queries)", guard_bad);
    CHECK(g_errors == 0 && g_ops > 200, "%d concurrent allocate/touch/protect/release operations, %d errors", (int)g_ops, (int)g_errors);
    printf("%s: %d check(s) failed\n", bad ? "FAIL" : "PASS", bad);
    return bad;
}
