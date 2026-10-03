/* SPDX-License-Identifier: GPL-2.0-only
 * PE64 fixture for the kernel32 runtime-startup topology exports. Linked against the real kernel32 import library.
 * Returns 0 only if every contract holds; distinct nonzero code per violation. Single CPU/group/NUMA node truth model. */
#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include "shzcrt.h"

#define FAIL(code, what) do { printf("FAIL %d: %s\n", (code), what); return (code); } while (0)

int main(void)
{
    ULONG node = 99, sz;
    GROUP_AFFINITY ga;
    USHORT n, groups[2];
    HANDLE bad = (HANDLE)(ULONG_PTR)0xdeadbeef0;

    if (!GetNumaHighestNodeNumber(&node) || node != 0) FAIL(10, "GetNumaHighestNodeNumber must be 0");
    printf("highest NUMA node=%lu\n", (unsigned long)node);
    if (GetNumaHighestNodeNumber(0)) FAIL(11, "NULL out must fail");

    memset(&ga, 0xcc, sizeof ga);
    if (!GetNumaNodeProcessorMaskEx(0, &ga) || ga.Group != 0 || ga.Mask != 1) FAIL(20, "node 0 mask must be group 0 mask 1");
    printf("node0 mask=%llx group=%u\n", (unsigned long long)ga.Mask, (unsigned)ga.Group);
    SetLastError(0);
    if (GetNumaNodeProcessorMaskEx(1, &ga) || GetLastError() != ERROR_INVALID_PARAMETER) FAIL(21, "NUMA node 1 must fail INVALID_PARAMETER");

    n = 1; groups[0] = 9;
    if (!GetProcessGroupAffinity(GetCurrentProcess(), &n, groups) || n != 1 || groups[0] != 0) FAIL(30, "current process: one group 0");
    n = 0;
    SetLastError(0);
    if (GetProcessGroupAffinity(GetCurrentProcess(), &n, groups) || GetLastError() != ERROR_INSUFFICIENT_BUFFER || n != 1)
        FAIL(31, "capacity 0 must fail INSUFFICIENT_BUFFER with count 1");
    n = 1;
    SetLastError(0);
    if (GetProcessGroupAffinity(bad, &n, groups) || GetLastError() == 0) FAIL(32, "invalid process handle must fail");
    printf("invalid handle error=%lu\n", (unsigned long)GetLastError());

    if (GetLargePageMinimum() != 0) FAIL(40, "large pages unsupported: minimum must be 0");

    sz = 0;
    if (!SetThreadStackGuarantee(&sz)) FAIL(50, "query-only stack guarantee must succeed");
    printf("stack guarantee=%lu\n", (unsigned long)sz);
    {
        ULONG cur = sz, grow = cur + 0x100000;
        SetLastError(0);
        if (SetThreadStackGuarantee(&grow) || GetLastError() != ERROR_NOT_SUPPORTED) FAIL(51, "growth must fail ERROR_NOT_SUPPORTED");
    }
    if (SetThreadStackGuarantee(0)) FAIL(52, "NULL must fail");
    printf("runtime topology contract PASS\n");
    return 0;
}
