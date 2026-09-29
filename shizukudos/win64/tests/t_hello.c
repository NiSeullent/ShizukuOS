/* SPDX-License-Identifier: GPL-2.0-only
 * First AMD64 PE32+ program: console output, argv, environment, exit code, >4 GiB image base. */
#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include "shzcrt.h"

int main(int argc, char **argv)
{
    char env[128];
    DWORD n = GetEnvironmentVariableA("PROCESSOR_ARCHITECTURE", env, sizeof env);
    printf("hello from Win64 PE32+: argc=%d argv1=%s image=%p pid=%u tid=%u\n", argc, argc > 1 ? argv[1] : "-",
           (void *)GetModuleHandleW(0), (unsigned)GetCurrentProcessId(), (unsigned)GetCurrentThreadId());
    printf("PROCESSOR_ARCHITECTURE=%s (%u chars)\n", n ? env : "(missing)", (unsigned)n);
    /* slots 16..18 are the Kernel64 ring-3 "high" test's; the Win64 app reports through 19..21 */
    shz_evidence(19, (unsigned long long)(uintptr_t)GetModuleHandleW(0));
    shz_evidence(20, n == 5 && !memcmp(env, "AMD64", 5) ? 1 : 0);
    shz_evidence(21, (unsigned long long)argc);
    return 7;
}
