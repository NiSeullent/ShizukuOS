/* SPDX-License-Identifier: GPL-2.0-only
 * GetSystemTimes reports actual scheduler CPU time at the kernel tick's
 * resolution. Kernel time includes idle time, per the Windows contract.
 * https://learn.microsoft.com/en-us/windows/win32/api/processthreadsapi/nf-processthreadsapi-getsystemtimes
 */
#include "k32.h"

K32API BOOL WINAPI GetSystemTimes(LPFILETIME idle, LPFILETIME kernel, LPFILETIME user)
{
    uint64_t times[3];
    NTSTATUS status = NtQuerySystemInformation(0x102, times, sizeof times, NULL);
    if (status) { k32_nt_error(status); return FALSE; }
    if (idle) { idle->dwLowDateTime = (DWORD)times[0]; idle->dwHighDateTime = (DWORD)(times[0] >> 32); }
    if (kernel) { kernel->dwLowDateTime = (DWORD)times[1]; kernel->dwHighDateTime = (DWORD)(times[1] >> 32); }
    if (user) { user->dwLowDateTime = (DWORD)times[2]; user->dwHighDateTime = (DWORD)(times[2] >> 32); }
    return TRUE;
}
