/* SPDX-License-Identifier: GPL-2.0-only
 * Wine port glue: critical sections with debug information.
 *
 * Wine code names its critical sections for debugging right after creating them:
 *     InitializeCriticalSectionEx(&cs, 0, RTL_CRITICAL_SECTION_FLAG_FORCE_DEBUG_INFO);
 *     cs.DebugInfo->Spare[0] = (DWORD_PTR)(__FILE__ ": cs");
 * Windows allocates cs.DebugInfo when that flag is given (and Wine always does); the Shizuku ntdll leaves it NULL. The
 * Wine modules therefore create their critical sections through these wrappers, which let ntdll initialise the lock and
 * attach a zeroed RTL_CRITICAL_SECTION_DEBUG block from the process heap, released again by DeleteCriticalSection.
 * The lock itself is entirely ntdll's; DebugInfo is only bookkeeping (Shizuku's ntdll never reads it).
 */
#include <stdarg.h>
#include "ntstatus.h"
#define WIN32_NO_STATUS
#include "windef.h"
#include "winbase.h"
#include "winternl.h"

#define SHZW_DEBUGINFO_TYPE 0x5a53       /* marks blocks allocated here (static Wine initialisers use Type 0) */

NTSTATUS NTAPI RtlInitializeCriticalSectionEx(RTL_CRITICAL_SECTION *cs, ULONG spin, ULONG flags);
NTSTATUS NTAPI RtlDeleteCriticalSection(RTL_CRITICAL_SECTION *cs);

static BOOL init_cs(CRITICAL_SECTION *cs, DWORD spin, DWORD flags)
{
    NTSTATUS st = RtlInitializeCriticalSectionEx(cs, spin, flags & ~RTL_CRITICAL_SECTION_FLAG_FORCE_DEBUG_INFO);
    RTL_CRITICAL_SECTION_DEBUG *d;
    if (st) { SetLastError(RtlNtStatusToDosError(st)); return FALSE; }
    if (!cs->DebugInfo && (d = HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, sizeof(*d)))) {
        d->Type = SHZW_DEBUGINFO_TYPE;
        d->CriticalSection = cs;
        cs->DebugInfo = d;
    }
    return TRUE;
}

BOOL WINAPI InitializeCriticalSectionEx(CRITICAL_SECTION *cs, DWORD spin, DWORD flags) { return init_cs(cs, spin, flags); }
BOOL WINAPI InitializeCriticalSectionAndSpinCount(CRITICAL_SECTION *cs, DWORD spin) { return init_cs(cs, spin, 0); }
void WINAPI InitializeCriticalSection(CRITICAL_SECTION *cs) { init_cs(cs, 0, 0); }

void WINAPI DeleteCriticalSection(CRITICAL_SECTION *cs)
{
    RTL_CRITICAL_SECTION_DEBUG *d = cs->DebugInfo;
    RtlDeleteCriticalSection(cs);
    if (d && d != (RTL_CRITICAL_SECTION_DEBUG *)~(ULONG_PTR)0 && d->Type == SHZW_DEBUGINFO_TYPE) {
        HeapFree(GetProcessHeap(), 0, d);
        cs->DebugInfo = NULL;
    }
}

void *__imp_InitializeCriticalSectionEx = (void *)InitializeCriticalSectionEx;
void *__imp_InitializeCriticalSectionAndSpinCount = (void *)InitializeCriticalSectionAndSpinCount;
void *__imp_InitializeCriticalSection = (void *)InitializeCriticalSection;
void *__imp_DeleteCriticalSection = (void *)DeleteCriticalSection;
