/* SPDX-License-Identifier: GPL-2.0-only
 * powrprof.dll - power information (also the host of api-ms-win-power-base-l1-1-0 and api-ms-win-power-setting-l1-1-0).
 *
 *   CallNtPowerInformation  ProcessorInformation: one PROCESSOR_POWER_INFORMATION per processor (Kernel64 runs one);
 *                           MaxMhz = CurrentMhz = MhzLimit = the time-stamp counter rate the kernel measured against its
 *                           tick (NtShzQueryK32 K32Q_CPU_CLOCK), idle states 0 (the kernel has no C-state control).
 *                           SystemBatteryState: AC power, no battery (no battery device is driven).
 *                           Other levels: STATUS_NOT_SUPPORTED (they describe power-management machinery that does not
 *                           exist here; nothing is invented).
 *   PowerDeterminePlatformRoleEx   PlatformRoleUnspecified: Windows reads the ACPI FADT preferred PM profile, which
 *                           Kernel64 does not parse, so the role is not known.
 *   PowerGetActiveScheme, PowerReadACValue, PowerReadDCValue   there is no power-scheme store (no power policy
 *                           manager): ERROR_FILE_NOT_FOUND, the error Windows returns for a scheme or setting that does not
 *                           exist.
 */
#include "nt.h"
#include <string.h>

typedef struct { ULONG Number, MaxMhz, CurrentMhz, MhzLimit, MaxIdleState, CurrentIdleState; } proc_power_info;
typedef struct {
    BOOLEAN AcOnLine, BatteryPresent, Charging, Discharging;
    BOOLEAN Spare1[3];
    BYTE Tag;
    ULONG MaxCapacity, RemainingCapacity, Rate, EstimatedTime, DefaultAlert1, DefaultAlert2;
} battery_state;

#define LEVEL_SYSTEM_BATTERY_STATE 5
#define LEVEL_PROCESSOR_INFORMATION 11
#define STATUS_NOT_SUPPORTED_ ((NTSTATUS)0xC00000BB)
#define STATUS_BUFFER_TOO_SMALL_ ((NTSTATUS)0xC0000023)

DLLAPI LONG WINAPI CallNtPowerInformation(int level, PVOID in, ULONG in_len, PVOID out, ULONG out_len)
{
    (void)in; (void)in_len;
    switch (level) {
    case LEVEL_PROCESSOR_INFORMATION: {
        proc_power_info info;
        ULONG64 hz = 0;
        ULONG got = 0;
        NTSTATUS st;
        if (!out) return STATUS_INVALID_PARAMETER;
        if (out_len < sizeof info) return STATUS_BUFFER_TOO_SMALL_;
        st = NtShzQueryK32(K32Q_CPU_CLOCK, 0, &hz, sizeof hz, &got);
        if (st) return st;
        memset(&info, 0, sizeof info);
        info.Number = 0;
        info.MaxMhz = info.CurrentMhz = info.MhzLimit = (ULONG)((hz + 500000) / 1000000);
        memcpy(out, &info, sizeof info);
        return STATUS_SUCCESS;
    }
    case LEVEL_SYSTEM_BATTERY_STATE: {
        battery_state b;
        if (!out) return STATUS_INVALID_PARAMETER;
        if (out_len < sizeof b) return STATUS_BUFFER_TOO_SMALL_;
        memset(&b, 0, sizeof b);
        b.AcOnLine = TRUE;                                     /* no battery device: mains power */
        memcpy(out, &b, sizeof b);
        return STATUS_SUCCESS;
    }
    default:
        return STATUS_NOT_SUPPORTED_;
    }
}

DLLAPI int WINAPI PowerDeterminePlatformRoleEx(ULONG version)
{
    if (version != 1 && version != 2) return 0;                /* POWER_PLATFORM_ROLE_V1 / _V2 */
    return 0;                                                  /* PlatformRoleUnspecified */
}

DLLAPI int WINAPI PowerDeterminePlatformRole(void) { return 0; }

DLLAPI DWORD WINAPI PowerGetActiveScheme(HKEY root, GUID **scheme)
{
    (void)root;
    if (!scheme) return ERROR_INVALID_PARAMETER;
    *scheme = 0;
    return ERROR_FILE_NOT_FOUND;
}

DLLAPI DWORD WINAPI PowerReadACValue(HKEY root, const GUID *scheme, const GUID *subgroup, const GUID *setting, PULONG type,
                                     LPBYTE buffer, LPDWORD size)
{
    (void)root; (void)scheme; (void)subgroup; (void)setting; (void)type; (void)buffer; (void)size;
    return ERROR_FILE_NOT_FOUND;
}

DLLAPI DWORD WINAPI PowerReadDCValue(HKEY root, const GUID *scheme, const GUID *subgroup, const GUID *setting, PULONG type,
                                     PUCHAR buffer, LPDWORD size)
{
    (void)root; (void)scheme; (void)subgroup; (void)setting; (void)type; (void)buffer; (void)size;
    return ERROR_FILE_NOT_FOUND;
}
