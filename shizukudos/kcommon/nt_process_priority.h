/* SPDX-License-Identifier: GPL-2.0-only
 * Native ProcessPriorityClass (18): two-byte BOOLEAN/UCHAR ABI. Native
 * ordinals are distinct from the Win32 DWORD flags kept in process_t.
 * This backend supports five non-realtime classes without foreground boosts
 * or resource background scheduling. UNKNOWN is not a default-class alias.
 * Pure conversions leave output bytes unchanged on failure.
 */
#ifndef SHZ_NT_PROCESS_PRIORITY_H
#define SHZ_NT_PROCESS_PRIORITY_H
#include <stddef.h>
#include "nt_sched_policy.h"

#define SHZ_NT_PROCESS_PRIORITY_INFO_CLASS 18u
typedef struct {
    uint8_t Foreground;
    uint8_t PriorityClass;
} shz_nt_process_priority_t;
_Static_assert(sizeof(shz_nt_process_priority_t) == 2, "native process priority size");
_Static_assert(offsetof(shz_nt_process_priority_t, Foreground) == 0, "native foreground offset");
_Static_assert(offsetof(shz_nt_process_priority_t, PriorityClass) == 1, "native priority offset");

enum {
    SHZ_NT_NATIVE_PROCESS_UNKNOWN = 0,
    SHZ_NT_NATIVE_PROCESS_IDLE = 1,
    SHZ_NT_NATIVE_PROCESS_NORMAL = 2,
    SHZ_NT_NATIVE_PROCESS_HIGH = 3,
    SHZ_NT_NATIVE_PROCESS_REALTIME = 4,
    SHZ_NT_NATIVE_PROCESS_BELOW_NORMAL = 5,
    SHZ_NT_NATIVE_PROCESS_ABOVE_NORMAL = 6
};

static inline shz_nt_sched_result_t shz_nt_process_class_from_native(uint8_t ordinal, uint32_t *out)
{
    uint32_t cls;
    if (!out) return SHZ_NT_SCHED_INVALID_ARGUMENT;
    switch (ordinal) {
    case SHZ_NT_NATIVE_PROCESS_IDLE: cls = SHZ_NT_PROCESS_IDLE; break;
    case SHZ_NT_NATIVE_PROCESS_NORMAL: cls = SHZ_NT_PROCESS_NORMAL; break;
    case SHZ_NT_NATIVE_PROCESS_HIGH: cls = SHZ_NT_PROCESS_HIGH; break;
    case SHZ_NT_NATIVE_PROCESS_BELOW_NORMAL: cls = SHZ_NT_PROCESS_BELOW_NORMAL; break;
    case SHZ_NT_NATIVE_PROCESS_ABOVE_NORMAL: cls = SHZ_NT_PROCESS_ABOVE_NORMAL; break;
    case SHZ_NT_NATIVE_PROCESS_REALTIME: return SHZ_NT_SCHED_UNSUPPORTED;
    default: return SHZ_NT_SCHED_INVALID_ARGUMENT;
    }
    *out = cls;
    return SHZ_NT_SCHED_OK;
}

static inline shz_nt_sched_result_t shz_nt_process_class_to_native(uint32_t cls, shz_nt_process_priority_t *out)
{
    shz_nt_process_priority_t value = { 0, 0 };
    if (!out) return SHZ_NT_SCHED_INVALID_ARGUMENT;
    switch (cls) {
    case SHZ_NT_PROCESS_IDLE: value.PriorityClass = SHZ_NT_NATIVE_PROCESS_IDLE; break;
    case SHZ_NT_PROCESS_NORMAL: value.PriorityClass = SHZ_NT_NATIVE_PROCESS_NORMAL; break;
    case SHZ_NT_PROCESS_HIGH: value.PriorityClass = SHZ_NT_NATIVE_PROCESS_HIGH; break;
    case SHZ_NT_PROCESS_BELOW_NORMAL: value.PriorityClass = SHZ_NT_NATIVE_PROCESS_BELOW_NORMAL; break;
    case SHZ_NT_PROCESS_ABOVE_NORMAL: value.PriorityClass = SHZ_NT_NATIVE_PROCESS_ABOVE_NORMAL; break;
    case SHZ_NT_PROCESS_REALTIME: return SHZ_NT_SCHED_UNSUPPORTED;
    default: return SHZ_NT_SCHED_INVALID_ARGUMENT;
    }
    *out = value;
    return SHZ_NT_SCHED_OK;
}
#endif
