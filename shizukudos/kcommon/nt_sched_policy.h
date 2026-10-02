/* SPDX-License-Identifier: GPL-2.0-only
 * Pure, partial Windows thread base-priority projection for future NT callers.
 * This does not set policy, resolve handles, grant rights or change VMM state.
 * It exposes no quantum information class and supplies no dynamic boost policy.
 *
 * Accepted process classes are the five non-realtime Win32 flags below. Zero
 * is not a default-class alias: callers must resolve their process default.
 * Accepted Win32 levels are -15, -2, -1, 0, 1, 2 and 15. The raw NT class-3
 * subset accepts -2..2 and saturation sentinels -16/+16; raw -15/+15 are invalid.
 * Realtime and Win32 background mode are explicitly unsupported. Other classes
 * or values are invalid. These result codes are helper results, not NTSTATUS.
 *
 * Output records retain the relative request, since High+2 and High+15 both
 * project to absolute 15 and cannot be distinguished from that number alone.
 * Absolute priority is the projected base, not an observed current priority.
 * Normal process + normal thread projects to absolute 8, relative increment 0.
 * On failure output bytes remain unchanged. NULL output is always invalid.
 * Validate the complete bounded scalar input before performing any arithmetic.
 *
 * Primary contracts (independent implementation, no imported source bodies):
 * https://learn.microsoft.com/en-us/windows/win32/procthread/scheduling-priorities
 * https://github.com/reactos/reactos/blob/master/dll/win32/kernel32/client/thread.c
 * https://github.com/reactos/reactos/blob/master/ntoskrnl/ps/query.c
 */
#ifndef SHZ_NT_SCHED_POLICY_H
#define SHZ_NT_SCHED_POLICY_H
#include <stdint.h>

typedef enum {
    SHZ_NT_PROCESS_IDLE = 0x40,
    SHZ_NT_PROCESS_BELOW_NORMAL = 0x4000,
    SHZ_NT_PROCESS_NORMAL = 0x20,
    SHZ_NT_PROCESS_ABOVE_NORMAL = 0x8000,
    SHZ_NT_PROCESS_HIGH = 0x80,
    SHZ_NT_PROCESS_REALTIME = 0x100
} shz_nt_process_priority_class_t;

typedef enum {
    SHZ_NT_SCHED_OK = 0,
    SHZ_NT_SCHED_INVALID_ARGUMENT,
    SHZ_NT_SCHED_UNSUPPORTED
} shz_nt_sched_result_t;

typedef struct {
    uint32_t process_class;
    int32_t win32_priority;
    int32_t nt_base_increment;
    uint32_t absolute_priority;
} shz_nt_sched_projection_t;

static inline shz_nt_sched_result_t shz_nt_sched_from_win32(
    uint32_t process_class, int32_t priority, shz_nt_sched_projection_t *out)
{
    uint32_t base;
    shz_nt_sched_projection_t value;
    if (!out) return SHZ_NT_SCHED_INVALID_ARGUMENT;
    switch (process_class) {
    case SHZ_NT_PROCESS_IDLE: base = 4; break;
    case SHZ_NT_PROCESS_BELOW_NORMAL: base = 6; break;
    case SHZ_NT_PROCESS_NORMAL: base = 8; break;
    case SHZ_NT_PROCESS_ABOVE_NORMAL: base = 10; break;
    case SHZ_NT_PROCESS_HIGH: base = 13; break;
    case SHZ_NT_PROCESS_REALTIME: return SHZ_NT_SCHED_UNSUPPORTED;
    default: return SHZ_NT_SCHED_INVALID_ARGUMENT;
    }
    if (priority == 0x10000 || priority == 0x20000)
        return SHZ_NT_SCHED_UNSUPPORTED; /* resource background mode is separate */
    if (priority != -15 && priority != 15 && (priority < -2 || priority > 2))
        return SHZ_NT_SCHED_INVALID_ARGUMENT;
    value.process_class = process_class;
    value.win32_priority = priority;
    value.nt_base_increment = priority == -15 ? -16 : priority == 15 ? 16 : priority;
    value.absolute_priority = priority == -15 ? 1u : priority == 15 ? 15u :
                              (uint32_t)((int32_t)base + priority);
    *out = value;
    return SHZ_NT_SCHED_OK;
}

static inline shz_nt_sched_result_t shz_nt_sched_from_base_increment(
    uint32_t process_class, int32_t increment, shz_nt_sched_projection_t *out)
{
    /* Translate only recognized sentinels. In particular INT32_MIN is never
     * negated, and raw +/-15 never acquire the meaning of Win32 +/-15. */
    if (!out) return SHZ_NT_SCHED_INVALID_ARGUMENT;
    if (process_class == SHZ_NT_PROCESS_REALTIME) return SHZ_NT_SCHED_UNSUPPORTED;
    if (increment != -16 && increment != 16 && (increment < -2 || increment > 2))
        return SHZ_NT_SCHED_INVALID_ARGUMENT;
    return shz_nt_sched_from_win32(process_class,
        increment == -16 ? -15 : increment == 16 ? 15 : increment, out);
}
#endif
