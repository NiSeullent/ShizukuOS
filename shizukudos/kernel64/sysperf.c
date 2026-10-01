/* SPDX-License-Identifier: GPL-2.0-only
 * Private CPU-time query used by genuine GetSystemTimes. The current scheduler
 * has one active CPU. No DPC/interrupt/frequency values are fabricated; standard
 * SystemProcessorPerformanceInformation remains outside this query's scope.
 */
#include "ipc.h"
extern void sched_processor_times(uint64_t *idle, uint64_t *kernel, uint64_t *user);

int32_t shz_query_processor_times(process_t *process, uint64_t output, uint64_t length, uint64_t return_length)
{
    uint64_t times[3];
    uint32_t required = sizeof times;
    if (return_length && copy_to_user(process, return_length, &required, sizeof required))
        return STATUS_ACCESS_VIOLATION;
    if (length < sizeof times) return STATUS_INFO_LENGTH_MISMATCH;
    sched_processor_times(&times[0], &times[1], &times[2]);
    return copy_to_user(process, output, times, sizeof times) ? STATUS_ACCESS_VIOLATION : STATUS_SUCCESS;
}
