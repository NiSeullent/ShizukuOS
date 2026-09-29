/* SPDX-License-Identifier: GPL-2.0-only
 * IsProcessInJob for processes this loader created. No job is assigned.
 * A process with no job returns success, writes FALSE through Result, and sets
 * last-error 0. A null Result or an invalid process or job handle fails.
 */
#ifndef NTW_JOB_H
#define NTW_JOB_H
#include <stdint.h>
uint32_t ntw_job_is_process(uint32_t process, uint32_t job, uint32_t *result, uint32_t *error, int valid);
#endif
