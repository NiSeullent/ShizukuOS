/* SPDX-License-Identifier: GPL-2.0-only
 * Microsoft documents IsProcessInJob in jobapi.h: a successful call returns
 * nonzero and writes FALSE through Result when the process is not in the job.
 * Chromium sandbox/policy/win/sandbox_win.cc checks that return and then
 * reads the BOOL. This loader never assigns a job, so a valid process and a
 * null job handle return success, write FALSE, and set last-error 0. A null
 * Result or an invalid process or job handle returns zero with a last-error.
 * Success is not returned for every input.
 */
#include "job.h"
uint32_t ntw_job_is_process(uint32_t process, uint32_t job, uint32_t *result, uint32_t *error, int valid) {
    (void)process;
    if (!result) {
        if (error) *error = 87;
        return 0;
    }
    if (!valid || job) {
        if (error) *error = 6;
        return 0;
    }
    *result = 0;
    if (error) *error = 0;
    return 1;
}
