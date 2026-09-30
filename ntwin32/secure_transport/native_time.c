/* SPDX-License-Identifier: GPL-2.0-only
 * Original Win98 clock adapter; no upstream algorithm copied.
 */
#include "mbedtls/platform_time.h"
#include "mbedtls/platform_util.h"

#if defined(_WIN32)
#include <windows.h>
#include <stdint.h>
#include <string.h>

#define EPOCH_1601_TO_1970 UINT64_C(116444736000000000)
#define TICKS_PER_SECOND UINT64_C(10000000)

int64_t ntwst_native_time(int64_t *result)
{
    SYSTEMTIME system_time;
    FILETIME file_time;
    uint64_t ticks;
    int64_t seconds = -1;
    GetSystemTime(&system_time);
    if (SystemTimeToFileTime(&system_time, &file_time)) {
        ticks = ((uint64_t)file_time.dwHighDateTime << 32) | file_time.dwLowDateTime;
        if (ticks >= EPOCH_1601_TO_1970)
            seconds = (int64_t)((ticks - EPOCH_1601_TO_1970) / TICKS_PER_SECOND);
    }
    if (result != NULL) *result = seconds;
    return seconds;
}

struct tm *mbedtls_platform_gmtime_r(const mbedtls_time_t *seconds,
                                    struct tm *output)
{
    uint64_t ticks;
    FILETIME file_time;
    SYSTEMTIME utc;
    static const unsigned int month_offsets[12] =
        { 0, 31, 59, 90, 120, 151, 181, 212, 243, 273, 304, 334 };
    unsigned int leap;
    if (seconds == NULL || output == NULL || *seconds < 0 ||
        (uint64_t)*seconds > (UINT64_MAX - EPOCH_1601_TO_1970) / TICKS_PER_SECOND)
        return NULL;
    ticks = (uint64_t)*seconds * TICKS_PER_SECOND + EPOCH_1601_TO_1970;
    file_time.dwLowDateTime = (DWORD)ticks;
    file_time.dwHighDateTime = (DWORD)(ticks >> 32);
    if (!FileTimeToSystemTime(&file_time, &utc) || utc.wMonth < 1 || utc.wMonth > 12)
        return NULL;
    memset(output, 0, sizeof(*output));
    output->tm_year = (int)utc.wYear - 1900;
    output->tm_mon = (int)utc.wMonth - 1;
    output->tm_mday = utc.wDay;
    output->tm_wday = utc.wDayOfWeek;
    output->tm_hour = utc.wHour;
    output->tm_min = utc.wMinute;
    output->tm_sec = utc.wSecond;
    leap = utc.wYear % 4 == 0 && (utc.wYear % 100 != 0 || utc.wYear % 400 == 0);
    output->tm_yday = (int)month_offsets[utc.wMonth - 1] + utc.wDay - 1 +
                      (int)(utc.wMonth > 2 && leap);
    output->tm_isdst = 0;
    return output;
}
#endif
