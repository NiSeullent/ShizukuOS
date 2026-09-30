/* SPDX-License-Identifier: GPL-2.0-only
 * Independent Windows clock/calendar acceptance probe. The epoch expectations
 * below were cross-checked against Python's UTC datetime, not this adapter.
 * Compile this translation unit alone: it includes the production adapter.
 */
#include <windows.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>

static int clock_model, conversion_failure;
static SYSTEMTIME model_time;

static void probe_get_system_time(SYSTEMTIME *output)
{
    if (clock_model) *output = model_time;
    else GetSystemTime(output);
}

static BOOL probe_system_time_to_file_time(const SYSTEMTIME *input, FILETIME *output)
{
    if (conversion_failure) return FALSE;
    return SystemTimeToFileTime(input, output);
}

#define GetSystemTime probe_get_system_time
#define SystemTimeToFileTime probe_system_time_to_file_time
#include "native_time.c"
#undef SystemTimeToFileTime
#undef GetSystemTime

struct expectation {
    int64_t seconds;
    int year, month, day, hour, minute, second, weekday, yearday;
};

static const struct expectation cases[] = {
    { INT64_C(0),           1970, 1,  1,  0,  0,  0, 4,   0 },
    { INT64_C(946684799),   1999, 12, 31, 23, 59, 59, 5, 364 },
    { INT64_C(951782400),   2000, 2, 29,  0,  0,  0, 2,  59 },
    { INT64_C(951868800),   2000, 3,  1,  0,  0,  0, 3,  60 },
    { INT64_C(2147483647),  2038, 1, 19,  3, 14,  7, 2,  18 },
    { INT64_C(2147483648),  2038, 1, 19,  3, 14,  8, 2,  18 },
    { INT64_C(4107542399),  2100, 2, 28, 23, 59, 59, 0,  58 },
    { INT64_C(4107542400),  2100, 3,  1,  0,  0,  0, 1,  59 },
    { INT64_C(13574563200), 2400, 2, 29,  0,  0,  0, 2,  59 },
    { INT64_C(13574649600), 2400, 3,  1,  0,  0,  0, 3,  60 }
};

static unsigned int checks, failures;
#define CHECK(test, label) do { \
    ++checks; \
    if (!(test)) { ++failures; printf("FAIL %s line=%u\n", label, (unsigned)__LINE__); } \
} while (0)

static void calendar_cases(void)
{
    size_t i;
    for (i = 0; i < sizeof cases / sizeof cases[0]; ++i) {
        const struct expectation *expected = &cases[i];
        mbedtls_time_t epoch = expected->seconds;
        struct tm observed;
        int64_t reported = -2;
        memset(&observed, 0xa5, sizeof observed);
        CHECK(mbedtls_platform_gmtime_r(&epoch, &observed) == &observed,
              "UTC conversion succeeds");
        CHECK(observed.tm_year == expected->year - 1900 &&
              observed.tm_mon == expected->month - 1 &&
              observed.tm_mday == expected->day &&
              observed.tm_hour == expected->hour &&
              observed.tm_min == expected->minute &&
              observed.tm_sec == expected->second,
              "independent date/time expectation");
        CHECK(observed.tm_wday == expected->weekday &&
              observed.tm_yday == expected->yearday && observed.tm_isdst == 0,
              "independent Gregorian calendar expectation");

        memset(&model_time, 0, sizeof model_time);
        model_time.wYear = (WORD)expected->year;
        model_time.wMonth = (WORD)expected->month;
        model_time.wDay = (WORD)expected->day;
        model_time.wHour = (WORD)expected->hour;
        model_time.wMinute = (WORD)expected->minute;
        model_time.wSecond = (WORD)expected->second;
        model_time.wMilliseconds = 999;
        clock_model = 1;
        CHECK(ntwst_native_time(&reported) == expected->seconds &&
              reported == expected->seconds,
              "native FILETIME epoch and millisecond floor");
        CHECK(ntwst_native_time(NULL) == expected->seconds,
              "optional epoch output");
    }
}

static void invalid_cases(void)
{
    mbedtls_time_t epoch = -1;
    struct tm observed, saved;
    int64_t reported = -2;
    memset(&observed, 0xa5, sizeof observed);
    saved = observed;
    CHECK(mbedtls_platform_gmtime_r(NULL, &observed) == NULL,
          "NULL epoch rejected");
    CHECK(mbedtls_platform_gmtime_r(&epoch, NULL) == NULL,
          "NULL result rejected");
    CHECK(mbedtls_platform_gmtime_r(&epoch, &observed) == NULL,
          "negative epoch rejected");
    epoch = INT64_MAX;
    CHECK(mbedtls_platform_gmtime_r(&epoch, &observed) == NULL,
          "64-bit FILETIME arithmetic overflow rejected");
    CHECK(memcmp(&observed, &saved, sizeof observed) == 0,
          "invalid conversion preserves output");

    clock_model = 1;
    conversion_failure = 1;
    CHECK(ntwst_native_time(&reported) == -1 && reported == -1,
          "native clock conversion failure propagated");
    conversion_failure = 0;
    model_time.wYear = 1969;
    model_time.wMonth = 12;
    model_time.wDay = 31;
    CHECK(ntwst_native_time(&reported) == -1 && reported == -1,
          "pre-epoch system clock rejected");
    model_time.wYear = 2100;
    model_time.wMonth = 2;
    model_time.wDay = 29;
    CHECK(ntwst_native_time(&reported) == -1 && reported == -1,
          "invalid Gregorian system clock rejected");
}

static void actual_clock(void)
{
    FILETIME before, after;
    uint64_t low, high;
    int64_t epoch, copied = -2;
    OSVERSIONINFOA version;
    clock_model = 0;
    conversion_failure = 0;
    GetSystemTimeAsFileTime(&before);
    epoch = ntwst_native_time(&copied);
    GetSystemTimeAsFileTime(&after);
    low = ((uint64_t)before.dwHighDateTime << 32) | before.dwLowDateTime;
    high = ((uint64_t)after.dwHighDateTime << 32) | after.dwLowDateTime;
    CHECK(epoch >= 0 && copied == epoch, "actual system clock succeeds");
    if (low >= EPOCH_1601_TO_1970 && high >= low) {
        CHECK((uint64_t)epoch >= (low - EPOCH_1601_TO_1970) / TICKS_PER_SECOND &&
              (uint64_t)epoch <= (high - EPOCH_1601_TO_1970) / TICKS_PER_SECOND,
              "actual system clock matches native UTC interval");
    } else CHECK(0, "actual native clock interval is valid");
    memset(&version, 0, sizeof version);
    version.dwOSVersionInfoSize = sizeof version;
    CHECK(GetVersionExA(&version) != FALSE, "OS identity queried");
    printf("NTWST_CLOCK_OS_PLATFORM=%lu VERSION=%lu.%lu\n",
           (unsigned long)version.dwPlatformId, (unsigned long)version.dwMajorVersion,
           (unsigned long)version.dwMinorVersion);
}

int main(void)
{
    calendar_cases();
    invalid_cases();
    actual_clock();
    printf("NTWST_CLOCK_CHECKS=%u FAILURES=%u\n", checks, failures);
    return failures ? 1 : 0;
}
