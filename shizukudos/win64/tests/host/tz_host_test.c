/* SPDX-License-Identifier: GPL-2.0-only
 * Native unit test of kernel32/tz_core.c (SystemTimeToTzSpecificLocalTime / TzSpecificLocalTimeToSystemTime / the local-time
 * conversions of kernel32). Expected values are published civil-time facts of real zones, not output of the code under test:
 *   US Pacific 2024: PDT from Sun 2024-03-10 02:00 PST (10:00 UTC) to Sun 2024-11-03 02:00 PDT (09:00 UTC); PST = UTC-8.
 *   Central Europe 2024: CEST from Sun 2024-03-31 01:00 UTC to Sun 2024-10-27 01:00 UTC (last Sundays); CET = UTC+1.
 *   Sydney 2024: AEST (UTC+10) from Sun 2024-04-07 03:00 AEDT (2024-04-06 16:00 UTC), AEDT (UTC+11) from Sun 2024-10-06
 *   02:00 AEST (2024-10-05 16:00 UTC).
 * Build and run: python3 shizukudos/win64/tests/host/run_host_tests.py */
#include <stdio.h>
#include "../../kernel32/tz_core.c"

static int failures, checks;
#define CHECK(cond, ...) do { ++checks; if (!(cond)) { ++failures; printf("FAIL %s:%d: ", __FILE__, __LINE__); printf(__VA_ARGS__); printf("\n"); } } while (0)

static int64_t ft(int y, int mo, int d, int h, int mi)
{
    tzc_time t = { y, mo, 0, d, h, mi, 0, 0 };
    int64_t v = -1;
    if (tzc_to_ft(&t, &v)) { printf("bad date %d-%d-%d\n", y, mo, d); ++failures; }
    return v;
}

static const char *fmt(int64_t v)
{
    static char buf[4][40];
    static int k;
    tzc_time t;
    char *b = buf[k++ & 3];
    if (tzc_from_ft(v, &t)) return "(invalid)";
    snprintf(b, 40, "%04d-%02d-%02d %02d:%02d", t.year, t.month, t.day, t.hour, t.minute);
    return b;
}

static void utc_to_local(const tzc_zone *z, int64_t utc, int64_t want, int want_id, const char *what)
{
    int64_t got = 0;
    const int id = tzc_utc_to_local(z, utc, &got);
    CHECK(id == want_id && got == want, "%s: UTC %s -> %s id %d (want %s id %d)", what, fmt(utc), fmt(got), id, fmt(want), want_id);
}

static void local_to_utc(const tzc_zone *z, int64_t local, int64_t want, int want_id, const char *what)
{
    int64_t got = 0;
    const int id = tzc_local_to_utc(z, local, &got);
    CHECK(id == want_id && got == want, "%s: local %s -> UTC %s id %d (want %s id %d)", what, fmt(local), fmt(got), id, fmt(want), want_id);
}

int main(void)
{
    /* rules as Windows' registry stores them (TZI): {bias, std bias, dst bias, StandardDate, DaylightDate} */
    const tzc_zone pacific = { 480, 0, -60, { 0, 11, 0, 1, 2, 0, 0, 0 }, { 0, 3, 0, 2, 2, 0, 0, 0 } };
    const tzc_zone europe = { -60, 0, -60, { 0, 10, 0, 5, 3, 0, 0, 0 }, { 0, 3, 0, 5, 2, 0, 0, 0 } };
    const tzc_zone sydney = { -600, 0, -60, { 0, 4, 0, 1, 3, 0, 0, 0 }, { 0, 10, 0, 1, 2, 0, 0, 0 } };
    const tzc_zone utc = { 0, 0, 0, { 0, 0, 0, 0, 0, 0, 0, 0 }, { 0, 0, 0, 0, 0, 0, 0, 0 } };
    const tzc_zone fixed = { -330, 0, 0, { 0, 0, 0, 0, 0, 0, 0, 0 }, { 0, 0, 0, 0, 0, 0, 0, 0 } };      /* India, no DST */
    tzc_time t;
    int64_t v;

    /* civil calendar */
    CHECK(tzc_from_ft(0, &t) == 0 && t.year == 1601 && t.month == 1 && t.day == 1 && t.dow == 1, "1601-01-01 is a Monday");
    CHECK(tzc_from_ft(ft(2024, 2, 29, 12, 0), &t) == 0 && t.month == 2 && t.day == 29 && t.dow == 4, "2024-02-29 is a Thursday");
    CHECK(tzc_from_ft(ft(2000, 1, 1, 0, 0), &t) == 0 && t.dow == 6, "2000-01-01 is a Saturday");
    CHECK(ft(1970, 1, 1, 0, 0) == 116444736000000000ll, "the Unix epoch is FILETIME 116444736000000000");
    { tzc_time bad = { 2023, 2, 0, 29, 0, 0, 0, 0 }; CHECK(tzc_to_ft(&bad, &v) == -1, "2023-02-29 does not exist"); }

    /* no daylight rule */
    utc_to_local(&utc, ft(2024, 7, 1, 12, 0), ft(2024, 7, 1, 12, 0), TZC_UNKNOWN, "UTC zone");
    utc_to_local(&fixed, ft(2024, 7, 1, 12, 0), ft(2024, 7, 1, 17, 30), TZC_UNKNOWN, "UTC+5:30");
    local_to_utc(&fixed, ft(2024, 1, 1, 0, 0), ft(2023, 12, 31, 18, 30), TZC_UNKNOWN, "UTC+5:30 back over the year boundary");

    /* US Pacific */
    utc_to_local(&pacific, ft(2024, 1, 15, 12, 0), ft(2024, 1, 15, 4, 0), TZC_STANDARD, "PST winter");
    utc_to_local(&pacific, ft(2024, 7, 1, 12, 0), ft(2024, 7, 1, 5, 0), TZC_DAYLIGHT, "PDT summer");
    utc_to_local(&pacific, ft(2024, 3, 10, 9, 59), ft(2024, 3, 10, 1, 59), TZC_STANDARD, "one minute before PDT starts");
    utc_to_local(&pacific, ft(2024, 3, 10, 10, 0), ft(2024, 3, 10, 3, 0), TZC_DAYLIGHT, "PDT starts: 02:00 PST becomes 03:00 PDT");
    utc_to_local(&pacific, ft(2024, 11, 3, 8, 59), ft(2024, 11, 3, 1, 59), TZC_DAYLIGHT, "one minute before PDT ends");
    utc_to_local(&pacific, ft(2024, 11, 3, 9, 0), ft(2024, 11, 3, 1, 0), TZC_STANDARD, "PDT ends: 02:00 PDT becomes 01:00 PST");
    utc_to_local(&pacific, ft(2025, 1, 1, 7, 0), ft(2024, 12, 31, 23, 0), TZC_STANDARD, "PST across the new year");
    local_to_utc(&pacific, ft(2024, 7, 1, 5, 0), ft(2024, 7, 1, 12, 0), TZC_DAYLIGHT, "PDT local to UTC");
    local_to_utc(&pacific, ft(2024, 1, 15, 4, 0), ft(2024, 1, 15, 12, 0), TZC_STANDARD, "PST local to UTC");
    local_to_utc(&pacific, ft(2024, 11, 3, 1, 30), ft(2024, 11, 3, 8, 30), TZC_DAYLIGHT, "the repeated hour is taken as daylight time");

    /* Central Europe: last Sunday rules */
    utc_to_local(&europe, ft(2024, 3, 31, 0, 59), ft(2024, 3, 31, 1, 59), TZC_STANDARD, "CET before the last Sunday of March");
    utc_to_local(&europe, ft(2024, 3, 31, 1, 0), ft(2024, 3, 31, 3, 0), TZC_DAYLIGHT, "CEST starts on the last Sunday of March");
    utc_to_local(&europe, ft(2024, 10, 27, 0, 59), ft(2024, 10, 27, 2, 59), TZC_DAYLIGHT, "CEST until the last Sunday of October");
    utc_to_local(&europe, ft(2024, 10, 27, 1, 0), ft(2024, 10, 27, 2, 0), TZC_STANDARD, "CET again on the last Sunday of October");
    utc_to_local(&europe, ft(2021, 3, 28, 1, 0), ft(2021, 3, 28, 3, 0), TZC_DAYLIGHT, "2021: the last Sunday of March is the 28th");

    /* Sydney: daylight time spans the new year */
    utc_to_local(&sydney, ft(2024, 1, 15, 0, 0), ft(2024, 1, 15, 11, 0), TZC_DAYLIGHT, "AEDT in January");
    utc_to_local(&sydney, ft(2024, 7, 1, 0, 0), ft(2024, 7, 1, 10, 0), TZC_STANDARD, "AEST in July");
    utc_to_local(&sydney, ft(2024, 4, 6, 15, 59), ft(2024, 4, 7, 2, 59), TZC_DAYLIGHT, "one minute before AEDT ends");
    utc_to_local(&sydney, ft(2024, 4, 6, 16, 0), ft(2024, 4, 7, 2, 0), TZC_STANDARD, "AEDT ends: 03:00 AEDT becomes 02:00 AEST");
    utc_to_local(&sydney, ft(2024, 10, 5, 16, 0), ft(2024, 10, 6, 3, 0), TZC_DAYLIGHT, "AEDT starts: 02:00 AEST becomes 03:00 AEDT");
    local_to_utc(&sydney, ft(2024, 12, 25, 12, 0), ft(2024, 12, 25, 1, 0), TZC_DAYLIGHT, "AEDT local to UTC");

    /* invalid rules */
    {
        tzc_zone bad = pacific;
        bad.std_date.month = 0;
        CHECK(tzc_utc_to_local(&bad, ft(2024, 1, 1, 0, 0), &v) == TZC_INVALID, "a daylight rule without a standard rule is invalid");
        bad = pacific;
        bad.dst_date.day = 6;
        CHECK(tzc_utc_to_local(&bad, ft(2024, 6, 1, 0, 0), &v) == TZC_INVALID, "occurrence 6 is invalid");
    }
    printf("tz_host_test: %d checks, %d failed\n", checks, failures);
    return failures != 0;
}
