/* SPDX-License-Identifier: GPL-2.0-only
 * Shizuku time-zone core: conversions between UTC and a local time described by a TIME_ZONE_INFORMATION rule (bias, standard
 * and daylight biases and the two yearly transition dates). Pure functions over FILETIME values (100 ns since 1601-01-01);
 * no Windows types, so tests/host/tz_host_test.c runs the same code natively.
 *
 * Rules (documented TIME_ZONE_INFORMATION semantics):
 *   local = UTC - (Bias + StandardBias) during standard time, UTC - (Bias + DaylightBias) during daylight time;
 *   no daylight rule (DaylightDate.wMonth == 0): local = UTC - Bias.
 *   A transition date with wYear == 0 is "the wDay-th wDayOfWeek of wMonth" (wDay 5 = the last one) at wHour:wMinute; with a
 *   year it is that absolute date. DaylightDate is given in standard (wall clock) time, StandardDate in daylight time.
 *   A local time that exists twice (the hour after daylight time ends) is taken as daylight time.
 */
#ifndef SHZ_TZ_CORE_H
#define SHZ_TZ_CORE_H
#include <stdint.h>

typedef struct { int year, month, dow, day, hour, minute, second, ms; } tzc_time;           /* SYSTEMTIME fields */
typedef struct { long bias, std_bias, dst_bias; tzc_time std_date, dst_date; } tzc_zone;

#define TZC_UNKNOWN 0
#define TZC_STANDARD 1
#define TZC_DAYLIGHT 2
#define TZC_INVALID (-1)

int tzc_to_ft(const tzc_time *t, int64_t *ft);          /* 0, or -1 for an invalid date */
int tzc_from_ft(int64_t ft, tzc_time *t);               /* 0, or -1 when out of range */
int tzc_zone_id(const tzc_zone *z, int64_t ft, int is_local);          /* TZC_* for a UTC (or local) instant */
int tzc_utc_to_local(const tzc_zone *z, int64_t utc, int64_t *local);  /* TZC_* id used, TZC_INVALID on error */
int tzc_local_to_utc(const tzc_zone *z, int64_t local, int64_t *utc);
#endif
