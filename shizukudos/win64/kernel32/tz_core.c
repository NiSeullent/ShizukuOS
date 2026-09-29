/* SPDX-License-Identifier: GPL-2.0-only
 * Shizuku time-zone core (see tz_core.h). The daylight test follows the documented model: an instant is in daylight time when
 * it is at or after the daylight transition (compared in standard time) and before the standard transition (compared in daylight
 * time) of the same year; where daylight time spans the new year (southern hemisphere) either condition suffices.
 */
#include "tz_core.h"

#define FT_PER_MS 10000ll
#define FT_PER_MIN (60ll * 1000 * FT_PER_MS)
#define FT_PER_DAY (1440ll * FT_PER_MIN)

static int leap(int y) { return (y % 4 == 0 && y % 100 != 0) || y % 400 == 0; }
static int month_days(int y, int m) { static const int d[12] = { 31, 28, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31 }; return d[m - 1] + (m == 2 && leap(y)); }

/* days since 1601-01-01 (a Monday) */
static int64_t days_from_civil(int y, int m, int d)
{
    int64_t n = 0;
    int k;
    const int64_t yy = y - 1601;
    n = yy * 365 + yy / 4 - yy / 100 + yy / 400;
    for (k = 1; k < m; ++k) n += month_days(y, k);
    return n + d - 1;
}

int tzc_to_ft(const tzc_time *t, int64_t *ft)
{
    if (t->year < 1601 || t->year > 30827 || t->month < 1 || t->month > 12 || t->day < 1 || t->day > month_days(t->year, t->month) ||
        t->hour < 0 || t->hour > 23 || t->minute < 0 || t->minute > 59 || t->second < 0 || t->second > 59 || t->ms < 0 || t->ms > 999)
        return -1;
    *ft = days_from_civil(t->year, t->month, t->day) * FT_PER_DAY +
          (((int64_t)t->hour * 60 + t->minute) * 60 + t->second) * 1000 * FT_PER_MS + (int64_t)t->ms * FT_PER_MS;
    return 0;
}

int tzc_from_ft(int64_t ft, tzc_time *t)
{
    int64_t days, ms;
    int y = 1601, m = 1;
    if (ft < 0) return -1;
    days = ft / FT_PER_DAY;
    ms = (ft % FT_PER_DAY) / FT_PER_MS;
    t->dow = (int)((days + 1) % 7);                       /* 1601-01-01 was a Monday (1) */
    {
        const int64_t per400 = 146097;                    /* days in 400 years */
        y += (int)(days / per400) * 400;
        days %= per400;
    }
    for (;;) {
        const int yd = leap(y) ? 366 : 365;
        if (days < yd) break;
        days -= yd;
        ++y;
    }
    while (days >= month_days(y, m)) { days -= month_days(y, m); ++m; }
    t->year = y; t->month = m; t->day = (int)days + 1;
    t->hour = (int)(ms / 3600000); t->minute = (int)(ms / 60000 % 60); t->second = (int)(ms / 1000 % 60); t->ms = (int)(ms % 1000);
    return 0;
}

/* The transition instant of `rule` in `year`, as a wall-clock FILETIME. -1 on an invalid rule. */
static int rule_ft(const tzc_time *rule, int year, int64_t *ft)
{
    tzc_time t = *rule;
    if (rule->month < 1 || rule->month > 12) return -1;
    if (rule->year == 0) {                                /* the day-th dow of the month; 5 = the last one */
        int64_t first;
        int first_dow, day;
        if (rule->day < 1 || rule->day > 5 || rule->dow < 0 || rule->dow > 6) return -1;
        first = days_from_civil(year, rule->month, 1);
        first_dow = (int)((first + 1) % 7);
        day = 1 + (rule->dow - first_dow + 7) % 7 + 7 * (rule->day - 1);
        while (day > month_days(year, rule->month)) day -= 7;
        t.year = year;
        t.day = day;
    }
    return tzc_to_ft(&t, ft);
}

int tzc_zone_id(const tzc_zone *z, int64_t ft, int is_local)
{
    tzc_time t;
    int64_t std_t, dst_t, when_std, when_dst;
    int year, before_std, after_dst;
    if (z->dst_date.month == 0) return TZC_UNKNOWN;
    if (z->std_date.month == 0) return TZC_INVALID;
    /* the instant in daylight wall-clock time (compared with the standard transition) and in standard wall-clock time
     * (compared with the daylight transition) */
    when_dst = is_local ? ft : ft - (z->bias + z->dst_bias) * FT_PER_MIN;
    when_std = is_local ? ft : ft - (z->bias + z->std_bias) * FT_PER_MIN;
    if (tzc_from_ft(is_local ? ft : ft - z->bias * FT_PER_MIN, &t)) return TZC_INVALID;
    year = t.year;
    if (tzc_from_ft(when_dst, &t)) return TZC_INVALID;
    if (t.year == year) {
        if (rule_ft(&z->std_date, year, &std_t)) return TZC_INVALID;
        before_std = when_dst < std_t;
    } else {
        before_std = t.year < year;
    }
    if (tzc_from_ft(when_std, &t)) return TZC_INVALID;
    if (t.year == year) {
        if (rule_ft(&z->dst_date, year, &dst_t)) return TZC_INVALID;
        after_dst = when_std >= dst_t;
    } else {
        after_dst = t.year > year;
    }
    if (z->dst_date.month < z->std_date.month) return before_std && after_dst ? TZC_DAYLIGHT : TZC_STANDARD;   /* north */
    return before_std || after_dst ? TZC_DAYLIGHT : TZC_STANDARD;                                           /* south */
}

static long bias_for(const tzc_zone *z, int id)
{
    return z->bias + (id == TZC_DAYLIGHT ? z->dst_bias : id == TZC_STANDARD ? z->std_bias : 0);
}

int tzc_utc_to_local(const tzc_zone *z, int64_t utc, int64_t *local)
{
    const int id = tzc_zone_id(z, utc, 0);
    if (id == TZC_INVALID) return id;
    *local = utc - bias_for(z, id) * FT_PER_MIN;
    return id;
}

int tzc_local_to_utc(const tzc_zone *z, int64_t local, int64_t *utc)
{
    const int id = tzc_zone_id(z, local, 1);
    if (id == TZC_INVALID) return id;
    *utc = local + bias_for(z, id) * FT_PER_MIN;
    return id;
}
