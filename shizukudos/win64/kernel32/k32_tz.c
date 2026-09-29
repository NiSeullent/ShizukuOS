/* SPDX-License-Identifier: GPL-2.0-only
 * kernel32.dll: local time conversions. The machine's time zone is UTC (the platform clock is UTC and there is no time-zone
 * database; GetTimeZoneInformation reports it), so the local-time functions of the current zone are identities; conversions
 * with an explicit TIME_ZONE_INFORMATION apply that zone's rules for real (tz_core.c, host-tested in tests/host/tz_host_test.c).
 */
#include "k32.h"
#include "tz_core.h"

static void st_to_tzc(const SYSTEMTIME *s, tzc_time *t)
{
    t->year = s->wYear; t->month = s->wMonth; t->dow = s->wDayOfWeek; t->day = s->wDay;
    t->hour = s->wHour; t->minute = s->wMinute; t->second = s->wSecond; t->ms = s->wMilliseconds;
}

static void zone_of(const TIME_ZONE_INFORMATION *tz, tzc_zone *z)
{
    z->bias = tz->Bias; z->std_bias = tz->StandardBias; z->dst_bias = tz->DaylightBias;
    st_to_tzc(&tz->StandardDate, &z->std_date);
    st_to_tzc(&tz->DaylightDate, &z->dst_date);
}

static LONGLONG ft64(const FILETIME *f) { return (LONGLONG)(((ULONGLONG)f->dwHighDateTime << 32) | f->dwLowDateTime); }
static void put_ft(LONGLONG v, FILETIME *f) { f->dwLowDateTime = (DWORD)v; f->dwHighDateTime = (DWORD)((ULONGLONG)v >> 32); }

/* the bias in effect now (FileTimeToLocalFileTime uses the current bias for every date, as documented) */
static LONGLONG current_bias_100ns(void)
{
    TIME_ZONE_INFORMATION tz;
    const DWORD id = GetTimeZoneInformation(&tz);
    LONG bias = tz.Bias;
    if (id == TIME_ZONE_ID_DAYLIGHT) bias += tz.DaylightBias;
    else if (id == TIME_ZONE_ID_STANDARD) bias += tz.StandardBias;
    return (LONGLONG)bias * 600000000ll;
}

K32API BOOL WINAPI FileTimeToLocalFileTime(const FILETIME *utc, LPFILETIME local)
{
    if (!utc || !local) { shz_set_last_error(ERROR_INVALID_PARAMETER); return FALSE; }
    put_ft(ft64(utc) - current_bias_100ns(), local);
    return TRUE;
}

K32API BOOL WINAPI LocalFileTimeToFileTime(const FILETIME *local, LPFILETIME utc)
{
    if (!utc || !local) { shz_set_last_error(ERROR_INVALID_PARAMETER); return FALSE; }
    put_ft(ft64(local) + current_bias_100ns(), utc);
    return TRUE;
}

K32API DWORD WINAPI GetDynamicTimeZoneInformation(PDYNAMIC_TIME_ZONE_INFORMATION d)
{
    TIME_ZONE_INFORMATION tz;
    DWORD id;
    static const WCHAR key[] = { 'U', 'T', 'C', 0 };
    if (!d) { shz_set_last_error(ERROR_INVALID_PARAMETER); return TIME_ZONE_ID_INVALID; }
    id = GetTimeZoneInformation(&tz);
    memset(d, 0, sizeof *d);
    d->Bias = tz.Bias;
    memcpy(d->StandardName, tz.StandardName, sizeof d->StandardName);
    d->StandardDate = tz.StandardDate;
    d->StandardBias = tz.StandardBias;
    memcpy(d->DaylightName, tz.DaylightName, sizeof d->DaylightName);
    d->DaylightDate = tz.DaylightDate;
    d->DaylightBias = tz.DaylightBias;
    memcpy(d->TimeZoneKeyName, key, sizeof key);          /* the registry key name of the UTC zone on Windows */
    d->DynamicDaylightTimeDisabled = FALSE;
    return id;
}

static BOOL convert(const TIME_ZONE_INFORMATION *tz, const SYSTEMTIME *in, LPSYSTEMTIME out, int to_local)
{
    TIME_ZONE_INFORMATION cur;
    tzc_zone z;
    tzc_time t;
    int64_t v, r;
    if (!in || !out) { shz_set_last_error(ERROR_INVALID_PARAMETER); return FALSE; }
    if (!tz) { GetTimeZoneInformation(&cur); tz = &cur; }
    zone_of(tz, &z);
    st_to_tzc(in, &t);
    if (tzc_to_ft(&t, &v)) { shz_set_last_error(ERROR_INVALID_PARAMETER); return FALSE; }
    if ((to_local ? tzc_utc_to_local(&z, v, &r) : tzc_local_to_utc(&z, v, &r)) == TZC_INVALID || tzc_from_ft(r, &t)) {
        shz_set_last_error(ERROR_INVALID_PARAMETER);
        return FALSE;
    }
    out->wYear = (WORD)t.year; out->wMonth = (WORD)t.month; out->wDayOfWeek = (WORD)t.dow; out->wDay = (WORD)t.day;
    out->wHour = (WORD)t.hour; out->wMinute = (WORD)t.minute; out->wSecond = (WORD)t.second; out->wMilliseconds = (WORD)t.ms;
    return TRUE;
}

K32API BOOL WINAPI SystemTimeToTzSpecificLocalTime(const TIME_ZONE_INFORMATION *tz, const SYSTEMTIME *utc, LPSYSTEMTIME local)
{
    return convert(tz, utc, local, 1);
}

K32API BOOL WINAPI TzSpecificLocalTimeToSystemTime(const TIME_ZONE_INFORMATION *tz, const SYSTEMTIME *local, LPSYSTEMTIME utc)
{
    return convert(tz, local, utc, 0);
}
