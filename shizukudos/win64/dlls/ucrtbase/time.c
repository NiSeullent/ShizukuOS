/* SPDX-License-Identifier: GPL-2.0-only
 * <time.h> of the Shizuku UCRT: calendar arithmetic (proleptic Gregorian, 1970 .. 3000 as Microsoft documents for the
 * 64-bit functions), strftime / wcsftime with the "C" locale formats Microsoft documents (%c = "%m/%d/%y %H:%M:%S",
 * %x = "%m/%d/%y", the # flag), asctime's "Www Mmm dd hh:mm:ss yyyy\n", the time-zone state (_tzset: the TZ variable,
 * e.g. "PST8PDT" with the UCRT's United States daylight rule, otherwise GetTimeZoneInformation), time / clock /
 * _ftime / timespec_get. The arithmetic core also builds on the host for comparison with glibc.
 */
#include "crtint.h"
#ifndef SHZ_HOST_TEST
#include "crtos.h"
#endif

#define MAX_TIME64 32535215999ll                  /* 3000-12-31 23:59:59 UTC */
#define MAX_TIME32 0x7fffffffll
static const char *const g_wday[] = { "Sunday", "Monday", "Tuesday", "Wednesday", "Thursday", "Friday", "Saturday" };
static const char *const g_mon[] = { "January", "February", "March", "April", "May", "June", "July", "August",
                                     "September", "October", "November", "December" };

static int is_leap(long long y) { return (y % 4 == 0 && y % 100 != 0) || y % 400 == 0; }
static long long days_from_civil(long long y, int m, int d)   /* m 1..12; days since 1970-01-01 */
{
    long long era, yoe, doy, doe;
    y -= m <= 2;
    era = (y >= 0 ? y : y - 399) / 400;
    yoe = y - era * 400;
    doy = (153 * (m + (m > 2 ? -3 : 9)) + 2) / 5 + d - 1;
    doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
    return era * 146097 + doe - 719468;
}
static const short g_cum[2][13] = { { 0, 31, 59, 90, 120, 151, 181, 212, 243, 273, 304, 334, 365 },
                                    { 0, 31, 60, 91, 121, 152, 182, 213, 244, 274, 305, 335, 366 } };

int crt_gmtime_core(crt_time64 t, struct crt_tm *tm)
{
    long long days, rem, y, era, doe, yoe, doy, mp;
    if (t < 0 || t > MAX_TIME64) return CRT_EINVAL;
    days = t / 86400;
    rem = t % 86400;
    tm->tm_hour = (int)(rem / 3600);
    tm->tm_min = (int)(rem % 3600 / 60);
    tm->tm_sec = (int)(rem % 60);
    tm->tm_wday = (int)((days + 4) % 7);
    days += 719468;
    era = days / 146097;
    doe = days - era * 146097;
    yoe = (doe - doe / 1460 + doe / 36524 - doe / 146096) / 365;
    y = yoe + era * 400;
    doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    mp = (5 * doy + 2) / 153;
    tm->tm_mday = (int)(doy - (153 * mp + 2) / 5 + 1);
    tm->tm_mon = (int)(mp < 10 ? mp + 2 : mp - 10);
    if (tm->tm_mon <= 1) ++y;
    tm->tm_year = (int)(y - 1900);
    tm->tm_yday = g_cum[is_leap(y)][tm->tm_mon] + tm->tm_mday - 1;
    tm->tm_isdst = 0;
    return 0;
}

/* normalises every field (carrying seconds into minutes ... months into years), fills wday/yday and returns the UTC
 * time value, or -1 when the result is outside 1970 .. 3000 */
crt_time64 crt_mkgmtime_core(struct crt_tm *tm)
{
    long long sec = tm->tm_sec, min = tm->tm_min, hour = tm->tm_hour, mday = tm->tm_mday, mon = tm->tm_mon, year = tm->tm_year;
    long long days, t;
    min += sec / 60; sec %= 60; if (sec < 0) { sec += 60; --min; }
    hour += min / 60; min %= 60; if (min < 0) { min += 60; --hour; }
    mday += hour / 24; hour %= 24; if (hour < 0) { hour += 24; --mday; }
    year += mon / 12; mon %= 12; if (mon < 0) { mon += 12; --year; }
    days = days_from_civil(year + 1900, (int)mon + 1, 1) + mday - 1;
    t = days * 86400 + hour * 3600 + min * 60 + sec;
    if (t < 0 || t > MAX_TIME64) return -1;
    crt_gmtime_core(t, tm);
    return t;
}

/* ---------------------------------------------------------------- strftime */
typedef struct { void *out; size_t max, n; int wide, overflow; } sbuf;
static void put_ch(sbuf *b, unsigned c)
{
    if (b->n + 1 >= b->max) { b->overflow = 1; return; }
    if (b->wide) ((wchar16 *)b->out)[b->n++] = (wchar16)c;
    else ((char *)b->out)[b->n++] = (char)c;
}
static void put_str(sbuf *b, const char *s) { while (*s) put_ch(b, (unsigned char)*s++); }
static void put_num(sbuf *b, long long v, int digits, int alt, char pad)
{
    char tmp[24];
    int n = 0, neg = v < 0;
    if (neg) v = -v;
    do { tmp[n++] = (char)('0' + v % 10); v /= 10; } while (v);
    if (!alt) while (n < digits) tmp[n++] = pad;
    if (neg) put_ch(b, '-');
    while (n) put_ch(b, (unsigned char)tmp[--n]);
}
static void put_abbr(sbuf *b, const char *s) { put_ch(b, (unsigned char)s[0]); put_ch(b, (unsigned char)s[1]); put_ch(b, (unsigned char)s[2]); }

/* ISO 8601 week-based year and week number */
static void iso_week(const struct crt_tm *tm, long long *iso_year, int *week)
{
    long long y = tm->tm_year + 1900LL;
    const int wday = (tm->tm_wday + 6) % 7;                 /* Monday = 0 */
    int w = (tm->tm_yday - wday + 10) / 7;
    if (w < 1) {
        --y;
        {
            const int ylen = is_leap(y) ? 366 : 365;
            w = (tm->tm_yday + ylen - wday + 10) / 7;
        }
    } else if (w == 53) {
        const int ylen = is_leap(y) ? 366 : 365;
        if (tm->tm_yday - wday + 3 >= ylen) { w = 1; ++y; }
    }
    *iso_year = y;
    *week = w;
}

static int fmt_one(sbuf *b, unsigned c, int alt, const struct crt_tm *tm, long tz_bias_min, const char *tzname);
static void fmt_sub(sbuf *b, const char *f, const struct crt_tm *tm, long tz, const char *tzn)
{
    for (; *f; ++f) {
        if (*f != '%') { put_ch(b, (unsigned char)*f); continue; }
        ++f;
        fmt_one(b, (unsigned char)*f, 0, tm, tz, tzn);
    }
}
static int fmt_one(sbuf *b, unsigned c, int alt, const struct crt_tm *tm, long tz_bias_min, const char *tzname)
{
    switch (c) {
    case 'a': if (tm->tm_wday < 0 || tm->tm_wday > 6) return -1; put_abbr(b, g_wday[tm->tm_wday]); break;
    case 'A': if (tm->tm_wday < 0 || tm->tm_wday > 6) return -1; put_str(b, g_wday[tm->tm_wday]); break;
    case 'b': case 'h': if (tm->tm_mon < 0 || tm->tm_mon > 11) return -1; put_abbr(b, g_mon[tm->tm_mon]); break;
    case 'B': if (tm->tm_mon < 0 || tm->tm_mon > 11) return -1; put_str(b, g_mon[tm->tm_mon]); break;
    case 'c':
        if (alt) {                                          /* long date and time: "Tuesday, March 14, 1995, 12:41:29" */
            if (fmt_one(b, 'x', 1, tm, tz_bias_min, tzname) < 0) return -1;
            put_str(b, ", ");
            fmt_sub(b, "%H:%M:%S", tm, tz_bias_min, tzname);
        } else fmt_sub(b, "%m/%d/%y %H:%M:%S", tm, tz_bias_min, tzname);
        break;
    case 'C': put_num(b, (tm->tm_year + 1900LL) / 100, 2, alt, '0'); break;
    case 'd': put_num(b, tm->tm_mday, 2, alt, '0'); break;
    case 'D': fmt_sub(b, "%m/%d/%y", tm, tz_bias_min, tzname); break;
    case 'e': put_num(b, tm->tm_mday, 2, alt, ' '); break;
    case 'F': fmt_sub(b, "%Y-%m-%d", tm, tz_bias_min, tzname); break;
    case 'g': case 'G': case 'V': {
        long long iy;
        int w;
        iso_week(tm, &iy, &w);
        if (c == 'g') put_num(b, iy % 100, 2, alt, '0');
        else if (c == 'G') put_num(b, iy, 0, alt, '0');
        else put_num(b, w, 2, alt, '0');
        break;
    }
    case 'H': put_num(b, tm->tm_hour, 2, alt, '0'); break;
    case 'I': put_num(b, tm->tm_hour % 12 ? tm->tm_hour % 12 : 12, 2, alt, '0'); break;
    case 'j': put_num(b, tm->tm_yday + 1, 3, alt, '0'); break;
    case 'm': put_num(b, tm->tm_mon + 1, 2, alt, '0'); break;
    case 'M': put_num(b, tm->tm_min, 2, alt, '0'); break;
    case 'n': put_ch(b, '\n'); break;
    case 'p': put_str(b, tm->tm_hour < 12 ? "AM" : "PM"); break;
    case 'r': fmt_sub(b, "%I:%M:%S %p", tm, tz_bias_min, tzname); break;
    case 'R': fmt_sub(b, "%H:%M", tm, tz_bias_min, tzname); break;
    case 'S': put_num(b, tm->tm_sec, 2, alt, '0'); break;
    case 't': put_ch(b, '\t'); break;
    case 'T': case 'X': fmt_sub(b, "%H:%M:%S", tm, tz_bias_min, tzname); break;
    case 'u': put_num(b, tm->tm_wday ? tm->tm_wday : 7, 1, alt, '0'); break;
    case 'U': put_num(b, (tm->tm_yday + 7 - tm->tm_wday) / 7, 2, alt, '0'); break;
    case 'w': put_num(b, tm->tm_wday, 1, alt, '0'); break;
    case 'W': put_num(b, (tm->tm_yday + 7 - (tm->tm_wday + 6) % 7) / 7, 2, alt, '0'); break;
    case 'x':
        if (alt) {                                          /* long date: "Tuesday, March 14, 1995" */
            if (tm->tm_wday < 0 || tm->tm_wday > 6 || tm->tm_mon < 0 || tm->tm_mon > 11) return -1;
            put_str(b, g_wday[tm->tm_wday]);
            put_str(b, ", ");
            put_str(b, g_mon[tm->tm_mon]);
            put_ch(b, ' ');
            put_num(b, tm->tm_mday, 2, 1, '0');
            put_str(b, ", ");
            put_num(b, tm->tm_year + 1900LL, 4, 1, '0');
        } else fmt_sub(b, "%m/%d/%y", tm, tz_bias_min, tzname);
        break;
    case 'y': put_num(b, ((tm->tm_year + 1900LL) % 100 + 100) % 100, 2, alt, '0'); break;
    case 'Y': put_num(b, tm->tm_year + 1900LL, 4, alt, '0'); break;
    case 'z':
        if (tz_bias_min != 0x7fffffffL) {                   /* ISO 8601 offset from UTC: -bias */
            long off = -tz_bias_min;
            put_ch(b, off < 0 ? '-' : '+');
            if (off < 0) off = -off;
            put_num(b, off / 60, 2, 0, '0');
            put_num(b, off % 60, 2, 0, '0');
        }
        break;
    case 'Z': if (tzname) put_str(b, tzname); break;
    case '%': put_ch(b, '%'); break;
    default: return -1;
    }
    return 0;
}

size_t crt_strftime_core(void *out, size_t max, int wide, const void *fmt, int wide_fmt, const struct crt_tm *tm, long tz_bias_min,
                         const char *tzname)
{
    sbuf b;
    size_t i = 0;
    CRT_VALIDATE(out != 0 && max > 0, CRT_EINVAL, 0);
    if (wide) ((wchar16 *)out)[0] = 0; else ((char *)out)[0] = 0;
    CRT_VALIDATE(fmt != 0 && tm != 0, CRT_EINVAL, 0);
    b.out = out;
    b.max = max;
    b.n = 0;
    b.wide = wide;
    b.overflow = 0;
    for (;;) {
        unsigned c = wide_fmt ? ((const wchar16 *)fmt)[i] : ((const unsigned char *)fmt)[i];
        int alt = 0;
        if (!c) break;
        ++i;
        if (c != '%') { put_ch(&b, c); continue; }
        c = wide_fmt ? ((const wchar16 *)fmt)[i] : ((const unsigned char *)fmt)[i];
        if (c == '#') { alt = 1; ++i; c = wide_fmt ? ((const wchar16 *)fmt)[i] : ((const unsigned char *)fmt)[i]; }
        if (c == 'E' || c == 'O') { ++i; c = wide_fmt ? ((const wchar16 *)fmt)[i] : ((const unsigned char *)fmt)[i]; }
        ++i;
        if (!c || fmt_one(&b, c, alt, tm, tz_bias_min, tzname) < 0) {
            if (wide) ((wchar16 *)out)[0] = 0; else ((char *)out)[0] = 0;
            crt_set_errno(CRT_EINVAL);
            crt_invalid_parameter();
            return 0;
        }
        if (b.overflow) break;
    }
    if (b.overflow) {
        if (wide) ((wchar16 *)out)[0] = 0; else ((char *)out)[0] = 0;
        crt_set_errno(CRT_ERANGE);
        return 0;
    }
    if (wide) ((wchar16 *)out)[b.n] = 0; else ((char *)out)[b.n] = 0;
    return b.n;
}

/* asctime: "Www Mmm dd hh:mm:ss yyyy\n" (26 characters with the terminator) */
static int asctime_core(char *out, size_t n, const struct crt_tm *tm)
{
    sbuf b;
    CRT_VALIDATE(out != 0 && n > 0, CRT_EINVAL, CRT_EINVAL);
    out[0] = 0;
    CRT_VALIDATE(n >= 26, CRT_EINVAL, CRT_EINVAL);
    CRT_VALIDATE(tm != 0, CRT_EINVAL, CRT_EINVAL);
    CRT_VALIDATE(tm->tm_mon >= 0 && tm->tm_mon <= 11 && tm->tm_wday >= 0 && tm->tm_wday <= 6 && tm->tm_mday >= 1 &&
                 tm->tm_mday <= 31 && tm->tm_hour >= 0 && tm->tm_hour <= 23 && tm->tm_min >= 0 && tm->tm_min <= 59 &&
                 tm->tm_sec >= 0 && tm->tm_sec <= 59 && tm->tm_year >= 0 && tm->tm_year <= 8099, CRT_EINVAL, CRT_EINVAL);
    b.out = out; b.max = n; b.n = 0; b.wide = 0; b.overflow = 0;
    put_abbr(&b, g_wday[tm->tm_wday]);
    put_ch(&b, ' ');
    put_abbr(&b, g_mon[tm->tm_mon]);
    put_ch(&b, ' ');
    put_num(&b, tm->tm_mday, 2, 0, '0');
    put_ch(&b, ' ');
    put_num(&b, tm->tm_hour, 2, 0, '0');
    put_ch(&b, ':');
    put_num(&b, tm->tm_min, 2, 0, '0');
    put_ch(&b, ':');
    put_num(&b, tm->tm_sec, 2, 0, '0');
    put_ch(&b, ' ');
    put_num(&b, tm->tm_year + 1900LL, 4, 0, '0');
    put_ch(&b, '\n');
    out[b.n] = 0;
    return 0;
}
DLLAPI crt_errno_t CRTAPI asctime_s(char *out, size_t n, const struct crt_tm *tm) { return asctime_core(out, n, tm); }
DLLAPI crt_errno_t CRTAPI _wasctime_s(wchar16 *out, size_t n, const struct crt_tm *tm)
{
    char tmp[32];
    crt_errno_t r;
    size_t i;
    CRT_VALIDATE(out != 0 && n > 0, CRT_EINVAL, CRT_EINVAL);
    out[0] = 0;
    CRT_VALIDATE(n >= 26, CRT_EINVAL, CRT_EINVAL);
    r = asctime_core(tmp, sizeof tmp, tm);
    if (r) return r;
    for (i = 0; tmp[i]; ++i) out[i] = (unsigned char)tmp[i];
    out[i] = 0;
    return 0;
}
DLLAPI char *CRTAPI asctime(const struct crt_tm *tm)
{
    char *buf = crt_getptd()->time_buf;
    return asctime_core(buf, 32, tm) ? 0 : buf;
}
DLLAPI wchar16 *CRTAPI _wasctime(const struct crt_tm *tm)
{
    wchar16 *buf = crt_getptd()->wtime_buf;
    return _wasctime_s(buf, 32, tm) ? 0 : buf;
}

/* ---------------------------------------------------------------- time zone */
static int g_tz_ready;
static long g_timezone = 28800;                  /* seconds west of UTC (the UCRT default before _tzset: PST) */
static int g_daylight = 1;
static long g_dstbias = -3600;
static char g_tzname_std[64] = "PST", g_tzname_dst[64] = "PDT";
static char *g_tzname[2] = { g_tzname_std, g_tzname_dst };
typedef struct { int use_rule, month, week, wday, hour; } dst_rule;   /* week 1..5 (5 = last) */
static dst_rule g_dst_start, g_dst_end;
static int g_tz_from_env;

#ifndef SHZ_HOST_TEST
static void rules_from_os(const os_tzinfo *tz)
{
    g_dst_start.use_rule = g_dst_end.use_rule = tz->DaylightDate.wMonth != 0 && tz->StandardDate.wMonth != 0;
    g_dst_start.month = tz->DaylightDate.wMonth;
    g_dst_start.week = tz->DaylightDate.wDay;
    g_dst_start.wday = tz->DaylightDate.wDayOfWeek;
    g_dst_start.hour = tz->DaylightDate.wHour;
    g_dst_end.month = tz->StandardDate.wMonth;
    g_dst_end.week = tz->StandardDate.wDay;
    g_dst_end.wday = tz->StandardDate.wDayOfWeek;
    g_dst_end.hour = tz->StandardDate.wHour;
}
#endif
static void us_rules(void)
{
    /* the UCRT applies the United States rule for a TZ variable with a daylight name: from 2007 on, second Sunday of
     * March 2:00 to first Sunday of November 2:00 */
    g_dst_start.use_rule = g_dst_end.use_rule = 1;
    g_dst_start.month = 3; g_dst_start.week = 2; g_dst_start.wday = 0; g_dst_start.hour = 2;
    g_dst_end.month = 11; g_dst_end.week = 1; g_dst_end.wday = 0; g_dst_end.hour = 2;
}

/* parses "SSS[+|-]hh[:mm[:ss]][DDD]"; returns 1 when valid */
static int parse_tz(const char *s)
{
    size_t i = 0, k;
    long secs = 0;
    int neg = 0;
    for (k = 0; s[i] && ((s[i] >= 'A' && s[i] <= 'Z') || (s[i] >= 'a' && s[i] <= 'z')) && k < 63; ++i, ++k) g_tzname_std[k] = s[i];
    g_tzname_std[k] = 0;
    if (k < 3) return 0;
    if (s[i] == '+' || s[i] == '-') neg = s[i++] == '-';
    if (s[i] < '0' || s[i] > '9') return 0;
    {
        long h = 0, m = 0, sec = 0;
        while (s[i] >= '0' && s[i] <= '9') h = h * 10 + (s[i++] - '0');
        if (s[i] == ':') { ++i; while (s[i] >= '0' && s[i] <= '9') m = m * 10 + (s[i++] - '0'); }
        if (s[i] == ':') { ++i; while (s[i] >= '0' && s[i] <= '9') sec = sec * 10 + (s[i++] - '0'); }
        secs = h * 3600 + m * 60 + sec;
    }
    g_timezone = neg ? -secs : secs;
    for (k = 0; s[i] && ((s[i] >= 'A' && s[i] <= 'Z') || (s[i] >= 'a' && s[i] <= 'z')) && k < 63; ++i, ++k) g_tzname_dst[k] = s[i];
    g_tzname_dst[k] = 0;
    g_daylight = k > 0;
    g_dstbias = -3600;
    if (g_daylight) us_rules();
    else g_dst_start.use_rule = g_dst_end.use_rule = 0;
    return 1;
}

DLLAPI void CRTAPI _tzset(void)
{
#ifdef SHZ_HOST_TEST
    g_tz_ready = 1;
#else
    char tzv[128];
    size_t req = 0;
    crt_errno_t CRTAPI getenv_s(size_t *, char *, size_t, const char *);
    crt_lock(CRT_LOCK_TIME);
    g_tz_from_env = 0;
    if (getenv_s(&req, tzv, sizeof tzv, "TZ") == 0 && req > 1 && parse_tz(tzv)) g_tz_from_env = 1;
    else {
        os_tzinfo tz;
        const os_dword id = GetTimeZoneInformation(&tz);
        if (id != OS_TIME_ZONE_ID_INVALID) {
            g_timezone = tz.Bias * 60L;
            g_daylight = tz.DaylightDate.wMonth != 0;
            g_dstbias = (tz.DaylightBias - tz.StandardBias) * 60L;
            if (!g_daylight) g_dstbias = 0;
            g_timezone += tz.StandardBias * 60L;
            WideCharToMultiByte(OS_CP_ACP, 0, tz.StandardName, -1, g_tzname_std, 63, 0, 0);
            WideCharToMultiByte(OS_CP_ACP, 0, tz.DaylightName, -1, g_tzname_dst, 63, 0, 0);
            rules_from_os(&tz);
        }
    }
    g_tz_ready = 1;
    crt_unlock(CRT_LOCK_TIME);
#endif
}
static void tz_init(void) { if (!g_tz_ready) _tzset(); }
void crt_time_init(void) { }
DLLAPI long *CRTAPI __timezone(void) { tz_init(); return &g_timezone; }
DLLAPI int *CRTAPI __daylight(void) { tz_init(); return &g_daylight; }
DLLAPI long *CRTAPI __dstbias(void) { tz_init(); return &g_dstbias; }
DLLAPI char **CRTAPI __tzname(void) { tz_init(); return g_tzname; }
DLLAPI crt_errno_t CRTAPI _get_timezone(long *v) { CRT_VALIDATE(v != 0, CRT_EINVAL, CRT_EINVAL); tz_init(); *v = g_timezone; return 0; }
DLLAPI crt_errno_t CRTAPI _get_daylight(int *v) { CRT_VALIDATE(v != 0, CRT_EINVAL, CRT_EINVAL); tz_init(); *v = g_daylight; return 0; }
DLLAPI crt_errno_t CRTAPI _get_dstbias(long *v) { CRT_VALIDATE(v != 0, CRT_EINVAL, CRT_EINVAL); tz_init(); *v = g_dstbias; return 0; }
DLLAPI crt_errno_t CRTAPI _get_tzname(size_t *ret, char *buf, size_t n, int index)
{
    const char *s;
    size_t len;
    CRT_VALIDATE((buf != 0 || n == 0) && (index == 0 || index == 1) && ret != 0, CRT_EINVAL, CRT_EINVAL);
    tz_init();
    s = g_tzname[index];
    len = crt_strlen(s) + 1;
    *ret = len;
    if (!buf) return 0;
    if (len > n) return CRT_ERANGE;
    crt_memcpy(buf, s, len);
    return 0;
}

/* day of month of the n-th (5 = last) weekday wday in month m (1..12) of year y */
static int rule_mday(long long y, int m, int week, int wday)
{
    const int first_wday = (int)((days_from_civil(y, m, 1) % 7 + 11) % 7);   /* 1970-01-01 was a Thursday (4) */
    const int mlen = g_cum[is_leap(y)][m] - g_cum[is_leap(y)][m - 1];
    int d = 1 + (wday - first_wday + 7) % 7 + (week - 1) * 7;
    while (d > mlen) d -= 7;
    return d;
}
/* is the local standard time t_std (seconds, local standard time) inside daylight time? */
static int in_dst(long long t_std)
{
    struct crt_tm tm;
    long long y, start, end;
    if (!g_daylight || !g_dst_start.use_rule) return 0;
    if (crt_gmtime_core(t_std < 0 ? 0 : t_std > MAX_TIME64 ? MAX_TIME64 : t_std, &tm)) return 0;
    y = tm.tm_year + 1900LL;
    start = (days_from_civil(y, g_dst_start.month, rule_mday(y, g_dst_start.month, g_dst_start.week, g_dst_start.wday))) * 86400 +
            g_dst_start.hour * 3600LL;
    /* the end transition is given in daylight time: convert it to standard time */
    end = (days_from_civil(y, g_dst_end.month, rule_mday(y, g_dst_end.month, g_dst_end.week, g_dst_end.wday))) * 86400 +
          g_dst_end.hour * 3600LL + g_dstbias;
    if (start < end) return t_std >= start && t_std < end;
    return t_std >= start || t_std < end;                       /* southern hemisphere */
}

static crt_errno_t localtime_core(crt_time64 t, struct crt_tm *tm, crt_time64 max)
{
    long long lt;
    int dst;
    CRT_VALIDATE(tm != 0, CRT_EINVAL, CRT_EINVAL);
    crt_memset(tm, 0xff, sizeof *tm);
    CRT_VALIDATE(t >= 0 && t <= max, CRT_EINVAL, CRT_EINVAL);
    tz_init();
    lt = t - g_timezone;
    dst = in_dst(lt);
    if (dst) lt -= g_dstbias;
    if (lt < 0 || lt > MAX_TIME64) { crt_set_errno(CRT_EINVAL); return CRT_EINVAL; }
    crt_gmtime_core(lt, tm);
    tm->tm_isdst = dst;
    return 0;
}
DLLAPI crt_errno_t CRTAPI _localtime64_s(struct crt_tm *tm, const crt_time64 *t)
{
    CRT_VALIDATE(tm != 0, CRT_EINVAL, CRT_EINVAL);
    if (!t) { crt_memset(tm, 0xff, sizeof *tm); CRT_VALIDATE(0, CRT_EINVAL, CRT_EINVAL); }
    return localtime_core(*t, tm, MAX_TIME64);
}
DLLAPI crt_errno_t CRTAPI _localtime32_s(struct crt_tm *tm, const int32_t *t)
{
    CRT_VALIDATE(tm != 0, CRT_EINVAL, CRT_EINVAL);
    if (!t) { crt_memset(tm, 0xff, sizeof *tm); CRT_VALIDATE(0, CRT_EINVAL, CRT_EINVAL); }
    return localtime_core(*t, tm, MAX_TIME32);
}
DLLAPI struct crt_tm *CRTAPI _localtime64(const crt_time64 *t)
{
    struct crt_tm *tm = &crt_getptd()->tm_buf;
    CRT_VALIDATE(t != 0, CRT_EINVAL, 0);
    return localtime_core(*t, tm, MAX_TIME64) ? 0 : tm;
}
DLLAPI struct crt_tm *CRTAPI _localtime32(const int32_t *t)
{
    struct crt_tm *tm = &crt_getptd()->tm_buf;
    CRT_VALIDATE(t != 0, CRT_EINVAL, 0);
    return localtime_core(*t, tm, MAX_TIME32) ? 0 : tm;
}
static crt_errno_t gmtime_s_core(struct crt_tm *tm, const crt_time64 *t, crt_time64 max)
{
    CRT_VALIDATE(tm != 0, CRT_EINVAL, CRT_EINVAL);
    crt_memset(tm, 0xff, sizeof *tm);
    CRT_VALIDATE(t != 0, CRT_EINVAL, CRT_EINVAL);
    CRT_VALIDATE(*t >= 0 && *t <= max, CRT_EINVAL, CRT_EINVAL);
    return (crt_errno_t)crt_gmtime_core(*t, tm);
}
DLLAPI crt_errno_t CRTAPI _gmtime64_s(struct crt_tm *tm, const crt_time64 *t) { return gmtime_s_core(tm, t, MAX_TIME64); }
DLLAPI crt_errno_t CRTAPI _gmtime32_s(struct crt_tm *tm, const int32_t *t)
{
    crt_time64 v;
    CRT_VALIDATE(tm != 0, CRT_EINVAL, CRT_EINVAL);
    if (!t) { crt_memset(tm, 0xff, sizeof *tm); CRT_VALIDATE(0, CRT_EINVAL, CRT_EINVAL); }
    v = *t;
    return gmtime_s_core(tm, &v, MAX_TIME32);
}
DLLAPI struct crt_tm *CRTAPI _gmtime64(const crt_time64 *t)
{
    struct crt_tm *tm = &crt_getptd()->tm_buf;
    return _gmtime64_s(tm, t) ? 0 : tm;
}
DLLAPI struct crt_tm *CRTAPI _gmtime32(const int32_t *t)
{
    struct crt_tm *tm = &crt_getptd()->tm_buf;
    return _gmtime32_s(tm, t) ? 0 : tm;
}

static crt_time64 mktime_core(struct crt_tm *tm, crt_time64 max, int utc)
{
    struct crt_tm t;
    crt_time64 r;
    CRT_VALIDATE(tm != 0, CRT_EINVAL, -1);
    t = *tm;
    r = crt_mkgmtime_core(&t);
    if (r < 0) { crt_set_errno(CRT_EINVAL); return -1; }
    if (!utc) {
        int dst;
        tz_init();
        dst = tm->tm_isdst > 0 ? 1 : tm->tm_isdst == 0 ? 0 : in_dst(r);
        r += g_timezone;
        if (dst) r += g_dstbias;
        if (r < 0 || r > max) { crt_set_errno(CRT_EINVAL); return -1; }
        if (localtime_core(r, &t, max)) return -1;
    } else if (r > max) { crt_set_errno(CRT_EINVAL); return -1; }
    *tm = t;
    return r;
}
DLLAPI crt_time64 CRTAPI _mktime64(struct crt_tm *tm) { return mktime_core(tm, MAX_TIME64, 0); }
DLLAPI int32_t CRTAPI _mktime32(struct crt_tm *tm) { return (int32_t)mktime_core(tm, MAX_TIME32, 0); }
DLLAPI crt_time64 CRTAPI _mkgmtime64(struct crt_tm *tm) { return mktime_core(tm, MAX_TIME64, 1); }
DLLAPI int32_t CRTAPI _mkgmtime32(struct crt_tm *tm) { return (int32_t)mktime_core(tm, MAX_TIME32, 1); }
DLLAPI double CRTAPI _difftime64(crt_time64 a, crt_time64 b)
{
    CRT_VALIDATE(a >= 0 && b >= 0, CRT_EINVAL, 0.0);
    return (double)(a - b);
}
DLLAPI double CRTAPI _difftime32(int32_t a, int32_t b)
{
    CRT_VALIDATE(a >= 0 && b >= 0, CRT_EINVAL, 0.0);
    return (double)a - (double)b;
}

DLLAPI size_t CRTAPI strftime(char *out, size_t max, const char *fmt, const struct crt_tm *tm)
{
    long bias;
    int dst = tm && tm->tm_isdst > 0;
    tz_init();
    bias = (long)(g_timezone / 60 + (dst ? g_dstbias / 60 : 0));
    return crt_strftime_core(out, max, 0, fmt, 0, tm, bias, dst ? g_tzname_dst : g_tzname_std);
}
DLLAPI size_t CRTAPI _strftime_l(char *out, size_t max, const char *fmt, const struct crt_tm *tm, void *l) { (void)l; return strftime(out, max, fmt, tm); }
DLLAPI size_t CRTAPI wcsftime(wchar16 *out, size_t max, const wchar16 *fmt, const struct crt_tm *tm)
{
    long bias;
    int dst = tm && tm->tm_isdst > 0;
    tz_init();
    bias = (long)(g_timezone / 60 + (dst ? g_dstbias / 60 : 0));
    return crt_strftime_core(out, max, 1, fmt, 1, tm, bias, dst ? g_tzname_dst : g_tzname_std);
}
DLLAPI size_t CRTAPI _wcsftime_l(wchar16 *out, size_t max, const wchar16 *fmt, const struct crt_tm *tm, void *l) { (void)l; return wcsftime(out, max, fmt, tm); }

#ifndef SHZ_HOST_TEST
/* ---------------------------------------------------------------- clocks */
static crt_time64 now64(void)
{
    os_filetime ft;
    GetSystemTimePreciseAsFileTime(&ft);
    return (crt_time64)((((uint64_t)ft.hi << 32) | ft.lo) / 10000000ull) - 11644473600ll;
}
DLLAPI crt_time64 CRTAPI _time64(crt_time64 *out)
{
    crt_time64 t = now64();
    if (out) *out = t;
    return t;
}
DLLAPI int32_t CRTAPI _time32(int32_t *out)
{
    crt_time64 t = now64();
    if (t > MAX_TIME32) { crt_set_errno(CRT_EINVAL); t = -1; }
    if (out) *out = (int32_t)t;
    return (int32_t)t;
}
static int64_t g_clock_start, g_clock_freq;
DLLAPI int32_t CRTAPI clock(void)                              /* clock_t is long: milliseconds since process start */
{
    int64_t now;
    if (!g_clock_freq && !QueryPerformanceFrequency(&g_clock_freq)) return -1;
    if (!g_clock_start) QueryPerformanceCounter(&g_clock_start);
    QueryPerformanceCounter(&now);
    {
        const int64_t d = now - g_clock_start;
        const int64_t ms = d / g_clock_freq * 1000 + d % g_clock_freq * 1000 / g_clock_freq;
        return ms > 0x7fffffff ? -1 : (int32_t)ms;
    }
}
void crt_clock_start(void)
{
    QueryPerformanceFrequency(&g_clock_freq);
    QueryPerformanceCounter(&g_clock_start);
}
struct crt_timeb64 { crt_time64 time; unsigned short millitm; short timezone, dstflag; };
struct crt_timeb32 { int32_t time; unsigned short millitm; short timezone, dstflag; };
DLLAPI crt_errno_t CRTAPI _ftime64_s(struct crt_timeb64 *tb)
{
    os_filetime ft;
    uint64_t v;
    struct crt_tm tm;
    CRT_VALIDATE(tb != 0, CRT_EINVAL, CRT_EINVAL);
    tz_init();
    GetSystemTimePreciseAsFileTime(&ft);
    v = ((uint64_t)ft.hi << 32) | ft.lo;
    tb->time = (crt_time64)(v / 10000000ull) - 11644473600ll;
    tb->millitm = (unsigned short)(v / 10000ull % 1000);
    tb->timezone = (short)(g_timezone / 60);
    tb->dstflag = (short)(localtime_core(tb->time, &tm, MAX_TIME64) == 0 && tm.tm_isdst > 0);
    return 0;
}
DLLAPI void CRTAPI _ftime64(struct crt_timeb64 *tb) { _ftime64_s(tb); }
DLLAPI crt_errno_t CRTAPI _ftime32_s(struct crt_timeb32 *tb)
{
    struct crt_timeb64 t;
    CRT_VALIDATE(tb != 0, CRT_EINVAL, CRT_EINVAL);
    _ftime64_s(&t);
    tb->time = (int32_t)t.time;
    tb->millitm = t.millitm;
    tb->timezone = t.timezone;
    tb->dstflag = t.dstflag;
    return 0;
}
DLLAPI void CRTAPI _ftime32(struct crt_timeb32 *tb) { _ftime32_s(tb); }
struct crt_timespec64 { crt_time64 tv_sec; int32_t tv_nsec; };
struct crt_timespec32 { int32_t tv_sec; int32_t tv_nsec; };
DLLAPI int CRTAPI _timespec64_get(struct crt_timespec64 *ts, int base)
{
    os_filetime ft;
    uint64_t v;
    CRT_VALIDATE(ts != 0, CRT_EINVAL, 0);
    if (base != 1 /* TIME_UTC */) return 0;
    GetSystemTimePreciseAsFileTime(&ft);
    v = (((uint64_t)ft.hi << 32) | ft.lo) - 116444736000000000ull;
    ts->tv_sec = (crt_time64)(v / 10000000ull);
    ts->tv_nsec = (int32_t)(v % 10000000ull * 100);
    return base;
}
DLLAPI int CRTAPI _timespec32_get(struct crt_timespec32 *ts, int base)
{
    struct crt_timespec64 t = { 0, 0 };
    CRT_VALIDATE(ts != 0, CRT_EINVAL, 0);
    if (_timespec64_get(&t, base) != base) return 0;
    ts->tv_sec = (int32_t)t.tv_sec;
    ts->tv_nsec = t.tv_nsec;
    return base;
}

/* ---------------------------------------------------------------- ctime family, _strdate / _strtime */
DLLAPI crt_errno_t CRTAPI _ctime64_s(char *out, size_t n, const crt_time64 *t)
{
    struct crt_tm tm;
    crt_errno_t r;
    CRT_VALIDATE(out != 0 && n > 0, CRT_EINVAL, CRT_EINVAL);
    out[0] = 0;
    CRT_VALIDATE(n >= 26 && t != 0, CRT_EINVAL, CRT_EINVAL);
    r = localtime_core(*t, &tm, MAX_TIME64);
    return r ? r : asctime_core(out, n, &tm);
}
DLLAPI crt_errno_t CRTAPI _ctime32_s(char *out, size_t n, const int32_t *t)
{
    crt_time64 v;
    CRT_VALIDATE(t != 0, CRT_EINVAL, CRT_EINVAL);
    v = *t;
    return _ctime64_s(out, n, &v);
}
DLLAPI char *CRTAPI _ctime64(const crt_time64 *t)
{
    char *buf = crt_getptd()->time_buf;
    return _ctime64_s(buf, 32, t) ? 0 : buf;
}
DLLAPI char *CRTAPI _ctime32(const int32_t *t)
{
    char *buf = crt_getptd()->time_buf;
    return _ctime32_s(buf, 32, t) ? 0 : buf;
}
DLLAPI crt_errno_t CRTAPI _wctime64_s(wchar16 *out, size_t n, const crt_time64 *t)
{
    char tmp[32];
    crt_errno_t r;
    size_t i;
    CRT_VALIDATE(out != 0 && n > 0, CRT_EINVAL, CRT_EINVAL);
    out[0] = 0;
    CRT_VALIDATE(n >= 26, CRT_EINVAL, CRT_EINVAL);
    r = _ctime64_s(tmp, sizeof tmp, t);
    if (r) return r;
    for (i = 0; tmp[i]; ++i) out[i] = (unsigned char)tmp[i];
    out[i] = 0;
    return 0;
}
DLLAPI wchar16 *CRTAPI _wctime64(const crt_time64 *t)
{
    wchar16 *buf = crt_getptd()->wtime_buf;
    return _wctime64_s(buf, 32, t) ? 0 : buf;
}
DLLAPI crt_errno_t CRTAPI _wctime32_s(wchar16 *out, size_t n, const int32_t *t)
{
    crt_time64 v;
    CRT_VALIDATE(t != 0, CRT_EINVAL, CRT_EINVAL);
    v = *t;
    return _wctime64_s(out, n, &v);
}
DLLAPI wchar16 *CRTAPI _wctime32(const int32_t *t)
{
    wchar16 *buf = crt_getptd()->wtime_buf;
    return _wctime32_s(buf, 32, t) ? 0 : buf;
}
static crt_errno_t date_or_time(char *out, size_t n, int date)
{
    struct crt_tm tm;
    crt_time64 t = now64();
    CRT_VALIDATE(out != 0 && n > 0, CRT_EINVAL, CRT_EINVAL);
    out[0] = 0;
    CRT_VALIDATE(n >= 9, CRT_ERANGE, CRT_ERANGE);
    if (localtime_core(t, &tm, MAX_TIME64)) return CRT_EINVAL;
    crt_strftime_core(out, n, 0, date ? "%m/%d/%y" : "%H:%M:%S", 0, &tm, 0, 0);
    return 0;
}
DLLAPI crt_errno_t CRTAPI _strdate_s(char *out, size_t n) { return date_or_time(out, n, 1); }
DLLAPI crt_errno_t CRTAPI _strtime_s(char *out, size_t n) { return date_or_time(out, n, 0); }
DLLAPI char *CRTAPI _strdate(char *out) { return _strdate_s(out, 9) ? 0 : out; }
DLLAPI char *CRTAPI _strtime(char *out) { return _strtime_s(out, 9) ? 0 : out; }
DLLAPI crt_errno_t CRTAPI _wstrdate_s(wchar16 *out, size_t n)
{
    char tmp[16];
    size_t i;
    crt_errno_t r;
    CRT_VALIDATE(out != 0 && n > 0, CRT_EINVAL, CRT_EINVAL);
    out[0] = 0;
    CRT_VALIDATE(n >= 9, CRT_ERANGE, CRT_ERANGE);
    r = date_or_time(tmp, sizeof tmp, 1);
    for (i = 0; !r && tmp[i]; ++i) out[i] = (unsigned char)tmp[i];
    if (!r) out[i] = 0;
    return r;
}
DLLAPI crt_errno_t CRTAPI _wstrtime_s(wchar16 *out, size_t n)
{
    char tmp[16];
    size_t i;
    crt_errno_t r;
    CRT_VALIDATE(out != 0 && n > 0, CRT_EINVAL, CRT_EINVAL);
    out[0] = 0;
    CRT_VALIDATE(n >= 9, CRT_ERANGE, CRT_ERANGE);
    r = date_or_time(tmp, sizeof tmp, 0);
    for (i = 0; !r && tmp[i]; ++i) out[i] = (unsigned char)tmp[i];
    if (!r) out[i] = 0;
    return r;
}
DLLAPI wchar16 *CRTAPI _wstrdate(wchar16 *out) { return _wstrdate_s(out, 9) ? 0 : out; }
DLLAPI wchar16 *CRTAPI _wstrtime(wchar16 *out) { return _wstrtime_s(out, 9) ? 0 : out; }
#endif
