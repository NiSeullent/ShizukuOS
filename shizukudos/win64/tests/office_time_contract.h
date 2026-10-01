/* SPDX-License-Identifier: GPL-2.0-only
 * Independent expectations for the published time-name ABI and formatting.
 * OFFICE_CHECK and OFFICE_CALL are supplied by the host or guest harness.
 */
#ifndef SHZ_OFFICE_TIME_CONTRACT_H
#define SHZ_OFFICE_TIME_CONTRACT_H
#include "../dlls/ucrtbase/ucrt_office_time.h"
struct office_time_api {
    char *(OFFICE_CALL *days)(void), *(OFFICE_CALL *months)(void);
    wchar16 *(OFFICE_CALL *wdays)(void), *(OFFICE_CALL *wmonths)(void);
    void *(OFFICE_CALL *names)(void), *(OFFICE_CALL *wnames)(void);
    size_t (OFFICE_CALL *format)(char *, size_t, const char *, const struct crt_tm *, void *);
    size_t (OFFICE_CALL *wformat)(wchar16 *, size_t, const wchar16 *, const struct crt_tm *, void *);
    void (OFFICE_CALL *release)(void *);
    int *(OFFICE_CALL *error)(void);
};
static int office_ascii_equals(const char *a, const char *b)
{
    while (*a && *a == *b) { ++a; ++b; }
    return *a == *b;
}
static int office_wide_equals(const wchar16 *a, const char *b)
{
    while (*a && *a == (unsigned char)*b) { ++a; ++b; }
    return *a == (unsigned char)*b;
}
static void office_widen(const char *s, wchar16 *out)
{
    do { *out++ = (unsigned char)*s; } while (*s++);
}
static void office_time_contract(const struct office_time_api *api)
{
    static const char day_names[] = ":Sun:Sunday:Mon:Monday:Tue:Tuesday:Wed:Wednesday:Thu:Thursday:Fri:Friday:Sat:Saturday";
    static const char month_names[] = ":Jan:January:Feb:February:Mar:March:Apr:April:May:May:Jun:June:Jul:July:Aug:August:Sep:September:Oct:October:Nov:November:Dec:December";
    struct crt_tm tm = {29, 41, 12, 14, 2, 95, 2, 72, 0};
    char *days = api->days(), *months = api->months(), output[256];
    wchar16 *wdays = api->wdays(), *wmonths = api->wmonths(), woutput[256], wformat[64];
    crt_office_time_data *names = api->names(), *second = api->wnames();
    unsigned i;
    size_t n;
    int error;
    OFFICE_CHECK(days && months && wdays && wmonths && names && second, "all six caller-owned name allocations succeed");
    if (!days || !months || !wdays || !wmonths || !names || !second) goto done;
    OFFICE_CHECK(office_ascii_equals(days, day_names), "narrow colon weekday list starts Sunday with abbreviated/full pairs");
    OFFICE_CHECK(office_ascii_equals(months, month_names), "narrow colon month list has all twelve abbreviated/full pairs");
    OFFICE_CHECK(office_wide_equals(wdays, day_names), "UTF-16 weekday list uses the same names");
    OFFICE_CHECK(office_wide_equals(wmonths, month_names), "UTF-16 month list uses the same names");
    OFFICE_CHECK(names != second && names->narrow[0] != second->narrow[0] && names->wide[0] != second->wide[0], "time snapshots own independent storage");
    OFFICE_CHECK(names->c_locale == 1 && names->references == -1, "C time snapshot preserves native 32-bit metadata");
    OFFICE_CHECK(office_wide_equals(names->locale_name, "en-US"), "C snapshot carries actual time locale identifier");
    for (i = 0; i < 43; ++i) {
        OFFICE_CHECK(names->narrow[i] && names->wide[i] && (uintptr_t)names->narrow[i] >= (uintptr_t)names + 704 &&
                     (uintptr_t)names->wide[i] > (uintptr_t)names->narrow[i] && !((uintptr_t)names->wide[i] & 1),
                     "snapshot pointers identify owned aligned narrow and UTF-16 strings");
        OFFICE_CHECK(office_wide_equals(names->wide[i], names->narrow[i]), "snapshot narrow/wide names agree in C locale");
    }
    n = api->format(output, sizeof output, "%a %A %b %B %p %Y-%m-%d", &tm, names);
    OFFICE_CHECK(n == 35 && office_ascii_equals(output, "Tue Tuesday Mar March PM 1995-03-14"), "snapshot names and numeric fields format together");
    n = api->format(output, sizeof output, "%c|%x|%X", &tm, names);
    OFFICE_CHECK(n == 35 && office_ascii_equals(output, "03/14/95 12:41:29|03/14/95|12:41:29"), "snapshot date/time pictures drive composite directives");
    office_widen("%A %B %p %Y", wformat);
    n = api->wformat(woutput, 256, wformat, &tm, names);
    OFFICE_CHECK(n == 21 && office_wide_equals(woutput, "Tuesday March PM 1995"), "UTF-16 formatting returns code-unit count");
    {
        static const wchar16 changed_name[] = {'C','h','a','n','g','e','d',0};
        static const wchar16 korean[] = {0xd654, 0xc694, 0xc77c, 0};
        static const wchar16 changed_picture[] = {'y','y','y','y','\'','/','\'','M','M','\'','/','\'','d','d',0};
        static const wchar16 quoted_picture[] = {'y','y','y','y','\'',' ','i','t','\'','\'','s',' ','\'','M','M',0};
        const wchar16 *saved_name = names->wide[9], *saved_picture = names->wide[40];
        names->wide[9] = changed_name;
        n = api->format(output, sizeof output, "%A", &tm, names);
        OFFICE_CHECK(n == 7 && office_ascii_equals(output, "Changed"), "supplied snapshot changes weekday output");
        OFFICE_CHECK(office_wide_equals(second->wide[9], "Tuesday"), "mutating one snapshot does not alter another");
        names->wide[40] = changed_picture;
        n = api->format(output, sizeof output, "%x", &tm, names);
        OFFICE_CHECK(n == 10 && office_ascii_equals(output, "1995/03/14"), "supplied snapshot changes date picture output");
        names->wide[40] = quoted_picture;
        n = api->format(output, sizeof output, "%x", &tm, names);
        OFFICE_CHECK(n == 12 && office_ascii_equals(output, "1995 it's 03"), "snapshot date pictures preserve quoted text and escaped apostrophe");
        names->wide[9] = korean; office_widen("%A", wformat);
        n = api->wformat(woutput, 256, wformat, &tm, names);
        OFFICE_CHECK(n == 3 && woutput[0] == 0xd654 && woutput[1] == 0xc694 && woutput[2] == 0xc77c && woutput[3] == 0,
                     "wide snapshot retains actual Korean UTF-16 characters");
        *api->error() = 0;
        n = api->format(output, sizeof output, "%A", &tm, names); error = *api->error();
        OFFICE_CHECK(n == 0 && output[0] == 0 && error == CRT_EILSEQ, "C-byte output rejects unrepresentable wide snapshot characters");
        names->wide[9] = saved_name; names->wide[40] = saved_picture;
    }
    {
        struct { char before; char output[4]; char after; } bounded = {'L', {1,2,3,4}, 'R'};
        *api->error() = 0;
        n = api->format(bounded.output, sizeof bounded.output, "%A", &tm, names); error = *api->error();
        OFFICE_CHECK(n == 0 && bounded.output[0] == 0 && error == CRT_ERANGE && bounded.before == 'L' && bounded.after == 'R',
                     "bounded byte formatter clears overflow without crossing its output extent");
        n = api->format(bounded.output, sizeof bounded.output, "%a", &tm, names);
        OFFICE_CHECK(n == 3 && office_ascii_equals(bounded.output, "Tue") && bounded.after == 'R', "exact byte capacity includes one terminator");
        n = api->format(bounded.output, 1, "", &tm, names);
        OFFICE_CHECK(n == 0 && bounded.output[0] == 0, "empty output fits a one-byte terminator buffer");
    }
    names->c_locale = 0; *api->error() = 0;
    n = api->format(output, sizeof output, "%A", &tm, names); error = *api->error();
    OFFICE_CHECK(n == 0 && output[0] == 0 && error == CRT_EINVAL, "unimplemented non-C snapshots fail explicitly");
    names->c_locale = 1;
    tm.tm_wday = -1; *api->error() = 0;
    n = api->format(output, sizeof output, "%A", &tm, names); error = *api->error();
    OFFICE_CHECK(n == 0 && output[0] == 0 && error == CRT_EINVAL, "weekday directives reject invalid weekday bounds");
    n = api->format(output, sizeof output, "%Y", &tm, names);
    OFFICE_CHECK(n == 4 && office_ascii_equals(output, "1995"), "numeric directive does not inspect an unused weekday");
    tm.tm_wday = 2;
    *api->error() = 0;
    n = api->format(output, sizeof output, "%q", &tm, names); error = *api->error();
    OFFICE_CHECK(n == 0 && output[0] == 0 && error == CRT_EINVAL, "unsupported directive propagates formatter failure");
    n = api->format(output, sizeof output, "%Y-%m-%d", &tm, NULL);
    OFFICE_CHECK(n == 10 && office_ascii_equals(output, "1995-03-14"), "NULL time snapshot delegates genuine existing C-locale formatter");
done:
    api->release(days); api->release(months); api->release(wdays); api->release(wmonths);
    api->release(names); api->release(second);
}
#endif
