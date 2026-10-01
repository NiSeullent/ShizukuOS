/* SPDX-License-Identifier: GPL-2.0-only
 * VC14 time-name allocation and snapshot-aware formatting for the existing
 * C-locale UCRT. Original implementation; no upstream code copied.
 * Source review: Wine11 db11d0fe6a169c457e23d007e20404643d067aa8
 * dlls/msvcrt/{locale.c,time.c,msvcrt.h}, and ReactOS
 * 9dc3ca87209fd8ebabd96c8ea95d439c13e7fdf8 dll/win32/msvcrt/{locale.c,time.c}.
 *
 * A snapshot has the actual MSVCR110+ pointer tables/32-bit metadata layout,
 * with one caller-owned malloc allocation containing all referenced strings.
 * Supplied snapshots drive names and date/time pictures; they are not ignored.
 * Existing strftime/wcsftime handle numeric/time-zone directives and the NULL
 * snapshot case. C multibyte characters remain U+0000..U+00FF. Non-C snapshots
 * fail explicitly because the current UCRT cannot select a non-C locale.
 */
#include "ucrt_office_time.h"

size_t CRTAPI strftime(char *, size_t, const char *, const struct crt_tm *);
size_t CRTAPI wcsftime(wchar16 *, size_t, const wchar16 *, const struct crt_tm *);

static const char *const c_names[43] = {
    "Sun", "Mon", "Tue", "Wed", "Thu", "Fri", "Sat",
    "Sunday", "Monday", "Tuesday", "Wednesday", "Thursday", "Friday", "Saturday",
    "Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec",
    "January", "February", "March", "April", "May", "June", "July", "August", "September", "October", "November", "December",
    "AM", "PM", "MM/dd/yy", "dddd, MMMM dd, yyyy", "HH:mm:ss"
};

static void *make_name_list(unsigned first, unsigned second, unsigned count, int wide)
{
    size_t units = 1, offset = 0;
    unsigned i, j;
    void *out;
    for (i = 0; i < count; ++i)
        units += 2 + crt_strlen(c_names[first + i]) + crt_strlen(c_names[second + i]);
    out = crt_malloc(units * (wide ? sizeof(wchar16) : 1));
    if (!out) return 0;
    for (i = 0; i < count; ++i) for (j = 0; j < 2; ++j) {
        const unsigned char *s = (const unsigned char *)c_names[(j ? second : first) + i];
        if (wide) ((wchar16 *)out)[offset++] = ':'; else ((char *)out)[offset++] = ':';
        while (*s) {
            if (wide) ((wchar16 *)out)[offset++] = *s++; else ((char *)out)[offset++] = (char)*s++;
        }
    }
    if (wide) ((wchar16 *)out)[offset] = 0; else ((char *)out)[offset] = 0;
    return out;
}

DLLAPI char *CRTAPI _Getdays(void) { return make_name_list(0, 7, 7, 0); }
DLLAPI char *CRTAPI _Getmonths(void) { return make_name_list(14, 26, 12, 0); }
DLLAPI wchar16 *CRTAPI _W_Getdays(void) { return make_name_list(0, 7, 7, 1); }
DLLAPI wchar16 *CRTAPI _W_Getmonths(void) { return make_name_list(14, 26, 12, 1); }

static crt_office_time_data *make_time_data(void)
{
    size_t bytes = 0, wide_offset, size, offset;
    crt_office_time_data *out;
    unsigned i;
    for (i = 0; i < 43; ++i) bytes += crt_strlen(c_names[i]) + 1;
    wide_offset = (offsetof(crt_office_time_data, data) + bytes + 1) & ~(size_t)1;
    size = wide_offset + 2 * bytes + 12; /* owned UTF-16 en-US and terminator */
    if (size < sizeof *out) size = sizeof *out;
    out = crt_malloc(size);
    if (!out) return 0;
    out->c_locale = 1; out->references = -1;
    offset = offsetof(crt_office_time_data, data);
    for (i = 0; i < 43; ++i) {
        size_t n = crt_strlen(c_names[i]) + 1;
        out->narrow[i] = (char *)out + offset;
        crt_memcpy((char *)out + offset, c_names[i], n);
        offset += n;
    }
    offset = wide_offset;
    for (i = 0; i < 44; ++i) {
        const unsigned char *s = (const unsigned char *)(i == 43 ? "en-US" : c_names[i]);
        wchar16 *w = (wchar16 *)((char *)out + offset);
        if (i == 43) out->locale_name = w; else out->wide[i] = w;
        do { *w++ = *s; offset += sizeof *w; } while (*s++);
    }
    return out;
}
DLLAPI void *CRTAPI _Gettnames(void) { return make_time_data(); }
DLLAPI void *CRTAPI _W_Gettnames(void) { return make_time_data(); }

typedef struct { void *out; size_t cap, used; int wide, error, invalid_reported; } time_buffer;
static void time_put(time_buffer *b, unsigned c)
{
    if (b->error) return;
    if (b->used >= b->cap - 1) { b->error = CRT_ERANGE; return; }
    if (!b->wide && c > 255) { b->error = CRT_EILSEQ; return; }
    if (b->wide) ((wchar16 *)b->out)[b->used++] = (wchar16)c;
    else ((char *)b->out)[b->used++] = (char)c;
}
static void time_name(time_buffer *b, const wchar16 *s)
{
    if (!s) { b->error = CRT_EINVAL; return; }
    while (*s && !b->error) time_put(b, *s++);
}
static void time_number(time_buffer *b, int value, unsigned width)
{
    char digits[16]; unsigned n = 0;
    if (value < 0) { b->error = CRT_EINVAL; return; }
    do { digits[n++] = (char)('0' + value % 10); value /= 10; } while (value);
    while (n < width) digits[n++] = '0';
    while (n) time_put(b, (unsigned char)digits[--n]);
}

/* Windows date/time pictures, as used in a genuine _Gettnames snapshot. */
static void time_picture(time_buffer *b, const wchar16 *p, const struct crt_tm *tm,
                         const crt_office_time_data *data)
{
    if (!p) { b->error = CRT_EINVAL; return; }
    while (*p && !b->error) {
        unsigned c = *p++, count = 1, extra;
        if (c == '\'') {
            if (*p == '\'') { time_put(b, *p++); continue; }
            for (;;) {
                if (!*p) { b->error = CRT_EINVAL; return; }
                if (*p == '\'') {
                    ++p;
                    if (*p != '\'') break;
                }
                time_put(b, *p++);
            }
            continue;
        }
        while (*p == c) { ++count; ++p; }
        switch (c) {
        case 'd':
            if ((count < 3 && (tm->tm_mday < 1 || tm->tm_mday > 31)) ||
                (count >= 3 && (tm->tm_wday < 0 || tm->tm_wday > 6))) { b->error = CRT_EINVAL; break; }
            if (count < 3) time_number(b, tm->tm_mday, count);
            else { for (extra = 4; extra < count; ++extra) time_put(b, c); time_name(b, data->wide[(count == 3 ? 0 : 7) + tm->tm_wday]); }
            break;
        case 'M':
            if (tm->tm_mon < 0 || tm->tm_mon > 11) { b->error = CRT_EINVAL; break; }
            if (count < 3) time_number(b, tm->tm_mon + 1, count);
            else { for (extra = 4; extra < count; ++extra) time_put(b, c); time_name(b, data->wide[(count == 3 ? 14 : 26) + tm->tm_mon]); }
            break;
        case 'y':
            if (count > 1 && (tm->tm_year < -1900 || tm->tm_year > 8099)) { b->error = CRT_EINVAL; break; }
            if (count == 1) time_put(b, 'y');
            else { for (extra = count < 4 ? 2 : 4; extra < count; ++extra) time_put(b, c); time_number(b, count < 4 ? (tm->tm_year + 1900) % 100 : tm->tm_year + 1900, count < 4 ? 2 : 4); }
            break;
        case 'H': case 'h': case 'm': case 's':
            if (((c == 'H' || c == 'h') && (tm->tm_hour < 0 || tm->tm_hour > 23)) ||
                (c == 'm' && (tm->tm_min < 0 || tm->tm_min > 59)) ||
                (c == 's' && (tm->tm_sec < 0 || tm->tm_sec > 60))) { b->error = CRT_EINVAL; break; }
            for (extra = 2; extra < count; ++extra) time_put(b, c);
            time_number(b, c == 'H' ? tm->tm_hour : c == 'h' ? ((tm->tm_hour + 11) % 12 + 1) : c == 'm' ? tm->tm_min : tm->tm_sec, count == 1 ? 1 : 2);
            break;
        case 't':
            if (tm->tm_hour < 0 || tm->tm_hour > 23) { b->error = CRT_EINVAL; break; }
            if (count == 1) { const wchar16 *s = data->wide[tm->tm_hour < 12 ? 38 : 39]; if (!s) b->error = CRT_EINVAL; else if (*s) time_put(b, *s); }
            else { for (extra = 2; extra < count; ++extra) time_put(b, c); time_name(b, data->wide[tm->tm_hour < 12 ? 38 : 39]); }
            break;
        default: while (count--) time_put(b, c); break;
        }
    }
}

static size_t snapshot_format(void *out, size_t cap, int wide, const void *format,
                              const struct crt_tm *tm, const crt_office_time_data *data)
{
    time_buffer b = {out, cap, 0, wide, 0, 0};
    size_t i = 0;
    CRT_VALIDATE(out != 0 && cap > 0, CRT_EINVAL, 0);
    if (wide) ((wchar16 *)out)[0] = 0; else ((char *)out)[0] = 0;
    CRT_VALIDATE(format != 0 && tm != 0, CRT_EINVAL, 0);
    if (data->c_locale != 1) { crt_set_errno(CRT_EINVAL); return 0; }
    for (;;) {
        unsigned c = wide ? ((const wchar16 *)format)[i] : ((const unsigned char *)format)[i];
        int alt = 0;
        if (!c || b.error) break;
        ++i;
        if (c != '%') { time_put(&b, c); continue; }
        c = wide ? ((const wchar16 *)format)[i] : ((const unsigned char *)format)[i];
        if (c == '#') { alt = 1; ++i; c = wide ? ((const wchar16 *)format)[i] : ((const unsigned char *)format)[i]; }
        if (c == 'E' || c == 'O') { ++i; c = wide ? ((const wchar16 *)format)[i] : ((const unsigned char *)format)[i]; }
        if (!c) { b.error = CRT_EINVAL; break; }
        ++i;
        if (((c == 'a' || c == 'A') && (tm->tm_wday < 0 || tm->tm_wday > 6)) ||
            ((c == 'b' || c == 'B' || c == 'h') && (tm->tm_mon < 0 || tm->tm_mon > 11)) ||
            (c == 'p' && (tm->tm_hour < 0 || tm->tm_hour > 23))) { b.error = CRT_EINVAL; break; }
        switch (c) {
        case 'a': time_name(&b, data->wide[tm->tm_wday]); break;
        case 'A': time_name(&b, data->wide[7 + tm->tm_wday]); break;
        case 'b': case 'h': time_name(&b, data->wide[14 + tm->tm_mon]); break;
        case 'B': time_name(&b, data->wide[26 + tm->tm_mon]); break;
        case 'p': time_name(&b, data->wide[tm->tm_hour < 12 ? 38 : 39]); break;
        case 'c':
            time_picture(&b, data->wide[alt ? 41 : 40], tm, data); time_put(&b, ' ');
            time_picture(&b, data->wide[42], tm, data); break;
        case 'x': time_picture(&b, data->wide[alt ? 41 : 40], tm, data); break;
        case 'X': case 'r': time_picture(&b, data->wide[42], tm, data); break;
        default: {
            wchar16 spec[4] = {'%', 0, 0, 0}, result[128]; size_t n, j;
            spec[1] = alt ? '#' : (wchar16)c; if (alt) spec[2] = (wchar16)c;
            n = wcsftime(result, sizeof result / sizeof result[0], spec, tm);
            if (!n) { b.error = crt_get_errno() ? crt_get_errno() : CRT_EINVAL; b.invalid_reported = 1; break; }
            for (j = 0; j < n; ++j) time_put(&b, result[j]);
            break;
        }
        }
    }
    if (b.error) {
        if (wide) ((wchar16 *)out)[0] = 0; else ((char *)out)[0] = 0;
        crt_set_errno(b.error);
        if (b.error == CRT_EINVAL && !b.invalid_reported) crt_invalid_parameter();
        return 0;
    }
    if (wide) ((wchar16 *)out)[b.used] = 0; else ((char *)out)[b.used] = 0;
    return b.used;
}

DLLAPI size_t CRTAPI _Strftime(char *out, size_t cap, const char *format, const struct crt_tm *tm, void *data)
{
    return data ? snapshot_format(out, cap, 0, format, tm, data) : strftime(out, cap, format, tm);
}
DLLAPI size_t CRTAPI _Wcsftime(wchar16 *out, size_t cap, const wchar16 *format, const struct crt_tm *tm, void *data)
{
    return data ? snapshot_format(out, cap, 1, format, tm, data) : wcsftime(out, cap, format, tm);
}
