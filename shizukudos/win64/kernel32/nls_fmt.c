/* SPDX-License-Identifier: GPL-2.0-only
 * Shizuku NLS formatting engine (see nls_fmt.h). English names only: this system has one locale, en-US (plus the
 * invariant locale, whose names are identical).
 */
#include "nls_fmt.h"

/* char16_t literals: same representation as UTF-16 WCHAR */
static const nls_w mn0[] = u"January", mn1[] = u"February", mn2[] = u"March", mn3[] = u"April", mn4[] = u"May", mn5[] = u"June",
                   mn6[] = u"July", mn7[] = u"August", mn8[] = u"September", mn9[] = u"October", mn10[] = u"November",
                   mn11[] = u"December";
static const nls_w ma0[] = u"Jan", ma1[] = u"Feb", ma2[] = u"Mar", ma3[] = u"Apr", ma4[] = u"May", ma5[] = u"Jun", ma6[] = u"Jul",
                   ma7[] = u"Aug", ma8[] = u"Sep", ma9[] = u"Oct", ma10[] = u"Nov", ma11[] = u"Dec";
static const nls_w dn0[] = u"Sunday", dn1[] = u"Monday", dn2[] = u"Tuesday", dn3[] = u"Wednesday", dn4[] = u"Thursday",
                   dn5[] = u"Friday", dn6[] = u"Saturday";
static const nls_w da0[] = u"Sun", da1[] = u"Mon", da2[] = u"Tue", da3[] = u"Wed", da4[] = u"Thu", da5[] = u"Fri", da6[] = u"Sat";
static const nls_w ds0[] = u"Su", ds1[] = u"Mo", ds2[] = u"Tu", ds3[] = u"We", ds4[] = u"Th", ds5[] = u"Fr", ds6[] = u"Sa";
const nls_w *const nls_month_names[12] = { mn0, mn1, mn2, mn3, mn4, mn5, mn6, mn7, mn8, mn9, mn10, mn11 };
const nls_w *const nls_month_abbrev[12] = { ma0, ma1, ma2, ma3, ma4, ma5, ma6, ma7, ma8, ma9, ma10, ma11 };
const nls_w *const nls_day_names[7] = { dn0, dn1, dn2, dn3, dn4, dn5, dn6 };
const nls_w *const nls_day_abbrev[7] = { da0, da1, da2, da3, da4, da5, da6 };
const nls_w *const nls_day_shortest[7] = { ds0, ds1, ds2, ds3, ds4, ds5, ds6 };

int nls_days_in_month(int y, int m)
{
    static const int md[12] = { 31, 28, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31 };
    if (m < 1 || m > 12) return 0;
    return md[m - 1] + (m == 2 && ((y % 4 == 0 && y % 100 != 0) || y % 400 == 0));
}

int nls_day_of_week(int y, int m, int d)
{
    static const int t[12] = { 0, 3, 2, 5, 0, 3, 5, 1, 4, 6, 2, 4 };       /* Sakamoto */
    if (m < 3) --y;
    return (y + y / 4 - y / 100 + y / 400 + t[m - 1] + d) % 7;
}

typedef struct { nls_w *out; int cap, len; } obuf_t;
static void oput(obuf_t *o, nls_w c) { if (o->out && o->len < o->cap) o->out[o->len] = c; ++o->len; }
static void oputs(obuf_t *o, const nls_w *s) { while (*s) oput(o, *s++); }
static void oputn(obuf_t *o, unsigned v, int width)
{
    nls_w tmp[12];
    int n = 0;
    do { tmp[n++] = (nls_w)('0' + v % 10); v /= 10; } while (v);
    while (width > n) { oput(o, '0'); --width; }
    while (n) oput(o, tmp[--n]);
}
static int ofinish(obuf_t *o)
{
    if (o->out && o->cap > 0) o->out[o->len < o->cap ? o->len : o->cap - 1] = 0;
    return o->out && o->len >= o->cap ? -1 : o->len;
}

int nls_picture(int kind, const nls_w *pic, const nls_dt *t, const nls_w *am, const nls_w *pm, nls_w *out, int cap)
{
    obuf_t o = { out, cap, 0 };
    int i = 0;
    while (pic[i]) {
        const nls_w c = pic[i];
        int run = 1;
        if (c == '\'') {                                                      /* quoted literal; '' is a quote */
            ++i;
            for (;;) {
                if (!pic[i]) break;
                if (pic[i] == '\'') {
                    if (pic[i + 1] == '\'') { oput(&o, '\''); i += 2; continue; }
                    ++i;
                    break;
                }
                oput(&o, pic[i++]);
            }
            continue;
        }
        while (pic[i + run] == c) ++run;
        if (kind == NLS_PIC_DATE && c == 'd') {
            if (run == 1) oputn(&o, (unsigned)t->day, 1);
            else if (run == 2) oputn(&o, (unsigned)t->day, 2);
            else if (run == 3) oputs(&o, nls_day_abbrev[t->wday]);
            else oputs(&o, nls_day_names[t->wday]);
            if (run > 4) { /* more than four d's: Windows treats extra letters as a new picture element */ }
            i += run > 4 ? 4 : run;
        } else if (kind == NLS_PIC_DATE && c == 'M') {
            if (run == 1) oputn(&o, (unsigned)t->month, 1);
            else if (run == 2) oputn(&o, (unsigned)t->month, 2);
            else if (run == 3) oputs(&o, nls_month_abbrev[t->month - 1]);
            else oputs(&o, nls_month_names[t->month - 1]);
            i += run > 4 ? 4 : run;
        } else if (kind == NLS_PIC_DATE && c == 'y') {
            if (run == 1) oputn(&o, (unsigned)(t->year % 100), 1);
            else if (run == 2) oputn(&o, (unsigned)(t->year % 100), 2);
            else if (run <= 4) oputn(&o, (unsigned)t->year, 4);
            else oputn(&o, (unsigned)t->year, 5);
            i += run > 5 ? 5 : run;
        } else if (kind == NLS_PIC_DATE && c == 'g') {
            if (run >= 2) { oputs(&o, u"A.D."); i += 2; }
            else { oput(&o, 'g'); ++i; }
        } else if (kind == NLS_PIC_TIME && (c == 'h' || c == 'H')) {
            int h = t->hour;
            if (c == 'h') { h %= 12; if (!h) h = 12; }
            oputn(&o, (unsigned)h, run >= 2 ? 2 : 1);
            i += run > 2 ? 2 : run;
        } else if (kind == NLS_PIC_TIME && c == 'm') {
            oputn(&o, (unsigned)t->minute, run >= 2 ? 2 : 1);
            i += run > 2 ? 2 : run;
        } else if (kind == NLS_PIC_TIME && c == 's') {
            oputn(&o, (unsigned)t->second, run >= 2 ? 2 : 1);
            i += run > 2 ? 2 : run;
        } else if (kind == NLS_PIC_TIME && c == 't') {
            const nls_w *mk = t->hour < 12 ? am : pm;
            if (run >= 2) oputs(&o, mk); else if (mk[0]) oput(&o, mk[0]);
            i += run > 2 ? 2 : run;
        } else {
            oput(&o, c);
            ++i;
        }
    }
    return ofinish(&o);
}

/* Time picture editing works on tokens: literal runs, quoted runs and element runs. */
typedef struct { int start, len; char kind; } tok_t;              /* kind: 'q' quoted, 'l' literal, 'h','m','s','t' elements */
#define MAX_TOK 64

int nls_time_picture_edit(const nls_w *pic, unsigned flags, nls_w *out, int cap)
{
    tok_t tk[MAX_TOK];
    int keep[MAX_TOK], n = 0, i = 0, k, len = 0;
    while (pic[i] && n < MAX_TOK) {
        const nls_w c = pic[i];
        tk[n].start = i;
        if (c == '\'') {
            ++i;
            while (pic[i] && !(pic[i] == '\'' && pic[i + 1] != '\'')) i += pic[i] == '\'' ? 2 : 1;
            if (pic[i]) ++i;
            tk[n].kind = 'q';
        } else if (c == 'h' || c == 'H' || c == 'm' || c == 's' || c == 't') {
            while (pic[i] == c) ++i;
            tk[n].kind = c == 'H' ? 'h' : (char)c;
        } else {
            while (pic[i] && pic[i] != '\'' && pic[i] != 'h' && pic[i] != 'H' && pic[i] != 'm' && pic[i] != 's' && pic[i] != 't') ++i;
            tk[n].kind = 'l';
        }
        tk[n].len = i - tk[n].start;
        keep[n] = 1;
        ++n;
    }
    if (pic[i]) return -2;                                                   /* picture too complex */
    for (k = 0; k < n; ++k) {
        int drop = 0;
        if (tk[k].kind == 'm' && (flags & 1)) drop = 1;                       /* TIME_NOMINUTESORSECONDS */
        if (tk[k].kind == 's' && (flags & (1 | 2))) drop = 1;                 /* ... or TIME_NOSECONDS */
        if (tk[k].kind == 't' && (flags & 4)) drop = 1;                       /* TIME_NOTIMEMARKER (FORCE24HOURFORMAT alone keeps it) */
        if (drop) {
            keep[k] = 0;
            if (tk[k].kind == 't') {                                           /* drop the whitespace around the marker */
                if (k > 0 && tk[k - 1].kind == 'l') keep[k - 1] = 0;
                else if (k + 1 < n && tk[k + 1].kind == 'l') keep[k + 1] = 0;
            } else if (k > 0 && tk[k - 1].kind == 'l') {
                keep[k - 1] = 0;                                              /* the separator before minutes/seconds */
            }
        }
    }
    for (k = 0; k < n; ++k) {
        int j;
        if (!keep[k]) continue;
        for (j = 0; j < tk[k].len; ++j) {
            nls_w c = pic[tk[k].start + j];
            if ((flags & 8) && tk[k].kind == 'h' && c == 'h') c = 'H';         /* 24-hour clock */
            if (out && len < cap) out[len] = c;
            ++len;
        }
    }
    if (out && cap > 0) out[len < cap ? len : cap - 1] = 0;
    return out && len >= cap ? -1 : len;
}

/* ---------------------------------------------------------------- numbers */
int nls_number(const nls_w *v, const nls_numfmt *f, int currency, nls_w *out, int cap)
{
    nls_w ip[320], fp[320];
    int neg = 0, ni = 0, nf = 0, i = 0, k, grp1, grp2, n_int;
    obuf_t o = { out, cap, 0 };
    if (f->digits > 99 || f->lzero > 1) return -2;
    if (currency ? (f->negorder > 15 || f->posorder > 3) : f->negorder > 4) return -2;
    if (f->grouping > 9 && f->grouping != 32) return -2;
    if (v[0] == '-') { neg = 1; ++i; }
    if (!(v[i] >= '0' && v[i] <= '9')) return -2;
    while (v[i] >= '0' && v[i] <= '9') { if (ni >= 300) return -2; ip[ni++] = v[i++]; }
    if (v[i] == '.') {
        ++i;
        while (v[i] >= '0' && v[i] <= '9') { if (nf >= 300) return -2; fp[nf++] = v[i++]; }
    }
    if (v[i]) return -2;
    /* strip leading zeros of the integer part, keep one digit */
    for (k = 0; k < ni - 1 && ip[k] == '0'; ++k) { }
    if (k) { for (i = 0; i < ni - k; ++i) ip[i] = ip[i + k]; ni -= k; }
    /* round half up (away from zero) to f->digits fractional digits, on the decimal string */
    if ((int)f->digits < nf) {
        const int up = fp[f->digits] >= '5';
        nf = (int)f->digits;
        if (up) {
            int c = nf - 1;
            for (; c >= 0; --c) { if (fp[c] == '9') fp[c] = '0'; else { ++fp[c]; break; } }
            if (c < 0) {
                for (c = ni - 1; c >= 0; --c) { if (ip[c] == '9') ip[c] = '0'; else { ++ip[c]; break; } }
                if (c < 0) {
                    if (ni >= 300) return -2;
                    for (c = ni; c > 0; --c) ip[c] = ip[c - 1];
                    ip[0] = '1';
                    ++ni;
                }
            }
        }
    }
    while (nf < (int)f->digits) fp[nf++] = '0';
    {                                                            /* a result that rounds to zero carries no sign */
        int nz = 0;
        for (i = 0; i < ni; ++i) if (ip[i] != '0') nz = 1;
        for (i = 0; i < nf; ++i) if (fp[i] != '0') nz = 1;
        if (!nz) neg = 0;
    }
    /* body: [0]integer with grouping, decimal separator, fraction */
    {
        nls_w body[700];
        obuf_t b = { body, 700, 0 };
        n_int = ni;
        grp1 = f->grouping == 32 ? 3 : (int)f->grouping;
        grp2 = f->grouping == 32 ? 2 : (int)f->grouping;
        if (ni == 1 && ip[0] == '0' && !f->lzero && f->digits > 0) { /* ".50": the leading zero is dropped */ }
        else {
            for (i = 0; i < n_int; ++i) {
                const int left = n_int - i;                         /* digits still to print, including this one */
                oput(&b, ip[i]);
                if (grp1 && left > 1) {
                    /* a separator follows this digit when the remaining digits are a whole number of groups */
                    int rem = left - 1, sep = 0;
                    if (rem == grp1) sep = 1;
                    else if (rem > grp1 && grp2 && (rem - grp1) % grp2 == 0) sep = 1;
                    if (sep) oputs(&b, f->thou);
                }
            }
        }
        if (f->digits) { oputs(&b, f->dec); for (i = 0; i < nf; ++i) oput(&b, fp[i]); }
        body[b.len < 700 ? b.len : 699] = 0;
        if (b.len >= 700) return -2;
        if (!currency) {
            if (neg) {
                switch (f->negorder) {
                case 0: oput(&o, '('); oputs(&o, body); oput(&o, ')'); break;
                case 1: oput(&o, '-'); oputs(&o, body); break;
                case 2: oput(&o, '-'); oput(&o, ' '); oputs(&o, body); break;
                case 3: oputs(&o, body); oput(&o, '-'); break;
                default: oputs(&o, body); oput(&o, ' '); oput(&o, '-'); break;
                }
            } else {
                oputs(&o, body);
            }
        } else {
            const nls_w *cs = f->curr;
            if (!neg) {
                switch (f->posorder) {
                case 0: oputs(&o, cs); oputs(&o, body); break;
                case 1: oputs(&o, body); oputs(&o, cs); break;
                case 2: oputs(&o, cs); oput(&o, ' '); oputs(&o, body); break;
                default: oputs(&o, body); oput(&o, ' '); oputs(&o, cs); break;
                }
            } else {
                switch (f->negorder) {
                case 0: oput(&o, '('); oputs(&o, cs); oputs(&o, body); oput(&o, ')'); break;
                case 1: oput(&o, '-'); oputs(&o, cs); oputs(&o, body); break;
                case 2: oputs(&o, cs); oput(&o, '-'); oputs(&o, body); break;
                case 3: oputs(&o, cs); oputs(&o, body); oput(&o, '-'); break;
                case 4: oput(&o, '('); oputs(&o, body); oputs(&o, cs); oput(&o, ')'); break;
                case 5: oput(&o, '-'); oputs(&o, body); oputs(&o, cs); break;
                case 6: oputs(&o, body); oput(&o, '-'); oputs(&o, cs); break;
                case 7: oputs(&o, body); oputs(&o, cs); oput(&o, '-'); break;
                case 8: oput(&o, '-'); oputs(&o, body); oput(&o, ' '); oputs(&o, cs); break;
                case 9: oput(&o, '-'); oputs(&o, cs); oput(&o, ' '); oputs(&o, body); break;
                case 10: oputs(&o, body); oput(&o, ' '); oputs(&o, cs); oput(&o, '-'); break;
                case 11: oputs(&o, cs); oput(&o, ' '); oputs(&o, body); oput(&o, '-'); break;
                case 12: oputs(&o, cs); oput(&o, ' '); oput(&o, '-'); oputs(&o, body); break;
                case 13: oputs(&o, body); oput(&o, '-'); oput(&o, ' '); oputs(&o, cs); break;
                case 14: oput(&o, '('); oputs(&o, cs); oput(&o, ' '); oputs(&o, body); oput(&o, ')'); break;
                default: oput(&o, '('); oputs(&o, body); oput(&o, ' '); oputs(&o, cs); oput(&o, ')'); break;
                }
            }
        }
    }
    return ofinish(&o);
}
