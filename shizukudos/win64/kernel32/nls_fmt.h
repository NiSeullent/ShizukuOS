/* SPDX-License-Identifier: GPL-2.0-only
 * Shizuku NLS formatting engine: date/time pictures and number/currency pictures over UTF-16. Pure functions (no Windows
 * types) shared by kernel32.dll and the native unit test tests/host/nls_host_test.c. */
#ifndef SHZ_NLS_FMT_H
#define SHZ_NLS_FMT_H
#include "nls_core.h"

typedef struct { int year, month, day, wday, hour, minute, second; } nls_dt;      /* wday: 0 = Sunday */

extern const nls_w *const nls_month_names[12];
extern const nls_w *const nls_month_abbrev[12];
extern const nls_w *const nls_day_names[7];             /* Sunday first */
extern const nls_w *const nls_day_abbrev[7];
extern const nls_w *const nls_day_shortest[7];

int nls_days_in_month(int year, int month);
int nls_day_of_week(int year, int month, int day);      /* 0 = Sunday, proleptic Gregorian */

#define NLS_PIC_DATE 0
#define NLS_PIC_TIME 1
/* Formats one picture. Returns the length without the terminator, or -1 if it does not fit in `cap` (the terminator is
 * written when cap allows). */
int nls_picture(int kind, const nls_w *pic, const nls_dt *t, const nls_w *am, const nls_w *pm, nls_w *out, int cap);
/* Rewrites a time picture for TIME_NOMINUTESORSECONDS/NOSECONDS/NOTIMEMARKER/FORCE24HOURFORMAT (the Windows flag values). */
int nls_time_picture_edit(const nls_w *pic, unsigned flags, nls_w *out, int cap);

typedef struct {
    unsigned digits, lzero, grouping, negorder, posorder;
    const nls_w *dec, *thou, *curr;
} nls_numfmt;
/* Formats a decimal string ("-1234.5678") per `f`. currency != 0 uses the currency orders. Returns the length, -1 if
 * `cap` is too small, -2 if the value string or the format is invalid. */
int nls_number(const nls_w *value, const nls_numfmt *f, int currency, nls_w *out, int cap);
#endif
