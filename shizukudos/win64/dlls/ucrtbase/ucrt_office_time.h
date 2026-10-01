/* SPDX-License-Identifier: GPL-2.0-only
 * Wine11/MSVCR110+ time-name ABI, using the Microsoft LLP64 field widths.
 */
#ifndef SHZ_UCRT_OFFICE_TIME_H
#define SHZ_UCRT_OFFICE_TIME_H
#include "crtint.h"
typedef struct {
    const char *narrow[43];
    int32_t c_locale, references;
    const wchar16 *wide[43];
    const wchar16 *locale_name;
    char data[1];
} crt_office_time_data;
_Static_assert(offsetof(crt_office_time_data, c_locale) == 344, "time names C flag ABI");
_Static_assert(offsetof(crt_office_time_data, wide) == 352, "time names wide table ABI");
_Static_assert(offsetof(crt_office_time_data, locale_name) == 696, "time names locale ABI");
_Static_assert(offsetof(crt_office_time_data, data) == 704, "time names payload ABI");
_Static_assert(sizeof(crt_office_time_data) == 712, "time names allocation ABI");
#endif
