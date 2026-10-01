/* SPDX-License-Identifier: GPL-2.0-only
 * C runtime for the Wine port: locale objects (_create_locale / _free_locale) of the only locale this runtime has, the
 * "C" locale (see setlocale in wcrt_stdlib.c). _create_locale returns one shared, read-only object for "C" (every
 * category) and NULL for any other locale name, as the UCRT does for a name it does not know; the _l functions of
 * this runtime ignore the locale argument. Written from MSDN.
 */
#include "shzwcrt.h"
#include <errno.h>
#include <locale.h>

static threadlocinfo c_locinfo;
static _locale_tstruct c_locale = { &c_locinfo, NULL };

_locale_t __cdecl _create_locale(int category, const char *locale)
{
    if (category < LC_ALL || category > LC_MAX || !locale) {
        shzw_set_errno(EINVAL);
        return NULL;
    }
    if (strcmp(locale, "C")) return NULL;                /* only the C locale exists */
    return &c_locale;
}

_locale_t __cdecl _wcreate_locale(int category, const wchar_t *locale)
{
    if (category < LC_ALL || category > LC_MAX || !locale) {
        shzw_set_errno(EINVAL);
        return NULL;
    }
    if (wcscmp(locale, L"C")) return NULL;
    return &c_locale;
}

void __cdecl _free_locale(_locale_t locale)
{
    (void)locale;                                        /* the C locale object is static */
}
