/* SPDX-License-Identifier: GPL-2.0-only
 * Current CRT C/POSIX locale adapters. The actual locale provider has one-byte
 * characters and codepage zero; these functions do not invent DBCS metadata.
 * Written from public contracts; pinned Wine was reviewed, not copied. */
#include "crtint.h"

extern unsigned CRTAPI ___lc_codepage_func(void);
extern int CRTAPI ___mb_cur_max_func(void);
extern crt_errno_t CRTAPI strncpy_s(char *, size_t, const char *, size_t);

static int legacy_single_byte(void)
{
    if (___lc_codepage_func() == 0 && ___mb_cur_max_func() == 1) return 1;
    crt_set_errno(CRT_ENOSYS);
    *crt_doserrno_ptr() = 120; /* ERROR_CALL_NOT_IMPLEMENTED */
    return 0;
}

DLLAPI unsigned char *CRTAPI _mbschr(const unsigned char *text, unsigned int character)
{
    unsigned char byte = (unsigned char)character;
    CRT_VALIDATE(text != 0, CRT_EINVAL, 0);
    if (!legacy_single_byte()) return 0;
    do {
        if (*text == byte) return (unsigned char *)text;
    } while (*text++);
    return 0;
}

DLLAPI unsigned char *CRTAPI _mbsinc(const unsigned char *text)
{
    CRT_VALIDATE(text != 0, CRT_EINVAL, 0);
    if (!legacy_single_byte()) return 0;
    return (unsigned char *)(text + 1);
}

DLLAPI unsigned char *CRTAPI _mbsdec(const unsigned char *start, const unsigned char *current)
{
    CRT_VALIDATE(start != 0 && current != 0, CRT_EINVAL, 0);
    if (!legacy_single_byte()) return 0;
    if ((uintptr_t)current <= (uintptr_t)start) return 0;
    return (unsigned char *)(current - 1);
}

DLLAPI int CRTAPI _mbsnbcmp(const unsigned char *left, const unsigned char *right, size_t count)
{
    if (!count) return 0;
    CRT_VALIDATE(left != 0 && right != 0, CRT_EINVAL, CRT_INT_MAX);
    if (!legacy_single_byte()) return CRT_INT_MAX; /* _NLSCMPERROR */
    while (count--) {
        if (*left != *right) return *left < *right ? -1 : 1;
        if (!*left) return 0;
        ++left; ++right;
    }
    return 0;
}

DLLAPI crt_errno_t CRTAPI _mbsnbcpy_s(unsigned char *destination, size_t size,
                                    const unsigned char *source, size_t count)
{
    if (!legacy_single_byte()) { if (destination && size) destination[0] = 0; return CRT_ENOSYS; }
    /* The actual C locale has no lead/trail bytes; retain the existing genuine
     * secure-copy provider's zero-count, range, and _TRUNCATE semantics. */
    return strncpy_s((char *)destination, size, (const char *)source, count);
}
