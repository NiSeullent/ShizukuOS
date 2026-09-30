/* SPDX-License-Identifier: GPL-2.0-only
 * Guest check of ICU (icuuc, icuin, icudt: data packaged as a DLL): full case mapping, NFC normalization, word and
 * line breaking, root collation, a Japanese-locale date pattern and UTF-8 conversion. Every item needs ICU data, so a
 * missing or unloadable data library fails here. */
#include <string.h>
#include <unicode/ubrk.h>
#include <unicode/ucol.h>
#include <unicode/udat.h>
#include <unicode/udatpg.h>
#include <unicode/uloc.h>
#include <unicode/unorm2.h>
#include <unicode/ustring.h>
#include <unicode/uversion.h>
#include "deptest.h"

int main(void)
{
    UErrorCode e = U_ZERO_ERROR;
    UChar in[64], out[64];
    char u8[128];
    UVersionInfo v;
    char vs[U_MAX_VERSION_STRING_LENGTH];
    u_getVersion(v);
    u_versionToString(v, vs);
    printf("ICU %s, default locale %s\n", vs, uloc_getDefault());
    u_strFromUTF8(in, 64, NULL, "stra\xc3\x9f" "e", -1, &e);                    /* "straße" */
    int32_t n = u_strToUpper(out, 64, in, -1, "", &e);
    u_strToUTF8(u8, sizeof u8, NULL, out, n, &e);
    CHECK(U_SUCCESS(e) && !strcmp(u8, "STRASSE"));
    const UNormalizer2 *nfc = unorm2_getNFCInstance(&e);
    u_strFromUTF8(in, 64, NULL, "e\xcc\x81", -1, &e);                            /* e + combining acute */
    n = nfc ? unorm2_normalize(nfc, in, -1, out, 64, &e) : 0;
    CHECK(U_SUCCESS(e) && n == 1 && out[0] == 0x00e9);
    u_strFromUTF8(in, 64, NULL, "Hello, world! It's 3.5 o'clock.", -1, &e);
    UBreakIterator *bi = ubrk_open(UBRK_WORD, "en", in, -1, &e);
    int words = 0;
    for (int32_t p = ubrk_first(bi); p != UBRK_DONE; p = ubrk_next(bi))
        if (ubrk_getRuleStatus(bi) >= UBRK_WORD_LETTER || ubrk_getRuleStatus(bi) == UBRK_WORD_NUMBER) ++words;
    ubrk_close(bi);
    CHECK(U_SUCCESS(e) && words == 5);                         /* Hello, world, It's, 3.5, o'clock */
    u_strFromUTF8(in, 64, NULL, "\xe6\x97\xa5\xe6\x9c\xac\xe8\xaa\x9e\xe3\x81\xae\xe6\x96\x87", -1, &e);   /* 日本語の文 */
    bi = ubrk_open(UBRK_LINE, "ja", in, -1, &e);
    int breaks = 0;
    for (int32_t p = ubrk_first(bi); p != UBRK_DONE; p = ubrk_next(bi)) ++breaks;
    ubrk_close(bi);
    CHECK(U_SUCCESS(e) && breaks >= 4);                        /* CJK: a break opportunity between most characters */
    UCollator *col = ucol_open("", &e);
    UChar a[4], b[4];
    u_uastrcpy(a, "a"); u_uastrcpy(b, "B");
    CHECK(U_SUCCESS(e) && ucol_strcoll(col, a, -1, b, -1) == UCOL_LESS);   /* root collation, not code point order */
    ucol_close(col);
    UDateTimePatternGenerator *g = udatpg_open("ja_JP", &e);
    UChar skel[16], pat[64];
    u_uastrcpy(skel, "yMMMd");
    n = g ? udatpg_getBestPattern(g, skel, -1, pat, 64, &e) : 0;
    u_strToUTF8(u8, sizeof u8, NULL, pat, n, &e);
    printf("ja_JP yMMMd -> %s\n", u8);
    CHECK(U_SUCCESS(e) && strstr(u8, "\xe5\xb9\xb4") != NULL);               /* contains 年 */
    udatpg_close(g);
    return DONE("t_dep_icu");
}
