/* SPDX-License-Identifier: GPL-2.0-only
 * Host logic controls for office_nls.c. The table backend stands in for
 * GetLocaleInfoA data only to exercise the core's parsing, selection and
 * buffer contracts; it is not Windows 98 runtime evidence.
 */
#include <stdio.h>
#include <string.h>
#include "office_nls.h"

struct row { uint32_t lcid; const char *lang, *ctry, *acp, *eng; };
static const struct row rows[] = {
    {0x0409, "en", "US", "1252", "English"}, {0x0809, "en", "GB", "1252", "English"},
    {0x0412, "ko", "KR", "949", "Korean"}, {0x0404, "zh", "TW", "950", "Chinese"},
    {0x0804, "zh", "CN", "936", "Chinese"}, {0x0c1a, "sr", "SP", "1251", "Serbian"},
    {0x081a, "sr", "SP", "1250", "Serbian"}, {0x0401, "ar", "SA", "1256", "Arabic"},
};
#define NROWS (sizeof rows / sizeof rows[0])
static uint32_t user = 0x0412, sys = 0x0412, overflow;

static const struct row *find(uint32_t lcid) { unsigned i; for (i = 0; i < NROWS; ++i) if (rows[i].lcid == lcid) return &rows[i]; return 0; }
static int q(void *c, uint32_t lcid, uint32_t t, char *out, int cch)
{
    const struct row *r = find(lcid); const char *s; int n;
    (void)c;
    if (!r) return -87;
    switch (t & 0x0fffffffu) {
    case 0x59: s = r->lang; break; case 0x5a: s = r->ctry; break;
    case 0x1004: s = r->acp; break; case 0x1001: s = r->eng; break; case 0x1: s = lcid == 0x412 ? "0412" : "0409"; break;
    default: return -1004;
    }
    n = (int)strlen(s) + 1;
    if (cch < n) return -122;
    memcpy(out, s, (size_t)n);
    return n;
}
static uint32_t e(void *c, uint32_t *l, uint32_t max) { unsigned i; (void)c; if (overflow || max < NROWS) return (uint32_t)-1; for (i = 0; i < NROWS; ++i) l[i] = rows[NROWS - 1 - i].lcid; return NROWS; }
static uint32_t u(void *c) { (void)c; return user; }
static uint32_t s(void *c) { (void)c; return sys; }
static int w(void *c, uint32_t cp, const char *in, int n, uint16_t *out, int cch)
{
    int i; (void)c; (void)cp;
    if (!out) return n;
    if (cch < n) return -122;
    for (i = 0; i < n; ++i) { if ((unsigned char)in[i] > 0x7f) return -1113; out[i] = (unsigned char)in[i]; }
    return n;
}
static const struct ofn_backend B = {0, q, e, u, s, w};
static int failures, checks;
#define CHECK(x) do { ++checks; if (!(x)) { ++failures; printf("FAIL %s:%d %s\n", __FILE__, __LINE__, #x); } } while (0)

static const uint16_t *W(const char *a) { static uint16_t buf[4][96]; static int k; uint16_t *o = buf[k++ & 3]; int i = 0; do o[i] = (unsigned char)a[i]; while (a[i++]); return o; }
static int weq(const uint16_t *x, const char *a) { while (*a && *x == (unsigned char)*a) { ++x; ++a; } return *x == 0 && *a == 0; }

int main(void)
{
    uint16_t out[96]; uint32_t r = 0, lcid = 0;
    /* SAL imp_getProcessLocale sequence */
    CHECK(ofn_user_default_locale_name(&B, out, 85, &r) == 0 && r == 6 && weq(out, "ko-KR"));
    CHECK(ofn_get_locale_info_ex(&B, out, 0x59, out + 10, 4, &r) == 0 && r == 3 && weq(out + 10, "ko"));
    CHECK(ofn_get_locale_info_ex(&B, out, 0x5a, out + 20, 3, &r) == 0 && r == 3 && weq(out + 20, "KR"));
    /* SAL osl_getTextEncodingFromLocale: GetLocaleInfoN(LOCALE_IDEFAULTANSICODEPAGE|RETURN_NUMBER, cch=2) */
    CHECK(ofn_get_locale_info_ex(&B, W("ko-KR"), 0x20001004u, out, 2, &r) == 0 && r == 2 && (out[0] | (uint32_t)out[1] << 16) == 949);
    CHECK(ofn_get_locale_info_ex(&B, W("ko-KR"), 0x20001004u, out, 1, &r) == 122);
    CHECK(ofn_get_locale_info_ex(&B, W("ko-KR"), 0x20001004u, 0, 0, &r) == 0 && r == 2);
    CHECK(ofn_get_locale_info_ex(&B, W("zz-ZZ"), 0x20001004u, out, 2, &r) == 87);
    CHECK(ofn_resolve_locale_name(&B, W("en-XX"), out, 85, &r) == 0 && weq(out, "en-US") && r == 6);
    CHECK(ofn_resolve_locale_name(&B, W("zh-Hant-TW"), out, 85, &r) == 0 && weq(out, "zh-TW"));
    CHECK(ofn_resolve_locale_name(&B, W("xx-YY"), out, 85, &r) == 87);
    CHECK(ofn_resolve_locale_name(&B, 0, out, 85, &r) == 0 && weq(out, "ko-KR"));
    CHECK(ofn_name_to_lcid(&B, W("EN_us"), &lcid) == 0 && lcid == 0x409);
    CHECK(ofn_name_to_lcid(&B, W("en"), &lcid) == 0 && lcid == 0x409);
    CHECK(ofn_name_to_lcid(&B, W("en-GB"), &lcid) == 0 && lcid == 0x809);
    CHECK(ofn_name_to_lcid(&B, W("zh"), &lcid) == 0 && lcid == 0x404);
    CHECK(ofn_name_to_lcid(&B, W("sr-SP"), &lcid) == 0 && lcid == 0x081a);
    CHECK(ofn_name_to_lcid(&B, W("zh-Hans"), &lcid) == 87);
    CHECK(ofn_name_to_lcid(&B, W("e"), &lcid) == 87);
    { uint16_t bad[] = {'k', 0x00f6, 0}; CHECK(ofn_name_to_lcid(&B, bad, &lcid) == 87); }
    CHECK(ofn_name_to_lcid(&B, W("en-"), &lcid) == 87);
    CHECK(ofn_get_locale_info_ex(&B, W(""), 0x59, out, 85, &r) == 50);
    CHECK(ofn_get_locale_info_ex(&B, W("!x-sys-default-locale"), 0x5c, out, 85, &r) == 0 && weq(out, "ko-KR"));
    CHECK(ofn_get_locale_info_ex(&B, W("en-US"), 0x5c, out, 5, &r) == 122);
    CHECK(ofn_get_locale_info_ex(&B, W("en-US"), 0x5c, 0, 0, &r) == 0 && r == 6);
    CHECK(ofn_get_locale_info_ex(&B, W("en-US"), 0x2000005cu, out, 85, &r) == 1004);
    CHECK(ofn_get_locale_info_ex(&B, W("en-US"), 0x20001001u, out, 85, &r) == 1004);
    CHECK(ofn_get_locale_info_ex(&B, W("en-US"), 0x10001001u, out, 85, &r) == 1004);
    CHECK(ofn_get_locale_info_ex(&B, W("en-US"), 0x1001u, out, 85, &r) == 0 && weq(out, "English") && r == 8);
    CHECK(ofn_get_locale_info_ex(&B, W("en-US"), 0x7777u, out, 85, &r) == 1004);
    CHECK(ofn_get_locale_info_ex(&B, W("ko-KR"), 0x20000001u, out, 2, &r) == 0 && out[0] == 0x412 && out[1] == 0);
    CHECK(ofn_lcid_to_name(&B, 0x1234, out, 85, &r) == 87);
    CHECK(ofn_lcid_to_name(&B, 0x409, 0, 5, &r) == 87);
    overflow = 1;
    CHECK(ofn_name_to_lcid(&B, W("en-US"), &lcid) == 8);
    overflow = 0; user = 0x0c1a;
    CHECK(ofn_name_to_lcid(&B, W("sr-SP"), &lcid) == 0 && lcid == 0x0c1a);
    printf("office_nls host controls: %d checks, %d failures\n", checks, failures);
    return failures != 0;
}
