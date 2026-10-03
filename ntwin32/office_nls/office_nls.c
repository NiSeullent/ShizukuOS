/* SPDX-License-Identifier: GPL-2.0-only
 * Locale-name to LCID provider core. See office_nls.h for scope and sources.
 * Pure logic over a real system backend; no fixed locale table and no
 * allocation. Every buffer is bounded and every pointer is validated.
 */
#include "office_nls.h"

#define LOCALE_ILANGUAGE_ 0x00000001u
#define LOCALE_SISO639_ 0x00000059u
#define LOCALE_SISO3166_ 0x0000005Au
#define LOCALE_SNAME_ 0x0000005Cu
#define LOCALE_IDEFAULTANSICODEPAGE_ 0x00001004u
#define LOCALE_NOUSEROVERRIDE_ 0x80000000u
#define LOCALE_USE_CP_ACP_ 0x40000000u
#define LOCALE_RETURN_NUMBER_ 0x20000000u
#define LOCALE_RETURN_GENITIVE_NAMES_ 0x10000000u
#define LOCALE_ALLOW_NEUTRAL_NAMES_ 0x08000000u
#define OFN_TYPE_MASK 0x07FFFFFFu
#define OFN_QUERY_MAX 1024

static const char sys_default_name[] = "!x-sys-default-locale";

static unsigned lower_ascii(unsigned c) { return (c >= 'A' && c <= 'Z') ? c + 32u : c; }
static int is_alpha(unsigned c) { c = lower_ascii(c); return c >= 'a' && c <= 'z'; }

static uint32_t query_error(int r) { return r < 0 ? (uint32_t)-r : OFN_ERROR_INVALID_FLAGS; }

/* ASCII ISO code into tag; rejects anything that is not 2..3 letters. */
static uint32_t query_iso(const struct ofn_backend *b, uint32_t lcid, uint32_t type, char *out, uint32_t cap)
{
    char text[16];
    int r = b->query(b->ctx, lcid, type, text, (int)sizeof text), i;
    if (r <= 0) return query_error(r);
    if (r > (int)sizeof text || text[r - 1] != 0) return OFN_ERROR_NOT_SUPPORTED;
    for (i = 0; text[i]; ++i)
        if (!is_alpha((unsigned char)text[i])) return OFN_ERROR_NOT_SUPPORTED;
    if (i < 2 || i > 3 || (uint32_t)i + 1u > cap) return OFN_ERROR_NOT_SUPPORTED;
    for (r = 0; r <= i; ++r) out[r] = text[r];
    return OFN_OK;
}

/* "ll-CC" from the system's own ISO 639 / ISO 3166 data for an LCID. */
static uint32_t lcid_tag(const struct ofn_backend *b, uint32_t lcid, char *tag, uint32_t cap)
{
    char lang[4], ctry[4];
    uint32_t n = 0, i, err = query_iso(b, lcid, LOCALE_SISO639_, lang, sizeof lang);
    if (err) return err;
    for (i = 0; lang[i]; ++i) tag[n++] = (char)lower_ascii((unsigned char)lang[i]);
    if (query_iso(b, lcid, LOCALE_SISO3166_, ctry, sizeof ctry) == OFN_OK) {
        tag[n++] = '-';
        for (i = 0; ctry[i]; ++i) tag[n++] = (char)(ctry[i] >= 'a' && ctry[i] <= 'z' ? ctry[i] - 32 : ctry[i]);
    }
    if (n + 1u > cap) return OFN_ERROR_INSUFFICIENT_BUFFER;
    tag[n] = 0;
    return OFN_OK;
}

static uint32_t put_ascii(const char *text, uint16_t *out, uint32_t cch, uint32_t *result)
{
    uint32_t n = 0, i;
    while (text[n]) ++n;
    if (cch == 0) { *result = n + 1u; return OFN_OK; }
    if (!out) return OFN_ERROR_INVALID_PARAMETER;
    if (cch < n + 1u) return OFN_ERROR_INSUFFICIENT_BUFFER;
    for (i = 0; i <= n; ++i) out[i] = (uint16_t)(unsigned char)text[i];
    *result = n + 1u;
    return OFN_OK;
}

/* Parsed request: lowercase language, uppercase region (may be empty).
 * Only language[-region] tags representable by an LCID are accepted;
 * script/variant subtags set *extra so resolution can fall back. */
struct ofn_tag { char lang[4]; char region[4]; int extra; };

static uint32_t parse_tag(const uint16_t *name, struct ofn_tag *t)
{
    uint32_t i = 0, n = 0;
    t->lang[0] = t->region[0] = 0;
    t->extra = 0;
    while (name[i] && name[i] != '-' && name[i] != '_') {
        if (name[i] > 0x7f || !is_alpha(name[i]) || n >= 3) return OFN_ERROR_INVALID_PARAMETER;
        t->lang[n++] = (char)lower_ascii(name[i++]);
    }
    if (n < 2) return OFN_ERROR_INVALID_PARAMETER;
    t->lang[n] = 0;
    while (name[i]) {
        uint32_t start = ++i, len;
        while (name[i] && name[i] != '-' && name[i] != '_') {
            if (name[i] > 0x7f || i - start >= OFN_NAME_MAX) return OFN_ERROR_INVALID_PARAMETER;
            ++i;
        }
        len = i - start;
        if (len == 0) return OFN_ERROR_INVALID_PARAMETER;
        if (len == 2 && !t->region[0] && is_alpha(name[start]) && is_alpha(name[start + 1])) {
            t->region[0] = (char)(lower_ascii(name[start]) - 32u);
            t->region[1] = (char)(lower_ascii(name[start + 1]) - 32u);
            t->region[2] = 0;
        } else {
            t->extra = 1;
        }
    }
    return OFN_OK;
}

static int tag_equal(const char *a, const char *b)
{
    while (*a && *b && lower_ascii((unsigned char)*a) == lower_ascii((unsigned char)*b)) { ++a; ++b; }
    return *a == 0 && *b == 0;
}

/* Choose one installed LCID for lang[-region]. Exact region if given,
 * else language only. Ties prefer the user LCID, the system LCID,
 * SUBLANG_DEFAULT (1), then the lowest LCID, deterministically. */
static uint32_t find_lcid(const struct ofn_backend *b, const struct ofn_tag *t, uint32_t *lcid)
{
    uint32_t list[OFN_MAX_LOCALES], count, i, best = 0, best_rank = 0, user, sys;
    count = b->enumerate(b->ctx, list, OFN_MAX_LOCALES);
    if (count == (uint32_t)-1) return OFN_ERROR_NOT_ENOUGH_MEMORY;
    if (count > OFN_MAX_LOCALES) return OFN_ERROR_INVALID_FUNCTION;
    user = b->user_lcid(b->ctx);
    sys = b->system_lcid(b->ctx);
    for (i = 0; i < count; ++i) {
        char tag[16], lang[4];
        uint32_t rank, j;
        if (lcid_tag(b, list[i], tag, sizeof tag) != OFN_OK) continue;
        for (j = 0; j < 3 && tag[j] && tag[j] != '-'; ++j) lang[j] = tag[j];
        lang[j] = 0;
        if (!tag_equal(lang, t->lang)) continue;
        if (t->region[0] && !(tag[j] == '-' && tag_equal(tag + j + 1, t->region))) continue;
        rank = list[i] == user ? 4u : list[i] == sys ? 3u : ((list[i] >> 10) & 0x3fu) == 1u ? 2u : 1u;
        if (rank > best_rank || (rank == best_rank && list[i] < best)) { best = list[i]; best_rank = rank; }
    }
    if (!best_rank) return OFN_ERROR_INVALID_PARAMETER;
    *lcid = best;
    return OFN_OK;
}

uint32_t ofn_lcid_to_name(const struct ofn_backend *b, uint32_t lcid, uint16_t *out, uint32_t cch, uint32_t *result)
{
    char tag[16];
    uint32_t err;
    if (!b || !result || (cch && !out)) return OFN_ERROR_INVALID_PARAMETER;
    err = lcid_tag(b, lcid, tag, sizeof tag);
    if (err) return err == OFN_ERROR_INVALID_FLAGS ? OFN_ERROR_INVALID_PARAMETER : err;
    return put_ascii(tag, out, cch, result);
}

static int is_sys_default(const uint16_t *name)
{
    uint32_t i;
    for (i = 0; sys_default_name[i]; ++i)
        if (lower_ascii(name[i]) != (unsigned char)sys_default_name[i]) return 0;
    return name[i] == 0;
}

/* NULL = user default; "!x-sys-default-locale" = system default. The
 * invariant locale ("") has no Windows 98 LCID and fails explicitly. */
static uint32_t name_lcid(const struct ofn_backend *b, const uint16_t *name, uint32_t *lcid)
{
    struct ofn_tag t;
    uint32_t err;
    if (!name) { *lcid = b->user_lcid(b->ctx); return *lcid ? OFN_OK : OFN_ERROR_NOT_SUPPORTED; }
    if (!name[0]) return OFN_ERROR_NOT_SUPPORTED;
    if (is_sys_default(name)) { *lcid = b->system_lcid(b->ctx); return *lcid ? OFN_OK : OFN_ERROR_NOT_SUPPORTED; }
    err = parse_tag(name, &t);
    if (err) return err;
    if (t.extra) return OFN_ERROR_INVALID_PARAMETER;
    return find_lcid(b, &t, lcid);
}

uint32_t ofn_name_to_lcid(const struct ofn_backend *b, const uint16_t *name, uint32_t *lcid)
{
    if (!b || !lcid) return OFN_ERROR_INVALID_PARAMETER;
    return name_lcid(b, name, lcid);
}

uint32_t ofn_resolve_locale_name(const struct ofn_backend *b, const uint16_t *name, uint16_t *out, uint32_t cch, uint32_t *result)
{
    struct ofn_tag t;
    uint32_t lcid, err;
    if (!b || !result || (cch && !out)) return OFN_ERROR_INVALID_PARAMETER;
    if (!name || !name[0] || is_sys_default(name)) {
        err = name_lcid(b, name, &lcid);
    } else {
        err = parse_tag(name, &t);
        if (err) return err;
        err = find_lcid(b, &t, &lcid);
        if (err == OFN_ERROR_INVALID_PARAMETER && t.region[0]) {   /* best match: same language */
            t.region[0] = 0;
            err = find_lcid(b, &t, &lcid);
        }
    }
    if (err) return err;
    return ofn_lcid_to_name(b, lcid, out, cch, result);
}

uint32_t ofn_user_default_locale_name(const struct ofn_backend *b, uint16_t *out, uint32_t cch, uint32_t *result)
{
    uint32_t lcid;
    if (!b || !result || (cch && !out)) return OFN_ERROR_INVALID_PARAMETER;
    lcid = b->user_lcid(b->ctx);
    if (!lcid) return OFN_ERROR_NOT_SUPPORTED;
    return ofn_lcid_to_name(b, lcid, out, cch, result);
}

/* LCTYPEs whose GetLocaleInfoA string is a plain decimal number. */
static int decimal_type(uint32_t type)
{
    static const uint32_t types[] = {
        0x0005u, 0x000Bu, 0x000Du, 0x0010u, 0x0011u, 0x0012u, 0x0014u, 0x0015u, 0x0019u, 0x001Bu, 0x001Cu,
        0x0021u, 0x0022u, 0x0023u, 0x1004u, 0x1009u, 0x100Au, 0x100Cu, 0x100Du, 0x1010u, 0x1011u, 0x1012u };
    uint32_t i;
    for (i = 0; i < sizeof types / sizeof types[0]; ++i)
        if (types[i] == type) return 1;
    return 0;
}

static uint32_t parse_number(const char *text, uint32_t base, uint32_t *value)
{
    uint32_t v = 0, digits = 0;
    for (; *text; ++text, ++digits) {
        unsigned c = lower_ascii((unsigned char)*text), d;
        if (c >= '0' && c <= '9') d = c - '0';
        else if (base == 16 && c >= 'a' && c <= 'f') d = c - 'a' + 10u;
        else return OFN_ERROR_INVALID_FLAGS;
        if (v > (0xffffffffu - d) / base) return OFN_ERROR_INVALID_FLAGS;
        v = v * base + d;
    }
    if (!digits) return OFN_ERROR_INVALID_FLAGS;
    *value = v;
    return OFN_OK;
}

uint32_t ofn_get_locale_info_ex(const struct ofn_backend *b, const uint16_t *name, uint32_t lctype,
                                uint16_t *out, uint32_t cch, uint32_t *result)
{
    char text[OFN_QUERY_MAX];
    uint32_t lcid, err, type = lctype & OFN_TYPE_MASK, pass = lctype & (LOCALE_NOUSEROVERRIDE_ | LOCALE_USE_CP_ACP_);
    uint32_t codepage = 0;
    int r, w;
    if (!b || !result || (cch && !out)) return OFN_ERROR_INVALID_PARAMETER;
    if (lctype & LOCALE_RETURN_GENITIVE_NAMES_) return OFN_ERROR_INVALID_FLAGS;
    err = name_lcid(b, name, &lcid);
    if (err) return err;
    if (type == LOCALE_SNAME_) {
        if (lctype & LOCALE_RETURN_NUMBER_) return OFN_ERROR_INVALID_FLAGS;
        return ofn_lcid_to_name(b, lcid, out, cch, result);
    }
    r = b->query(b->ctx, lcid, pass | type, text, (int)sizeof text);
    if (r <= 0) return query_error(r);
    if (r > (int)sizeof text || text[r - 1] != 0) return OFN_ERROR_INSUFFICIENT_BUFFER;
    if (lctype & LOCALE_RETURN_NUMBER_) {
        uint32_t value;
        if (type != LOCALE_ILANGUAGE_ && !decimal_type(type)) return OFN_ERROR_INVALID_FLAGS;
        err = parse_number(text, type == LOCALE_ILANGUAGE_ ? 16u : 10u, &value);
        if (err) return err;
        if (cch == 0) { *result = 2u; return OFN_OK; }
        if (cch < 2u) return OFN_ERROR_INSUFFICIENT_BUFFER;
        out[0] = (uint16_t)(value & 0xffffu);
        out[1] = (uint16_t)(value >> 16);
        *result = 2u;
        return OFN_OK;
    }
    /* GetLocaleInfoA strings use the locale's ANSI code page unless the
     * caller asked for the system ANSI code page (CP_ACP = 0). */
    if (!(lctype & LOCALE_USE_CP_ACP_)) {
        char cp[16];
        int c = b->query(b->ctx, lcid, LOCALE_NOUSEROVERRIDE_ | LOCALE_IDEFAULTANSICODEPAGE_, cp, (int)sizeof cp);
        if (c <= 0) return query_error(c);
        if (c > (int)sizeof cp || cp[c - 1] != 0 || parse_number(cp, 10u, &codepage)) return OFN_ERROR_NOT_SUPPORTED;
    }
    w = b->to_wide(b->ctx, codepage, text, r, 0, 0);
    if (w <= 0) return w < 0 ? (uint32_t)-w : OFN_ERROR_NOT_SUPPORTED;
    if (cch == 0) { *result = (uint32_t)w; return OFN_OK; }
    if (cch < (uint32_t)w) return OFN_ERROR_INSUFFICIENT_BUFFER;
    if (b->to_wide(b->ctx, codepage, text, r, out, (int)cch) != w) return OFN_ERROR_NOT_SUPPORTED;
    *result = (uint32_t)w;
    return OFN_OK;
}
