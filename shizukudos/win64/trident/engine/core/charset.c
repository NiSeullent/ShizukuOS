/* SPDX-License-Identifier: GPL-2.0-only
 *
 * ShizukuTrident Lite - character encodings (see charset.h). Decoder behaviour follows the WHATWG Encoding Standard
 * (UTF-8 decoder with maximal-subpart U+FFFD replacement; single-byte index for windows-1252; UTF-16 surrogates).
 */
#include "charset.h"

static const uint16_t cp1252_c1[32] = {
    0x20AC, 0x0081, 0x201A, 0x0192, 0x201E, 0x2026, 0x2020, 0x2021, 0x02C6, 0x2030, 0x0160, 0x2039, 0x0152, 0x008D,
    0x017D, 0x008F, 0x0090, 0x2018, 0x2019, 0x201C, 0x201D, 0x2022, 0x2013, 0x2014, 0x02DC, 0x2122, 0x0161, 0x203A,
    0x0153, 0x009D, 0x017E, 0x0178
};

uint16_t shz_cp1252_c1(uint8_t b)
{
    return b >= 0x80 && b <= 0x9F ? cp1252_c1[b - 0x80] : b;
}

static uint16_t iso8859_15(uint8_t b)
{
    switch (b) {
    case 0xA4: return 0x20AC;
    case 0xA6: return 0x0160;
    case 0xA8: return 0x0161;
    case 0xB4: return 0x017D;
    case 0xB8: return 0x017E;
    case 0xBC: return 0x0152;
    case 0xBD: return 0x0153;
    case 0xBE: return 0x0178;
    default: return b;
    }
}

static const struct { const char *label; shz_charset cs; } labels[] = {
    { "unicode-1-1-utf-8", SHZ_CS_UTF8 }, { "unicode11utf8", SHZ_CS_UTF8 }, { "unicode20utf8", SHZ_CS_UTF8 },
    { "utf-8", SHZ_CS_UTF8 }, { "utf8", SHZ_CS_UTF8 }, { "x-unicode20utf8", SHZ_CS_UTF8 },
    { "ansi_x3.4-1968", SHZ_CS_WINDOWS_1252 }, { "ascii", SHZ_CS_WINDOWS_1252 }, { "cp1252", SHZ_CS_WINDOWS_1252 },
    { "cp819", SHZ_CS_WINDOWS_1252 }, { "csisolatin1", SHZ_CS_WINDOWS_1252 }, { "ibm819", SHZ_CS_WINDOWS_1252 },
    { "iso-8859-1", SHZ_CS_WINDOWS_1252 }, { "iso-ir-100", SHZ_CS_WINDOWS_1252 }, { "iso8859-1", SHZ_CS_WINDOWS_1252 },
    { "iso88591", SHZ_CS_WINDOWS_1252 }, { "iso_8859-1", SHZ_CS_WINDOWS_1252 },
    { "iso_8859-1:1987", SHZ_CS_WINDOWS_1252 }, { "l1", SHZ_CS_WINDOWS_1252 }, { "latin1", SHZ_CS_WINDOWS_1252 },
    { "us-ascii", SHZ_CS_WINDOWS_1252 }, { "windows-1252", SHZ_CS_WINDOWS_1252 }, { "x-cp1252", SHZ_CS_WINDOWS_1252 },
    { "csisolatin9", SHZ_CS_ISO_8859_15 }, { "iso-8859-15", SHZ_CS_ISO_8859_15 }, { "iso8859-15", SHZ_CS_ISO_8859_15 },
    { "iso885915", SHZ_CS_ISO_8859_15 }, { "iso_8859-15", SHZ_CS_ISO_8859_15 }, { "l9", SHZ_CS_ISO_8859_15 },
    { "csunicode", SHZ_CS_UTF16LE }, { "iso-10646-ucs-2", SHZ_CS_UTF16LE }, { "ucs-2", SHZ_CS_UTF16LE },
    { "unicode", SHZ_CS_UTF16LE }, { "unicodefeff", SHZ_CS_UTF16LE }, { "utf-16", SHZ_CS_UTF16LE },
    { "utf-16le", SHZ_CS_UTF16LE }, { "unicodefffe", SHZ_CS_UTF16BE }, { "utf-16be", SHZ_CS_UTF16BE },
};

shz_charset shz_charset_from_label(const shz_char *label, size_t n)
{
    size_t i;
    if (!label) return SHZ_CS_NONE;
    label = shz_trim(label, &n);
    for (i = 0; i < SHZ_ARRAY_SIZE(labels); ++i)
        if (shz_strnieq_ascii(label, n, labels[i].label)) return labels[i].cs;
    return SHZ_CS_NONE;
}

shz_charset shz_charset_from_label_ascii(const char *label, size_t n)
{
    shz_char buf[64];
    size_t i;
    if (n >= SHZ_ARRAY_SIZE(buf)) return SHZ_CS_NONE;
    for (i = 0; i < n; ++i) buf[i] = (unsigned char)label[i];
    return shz_charset_from_label(buf, n);
}

const char *shz_charset_name(shz_charset cs)
{
    switch (cs) {
    case SHZ_CS_UTF8: return "UTF-8";
    case SHZ_CS_WINDOWS_1252: return "windows-1252";
    case SHZ_CS_ISO_8859_15: return "ISO-8859-15";
    case SHZ_CS_UTF16LE: return "UTF-16LE";
    case SHZ_CS_UTF16BE: return "UTF-16BE";
    default: return "";
    }
}

size_t shz_charset_sniff_bom(const uint8_t *b, size_t n, shz_charset *cs)
{
    if (n >= 3 && b[0] == 0xEF && b[1] == 0xBB && b[2] == 0xBF) { *cs = SHZ_CS_UTF8; return 3; }
    if (n >= 2 && b[0] == 0xFE && b[1] == 0xFF) { *cs = SHZ_CS_UTF16BE; return 2; }
    if (n >= 2 && b[0] == 0xFF && b[1] == 0xFE) { *cs = SHZ_CS_UTF16LE; return 2; }
    return 0;
}

/* ---------------------------------------------------------------------------------------------------- prescan */

static int is_ws_byte(uint8_t c)
{
    return c == 0x09 || c == 0x0A || c == 0x0C || c == 0x0D || c == 0x20;
}

static uint8_t lower_byte(uint8_t c)
{
    return c >= 'A' && c <= 'Z' ? (uint8_t)(c + 32) : c;
}

static int bytes_ieq(const uint8_t *b, size_t n, const char *s)
{
    size_t i;
    for (i = 0; i < n; ++i)
        if (!s[i] || lower_byte(b[i]) != (uint8_t)s[i]) return 0;
    return s[n] == 0;
}

/* HTML "get an attribute": returns 0 when there is none (stops at '>') */
static int get_attr(const uint8_t *b, size_t n, size_t *pos, size_t *ns, size_t *nl, size_t *vs, size_t *vl)
{
    size_t i = *pos;
    while (i < n && (is_ws_byte(b[i]) || b[i] == '/')) ++i;
    if (i >= n || b[i] == '>') { *pos = i; return 0; }
    *ns = i;
    if (b[i] == '=') ++i;               /* an attribute name may start with '=' */
    while (i < n && b[i] != '=' && !is_ws_byte(b[i]) && b[i] != '/' && b[i] != '>') ++i;
    *nl = i - *ns;
    while (i < n && is_ws_byte(b[i])) ++i;
    *vs = i;
    *vl = 0;
    if (i >= n || b[i] != '=') { *pos = i; return 1; }
    ++i;
    while (i < n && is_ws_byte(b[i])) ++i;
    if (i < n && (b[i] == '"' || b[i] == '\'')) {
        uint8_t q = b[i++];
        *vs = i;
        while (i < n && b[i] != q) ++i;
        *vl = i - *vs;
        if (i < n) ++i;
    } else {
        *vs = i;
        while (i < n && !is_ws_byte(b[i]) && b[i] != '>') ++i;
        *vl = i - *vs;
    }
    *pos = i;
    return 1;
}

/* "extract a character encoding from a meta element" over a content attribute value */
static shz_charset from_content(const uint8_t *b, size_t n)
{
    size_t i = 0;
    for (;;) {
        size_t s;
        while (i + 7 <= n && !bytes_ieq(b + i, 7, "charset")) ++i;
        if (i + 7 > n) return SHZ_CS_NONE;
        i += 7;
        while (i < n && is_ws_byte(b[i])) ++i;
        if (i >= n || b[i] != '=') continue;
        ++i;
        while (i < n && is_ws_byte(b[i])) ++i;
        if (i >= n) return SHZ_CS_NONE;
        if (b[i] == '"' || b[i] == '\'') {
            uint8_t q = b[i++];
            s = i;
            while (i < n && b[i] != q) ++i;
            if (i >= n) return SHZ_CS_NONE;
            return shz_charset_from_label_ascii((const char *)b + s, i - s);
        }
        s = i;
        while (i < n && !is_ws_byte(b[i]) && b[i] != ';') ++i;
        return shz_charset_from_label_ascii((const char *)b + s, i - s);
    }
}

shz_charset shz_charset_prescan(const uint8_t *b, size_t n)
{
    size_t i = 0;
    while (i < n) {
        if (i + 4 <= n && b[i] == '<' && b[i + 1] == '!' && b[i + 2] == '-' && b[i + 3] == '-') {
            i += 2;                     /* the "-->" may overlap the "<!--" (e.g. "<!-->") */
            while (i + 3 <= n && !(b[i] == '-' && b[i + 1] == '-' && b[i + 2] == '>')) ++i;
            i += 3;
            continue;
        }
        if (i + 6 <= n && b[i] == '<' && bytes_ieq(b + i + 1, 4, "meta") && (is_ws_byte(b[i + 5]) || b[i + 5] == '/')) {
            size_t pos = i + 6, ns, nl, vs, vl;
            int got_pragma = 0, need_pragma = -1, seen_he = 0, seen_ct = 0, seen_cs = 0;
            shz_charset cs = SHZ_CS_NONE;
            while (get_attr(b, n, &pos, &ns, &nl, &vs, &vl)) {
                if (bytes_ieq(b + ns, nl, "http-equiv")) {
                    if (seen_he) continue;
                    seen_he = 1;
                    if (bytes_ieq(b + vs, vl, "content-type")) got_pragma = 1;
                } else if (bytes_ieq(b + ns, nl, "content")) {
                    if (seen_ct) continue;
                    seen_ct = 1;
                    if (cs == SHZ_CS_NONE) {
                        cs = from_content(b + vs, vl);
                        if (cs != SHZ_CS_NONE) need_pragma = 1;
                    }
                } else if (bytes_ieq(b + ns, nl, "charset")) {
                    if (seen_cs) continue;
                    seen_cs = 1;
                    cs = shz_charset_from_label_ascii((const char *)b + vs, vl);
                    need_pragma = 0;
                }
            }
            i = pos;
            if (need_pragma == -1 || (need_pragma == 1 && !got_pragma) || cs == SHZ_CS_NONE) continue;
            if (cs == SHZ_CS_UTF16LE || cs == SHZ_CS_UTF16BE) cs = SHZ_CS_UTF8;
            return cs;
        }
        if (i + 2 <= n && b[i] == '<' && (((b[i + 1] | 0x20) >= 'a' && (b[i + 1] | 0x20) <= 'z')
                                          || (b[i + 1] == '/' && i + 2 < n && (b[i + 2] | 0x20) >= 'a'
                                              && (b[i + 2] | 0x20) <= 'z'))) {
            size_t pos = i + 2, ns, nl, vs, vl;
            while (pos < n && !is_ws_byte(b[pos]) && b[pos] != '>') ++pos;
            while (get_attr(b, n, &pos, &ns, &nl, &vs, &vl)) {}
            i = pos + 1;
            continue;
        }
        if (i + 2 <= n && b[i] == '<' && (b[i + 1] == '!' || b[i + 1] == '/' || b[i + 1] == '?')) {
            while (i < n && b[i] != '>') ++i;
            ++i;
            continue;
        }
        ++i;
    }
    return SHZ_CS_NONE;
}

/* ---------------------------------------------------------------------------------------------------- decoding */

void shz_decoder_init(shz_decoder *d, shz_charset cs)
{
    memset(d, 0, sizeof(*d));
    d->cs = cs == SHZ_CS_NONE ? SHZ_CS_UTF8 : cs;
    d->lower = 0x80;
    d->upper = 0xBF;
    d->pending = -1;
    d->lead = -1;
}

static void utf8_decode(shz_decoder *d, const uint8_t *in, size_t n, shz_buf *out, int flush)
{
    size_t i = 0;
    while (i < n) {
        uint8_t b = in[i];
        if (!d->need) {
            if (b < 0x80) {
                /* fast path for ASCII runs */
                size_t j = i;
                while (j < n && in[j] < 0x80) ++j;
                if (shz_buf_reserve(out, j - i)) {
                    while (i < j) out->s[out->len++] = in[i++];
                } else {
                    i = j;
                }
                continue;
            }
            if (b >= 0xC2 && b <= 0xDF) { d->need = 1; d->cp = b & 0x1F; }
            else if (b >= 0xE0 && b <= 0xEF) {
                if (b == 0xE0) d->lower = 0xA0;
                if (b == 0xED) d->upper = 0x9F;
                d->need = 2; d->cp = b & 0x0F;
            } else if (b >= 0xF0 && b <= 0xF4) {
                if (b == 0xF0) d->lower = 0x90;
                if (b == 0xF4) d->upper = 0x8F;
                d->need = 3; d->cp = b & 0x07;
            } else {
                shz_buf_putc(out, 0xFFFD);
            }
            ++i;
            continue;
        }
        if (b < d->lower || b > d->upper) {
            /* invalid continuation: emit U+FFFD for the incomplete sequence and reprocess b */
            d->need = d->seen = 0;
            d->cp = 0;
            d->lower = 0x80; d->upper = 0xBF;
            shz_buf_putc(out, 0xFFFD);
            continue;
        }
        d->lower = 0x80; d->upper = 0xBF;
        d->cp = (d->cp << 6) | (b & 0x3F);
        ++i;
        if (++d->seen == d->need) {
            shz_buf_put_cp(out, d->cp);
            d->need = d->seen = 0;
            d->cp = 0;
        }
    }
    if (flush && d->need) {
        d->need = d->seen = 0;
        d->cp = 0;
        d->lower = 0x80; d->upper = 0xBF;
        shz_buf_putc(out, 0xFFFD);
    }
}

static void utf16_unit(shz_decoder *d, uint32_t u, shz_buf *out)
{
    if (d->lead >= 0) {
        if (shz_is_low_surrogate(u)) {
            shz_buf_putc(out, (shz_char)d->lead);
            shz_buf_putc(out, (shz_char)u);
            d->lead = -1;
            return;
        }
        shz_buf_putc(out, 0xFFFD);
        d->lead = -1;
    }
    if (shz_is_high_surrogate(u)) d->lead = (int)u;
    else if (shz_is_low_surrogate(u)) shz_buf_putc(out, 0xFFFD);
    else shz_buf_putc(out, (shz_char)u);
}

void shz_decode(shz_decoder *d, const uint8_t *in, size_t n, shz_buf *out, int flush)
{
    size_t i;
    switch (d->cs) {
    case SHZ_CS_UTF8:
    default:
        utf8_decode(d, in, n, out, flush);
        break;
    case SHZ_CS_WINDOWS_1252:
        if (!shz_buf_reserve(out, n)) return;
        for (i = 0; i < n; ++i) out->s[out->len++] = shz_cp1252_c1(in[i]);
        break;
    case SHZ_CS_ISO_8859_15:
        if (!shz_buf_reserve(out, n)) return;
        for (i = 0; i < n; ++i) out->s[out->len++] = iso8859_15(in[i]);
        break;
    case SHZ_CS_UTF16LE:
    case SHZ_CS_UTF16BE:
        for (i = 0; i < n; ++i) {
            if (d->pending < 0) { d->pending = in[i]; continue; }
            if (d->cs == SHZ_CS_UTF16LE) utf16_unit(d, (uint32_t)d->pending | ((uint32_t)in[i] << 8), out);
            else utf16_unit(d, ((uint32_t)d->pending << 8) | in[i], out);
            d->pending = -1;
        }
        if (flush) {
            if (d->pending >= 0 || d->lead >= 0) shz_buf_putc(out, 0xFFFD);
            d->pending = d->lead = -1;
        }
        break;
    }
}
