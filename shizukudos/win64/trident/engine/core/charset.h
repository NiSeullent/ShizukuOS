/* SPDX-License-Identifier: GPL-2.0-only
 *
 * ShizukuTrident Lite - character encodings (core): labels (WHATWG Encoding Standard names), BOM sniffing, the HTML
 * <meta> prescan, and streaming decoders for UTF-8, windows-1252 (which also serves iso-8859-1 and us-ascii, as the
 * Encoding Standard specifies), iso-8859-15, UTF-16LE and UTF-16BE.
 */
#ifndef SHZ_CHARSET_H
#define SHZ_CHARSET_H

#include "base.h"

typedef enum {
    SHZ_CS_NONE = -1,
    SHZ_CS_UTF8 = 0,
    SHZ_CS_WINDOWS_1252,
    SHZ_CS_ISO_8859_15,
    SHZ_CS_UTF16LE,
    SHZ_CS_UTF16BE
} shz_charset;

/* label -> encoding (surrounding whitespace ignored, case-insensitive); SHZ_CS_NONE when unknown */
shz_charset shz_charset_from_label(const shz_char *label, size_t n);
shz_charset shz_charset_from_label_ascii(const char *label, size_t n);
const char *shz_charset_name(shz_charset cs);      /* canonical name: "UTF-8", "windows-1252", ... */
/* BOM at the start of b: returns its length (0 = none) and sets *cs */
size_t      shz_charset_sniff_bom(const uint8_t *b, size_t n, shz_charset *cs);
/* HTML "prescan a byte stream to determine its encoding" over b[0..n) (callers pass at most 1024 bytes).
 * UTF-16 results become UTF-8 as the spec requires. SHZ_CS_NONE when nothing was found. */
shz_charset shz_charset_prescan(const uint8_t *b, size_t n);
/* windows-1252 mapping of a byte 0x80..0x9F (also the HTML numeric character reference replacement table) */
uint16_t    shz_cp1252_c1(uint8_t b);

typedef struct shz_decoder {
    shz_charset cs;
    uint32_t cp;                /* UTF-8: code point being assembled */
    uint8_t need, seen;         /* UTF-8: continuation bytes needed / seen */
    uint8_t lower, upper;       /* UTF-8: bounds for the next continuation byte */
    int pending;                /* UTF-16: a buffered first byte (-1 = none) */
    int lead;                   /* UTF-16: a buffered high surrogate (-1 = none) */
} shz_decoder;

void shz_decoder_init(shz_decoder *d, shz_charset cs);
/* Decode in[0..n) and append to out; flush = end of stream (incomplete sequences become U+FFFD). */
void shz_decode(shz_decoder *d, const uint8_t *in, size_t n, shz_buf *out, int flush);

#endif /* SHZ_CHARSET_H */
