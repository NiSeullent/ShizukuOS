/* SPDX-License-Identifier: GPL-2.0-only
 * Sapphire private image model: bounded BMP/PNG probing and decoding into caller-owned 0x00RRGGBB pixels, BMP24 encoder.
 * No Win32 dependency, so the same code is host-checked and linked into the native app. PNG decoding is the vendored
 * LodePNG (src/vendor/lodepng, zlib licence), unmodified. */
#ifndef SAPPHIRE_IMG_H
#define SAPPHIRE_IMG_H
#include <stddef.h>
#include <stdint.h>

#define SAP_MAX_FILE   (32u * 1024u * 1024u)
#define SAP_MAX_DIM    8192u
#define SAP_MAX_PIXELS (8u * 1024u * 1024u)

enum sap_status {
    SAP_OK = 0,
    SAP_E_ARG,          /* null/empty input */
    SAP_E_TOO_BIG,      /* file or dimensions exceed the limits above */
    SAP_E_TRUNCATED,    /* headers or pixel data run past the file */
    SAP_E_FORMAT,       /* neither BMP nor PNG, or inconsistent header */
    SAP_E_UNSUPPORTED,  /* recognised but not decoded (RLE/16-bit/OS2 BMP, ...) */
    SAP_E_DECODE,       /* PNG decoder reported an error */
    SAP_E_NOMEM
};
enum sap_kind { SAP_NONE = 0, SAP_BMP, SAP_PNG };

typedef struct {
    enum sap_kind kind;
    uint32_t width, height;
    uint32_t bpp;               /* BMP bits per pixel; 0 for PNG */
    int bottom_up;              /* BMP row order */
    uint32_t data_off, stride;  /* BMP only */
    uint32_t pal_off, pal_n;    /* BMP 8bpp only */
} sap_info;

/* Validates every header field and size arithmetic in 64 bits BEFORE any pixel allocation. */
enum sap_status sap_probe(const uint8_t *data, size_t len, sap_info *info);
/* Decodes into dst (width*height dwords, row 0 = top, 0x00RRGGBB); dst_count must equal width*height from sap_probe. */
enum sap_status sap_decode(const uint8_t *data, size_t len, const sap_info *info, uint32_t *dst, size_t dst_count);
/* 24bpp bottom-up BMP. *out is allocated with sap_alloc and must be released with sap_free. */
enum sap_status sap_encode_bmp24(const uint32_t *px, uint32_t w, uint32_t h, uint8_t **out, size_t *out_len);
const char *sap_status_text(enum sap_status s);

void *sap_alloc(size_t n);
void sap_free(void *p);
#endif
