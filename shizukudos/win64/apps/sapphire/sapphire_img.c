/* SPDX-License-Identifier: GPL-2.0-only
 * Sapphire image model implementation. See sapphire_img.h. */
#include "sapphire_img.h"
/* vendored, unmodified; same feature flags as sapphire_png.c / the Trident engine build (decoder only) */
#define LODEPNG_NO_COMPILE_ALLOCATORS
#define LODEPNG_NO_COMPILE_DISK
#define LODEPNG_NO_COMPILE_CPP
#define LODEPNG_NO_COMPILE_ENCODER
#define LODEPNG_NO_COMPILE_ERROR_TEXT
#include "../../../../src/vendor/lodepng/lodepng.h"
void lodepng_free(void *ptr);   /* declared by lodepng.h only when it also compiles the allocators */

#ifdef SAPPHIRE_HOST
#include <stdlib.h>
#include <string.h>
void *sap_alloc(size_t n) { return malloc(n); }
void sap_free(void *p) { free(p); }
#else
void *shz_malloc(size_t n);
void shz_free(void *p);
void *memcpy(void *d, const void *s, size_t n);
void *memset(void *d, int c, size_t n);
void *sap_alloc(size_t n) { return shz_malloc(n); }
void sap_free(void *p) { shz_free(p); }
#endif

static uint32_t rd16(const uint8_t *p) { return (uint32_t)p[0] | (uint32_t)p[1] << 8; }
static uint32_t rd32(const uint8_t *p) { return rd16(p) | rd16(p + 2) << 16; }
static uint32_t be32(const uint8_t *p) { return (uint32_t)p[0] << 24 | (uint32_t)p[1] << 16 | (uint32_t)p[2] << 8 | p[3]; }

const char *sap_status_text(enum sap_status s)
{
    switch (s) {
    case SAP_OK: return "ok";
    case SAP_E_ARG: return "empty file";
    case SAP_E_TOO_BIG: return "image or file too large";
    case SAP_E_TRUNCATED: return "file is truncated";
    case SAP_E_FORMAT: return "not a valid BMP or PNG";
    case SAP_E_UNSUPPORTED: return "unsupported image variant";
    case SAP_E_DECODE: return "PNG data is corrupt";
    case SAP_E_NOMEM: return "out of memory";
    }
    return "error";
}

static enum sap_status check_dims(uint64_t w, uint64_t h)
{
    if (!w || !h) return SAP_E_FORMAT;
    if (w > SAP_MAX_DIM || h > SAP_MAX_DIM || w * h > SAP_MAX_PIXELS) return SAP_E_TOO_BIG;
    return SAP_OK;
}

static enum sap_status probe_png(const uint8_t *d, size_t len, sap_info *i)
{
    static const uint8_t sig[8] = {0x89, 'P', 'N', 'G', 0x0d, 0x0a, 0x1a, 0x0a};
    enum sap_status s;
    uint32_t w, h;
    unsigned k;
    if (len < 33) return SAP_E_TRUNCATED;
    for (k = 0; k < 8; ++k) if (d[k] != sig[k]) return SAP_E_FORMAT;
    if (be32(d + 8) != 13 || d[12] != 'I' || d[13] != 'H' || d[14] != 'D' || d[15] != 'R') return SAP_E_FORMAT;
    w = be32(d + 16); h = be32(d + 20);
    if ((s = check_dims(w, h)) != SAP_OK) return s;
    i->kind = SAP_PNG; i->width = w; i->height = h;
    return SAP_OK;
}

static enum sap_status probe_bmp(const uint8_t *d, size_t len, sap_info *i)
{
    uint32_t hs, off, bpp, comp, used;
    int32_t w, h;
    uint64_t stride, need, hdr_end;
    enum sap_status s;
    if (len < 14 + 40) return SAP_E_TRUNCATED;
    off = rd32(d + 10); hs = rd32(d + 14);
    if (hs == 12 || hs == 64) return SAP_E_UNSUPPORTED;                       /* OS/2 core headers */
    if (hs != 40 && hs != 52 && hs != 56 && hs != 108 && hs != 124) return SAP_E_FORMAT;
    if (len < 14u + hs) return SAP_E_TRUNCATED;
    w = (int32_t)rd32(d + 18); h = (int32_t)rd32(d + 22);
    if (rd16(d + 26) != 1) return SAP_E_FORMAT;
    bpp = rd16(d + 28); comp = rd32(d + 30); used = rd32(d + 46);
    if (w <= 0 || h == 0 || h == INT32_MIN) return SAP_E_FORMAT;
    if ((s = check_dims((uint64_t)w, h < 0 ? (uint64_t)(-(int64_t)h) : (uint64_t)h)) != SAP_OK) return s;
    if (comp == 0 && (bpp == 24 || bpp == 32 || bpp == 8)) { /* BI_RGB */ }
    else if (comp == 3 && bpp == 32 && hs >= 52 && len >= 14u + 40u + 12u) {   /* BI_BITFIELDS: only the standard XRGB layout */
        if (rd32(d + 54) != 0x00ff0000u || rd32(d + 58) != 0x0000ff00u || rd32(d + 62) != 0x000000ffu) return SAP_E_UNSUPPORTED;
    } else return SAP_E_UNSUPPORTED;                                          /* RLE, 1/4/16-bit, JPEG/PNG-in-BMP ... */
    i->kind = SAP_BMP; i->width = (uint32_t)w; i->bpp = bpp; i->bottom_up = h > 0;
    i->height = (uint32_t)(h < 0 ? -(int64_t)h : (int64_t)h);
    stride = (((uint64_t)w * bpp + 31) / 32) * 4;
    hdr_end = 14u + hs;
    i->pal_off = (uint32_t)hdr_end; i->pal_n = 0;
    if (bpp == 8) {
        uint64_t n = used ? used : 256;
        if (n > 256) return SAP_E_FORMAT;
        i->pal_n = (uint32_t)n;
        if (hdr_end + n * 4 > len) return SAP_E_TRUNCATED;
        hdr_end += n * 4;
    } else if (comp == 3 && hs == 40) hdr_end += 12;
    if (off < hdr_end || off > len) return off > len ? SAP_E_TRUNCATED : SAP_E_FORMAT;
    need = (uint64_t)off + stride * i->height;
    if (need > len) return SAP_E_TRUNCATED;
    i->data_off = off; i->stride = (uint32_t)stride;
    return SAP_OK;
}

enum sap_status sap_probe(const uint8_t *data, size_t len, sap_info *info)
{
    if (!data || !len || !info) return SAP_E_ARG;
    memset(info, 0, sizeof *info);
    if (len > SAP_MAX_FILE) return SAP_E_TOO_BIG;
    if (len >= 2 && data[0] == 'B' && data[1] == 'M') return probe_bmp(data, len, info);
    if (len >= 8 && data[0] == 0x89 && data[1] == 'P') return probe_png(data, len, info);
    return SAP_E_FORMAT;
}

enum sap_status sap_decode(const uint8_t *data, size_t len, const sap_info *info, uint32_t *dst, size_t dst_count)
{
    uint32_t x, y;
    if (!data || !info || !dst || info->kind == SAP_NONE) return SAP_E_ARG;
    if ((uint64_t)info->width * info->height != dst_count) return SAP_E_ARG;
    if (info->kind == SAP_PNG) {
        unsigned char *rgba = 0;
        unsigned w = 0, h = 0, err;
        LodePNGState state;
        uint64_t limit;
        size_t n, k;
        if (check_dims(info->width, info->height) != SAP_OK) return SAP_E_TOO_BIG;
        /* At most 64 bits per pixel, plus one filter byte per row in each
         * of seven Adam7 passes. This bounds malformed IDAT expansion too. */
        limit = (uint64_t)info->width * info->height * 8u + (uint64_t)info->height * 7u;
        if (limit > SIZE_MAX) return SAP_E_TOO_BIG;
        lodepng_state_init(&state);
        state.info_raw.colortype = LCT_RGBA;
        state.info_raw.bitdepth = 8;
        /* The viewer does not consume text metadata; repeated compressed
         * text chunks must not accumulate decoded allocations. */
        state.decoder.read_text_chunks = 0;
        state.decoder.zlibsettings.max_output_size = (size_t)limit;
        err = lodepng_decode(&rgba, &w, &h, &state, data, len);
        lodepng_state_cleanup(&state);
        if (err || !rgba) { if (rgba) lodepng_free(rgba); return err == 83 ? SAP_E_NOMEM : SAP_E_DECODE; }
        if (w != info->width || h != info->height) { lodepng_free(rgba); return SAP_E_DECODE; }
        n = (size_t)w * h;
        for (k = 0; k < n; ++k) {                   /* composite over white so transparent PNG pixels stay visible */
            const unsigned char *p = rgba + k * 4;
            unsigned a = p[3];
            unsigned r = (p[0] * a + 255u * (255u - a) + 127u) / 255u;
            unsigned g = (p[1] * a + 255u * (255u - a) + 127u) / 255u;
            unsigned b = (p[2] * a + 255u * (255u - a) + 127u) / 255u;
            dst[k] = r << 16 | g << 8 | b;
        }
        lodepng_free(rgba);
        return SAP_OK;
    }
    for (y = 0; y < info->height; ++y) {
        const uint8_t *row = data + info->data_off + (size_t)(info->bottom_up ? info->height - 1 - y : y) * info->stride;
        uint32_t *out = dst + (size_t)y * info->width;
        for (x = 0; x < info->width; ++x) {
            if (info->bpp == 24) out[x] = (uint32_t)row[x * 3 + 2] << 16 | (uint32_t)row[x * 3 + 1] << 8 | row[x * 3];
            else if (info->bpp == 32) out[x] = rd32(row + x * 4) & 0x00ffffffu;
            else {
                uint32_t idx = row[x];
                if (idx >= info->pal_n) return SAP_E_FORMAT;               /* index outside the declared palette */
                out[x] = rd32(data + info->pal_off + idx * 4) & 0x00ffffffu;
            }
        }
    }
    return SAP_OK;
}

static void wr32(uint8_t *p, uint32_t v) { p[0] = (uint8_t)v; p[1] = (uint8_t)(v >> 8); p[2] = (uint8_t)(v >> 16); p[3] = (uint8_t)(v >> 24); }

enum sap_status sap_encode_bmp24(const uint32_t *px, uint32_t w, uint32_t h, uint8_t **out, size_t *out_len)
{
    uint64_t stride, total;
    uint8_t *b;
    uint32_t x, y;
    enum sap_status s;
    if (!px || !out || !out_len) return SAP_E_ARG;
    *out = 0; *out_len = 0;
    if ((s = check_dims(w, h)) != SAP_OK) return s;
    stride = ((uint64_t)w * 3 + 3) & ~3ull;
    total = 54 + stride * h;
    if (total > SAP_MAX_FILE * 4ull) return SAP_E_TOO_BIG;
    b = (uint8_t *)sap_alloc((size_t)total);
    if (!b) return SAP_E_NOMEM;
    memset(b, 0, (size_t)total);
    b[0] = 'B'; b[1] = 'M'; wr32(b + 2, (uint32_t)total); wr32(b + 10, 54); wr32(b + 14, 40);
    wr32(b + 18, w); wr32(b + 22, h); b[26] = 1; b[28] = 24; wr32(b + 34, (uint32_t)(stride * h));
    for (y = 0; y < h; ++y) {
        uint8_t *row = b + 54 + (size_t)(h - 1 - y) * stride;
        for (x = 0; x < w; ++x) {
            uint32_t c = px[(size_t)y * w + x];
            row[x * 3] = (uint8_t)c; row[x * 3 + 1] = (uint8_t)(c >> 8); row[x * 3 + 2] = (uint8_t)(c >> 16);
        }
    }
    *out = b; *out_len = (size_t)total;
    return SAP_OK;
}
