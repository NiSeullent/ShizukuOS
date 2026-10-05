/* SPDX-License-Identifier: GPL-2.0-only
 * Installed driver catalog v2 importer (routing02 contract C5; types in drivers/common/shz_catalog.h).
 *
 * Pure part (compiled by the kernel and by drivers/common/tests/test_shz_catalog.c with -DSHZ_CATALOG_HOST): a bounded
 * strict parser over a byte buffer. It allocates nothing, follows no path and calls back only for service rows of a
 * file whose header and summary validated, after the image hash callback succeeded.
 *
 * Kernel64 glue: reads <system volume>:\SHZ\DRIVERS\CATALOG.INI (sfsk_system_volume + fs.c, <= 16 KiB), verifies
 * every service image with the kernel SHA-256 (accounts/sha256.c, linked through auth_core.c), matches builtin rows
 * against the drivers linked into Kernel64 (never registering a service for them) and, for validated service rows,
 * writes the Services\<svc> + Enum\PCI\VEN_v&DEV_d\BbbDddFf records shzpnp add-driver --install writes, only for present
 * PCI functions no native driver claimed or matches. ntdrv_pnp.c bring-up then loads those services through the
 * existing NtLoadDriver core. No physical range, IRQ, DMA or port is granted here.
 */
#ifdef SHZ_CATALOG_HOST
#include <stddef.h>
#include <stdint.h>
#else
#include "k64.h"
#include "fs.h"
#include "pci.h"
#include "registry.h"
#include "sfs_mount.h"
#include "ntdrv.h"
#include "../accounts/sha256.h"
#if defined(__has_include)
#if __has_include("install_identity.h")
#include "install_identity.h"
#define NTDRV_HAVE_INSTALL_IDENTITY 1
#endif
#endif
#endif
#include "../../drivers/common/shz_bringup.h"
#include "../../drivers/common/shz_catalog.h"

/* ================================================================ pure parser */
enum { K_PACKAGE = 1, K_KIND = 2, K_MATCH = 4, K_SERVICE = 8, K_IMAGE = 16, K_IMAGESHA = 32, K_START = 64, K_PATH = 128,
       K_BYTES = 256, K_SHA = 512 };
enum { H_SCHEMA = 1, H_SELECTION = 2, H_GENERATION = 4, H_KERNEL = 8, H_ALL = 15 };

static void cat_zero(void *p, size_t n) { unsigned char *b = p; while (n--) *b++ = 0; }
static int cat_eq(const char *a, unsigned n, const char *lit)
{
    unsigned i;
    for (i = 0; i < n; ++i) if (!lit[i] || a[i] != lit[i]) return 0;
    return lit[n] == 0;
}
static char cat_up(char c) { return c >= 'a' && c <= 'z' ? (char)(c - 32) : c; }
static int cat_ieq_prefix(const char *a, unsigned n, const char *lit)
{
    unsigned i;
    for (i = 0; lit[i]; ++i) if (i >= n || cat_up(a[i]) != cat_up(lit[i])) return 0;
    return 1;
}
static int cat_hexd(char c)
{
    if (c >= '0' && c <= '9') return c - '0';
    if (c >= 'a' && c <= 'f') return c - 'a' + 10;
    if (c >= 'A' && c <= 'F') return c - 'A' + 10;
    return -1;
}
static int cat_hexn(const char *v, unsigned n, uint32_t *out)
{
    unsigned i;
    uint32_t x = 0;
    for (i = 0; i < n; ++i) { int d = cat_hexd(v[i]); if (d < 0) return 0; x = x << 4 | (uint32_t)d; }
    *out = x;
    return 1;
}
static int cat_sha(const char *v, unsigned n, uint8_t out[32])
{
    unsigned i;
    if (n != 64) return 0;
    for (i = 0; i < 32; ++i) {
        const int a = cat_hexd(v[2 * i]), b = cat_hexd(v[2 * i + 1]);
        if (a < 0 || b < 0) return 0;
        out[i] = (uint8_t)(a << 4 | b);
    }
    return 1;
}
static int cat_dec(const char *v, unsigned n, uint64_t *out)
{
    unsigned i;
    uint64_t x = 0;
    if (!n || n > 20 || (n > 1 && v[0] == '0')) return 0;
    for (i = 0; i < n; ++i) {
        if (v[i] < '0' || v[i] > '9') return 0;
        if (x > (UINT64_MAX - (uint64_t)(v[i] - '0')) / 10) return 0;
        x = x * 10 + (uint64_t)(v[i] - '0');
    }
    *out = x;
    return 1;
}
static int cat_name_char(char c, int dot_dash)
{
    return (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9') || c == '_' ||
           (dot_dash && (c == '.' || c == '-'));
}
static int cat_copy(char *dst, unsigned cap, const char *v, unsigned n)
{
    unsigned i;
    if (n >= cap) return 0;
    for (i = 0; i < n; ++i) dst[i] = v[i];
    dst[n] = 0;
    return 1;
}
static int cat_sha_eq(const uint8_t *a, const uint8_t *b)
{
    unsigned i, d = 0;
    for (i = 0; i < 32; ++i) d |= (unsigned)(a[i] ^ b[i]);
    return d == 0;
}

/* "vvvv:dddd" | "vvvv:dddd-dddd" | "class cc:ss" | "class cc:ss:pp" */
static int cat_match_item(const char *v, unsigned n, shz_cat_match_t *m)
{
    uint32_t a, b, c;
    cat_zero(m, sizeof *m);
    if (n > 6 && cat_eq(v, 6, "class ")) {
        v += 6; n -= 6;
        if ((n != 5 && n != 8) || v[2] != ':' || !cat_hexn(v, 2, &a) || !cat_hexn(v + 3, 2, &b)) return 0;
        m->type = SHZ_CAT_MATCH_CLASS; m->class_code = (uint8_t)a; m->subclass = (uint8_t)b;
        if (n == 8) {
            if (v[5] != ':' || !cat_hexn(v + 6, 2, &c)) return 0;
            m->has_prog_if = 1; m->prog_if = (uint8_t)c;
        }
        return 1;
    }
    if ((n != 9 && n != 14) || v[4] != ':' || !cat_hexn(v, 4, &a) || !cat_hexn(v + 5, 4, &b)) return 0;
    c = b;
    if (n == 14 && (v[9] != '-' || !cat_hexn(v + 10, 4, &c) || c < b)) return 0;
    if (a == 0xffff || a == 0) return 0;
    m->type = SHZ_CAT_MATCH_ID; m->vendor = (uint16_t)a; m->device_lo = (uint16_t)b; m->device_hi = (uint16_t)c;
    return 1;
}
static int cat_match_list(const char *v, unsigned n, shz_cat_row_t *r)
{
    unsigned i = 0;
    r->nmatch = 0;
    while (i < n) {
        unsigned s = i, e;
        while (s < n && v[s] == ' ') ++s;
        e = s;
        while (e < n && v[e] != ',') ++e;
        i = e + 1;
        while (e > s && v[e - 1] == ' ') --e;
        if (e == s || r->nmatch >= SHZ_CAT_MAX_MATCH || !cat_match_item(v + s, e - s, &r->match[r->nmatch])) return 0;
        ++r->nmatch;
        if (i == n) return 0;                       /* trailing comma */
    }
    return r->nmatch != 0;
}
/* \SHZ\DRIVERS\<components>\X.SYS: [A-Za-z0-9_.-] components, no empty / "." / ".." component, <= 127 bytes */
static int cat_image(const char *v, unsigned n)
{
    unsigned i, seg = 0;
    if (n >= 128 || n < 18 || !cat_ieq_prefix(v, n, "\\SHZ\\DRIVERS\\") || !cat_ieq_prefix(v + n - 4, 4, ".SYS")) return 0;
    for (i = 12; i <= n; ++i) {
        if (i == n || v[i] == '\\') {
            const unsigned len = i - seg - 1;
            if (!len || (len == 1 && v[seg + 1] == '.') || (len == 2 && v[seg + 1] == '.' && v[seg + 2] == '.')) return 0;
            seg = i;
        } else if (!cat_name_char(v[i], 1)) return 0;
    }
    return 1;
}

static uint32_t cat_row_key(shz_cat_row_t *r, const shz_cat_result_t *res, const char *k, unsigned kn, const char *v,
                            unsigned vn)
{
    static const struct { const char *name; uint32_t bit; } keys[] = {
        { "Package", K_PACKAGE }, { "Kind", K_KIND }, { "Match", K_MATCH }, { "Service", K_SERVICE }, { "Image", K_IMAGE },
        { "ImageSha256", K_IMAGESHA }, { "Start", K_START }, { "Path", K_PATH }, { "Bytes", K_BYTES }, { "Sha256", K_SHA } };
    unsigned i;
    uint32_t bit = 0;
    uint64_t dummy;
    uint8_t h[32];
    (void)res;
    for (i = 0; i < sizeof keys / sizeof keys[0]; ++i) if (cat_eq(k, kn, keys[i].name)) bit = keys[i].bit;
    if (!bit || (r->seen & bit)) return SHZ_CAT_R_KEY;
    r->seen |= bit;
    switch (bit) {
    case K_PACKAGE:
        if (vn < 8 || !cat_eq(v, 7, "driver-")) return SHZ_CAT_R_VALUE;
        for (i = 7; i < vn; ++i) if (!cat_name_char(v[i], 1)) return SHZ_CAT_R_VALUE;
        return cat_copy(r->package, sizeof r->package, v, vn) ? 0 : SHZ_CAT_R_VALUE;
    case K_KIND:
        if (cat_eq(v, vn, "builtin")) r->kind = SHZ_CAT_KIND_BUILTIN;
        else if (cat_eq(v, vn, "service")) r->kind = SHZ_CAT_KIND_SERVICE;
        else return SHZ_CAT_R_VALUE;
        return 0;
    case K_MATCH: return cat_match_list(v, vn, r) ? 0 : SHZ_CAT_R_MATCH;
    case K_SERVICE:
        if (!vn || vn > 31) return SHZ_CAT_R_VALUE;
        for (i = 0; i < vn; ++i) if (!cat_name_char(v[i], 0)) return SHZ_CAT_R_VALUE;
        return cat_copy(r->service, sizeof r->service, v, vn) ? 0 : SHZ_CAT_R_VALUE;
    case K_IMAGE: return cat_image(v, vn) && cat_copy(r->image, sizeof r->image, v, vn) ? 0 : SHZ_CAT_R_VALUE;
    case K_IMAGESHA: return cat_sha(v, vn, r->image_sha256) ? 0 : SHZ_CAT_R_VALUE;
    case K_START:
        if (cat_eq(v, vn, "boot")) r->start = SHZ_CAT_START_BOOT;
        else if (cat_eq(v, vn, "system")) r->start = SHZ_CAT_START_SYSTEM;
        else if (cat_eq(v, vn, "demand")) r->start = SHZ_CAT_START_DEMAND;
        else return SHZ_CAT_R_VALUE;
        return 0;
    case K_PATH: return vn && vn < 128 ? 0 : SHZ_CAT_R_VALUE;
    case K_BYTES: return cat_dec(v, vn, &dummy) ? 0 : SHZ_CAT_R_VALUE;
    default: return cat_sha(v, vn, h) ? 0 : SHZ_CAT_R_VALUE;   /* K_SHA */
    }
}

uint32_t shz_catalog_builtin_driver(const shz_cat_match_t *m)
{
    if (m->type == SHZ_CAT_MATCH_ID) {
        if (m->device_lo != m->device_hi) return SHZ_BRINGUP_DRV_NONE;
        if (m->vendor == 0x1234 && m->device_lo == 0x1111) return SHZ_BRINGUP_DRV_GFX_BOCHS;    /* gfx_fb.c */
        if (m->vendor == 0x1af4 && m->device_lo == 0x1050) return SHZ_BRINGUP_DRV_GFX_VIRTIO;   /* gfx_virtio.c */
        if (m->vendor == 0x10ec && m->device_lo == 0x8139) return SHZ_BRINGUP_DRV_NET_RTL8139;  /* net_rtl8139.c */
        return SHZ_BRINGUP_DRV_NONE;
    }
    if (m->type != SHZ_CAT_MATCH_CLASS) return SHZ_BRINGUP_DRV_NONE;
    if (m->class_code == 0x01 && m->subclass == 0x06 && m->has_prog_if && m->prog_if == 0x01) return SHZ_BRINGUP_DRV_AHCI;
    if (m->class_code == 0x01 && m->subclass == 0x08 && m->has_prog_if && m->prog_if == 0x02) return SHZ_BRINGUP_DRV_NVME;
    if (m->class_code == 0x08 && m->subclass == 0x05) return SHZ_BRINGUP_DRV_SDHCI;
    if (m->class_code == 0x03) return SHZ_BRINGUP_DRV_GFX_GOP;   /* claimed only when the GOP framebuffer is in its BAR */
    return SHZ_BRINGUP_DRV_NONE;                                 /* xHCI 0c.03.30, EC, HID, bridges: no Kernel64 binding */
}

int shz_catalog_row_matches(const shz_cat_row_t *row, uint16_t vendor, uint16_t device, uint8_t cc, uint8_t sc, uint8_t pi)
{
    unsigned i;
    for (i = 0; i < row->nmatch && i < SHZ_CAT_MAX_MATCH; ++i) {
        const shz_cat_match_t *m = &row->match[i];
        if (m->type == SHZ_CAT_MATCH_ID && m->vendor == vendor && device >= m->device_lo && device <= m->device_hi) return 1;
        if (m->type == SHZ_CAT_MATCH_CLASS && m->class_code == cc && m->subclass == sc && (!m->has_prog_if || m->prog_if == pi))
            return 1;
    }
    return 0;
}

static int cat_svc_ieq(const char *a, const char *b)
{
    for (; *a && *b; ++a, ++b) if (cat_up(*a) != cat_up(*b)) return 0;
    return *a == *b;
}

int shz_catalog_parse(const char *buf, size_t len, const shz_cat_ops_t *ops, shz_cat_result_t *res)
{
    enum { S_NONE, S_CATALOG, S_DRIVER, S_SUMMARY } state = S_NONE;
    uint32_t hseen = 0, summary_seen = 0, count_seen = 0;
    shz_cat_row_t *cur = 0;
    size_t pos = 0;
    unsigned i, j;
    int rc = SHZ_CAT_OK;
    cat_zero(res, sizeof *res);
    if (!buf || !len || len > SHZ_CAT_MAX_BYTES) return SHZ_CAT_E_SIZE;
    while (pos < len && rc == SHZ_CAT_OK) {
        size_t e = pos;
        unsigned n, eq;
        const char *l = buf + pos;
        while (e < len && buf[e] != '\n') ++e;
        n = (unsigned)(e - pos);
        pos = e + 1;
        if (n && l[n - 1] == '\r') --n;
        if (n > SHZ_CAT_LINE_MAX) { rc = SHZ_CAT_E_SYNTAX; break; }
        for (i = 0; i < n; ++i) if ((unsigned char)l[i] < 0x20 || (unsigned char)l[i] > 0x7e) rc = SHZ_CAT_E_SYNTAX;
        if (rc) break;
        if (!n || l[0] == ';') continue;
        if (l[0] == '[') {
            uint64_t idx;
            if (l[n - 1] != ']' || n < 3) { rc = SHZ_CAT_E_SYNTAX; break; }
            if (cat_eq(l, n, "[Catalog]")) {
                if (state != S_NONE) rc = SHZ_CAT_E_HEADER;
                state = S_CATALOG;
            } else if (state == S_NONE) {
                rc = SHZ_CAT_E_HEADER;                                          /* [Catalog] must come first */
            } else if (state == S_SUMMARY) {
                rc = SHZ_CAT_E_SECTION;                                         /* [Summary] is last */
            } else if (hseen != H_ALL) {
                rc = SHZ_CAT_E_HEADER;
            } else if (cat_eq(l, n, "[Summary]")) {
                state = S_SUMMARY; summary_seen = 1; cur = 0;
            } else if (n > 9 && cat_eq(l, 8, "[Driver.") && n - 9 <= 2 && cat_dec(l + 8, n - 9, &idx)) {
                if (res->entries >= SHZ_CAT_MAX_ROWS) { rc = SHZ_CAT_E_SECTION; break; }
                cur = &res->row[res->entries];
                cur->index = (uint32_t)idx;
                if (idx != res->entries) cur->reject = SHZ_CAT_R_INDEX;            /* gap, repeat or out of order */
                ++res->entries;
                state = S_DRIVER;
            } else {
                rc = SHZ_CAT_E_SECTION;
            }
            continue;
        }
        for (eq = 0; eq < n && l[eq] != '='; ++eq) {}
        if (state == S_NONE) { rc = SHZ_CAT_E_SYNTAX; break; }
        if (eq == n || !eq) {
            if (state == S_DRIVER) { if (!cur->reject) cur->reject = SHZ_CAT_R_KEY; continue; }
            rc = state == S_CATALOG ? SHZ_CAT_E_HEADER : SHZ_CAT_E_SUMMARY;
            break;
        }
        {
            const char *k = l, *v = l + eq + 1;
            const unsigned kn = eq, vn = n - eq - 1;
            if (state == S_DRIVER) {
                const uint32_t why = cat_row_key(cur, res, k, kn, v, vn);
                if (why && !cur->reject) cur->reject = why;
            } else if (state == S_SUMMARY) {
                uint64_t c;
                if (!cat_eq(k, kn, "Count") || count_seen || !cat_dec(v, vn, &c) || c > SHZ_CAT_MAX_ROWS) rc = SHZ_CAT_E_SUMMARY;
                else { count_seen = 1; res->count = (uint32_t)c; }
            } else {
                uint32_t bit = cat_eq(k, kn, "Schema") ? H_SCHEMA : cat_eq(k, kn, "Selection") ? H_SELECTION
                             : cat_eq(k, kn, "InstallGeneration") ? H_GENERATION : cat_eq(k, kn, "Kernel64Sha256") ? H_KERNEL : 0;
                if (!bit || (hseen & bit)) { rc = SHZ_CAT_E_HEADER; break; }
                hseen |= bit;
                if ((bit == H_SCHEMA && !cat_eq(v, vn, SHZ_CAT_SCHEMA)) ||
                    (bit == H_SELECTION && !cat_copy(res->selection, sizeof res->selection, v, vn)) ||
                    (bit == H_GENERATION && !cat_dec(v, vn, &res->install_generation)) ||
                    (bit == H_KERNEL && !cat_sha(v, vn, res->kernel64_sha256)))
                    rc = SHZ_CAT_E_HEADER;
            }
        }
    }
    if (rc == SHZ_CAT_OK && hseen != H_ALL) rc = SHZ_CAT_E_HEADER;
    if (rc == SHZ_CAT_OK && (!summary_seen || !count_seen || res->count != res->entries)) rc = SHZ_CAT_E_SUMMARY;
    if (rc == SHZ_CAT_OK && ops && ops->install_generation && res->install_generation != ops->install_generation)
        rc = SHZ_CAT_E_GENERATION;
    if (rc != SHZ_CAT_OK) {
        cat_zero(res, sizeof *res);
        return rc;
    }
    /* Row semantics, then (only for a file that validated as a whole) image verification and service callbacks. */
    for (i = 0; i < res->entries; ++i) {
        shz_cat_row_t *r = &res->row[i];
        if (!r->reject && ((r->seen & (K_PACKAGE | K_KIND | K_MATCH | K_START)) != (K_PACKAGE | K_KIND | K_MATCH | K_START)))
            r->reject = SHZ_CAT_R_MISSING;
        if (!r->reject && r->kind == SHZ_CAT_KIND_BUILTIN) {
            if (r->seen & (K_SERVICE | K_IMAGE)) r->reject = SHZ_CAT_R_MISSING;   /* service-only keys on a builtin row */
            else if ((r->seen & K_IMAGESHA) && !cat_sha_eq(r->image_sha256, res->kernel64_sha256))
                r->reject = SHZ_CAT_R_BUILTIN_HASH;
            else
                for (j = 0; j < r->nmatch && !r->reject; ++j) {
                    const uint32_t d = shz_catalog_builtin_driver(&r->match[j]);
                    if (!d) r->reject = SHZ_CAT_R_BUILTIN_UNLINKED;
                    else if (!r->builtin_driver) r->builtin_driver = d;
                }
        } else if (!r->reject) {
            if ((r->seen & (K_SERVICE | K_IMAGE | K_IMAGESHA)) != (K_SERVICE | K_IMAGE | K_IMAGESHA)) r->reject = SHZ_CAT_R_MISSING;
            for (j = 0; j < i && !r->reject; ++j)
                if (!res->row[j].reject && res->row[j].kind == SHZ_CAT_KIND_SERVICE && cat_svc_ieq(res->row[j].service, r->service))
                    r->reject = SHZ_CAT_R_DUPLICATE_SERVICE;
            if (!r->reject && (!ops || !ops->verify_image || ops->verify_image(ops->ctx, r->image, r->image_sha256) != 0))
                r->reject = SHZ_CAT_R_IMAGE;
        }
        if (r->reject) { ++res->rejected; continue; }
        ++res->accepted;
        if (r->kind == SHZ_CAT_KIND_BUILTIN) ++res->builtin_matched;
        else ++res->service_accepted;
    }
    for (i = 0; i < res->entries; ++i)
        if (!res->row[i].reject && res->row[i].kind == SHZ_CAT_KIND_SERVICE && ops && ops->service_row)
            ops->service_row(ops->ctx, &res->row[i]);
    return SHZ_CAT_OK;
}

#ifndef SHZ_CATALOG_HOST
/* ================================================================ Kernel64 glue */
#define CAT_IMAGE_MAX (32ull << 20)

/* The ~30 KiB file buffer and parse result are transient: they live in one bounded heap block for the duration of the
 * import (the 3 MiB image+bss window is full) and only the counters needed by ntdrv_catalog_report() stay resident. */
struct cat_work {
    shz_cat_result_t res;
    char buf[SHZ_CAT_MAX_BYTES];
};
static struct { uint32_t entries, accepted, rejected; } cat_sum;
static uint8_t cat_io[4096];
static char cat_letter;
static int cat_done;
static int32_t cat_status = 1;                 /* 1 = no catalog (not attempted / absent), 0 imported, < 0 rejected */
static uint32_t cat_registered;

uint64_t ntdrv_install_generation(void)
{
#ifdef NTDRV_HAVE_INSTALL_IDENTITY
    return k64_install_generation();
#else
    return 0;                                   /* install_identity.c not in this tree yet: unattested */
#endif
}

static int cat_verify_image(void *ctx, const char *image, const uint8_t want[32])
{
    char path[136];
    fsnode_t *n;
    sha256_ctx c;
    uint8_t got[32];
    uint64_t off = 0;
    unsigned i, k = 0;
    (void)ctx;
    path[k++] = cat_letter; path[k++] = ':';
    for (i = 0; image[i] && k + 1 < sizeof path; ++i) path[k++] = image[i];
    path[k] = 0;
    n = fs_lookup(path);
    if (!n || n->is_dir || !n->size || n->size > CAT_IMAGE_MAX) {
        kprintf("K64 catalog: service image %s absent or out of bounds\n", path);
        return -1;
    }
    sha256_init(&c);
    while (off < n->size) {
        uint64_t want_len = n->size - off < sizeof cat_io ? n->size - off : sizeof cat_io, done = 0;
        if (fs_read(n, off, cat_io, want_len, &done) || done != want_len) {
            kprintf("K64 catalog: service image %s read failed at %llu\n", path, (unsigned long long)off);
            return -1;
        }
        sha256_update(&c, cat_io, (size_t)done);
        off += done;
    }
    sha256_final(&c, got);
    if (!cat_sha_eq(got, want)) { kprintf("K64 catalog: service image %s SHA-256 mismatch: rejected\n", path); return -1; }
    return 0;
}

#ifdef SHZ_STANDALONE
static unsigned cat_wide(uint16_t *w, unsigned n, unsigned cap, const char *s)
{
    while (*s && n + 1 < cap) w[n++] = (uint16_t)(uint8_t)*s++;
    w[n] = 0;
    return n;
}
static void cat_hex(char *o, uint32_t v, unsigned digits)
{
    static const char h[] = "0123456789ABCDEF";
    unsigned i;
    for (i = 0; i < digits; ++i) o[i] = h[(v >> (4 * (digits - 1 - i))) & 15];
    o[digits] = 0;
}
static int32_t cat_set_sz(regkey_t *k, const uint16_t *name, unsigned chars, uint32_t type, const char *s)
{
    uint16_t w[160];
    const unsigned n = cat_wide(w, 0, sizeof w / 2, s);
    return reg_set_value(k, name, chars, type, w, (n + 1) * 2);
}
/* REG_MULTI_SZ from `count` NUL-separated strings */
static int32_t cat_set_multi(regkey_t *k, const uint16_t *name, unsigned chars, const char *const *s, unsigned count)
{
    uint16_t w[320];
    unsigned n = 0, i;
    for (i = 0; i < count; ++i) { n = cat_wide(w, n, sizeof w / 2 - 1, s[i]); ++n; }
    w[n++] = 0;
    return reg_set_value(k, name, chars, REG_MULTI_SZ, w, n * 2);
}
static int cat_native_owner(const pci_dev_t *d)
{
    shz_cat_match_t m;
    cat_zero(&m, sizeof m);
    m.type = SHZ_CAT_MATCH_ID; m.vendor = d->vendor; m.device_lo = m.device_hi = d->device;
    if (shz_catalog_builtin_driver(&m)) return 1;
    m.type = SHZ_CAT_MATCH_CLASS; m.class_code = d->class_code; m.subclass = d->subclass; m.prog_if = d->prog_if;
    m.has_prog_if = 1;
    return shz_catalog_builtin_driver(&m) != 0 || d->class_code == 0x06 || d->class_code == 0x05;
}
/* any Enum\PCI\*\BbbDddFf instance already present (shzpnp or an earlier row): left as it is */
static int cat_devnode_exists(const char *inst)
{
    static const uint16_t path[] = u"Machine\\System\\CurrentControlSet\\Enum\\PCI";
    regkey_t *pci, *hw, *k;
    uint32_t i, j;
    unsigned n = 0, x;
    while (inst[n]) ++n;
    if (reg_resolve(reg_root(), path, sizeof path / 2 - 1, 0, 0, 1, 0, 0, &pci, 0)) return 0;
    for (i = 0; (hw = reg_nth_child(pci, i)) != 0; ++i)
        for (j = 0; (k = reg_nth_child(hw, j)) != 0; ++j)
            if (k->name_len == n) {
                const uint16_t *w = regkey_name(k);
                for (x = 0; x < n && cat_up((char)w[x]) == inst[x]; ++x) {}
                if (x == n) return 1;
            }
    return 0;
}
#endif

static void cat_service_row(void *ctx, const shz_cat_row_t *r)
{
#ifdef SHZ_STANDALONE
    static const uint16_t one_type[] = u"Type", start_n[] = u"Start", err_n[] = u"ErrorControl", img_n[] = u"ImagePath",
                          hw_n[] = u"HardwareID", cp_n[] = u"CompatibleIDs", desc_n[] = u"DeviceDesc", mfg_n[] = u"Mfg",
                          svc_n[] = u"Service", cfg_n[] = u"ConfigFlags";
    pci_dev_t all[SHZ_BRINGUP_ROWS];
    unsigned n = pci_enumerate(all, SHZ_BRINGUP_ROWS), i, made_service = 0;
    (void)ctx;
    for (i = 0; i < n; ++i) {
        const pci_dev_t *d = &all[i];
        char ven[5], dev[5], cc6[7], cc4[5], inst[12], base[32], hw1[48], hw2[48], cp[5][40], img[136];
        const char *hws[3], *cps[5];
        uint16_t wpath[160];
        unsigned wn, k;
        regkey_t *key;
        int created = 0;
        uint32_t dword;
        int32_t st = 0;
        if (pci_claimed_by(d) || cat_native_owner(d) ||
            !shz_catalog_row_matches(r, d->vendor, d->device, d->class_code, d->subclass, d->prog_if))
            continue;
        cat_hex(ven, d->vendor, 4); cat_hex(dev, d->device, 4);
        cat_hex(cc6, (uint32_t)d->class_code << 16 | (uint32_t)d->subclass << 8 | d->prog_if, 6);
        cat_hex(cc4, (uint32_t)d->class_code << 8 | d->subclass, 4);
        inst[0] = 'B'; cat_hex(inst + 1, d->bus, 2); inst[3] = 'D'; cat_hex(inst + 4, d->dev, 2); inst[6] = 'F';
        cat_hex(inst + 7, d->fn, 1);
        k = 0;
        { const char *p = "PCI\\VEN_"; while (*p) base[k++] = *p++; }
        for (wn = 0; ven[wn]; ++wn) base[k++] = ven[wn];
        { const char *p = "&DEV_"; while (*p) base[k++] = *p++; }
        for (wn = 0; dev[wn]; ++wn) base[k++] = dev[wn];
        base[k] = 0;
        reg_lock();
        if (cat_devnode_exists(inst)) {
            reg_unlock();
            kprintf("K64 catalog: PCI %x:%x.%x already has an installed devnode; %s not attached\n", d->bus, d->dev, d->fn, r->service);
            continue;
        }
        if (!made_service) {
            wn = cat_wide(wpath, 0, 160, "Machine\\System\\CurrentControlSet\\Services\\");
            wn = cat_wide(wpath, wn, 160, r->service);
            if (!reg_resolve(reg_root(), wpath, wn, 0, 0, 1, 0, 0, &key, 0)) {
                reg_unlock();
                kprintf("K64 catalog: Services\\%s already defined; row %u not applied\n", r->service, r->index);
                return;
            }
            k = 0; img[k++] = cat_letter; img[k++] = ':';
            for (wn = 0; r->image[wn] && k + 1 < sizeof img; ++wn) img[k++] = r->image[wn];
            img[k] = 0;
            wn = cat_wide(wpath, 0, 160, "Machine\\System\\CurrentControlSet\\Services\\");
            wn = cat_wide(wpath, wn, 160, r->service);
            st = reg_resolve(reg_root(), wpath, wn, 1, 0, 1, 0, 0, &key, &created);
            if (!st) { dword = 1; st = reg_set_value(key, one_type, 4, REG_DWORD, &dword, 4); }
            if (!st) { dword = r->start; st = reg_set_value(key, start_n, 5, REG_DWORD, &dword, 4); }
            if (!st) { dword = 1; st = reg_set_value(key, err_n, 12, REG_DWORD, &dword, 4); }
            if (!st) st = cat_set_sz(key, img_n, 9, REG_EXPAND_SZ, img);
            if (st) {
                reg_unlock();
                kprintf("K64 catalog: Services\\%s write failed (%x)\n", r->service, (uint32_t)st);
                return;
            }
            made_service = 1;
        }
        k = 0;
        { const char *p = base; while (*p) hw1[k++] = *p++; const char *q = "&CC_"; while (*q) hw1[k++] = *q++; }
        for (wn = 0; cc6[wn]; ++wn) hw1[k++] = cc6[wn];
        hw1[k] = 0;
        for (wn = 0; wn < k - 2; ++wn) hw2[wn] = hw1[wn];
        hw2[k - 2] = 0;
        hws[0] = base; hws[1] = hw1; hws[2] = hw2;
        {   /* the shzpnp scan forms: VEN&CC_cccccc, VEN&CC_cccc, VEN, CC_cccccc, CC_cccc */
            static const char *const pre[5] = { "PCI\\VEN_", "PCI\\VEN_", "PCI\\VEN_", "PCI\\CC_", "PCI\\CC_" };
            unsigned c;
            for (c = 0; c < 5; ++c) {
                const char *p = pre[c], *tail = c == 0 || c == 3 ? cc6 : c == 1 || c == 4 ? cc4 : "";
                k = 0;
                while (*p) cp[c][k++] = *p++;
                if (c < 3) { for (wn = 0; ven[wn]; ++wn) cp[c][k++] = ven[wn]; if (c < 2) { cp[c][k++] = '&'; cp[c][k++] = 'C'; cp[c][k++] = 'C'; cp[c][k++] = '_'; } }
                while (*tail) cp[c][k++] = *tail++;
                cp[c][k] = 0;
                cps[c] = cp[c];
            }
        }
        wn = cat_wide(wpath, 0, 160, "Machine\\System\\CurrentControlSet\\Enum\\");
        wn = cat_wide(wpath, wn, 160, base);
        wn = cat_wide(wpath, wn, 160, "\\");
        wn = cat_wide(wpath, wn, 160, inst);
        st = reg_resolve(reg_root(), wpath, wn, 1, 0, 1, 0, 0, &key, &created);
        if (!st) st = cat_set_multi(key, hw_n, 10, hws, 3);
        if (!st) st = cat_set_multi(key, cp_n, 13, cps, 5);
        if (!st) st = cat_set_sz(key, desc_n, 10, REG_SZ, r->package);
        if (!st) st = cat_set_sz(key, mfg_n, 3, REG_SZ, "");
        if (!st) { dword = 0; st = reg_set_value(key, cfg_n, 11, REG_DWORD, &dword, 4); }
        if (!st) st = cat_set_sz(key, svc_n, 7, REG_SZ, r->service);
        reg_unlock();
        if (st) kprintf("K64 catalog: devnode %s\\%s write failed (%x)\n", base, inst, (uint32_t)st);
        else {
            ++cat_registered;
            kprintf("K64 catalog: PCI %x:%x.%x %s:%s -> installed service %s (%s)\n", d->bus, d->dev, d->fn, ven, dev,
                    r->service, r->package);
        }
    }
    if (!made_service) kprintf("K64 catalog: %s: no present, unclaimed PCI function matches\n", r->service);
#else
    (void)ctx;
    kprintf("K64 catalog: %s: PCI functions are not owned by Kernel64 in this profile; not registered\n", r->service);
#endif
}

int ntdrv_catalog_import(void)
{
    static const char tail[] = ":\\SHZ\\DRIVERS\\CATALOG.INI";
    shz_cat_ops_t ops;
    char path[40];
    fsnode_t *n;
    uint64_t done = 0;
    unsigned i;
    int rc;
    struct cat_work *w;
    if (cat_done) return cat_status;
    cat_done = 1;
    cat_letter = sfsk_system_volume(0);
    if (!cat_letter) { kprintf("K64 catalog: no installed system volume; installed driver catalog absent\n"); return cat_status = 1; }
    path[0] = cat_letter;
    for (i = 0; tail[i]; ++i) path[i + 1] = tail[i];
    path[i + 1] = 0;
    n = fs_lookup(path);
    if (!n) { kprintf("K64 catalog: %s absent\n", path); return cat_status = 1; }
    if (n->is_dir || !n->size || n->size > SHZ_CAT_MAX_BYTES) {
        kprintf("K64 catalog: %s size %llu outside 1..%u: rejected\n", path, (unsigned long long)n->size, SHZ_CAT_MAX_BYTES);
        return cat_status = SHZ_CAT_E_SIZE;
    }
    w = kmalloc(sizeof *w);
    if (!w) {
        kprintf("K64 catalog: no heap for the import work area (%u bytes)\n", (unsigned)sizeof *w);
        return cat_status = SHZ_CAT_E_SIZE;
    }
    cat_zero(w, sizeof *w);
    if (fs_read(n, 0, w->buf, n->size, &done) || done != n->size) {
        kprintf("K64 catalog: %s read failed\n", path);
        kfree(w);
        return cat_status = SHZ_CAT_E_SIZE;
    }
    cat_zero(&ops, sizeof ops);
    ops.install_generation = ntdrv_install_generation();
    ops.verify_image = cat_verify_image;
    ops.service_row = cat_service_row;
    rc = shz_catalog_parse(w->buf, (size_t)done, &ops, &w->res);
    if (rc) {
        kprintf("K64 catalog: %s rejected as a whole (%d)\n", path, rc);
        kfree(w);
        return cat_status = rc;
    }
    for (i = 0; i < w->res.entries; ++i)
        if (w->res.row[i].reject)
            kprintf("K64 catalog: row %u (%s) rejected, reason %u\n", i, w->res.row[i].package[0] ? w->res.row[i].package : "-",
                    w->res.row[i].reject);
    cat_sum.entries = w->res.entries;
    cat_sum.accepted = w->res.accepted;
    cat_sum.rejected = w->res.rejected;
    kprintf("CATALOG-IMPORT: generation=%llu%s entries=%u builtin_matched=%u services_accepted=%u rejected=%u devnodes=%u "
            "kernel64_sha256=unverified-against-running-image\n", (unsigned long long)w->res.install_generation,
            ops.install_generation ? " attested" : " unattested", w->res.entries, w->res.builtin_matched,
            w->res.service_accepted, w->res.rejected, cat_registered);
    kfree(w);
    return cat_status = 0;
}

void ntdrv_catalog_report(shz_bringup_report_t *r)
{
    r->catalog_status = cat_status;
    r->catalog_entries = cat_sum.entries;
    r->catalog_matched = cat_sum.accepted;
    r->catalog_rejected = cat_sum.rejected;
    r->catalog_registered = cat_registered;
}
#endif
