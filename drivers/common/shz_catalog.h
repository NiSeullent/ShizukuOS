/* SPDX-License-Identifier: GPL-2.0-only
 * Installed driver catalog v2 (\SHZ\DRIVERS\CATALOG.INI, routing02 contract C5): bounded strict parser types.
 *
 * The parser (shizukudos/kernel64/ntdrv_catalog.c, pure part) takes a byte buffer and callbacks; it allocates nothing
 * and calls no kernel service, so the same code is compiled by the host control drivers/common/tests/test_shz_catalog.c.
 * The Kernel64 glue in the same file reads the file from the installed system volume, verifies service images with the
 * kernel SHA-256 and turns validated service rows into the Enum\PCI devnode + Services records shzpnp add-driver
 * --install writes. Builtin rows are only matched against the drivers linked into Kernel64; they never become services.
 */
#ifndef SHZ_COMMON_CATALOG_H
#define SHZ_COMMON_CATALOG_H
#include <stddef.h>
#include <stdint.h>

#define SHZ_CAT_SCHEMA "shizuku-driver-catalog/2"
#define SHZ_CAT_MAX_BYTES 16384u
#define SHZ_CAT_MAX_ROWS 32u
#define SHZ_CAT_MAX_MATCH 8u
#define SHZ_CAT_LINE_MAX 255u

enum { SHZ_CAT_KIND_BUILTIN = 1, SHZ_CAT_KIND_SERVICE = 2 };
enum { SHZ_CAT_START_BOOT = 0, SHZ_CAT_START_SYSTEM = 1, SHZ_CAT_START_DEMAND = 3 };   /* = Services Start values */
enum { SHZ_CAT_MATCH_ID = 1, SHZ_CAT_MATCH_CLASS = 2 };

/* whole-file results (shz_catalog_parse return value) */
#define SHZ_CAT_OK 0
#define SHZ_CAT_E_SIZE (-1)          /* empty or larger than SHZ_CAT_MAX_BYTES */
#define SHZ_CAT_E_SYNTAX (-2)        /* bad byte, over-long line, text outside a section, malformed section header */
#define SHZ_CAT_E_HEADER (-3)        /* [Catalog] missing/not first, unknown or duplicate key, bad Schema/hex/decimal */
#define SHZ_CAT_E_SECTION (-4)       /* unknown section, section after [Summary], too many [Driver.n] sections */
#define SHZ_CAT_E_SUMMARY (-5)       /* [Summary] missing, unknown/duplicate key, or Count != number of [Driver.n] */
#define SHZ_CAT_E_GENERATION (-6)    /* InstallGeneration differs from the attested install generation */

/* per-row rejection reasons (shz_cat_row_t.reject) */
enum shz_cat_reject {
    SHZ_CAT_R_NONE = 0,
    SHZ_CAT_R_INDEX,                 /* [Driver.n] out of order or not contiguous from 0 */
    SHZ_CAT_R_KEY,                   /* unknown or duplicate key */
    SHZ_CAT_R_VALUE,                 /* malformed value (bad hex, name, path, kind, start, decimal) */
    SHZ_CAT_R_MISSING,               /* required key absent, or a service-only key on a builtin row */
    SHZ_CAT_R_MATCH,                 /* Match list empty, malformed or more than SHZ_CAT_MAX_MATCH items */
    SHZ_CAT_R_BUILTIN_HASH,          /* builtin ImageSha256 != Kernel64Sha256 */
    SHZ_CAT_R_BUILTIN_UNLINKED,      /* builtin row names a function no driver linked into Kernel64 drives */
    SHZ_CAT_R_IMAGE,                 /* service image absent, unreadable or its SHA-256 differs from ImageSha256 */
    SHZ_CAT_R_DUPLICATE_SERVICE      /* a previous accepted row already declared this Service */
};

typedef struct {
    uint8_t type, class_code, subclass, prog_if;   /* type SHZ_CAT_MATCH_*; class form: has_prog_if says whether pp given */
    uint8_t has_prog_if, reserved[3];
    uint16_t vendor, device_lo, device_hi, reserved2;   /* id form: device_lo..device_hi inclusive */
} shz_cat_match_t;

typedef struct {
    uint32_t index, kind, start, nmatch;
    uint32_t reject;                                /* enum shz_cat_reject; SHZ_CAT_R_NONE = accepted */
    uint32_t builtin_driver;                        /* builtin rows: shz_bringup_driver of the linked driver */
    shz_cat_match_t match[SHZ_CAT_MAX_MATCH];
    char package[64], service[32], image[128];
    uint8_t image_sha256[32];
    uint32_t seen;                                  /* key bitmap (parser internal) */
} shz_cat_row_t;

typedef struct {
    uint64_t install_generation;
    uint8_t kernel64_sha256[32];
    char selection[64];
    uint32_t count;                                 /* [Summary] Count == rows seen */
    uint32_t entries, accepted, builtin_matched, service_accepted, rejected;
    shz_cat_row_t row[SHZ_CAT_MAX_ROWS];
} shz_cat_result_t;

typedef struct {
    void *ctx;
    uint64_t install_generation;                    /* nonzero: InstallGeneration must equal it (attested boot) */
    /* Service rows only: 0 when the image file named by `image` exists and its bytes hash to `sha256`. */
    int (*verify_image)(void *ctx, const char *image, const uint8_t sha256[32]);
    /* Called once per accepted service row after the whole file validated. Never called for builtin rows. */
    void (*service_row)(void *ctx, const shz_cat_row_t *row);
} shz_cat_ops_t;

/* Parses and validates `buf[0..len)`. Returns SHZ_CAT_OK with res filled (rows accepted/rejected individually), or a
 * negative SHZ_CAT_E_* when the whole file is rejected (then no callback ran and res counts are zero). */
int shz_catalog_parse(const char *buf, size_t len, const shz_cat_ops_t *ops, shz_cat_result_t *res);
/* Driver linked into Kernel64 for one match item (shz_bringup_driver value), 0 when none: the same table as
 * ntdrv_pnp.c bu_native_match(), restricted to drivers with a production Kernel64 binding (no xHCI, no bridges). */
uint32_t shz_catalog_builtin_driver(const shz_cat_match_t *m);
/* 1 when a PCI function (vendor, device, class triple) matches one of the row's items. */
int shz_catalog_row_matches(const shz_cat_row_t *row, uint16_t vendor, uint16_t device, uint8_t cc, uint8_t sc, uint8_t pi);
#endif
