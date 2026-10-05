/* SPDX-License-Identifier: GPL-2.0-only
 * ShizukuCore installed-target boot manifest (SHZBOOT.MAN).
 *
 * Written by the project installer onto the installed target ESP next to the
 * Supervisor guest kernels and delivered to the payload by the UEFI loader as
 * one immutable named blob ("SHZBOOT.MAN"). The Supervisor never writes it.
 * It binds the exact ShizukuCore parent hierarchy (ShizukuCore -> ShizukuDOS
 * SZRm / Shizuku32 SZPrtm / Shizuku64 SZLm / ShizukuOS Windows 98), the
 * installed target path, size and SHA-256 of every loader blob, inter-component
 * dependencies and required CPU capabilities. ShizukuCore admits a child only
 * when this manifest admits it, and rolls the whole creation back otherwise.
 *
 * All fields are little endian, fixed width and pointer free. Strings are
 * NUL terminated inside their fixed field; unused bytes must be zero.
 */
#ifndef SHZ_BOOT_MANIFEST_H
#define SHZ_BOOT_MANIFEST_H
#include <stdint.h>
#include "../include/shz_info.h"

#define SHZ_BMAN_BLOB_NAME "SHZBOOT.MAN"
#define SHZ_BMAN_MAGIC 0x314E414D54425A53ull  /* "SZBTMAN1" little endian bytes */
#define SHZ_BMAN_VERSION 1u
#define SHZ_BMAN_MAX_ENTRIES 16u
#define SHZ_BMAN_MAX_BYTES 4096u
#define SHZ_BMAN_ROOT_NAME "ShizukuCore"

enum shz_bman_kind {
    SHZ_BMAN_KIND_CORE = 0,      /* exactly one, entry 0, parent "" */
    SHZ_BMAN_KIND_CHILD = 1,     /* a ShizukuCore child domain, parent "ShizukuCore" */
    SHZ_BMAN_KIND_RESOURCE = 2   /* blob consumed by a child, parent = that child */
};

enum shz_bman_entry_flags {
    SHZ_BMAN_REQUIRED = 1u << 0  /* absence or mismatch refuses the whole boot */
};

typedef struct {
    uint64_t magic;                  /*  0 SHZ_BMAN_MAGIC */
    uint16_t version;                /*  8 SHZ_BMAN_VERSION */
    uint16_t header_size;            /* 10 sizeof(shz_bman_header_t) = 96 */
    uint16_t entry_size;             /* 12 sizeof(shz_bman_entry_t) = 176 */
    uint16_t entry_count;            /* 14 1..SHZ_BMAN_MAX_ENTRIES */
    uint32_t total_size;             /* 16 header_size + entry_count * entry_size == blob size */
    uint32_t loader_profile;         /* 20 must equal shz_info_t.loader_flags */
    uint64_t install_generation;     /* 24 installer generation, nonzero */
    uint32_t required_caps;          /* 32 enum shz_cap_bits mask, subset of cap_bits */
    uint32_t flags;                  /* 36 must be zero in version 1 */
    uint8_t entries_sha256[32];      /* 40 SHA-256 of bytes [header_size, total_size) */
    uint8_t install_id[16];          /* 72 opaque installed-target identity, nonzero */
    uint32_t reserved[2];            /* 88 zero */
} shz_bman_header_t;                 /* 96 */

typedef struct {
    char component[16];              /*   0 "ShizukuCore", "ShizukuDOS", ... or resource name */
    char parent[16];                 /*  16 "" for core, "ShizukuCore" for children */
    char blob[16];                   /*  32 loader blob name, "" when no blob */
    char install_path[64];           /*  48 ESP path written by installer, e.g. "\\SHZDOS\\KERNEL64.BIN" */
    uint32_t kind;                   /* 112 enum shz_bman_kind */
    uint32_t domain_id;              /* 116 enum shz_domain_id for children, 0 otherwise */
    uint32_t depends;                /* 120 bitmask of entry indices this entry needs */
    uint32_t flags;                  /* 124 enum shz_bman_entry_flags */
    uint32_t required_caps;          /* 128 enum shz_cap_bits mask for this entry */
    uint32_t reserved;               /* 132 zero */
    uint64_t size;                   /* 136 exact blob byte size (0 when no blob) */
    uint8_t sha256[32];              /* 144 SHA-256 of blob bytes (zero when no blob) */
} shz_bman_entry_t;                  /* 176 */

_Static_assert(sizeof(shz_bman_header_t) == 96, "manifest header layout is installer ABI");
_Static_assert(sizeof(shz_bman_entry_t) == 176, "manifest entry layout is installer ABI");
_Static_assert(96u + SHZ_BMAN_MAX_ENTRIES * 176u <= SHZ_BMAN_MAX_BYTES, "manifest bound");

/* Immutable admitted view. Entries point into the loader-owned blob, which
 * resources_valid() already keeps disjoint from every writable allocation. */
typedef struct {
    const shz_bman_header_t *header;
    const shz_bman_entry_t *entries;
    uint32_t count;
    uint32_t present;                /* entry mask whose blob was found and verified */
} shz_bman_t;

/* Unstamped installer template (install_generation == 0 and install_id all
 * zero, every other rule satisfied). Never an installed-target attestation. */
#define SHZ_BMAN_TEMPLATE 1

void shz_sha256(const void *data, uint64_t len, uint8_t out[32]);
/* Pure, freestanding table check over the raw manifest bytes: header fields,
 * stamped/template identity, entry-table SHA-256, per-entry field rules,
 * ShizukuCore parent hierarchy shape, resource->child parenting, duplicate
 * component/blob names, self-binding refusal and acyclic dependencies. It
 * does NOT check loader_profile, capabilities or any blob bytes (callers
 * do, against their own loaded images). Returns 0 for a stamped manifest,
 * SHZ_BMAN_TEMPLATE for an unstamped template, -1 with reason in err. */
int shz_bman_check_table(const void *blob, uint64_t size, char *err, unsigned err_size);
/* shz_bman_check_table plus profile, capabilities and every blob size/hash
 * against the loader blob table. Every loader blob other than the manifest
 * itself must be covered by an entry. Returns 0 (stamped) or
 * SHZ_BMAN_TEMPLATE and fills *out, or -1 with reason in err. */
int shz_bman_parse(const shz_info_t *info, const shz_blob_t *blob, uint32_t cap_bits,
                   shz_bman_t *out, char *err, unsigned err_size);
const shz_bman_entry_t *shz_bman_component(const shz_bman_t *m, const char *component, unsigned *index);
#endif
