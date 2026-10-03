/* SPDX-License-Identifier: GPL-2.0-only
 * SZOU v1: original-Windows-userland payload image for the explicit
 * original-userland install phase. This is a distinct route; the strict
 * DOS/native image schema handled by ../native_install.c is unchanged.
 *
 * Layout (little-endian, normative copy in .codex/handoff/original-userland-schema.md):
 *   header 64 bytes | entry table 320*entry_count bytes | payload blob.
 * The parser never trusts a field it has not range-checked and never
 * returns success for an image it has not fully validated. Payload content
 * hashes are verified separately by streaming (szou_verify_entry), because
 * payloads may be gigabytes and are read through the caller's actual
 * retained source handle.
 */
#ifndef SHZ_SZOU_MANIFEST_H
#define SHZ_SZOU_MANIFEST_H
#include <stddef.h>
#include <stdint.h>

#define SZOU_MAGIC_U32        0x554F5A53u /* bytes 53 5A 4F 55 */
#define SZOU_VERSION          1u
#define SZOU_HEADER_BYTES     64u
#define SZOU_ENTRY_BYTES      320u
#define SZOU_PATH_FIELD       260u
#define SZOU_PATH_MAX         259u
#define SZOU_MAX_ENTRIES      65535u
#define SZOU_ATTR_ALLOWED     0x27u /* READONLY|HIDDEN|SYSTEM|ARCHIVE */

/* SZOU v2 = v1 + append-only SZLN long-name/directory extension (boot-install
 * producer native_payload_ingest.py szou_image/szou_names). version 2 requires
 * flags == SZOU_FLAG_NAMES; the extension starts at payload_start + total. */
#define SZOU_VERSION_NAMES    2u
#define SZOU_FLAG_NAMES       1u
#define SZLN_HEADER_BYTES     48u
#define SZLN_RECORD_BYTES     784u
#define SZLN_VERSION          1u
#define SZLN_NAME_UNITS       255u
#define SZLN_KIND_FILE        1u   /* long name of an SZOU entry */
#define SZLN_KIND_DIR         2u   /* directory (complete list incl. empty dirs) */

enum {
    SZOU_OK = 0,
    SZOU_E_ARG = -1,
    SZOU_E_MAGIC = -2,
    SZOU_E_VERSION = -3,
    SZOU_E_HEADER = -4,       /* header_size/flags/reserved/count invalid */
    SZOU_E_LENGTH = -5,       /* image length inconsistent with header */
    SZOU_E_TABLE_SHA = -6,
    SZOU_E_PATH = -7,         /* traversal, drive letter, bad char, bad component */
    SZOU_E_DUPLICATE = -8,    /* case-insensitive duplicate */
    SZOU_E_CONFLICT = -9,     /* file is also a directory prefix of another entry */
    SZOU_E_LAYOUT = -10,      /* unordered/overlapping/gapped payload, size sum */
    SZOU_E_ATTR = -11,
    SZOU_E_RESERVED = -12,    /* nonzero entry reserved bytes or path padding */
    SZOU_E_IO = -13,
    SZOU_E_SHA = -14,         /* payload content hash mismatch */
    SZOU_E_NOMEM = -15,
    SZOU_E_NO_AUTHORITY = -16,/* no actual file-write authority bound */
    SZOU_E_STATE = -17,       /* inconsistent staging/commit state on target */
    SZOU_E_EXISTS = -18,
    SZOU_E_FULL = -19,        /* no free clusters/directory slots on target volume */
    SZOU_E_UNSUPPORTED = -20, /* FAT12/16, >4GiB file, dir rename, missing LFN sink op, ... */
    SZOU_E_NAMES = -21,       /* invalid SZLN record: kind, unsorted, missing dir, long-name rule */
    SZOU_E_ORDER = -22        /* SZLN records not strictly sorted by upper-cased short path */
};

typedef struct szou_header {
    uint16_t version;                  /* 1 or 2 */
    uint32_t entry_count, flags;
    uint64_t total_payload_bytes;
    uint64_t table_offset, payload_offset; /* absolute image offsets */
    uint8_t entries_sha256[32];
    uint64_t names_offset;             /* v2: absolute SZLN header offset; v1: 0 */
} szou_header_t;

typedef struct szou_names_header {
    uint32_t record_count;
    uint64_t records_offset;           /* absolute image offset of record 0 */
    uint8_t records_sha256[32];
} szou_names_header_t;

/* One validated SZLN record. path is the ORIGINAL 8.3 short path (alias kept
 * verbatim, e.g. PROGRA~1); name holds `units` UTF-16 code units. */
typedef struct szou_name {
    char path[SZOU_PATH_FIELD];
    uint8_t kind, attributes;
    uint16_t units;
    uint16_t name[SZLN_NAME_UNITS + 1];
} szou_name_t;

typedef struct szou_entry {
    char path[SZOU_PATH_FIELD];  /* validated, NUL-terminated */
    uint32_t attributes;
    uint64_t size, payload_offset; /* payload_offset relative to payload start */
    uint8_t sha256[32];
} szou_entry_t;

/* Validate the 64-byte header against the actual image length. v1: exact
 * length. v2: room for at least the SZLN header; the exact length is then
 * enforced by szou_parse_names_header. */
int szou_parse_header(const uint8_t hdr[SZOU_HEADER_BYTES], uint64_t image_bytes, szou_header_t *out);

/* Validate one dest_path field (260 bytes incl. NUL padding). 0 or SZOU_E_PATH/RESERVED. */
int szou_validate_path(const uint8_t field[SZOU_PATH_FIELD]);

/* Validate the whole entry table: entries_sha256, every entry, contiguous
 * ordered payload layout summing to total_payload_bytes, case-insensitive
 * duplicate and file/directory conflicts. `order` is caller scratch of
 * entry_count uint32 (sorted index, retained for later lookups). */
int szou_parse_table(const szou_header_t *h, const uint8_t *table, size_t table_bytes,
                     szou_entry_t *entries, uint32_t *order);

/* Payload reader bound to the caller's retained source handle. Reads exactly
 * len bytes at absolute image offset; 0 on success. */
typedef int (*szou_read_fn)(void *ctx, uint64_t image_offset, void *buf, uint32_t len);

/* Stream one entry's payload, recompute SHA-256 and compare. `buf`/`buf_bytes`
 * is caller scratch (>= 512). */
int szou_verify_entry(const szou_header_t *h, const szou_entry_t *e, szou_read_fn rd, void *ctx,
                      uint8_t *buf, uint32_t buf_bytes);

/* v2: validate the 48-byte SZLN header at h->names_offset and the exact image
 * length ext + 48 + 784*record_count (no trailer). */
int szou_parse_names_header(const szou_header_t *h, const uint8_t ext[SZLN_HEADER_BYTES], uint64_t image_bytes,
                            szou_names_header_t *out);

/* Scratch uint32 count for szou_parse_names. */
#define SZOU_NAMES_SCRATCH(entries, records) ((size_t)(entries) + 2u * (size_t)(records))

/* v2: validate the SZLN records (records_sha256, path rules, kind rules,
 * strict sort/uniqueness, UTF-16 long-name rules incl. surrogate pairing,
 * complete directory list, sibling long/short name collisions) against an
 * already validated entry table (entries + order from szou_parse_table). */
int szou_parse_names(const szou_header_t *h, const szou_names_header_t *nh, const uint8_t *records, size_t bytes,
                     const szou_entry_t *entries, const uint32_t *order, szou_name_t *out, uint32_t *scratch);

/* Binary search of validated (sorted) records by short path; NULL if none. */
const szou_name_t *szou_names_find(const szou_name_t *n, uint32_t count, const char *short_path);

/* Canonical 784-byte serialization of a validated record. */
void szou_name_serialize(const szou_name_t *n, uint8_t out[SZLN_RECORD_BYTES]);

/* Long-name policy: 1..255 units, no unit < 0x20, none of " * / : < > ? \ |,
 * paired surrogates only, not "." / "..", no trailing space or dot. */
int szou_validate_long_name(const uint16_t *u, uint32_t units);

/* Conservative simple upper-case fold (ASCII, Latin-1, Latin Ext-A, Greek,
 * Cyrillic, full-width ASCII) used for sibling-name collision checks. */
uint16_t szou_upcase16(uint16_t c);

/* ASCII case-insensitive compare used for duplicates and target lookups. */
int szou_path_casecmp(const char *a, const char *b);

const char *szou_strerror(int code);
#endif
