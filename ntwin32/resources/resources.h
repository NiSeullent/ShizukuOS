/* SPDX-License-Identifier: GPL-2.0-only */
#ifndef NTW_RESOURCES_H
#define NTW_RESOURCES_H
#include "../native_loader/pe.h"

/* This independent read-only prerequisite changes no native-loader budget. */
#define NR_LEAVES 1024u
#define NR_REGIONS 4096u
#define NR_NAME_WORK 262144u
#define NR_KEY_ID 0u
#define NR_KEY_NAME 1u

typedef struct nr_key {
    uint32_t kind, id, units;
    const uint8_t *utf16; /* counted little-endian UTF16 code units, not a C string */
} nr_key;
typedef struct nr_leaf {
    nr_key type, name;
    uint32_t entry_offset, data_rva, bytes, codepage;
    uint16_t language;
} nr_leaf;
typedef const nr_leaf *nr_handle;
typedef struct nr_region { uint32_t offset, bytes; } nr_region;
typedef struct nr_resources {
    const struct nr_resources *self;
    np_image image;
    uint32_t present, directory_rva, directory_bytes;
    uint32_t count, regions, name_work;
    nr_region region[NR_REGIONS];
    nr_leaf leaf[NR_LEAVES];
} nr_resources;
typedef struct nr_data {
    const uint8_t *data;
    uint32_t bytes, rva, codepage;
    uint16_t language;
} nr_data;

/* p is a successful np_parse[_limited] result for a live immutable file.
 * out is a naturally aligned, exclusively owned writable context. Its address
 * is stable after success: copying/moving the context invalidates its handles.
 * It owns metadata values and borrows p->file; no module registration occurs.
 * The file/context must stay alive and immutable until all handles are unused.
 * Reparse/reuse of that storage is allowed only after every borrowed handle is
 * discarded. Raw pointer identities provide no generation/ABA detection.
 * Three levels (type/name/WORD language) are supported; all metadata reads are
 * bytewise, bounded by the resource directory and raw file backing. Numeric
 * type/name IDs retain the PE's 31-bit range, including zero. Names retain all
 * counted UTF16 code units, including NUL/unpaired surrogates, without decoding.
 * Repeated/overlapping directory/name/data-entry metadata is an unsupported
 * graph profile, not a claim that every such PE is corrupt. Shared/overlapping
 * immutable PAYLOADS are legal and do not create multiple ownership claims.
 * Payload RVAs need not lie inside the resource directory; require file-backed
 * image bytes, without imposing section permissions on opaque data. Zero-size
 * resources are supported, including a zero RVA when their size is zero.
 * Failure clears out, except detected output/input aliases which write neither
 * aliased object. error must be writable/disjoint from every input/output; an
 * error alias returns failure without writing it. No code is ever executed.
 */
int nr_parse(const np_image *p, nr_resources *out, const char **error);

/* Exact counted key and language lookup. Missing returns 0/NR_NOT_FOUND.
 * LANGUAGE 0 means an exact neutral leaf here. FindResourceExW's thread/user/
 * system language fallback, MUI, '#decimal', ANSI conversion and NULL HMODULE
 * belong to a future real module adapter and are deliberately not simulated.
 * Keys must be live C objects; name bytes must be live through this call only.
 * Handles are borrowed information-block identities, not HGLOBAL allocations.
 */
int nr_lookup(const nr_resources *owner, const nr_key *type, const nr_key *name,
              uint16_t language, nr_handle *out, const char **error);
/* No supplied handle is dereferenced until identity membership is proven.
 * Null, interior, copied and foreign-owner handles, plus inactive/copied owner
 * contexts, are refused. Caller lifetime rules exclude stale storage reuse.
 * Payload/data pointers are borrowed and need no free or GlobalLock/GlobalFree.
 * There is no release API and therefore no double-free state machine.
 * The caller must exclude concurrent mutation/destruction of owner/file.
 */
int nr_load(const nr_resources *owner, nr_handle handle, nr_data *out,
            const char **error);
int nr_sizeof(const nr_resources *owner, nr_handle handle, uint32_t *out,
              const char **error);
#endif
