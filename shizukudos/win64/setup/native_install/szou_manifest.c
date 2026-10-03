/* SPDX-License-Identifier: GPL-2.0-only
 * SZOU v1 original-userland payload parser/validator. Freestanding C99:
 * needs memcpy/memset/memcmp only, plus the tree's existing SHA-256 core
 * (shizukudos/accounts/sha256.c, also linked into the installer through
 * ../native_runtime_sha.c). No heap allocation; callers supply arrays.
 */
#include "szou_manifest.h"
#include "../../../accounts/sha256.h"
#include <string.h>

static uint16_t rd16(const uint8_t *p) { return (uint16_t)(p[0] | (p[1] << 8)); }
static uint32_t rd32(const uint8_t *p)
{
    return (uint32_t)p[0] | ((uint32_t)p[1] << 8) | ((uint32_t)p[2] << 16) | ((uint32_t)p[3] << 24);
}
static uint64_t rd64(const uint8_t *p) { return (uint64_t)rd32(p) | ((uint64_t)rd32(p + 4) << 32); }

static int all_zero(const uint8_t *p, size_t n)
{
    uint8_t acc = 0;
    while (n--) acc |= *p++;
    return acc == 0;
}

static char up(char c) { return (c >= 'a' && c <= 'z') ? (char)(c - 32) : c; }

int szou_path_casecmp(const char *a, const char *b)
{
    for (;; a++, b++) {
        char x = up(*a), y = up(*b);
        if (x != y) return (unsigned char)x < (unsigned char)y ? -1 : 1;
        if (!x) return 0;
    }
}

/* Compare the first n chars of a (as a whole string) against string b. */
static int casecmp_n(const char *a, size_t n, const char *b)
{
    size_t i;
    for (i = 0; i < n; i++) {
        char x = up(a[i]), y = up(b[i]);
        if (x != y) return (unsigned char)x < (unsigned char)y ? -1 : 1;
        if (!y) return 1;
    }
    return b[n] ? -1 : 0;
}

int szou_parse_header(const uint8_t hdr[SZOU_HEADER_BYTES], uint64_t image_bytes, szou_header_t *out)
{
    uint32_t count;
    uint64_t table_bytes, need;
    if (!hdr || !out) return SZOU_E_ARG;
    memset(out, 0, sizeof *out);
    if (image_bytes < SZOU_HEADER_BYTES) return SZOU_E_LENGTH;
    if (hdr[0] != 0x53 || hdr[1] != 0x5A || hdr[2] != 0x4F || hdr[3] != 0x55) return SZOU_E_MAGIC;
    out->version = rd16(hdr + 4);
    if (out->version != SZOU_VERSION && out->version != SZOU_VERSION_NAMES) return SZOU_E_VERSION;
    if (rd16(hdr + 6) != SZOU_HEADER_BYTES) return SZOU_E_HEADER;
    count = rd32(hdr + 8);
    if (count == 0 || count > SZOU_MAX_ENTRIES) return SZOU_E_HEADER;
    if (rd32(hdr + 12) != (out->version == SZOU_VERSION_NAMES ? SZOU_FLAG_NAMES : 0u)) return SZOU_E_HEADER;
    if (!all_zero(hdr + 56, 8)) return SZOU_E_HEADER;
    out->entry_count = count;
    out->total_payload_bytes = rd64(hdr + 16);
    memcpy(out->entries_sha256, hdr + 24, 32);
    table_bytes = (uint64_t)count * SZOU_ENTRY_BYTES;
    out->table_offset = SZOU_HEADER_BYTES;
    out->payload_offset = SZOU_HEADER_BYTES + table_bytes;
    if (out->total_payload_bytes > UINT64_MAX - out->payload_offset) return SZOU_E_LENGTH;
    need = out->payload_offset + out->total_payload_bytes;
    if (out->version == SZOU_VERSION) {
        if (need != image_bytes) return SZOU_E_LENGTH; /* no truncation, no trailing bytes */
    } else {
        if (image_bytes < need || image_bytes - need < SZLN_HEADER_BYTES) return SZOU_E_LENGTH;
        out->names_offset = need;
    }
    return SZOU_OK;
}

static int bad_char(uint8_t c)
{
    if (c < 0x20 || c > 0x7E) return 1;
    switch (c) {
    case '<': case '>': case ':': case '"': case '/': case '|': case '?': case '*':
        return 1;
    default:
        return 0;
    }
}

int szou_validate_path(const uint8_t f[SZOU_PATH_FIELD])
{
    size_t len = 0, i, comp = 0;
    if (!f) return SZOU_E_ARG;
    while (len < SZOU_PATH_FIELD && f[len]) len++;
    if (len == 0 || len > SZOU_PATH_MAX) return SZOU_E_PATH; /* also: no NUL inside field */
    if (!all_zero(f + len, SZOU_PATH_FIELD - len)) return SZOU_E_RESERVED;
    if (f[0] == '\\') return SZOU_E_PATH;                       /* leading backslash/UNC */
    if (len >= 2 && f[1] == ':') return SZOU_E_PATH;            /* drive letter */
    for (i = 0; i <= len; i++) {
        if (i == len || f[i] == '\\') {
            size_t n = i - comp;
            const uint8_t *c = f + comp;
            if (n == 0) return SZOU_E_PATH;                      /* empty or trailing component */
            if (n == 1 && c[0] == '.') return SZOU_E_PATH;
            if (n == 2 && c[0] == '.' && c[1] == '.') return SZOU_E_PATH;
            if (c[n - 1] == '.' || c[n - 1] == ' ') return SZOU_E_PATH;
            if (n > 255) return SZOU_E_PATH;
            comp = i + 1;
            continue;
        }
        if (bad_char(f[i])) return SZOU_E_PATH;
    }
    return SZOU_OK;
}

/* In-place heapsort of index array by case-folded path (no libc qsort). */
static void sift(uint32_t *o, const szou_entry_t *e, size_t root, size_t n)
{
    for (;;) {
        size_t c = 2 * root + 1;
        uint32_t t;
        if (c >= n) return;
        if (c + 1 < n && szou_path_casecmp(e[o[c]].path, e[o[c + 1]].path) < 0) c++;
        if (szou_path_casecmp(e[o[root]].path, e[o[c]].path) >= 0) return;
        t = o[root]; o[root] = o[c]; o[c] = t;
        root = c;
    }
}

static void sort_order(uint32_t *o, const szou_entry_t *e, size_t n)
{
    size_t i;
    for (i = n / 2; i-- > 0;) sift(o, e, i, n);
    for (i = n; i-- > 1;) {
        uint32_t t = o[0]; o[0] = o[i]; o[i] = t;
        sift(o, e, 0, i);
    }
}

static int find_prefix(const uint32_t *o, const szou_entry_t *e, size_t n, const char *p, size_t plen)
{
    size_t lo = 0, hi = n;
    while (lo < hi) {
        size_t mid = lo + (hi - lo) / 2;
        int r = casecmp_n(p, plen, e[o[mid]].path);
        if (r == 0) return 1;
        if (r < 0) hi = mid; else lo = mid + 1;
    }
    return 0;
}

int szou_parse_table(const szou_header_t *h, const uint8_t *table, size_t table_bytes,
                     szou_entry_t *entries, uint32_t *order)
{
    sha256_ctx sc;
    uint8_t dig[32];
    uint64_t expect_off = 0;
    uint32_t i;
    int rc;
    if (!h || !table || !entries || !order) return SZOU_E_ARG;
    if (h->entry_count == 0 || h->entry_count > SZOU_MAX_ENTRIES) return SZOU_E_HEADER;
    if (table_bytes != (size_t)h->entry_count * SZOU_ENTRY_BYTES) return SZOU_E_LENGTH;
    sha256_init(&sc);
    sha256_update(&sc, table, table_bytes);
    sha256_final(&sc, dig);
    if (memcmp(dig, h->entries_sha256, 32) != 0) return SZOU_E_TABLE_SHA;

    for (i = 0; i < h->entry_count; i++) {
        const uint8_t *r = table + (size_t)i * SZOU_ENTRY_BYTES;
        szou_entry_t *e = &entries[i];
        if ((rc = szou_validate_path(r)) != SZOU_OK) return rc;
        memset(e, 0, sizeof *e);
        memcpy(e->path, r, SZOU_PATH_FIELD);
        e->attributes = rd32(r + 260);
        e->size = rd64(r + 264);
        e->payload_offset = rd64(r + 272);
        memcpy(e->sha256, r + 280, 32);
        if (!all_zero(r + 312, 8)) return SZOU_E_RESERVED;
        if (e->attributes & ~SZOU_ATTR_ALLOWED) return SZOU_E_ATTR;
        /* Ordered, contiguous, non-overlapping: each entry starts where the previous ended. */
        if (e->payload_offset != expect_off) return SZOU_E_LAYOUT;
        if (e->size > h->total_payload_bytes - expect_off) return SZOU_E_LAYOUT;
        expect_off += e->size;
        order[i] = i;
    }
    if (expect_off != h->total_payload_bytes) return SZOU_E_LAYOUT;

    sort_order(order, entries, h->entry_count);
    for (i = 1; i < h->entry_count; i++)
        if (szou_path_casecmp(entries[order[i - 1]].path, entries[order[i]].path) == 0)
            return SZOU_E_DUPLICATE;
    /* A file must not also be a parent directory of another entry. */
    for (i = 0; i < h->entry_count; i++) {
        const char *p = entries[i].path;
        size_t k;
        for (k = 0; p[k]; k++)
            if (p[k] == '\\' && find_prefix(order, entries, h->entry_count, p, k))
                return SZOU_E_CONFLICT;
    }
    return SZOU_OK;
}

int szou_verify_entry(const szou_header_t *h, const szou_entry_t *e, szou_read_fn rd, void *ctx,
                      uint8_t *buf, uint32_t buf_bytes)
{
    sha256_ctx sc;
    uint8_t dig[32];
    uint64_t done = 0;
    if (!h || !e || !rd || !buf || buf_bytes < 512) return SZOU_E_ARG;
    if (e->payload_offset > h->total_payload_bytes || e->size > h->total_payload_bytes - e->payload_offset)
        return SZOU_E_LAYOUT;
    sha256_init(&sc);
    while (done < e->size) {
        uint64_t left = e->size - done;
        uint32_t n = left < buf_bytes ? (uint32_t)left : buf_bytes;
        if (rd(ctx, h->payload_offset + e->payload_offset + done, buf, n) != 0) return SZOU_E_IO;
        sha256_update(&sc, buf, n);
        done += n;
    }
    sha256_final(&sc, dig);
    return memcmp(dig, e->sha256, 32) == 0 ? SZOU_OK : SZOU_E_SHA;
}

const char *szou_strerror(int code)
{
    switch (code) {
    case SZOU_OK: return "ok";
    case SZOU_E_ARG: return "invalid argument";
    case SZOU_E_MAGIC: return "bad SZOU magic";
    case SZOU_E_VERSION: return "unsupported SZOU version";
    case SZOU_E_HEADER: return "invalid SZOU header field";
    case SZOU_E_LENGTH: return "image length does not match header";
    case SZOU_E_TABLE_SHA: return "entry table SHA-256 mismatch";
    case SZOU_E_PATH: return "invalid destination path";
    case SZOU_E_DUPLICATE: return "duplicate destination path (case-insensitive)";
    case SZOU_E_CONFLICT: return "file path is also a directory of another entry";
    case SZOU_E_LAYOUT: return "payload layout not ordered/contiguous/non-overlapping";
    case SZOU_E_ATTR: return "unsupported attribute bits";
    case SZOU_E_RESERVED: return "nonzero reserved bytes";
    case SZOU_E_IO: return "source or target I/O failed";
    case SZOU_E_SHA: return "payload SHA-256 mismatch";
    case SZOU_E_NOMEM: return "out of memory";
    case SZOU_E_NO_AUTHORITY: return "no file-write authority bound for target volume";
    case SZOU_E_STATE: return "inconsistent staging/commit state";
    case SZOU_E_EXISTS: return "target already exists";
    case SZOU_E_FULL: return "target volume full";
    case SZOU_E_UNSUPPORTED: return "unsupported by target FAT32 writer";
    case SZOU_E_NAMES: return "invalid SZLN long-name/directory record";
    case SZOU_E_ORDER: return "SZLN records not strictly sorted by short path";
    default: return "unknown SZOU error";
    }
}

/* ---------------- SZOU v2 SZLN long-name/directory extension ---------------- */

int szou_parse_names_header(const szou_header_t *h, const uint8_t ext[SZLN_HEADER_BYTES], uint64_t image_bytes,
                            szou_names_header_t *out)
{
    uint32_t count;
    uint64_t rec_off;
    if (!h || !ext || !out) return SZOU_E_ARG;
    memset(out, 0, sizeof *out);
    if (h->version != SZOU_VERSION_NAMES || !h->names_offset) return SZOU_E_VERSION;
    if (ext[0] != 'S' || ext[1] != 'Z' || ext[2] != 'L' || ext[3] != 'N') return SZOU_E_MAGIC;
    if (rd16(ext + 4) != SZLN_VERSION) return SZOU_E_VERSION;
    if (rd16(ext + 6) != SZLN_HEADER_BYTES || rd32(ext + 12) != 0) return SZOU_E_HEADER;
    count = rd32(ext + 8);
    if (count == 0 || count > SZOU_MAX_ENTRIES) return SZOU_E_HEADER;
    if (h->names_offset > UINT64_MAX - SZLN_HEADER_BYTES) return SZOU_E_LENGTH;
    rec_off = h->names_offset + SZLN_HEADER_BYTES;
    if (image_bytes < rec_off || image_bytes - rec_off != (uint64_t)count * SZLN_RECORD_BYTES) return SZOU_E_LENGTH;
    out->record_count = count;
    out->records_offset = rec_off;
    memcpy(out->records_sha256, ext + 16, 32);
    return SZOU_OK;
}

uint16_t szou_upcase16(uint16_t c)
{
    if (c >= 'a' && c <= 'z') return (uint16_t)(c - 32);
    if (c >= 0xE0 && c <= 0xFE && c != 0xF7) return (uint16_t)(c - 32);
    if (c == 0xFF) return 0x178;
    if ((c >= 0x100 && c <= 0x137 && (c & 1)) || (c >= 0x139 && c <= 0x148 && !(c & 1)) ||
        (c >= 0x14A && c <= 0x177 && (c & 1)) || (c >= 0x179 && c <= 0x17E && !(c & 1)))
        return (uint16_t)(c - 1);
    if (c >= 0x3B1 && c <= 0x3C9 && c != 0x3C2) return (uint16_t)(c - 32);
    if (c >= 0x430 && c <= 0x44F) return (uint16_t)(c - 32);
    if (c >= 0x450 && c <= 0x45F) return (uint16_t)(c - 80);
    if (c >= 0xFF41 && c <= 0xFF5A) return (uint16_t)(c - 32);
    return c;
}

int szou_validate_long_name(const uint16_t *u, uint32_t n)
{
    uint32_t i;
    if (!u || n == 0 || n > SZLN_NAME_UNITS) return SZOU_E_NAMES;
    for (i = 0; i < n; i++) {
        uint16_t c = u[i];
        if (c < 0x20) return SZOU_E_NAMES;
        switch (c) {
        case '"': case '*': case '/': case ':': case '<': case '>': case '?': case '\\': case '|':
            return SZOU_E_NAMES;
        default: break;
        }
        if (c >= 0xD800 && c <= 0xDBFF) {
            if (i + 1 >= n || u[i + 1] < 0xDC00 || u[i + 1] > 0xDFFF) return SZOU_E_NAMES;
            i++;
        } else if (c >= 0xDC00 && c <= 0xDFFF) {
            return SZOU_E_NAMES;                          /* unpaired low surrogate */
        }
    }
    if (n == 1 && u[0] == '.') return SZOU_E_NAMES;
    if (n == 2 && u[0] == '.' && u[1] == '.') return SZOU_E_NAMES;
    if (u[n - 1] == ' ' || u[n - 1] == '.') return SZOU_E_NAMES;
    return SZOU_OK;
}

static size_t slen(const char *s) { size_t n = 0; while (s[n]) n++; return n; }

/* Find record by first plen chars of p (exact length match). */
static const szou_name_t *names_find_n(const szou_name_t *r, uint32_t n, const char *p, size_t plen)
{
    size_t lo = 0, hi = n;
    while (lo < hi) {
        size_t mid = lo + (hi - lo) / 2;
        int c = casecmp_n(p, plen, r[mid].path);
        if (c == 0) return &r[mid];
        if (c < 0) hi = mid; else lo = mid + 1;
    }
    return 0;
}

const szou_name_t *szou_names_find(const szou_name_t *n, uint32_t count, const char *p)
{
    if (!n || !p) return 0;
    return names_find_n(n, count, p, slen(p));
}

void szou_name_serialize(const szou_name_t *n, uint8_t out[SZLN_RECORD_BYTES])
{
    uint32_t k;
    memset(out, 0, SZLN_RECORD_BYTES);
    memcpy(out, n->path, slen(n->path));
    out[260] = n->kind;
    out[261] = n->attributes;
    out[262] = (uint8_t)n->units; out[263] = (uint8_t)(n->units >> 8);
    for (k = 0; k < n->units && k < SZLN_NAME_UNITS; k++) {
        out[264 + 2 * k] = (uint8_t)n->name[k];
        out[265 + 2 * k] = (uint8_t)(n->name[k] >> 8);
    }
}

/* Sibling-collision keys: bits 31..30 = 0 entry short name, 1 dir record
 * short name, 2 record long name; low 30 bits = index. */
typedef struct names_ctx { const szou_entry_t *e; const szou_name_t *r; } names_ctx_t;

static const char *key_path(const names_ctx_t *x, uint32_t k)
{
    return (k >> 30) == 0 ? x->e[k & 0x3FFFFFFFu].path : x->r[k & 0x3FFFFFFFu].path;
}
static size_t parent_len(const char *p) { size_t i, l = 0; for (i = 0; p[i]; i++) if (p[i] == '\\') l = i; return l; }

static int key_cmp(const names_ctx_t *x, uint32_t a, uint32_t b)
{
    const char *pa = key_path(x, a), *pb = key_path(x, b);
    size_t la = parent_len(pa), lb = parent_len(pb), i, na, nb;
    const char *sa, *sb;
    const uint16_t *ua = 0, *ub = 0;
    for (i = 0; i < la && i < lb; i++)
        if (up(pa[i]) != up(pb[i])) return (unsigned char)up(pa[i]) < (unsigned char)up(pb[i]) ? -1 : 1;
    if (la != lb) return la < lb ? -1 : 1;
    sa = pa + la + (pa[la] == '\\'); sb = pb + lb + (pb[lb] == '\\');
    if ((a >> 30) == 2) { ua = x->r[a & 0x3FFFFFFFu].name; na = x->r[a & 0x3FFFFFFFu].units; } else na = slen(sa);
    if ((b >> 30) == 2) { ub = x->r[b & 0x3FFFFFFFu].name; nb = x->r[b & 0x3FFFFFFFu].units; } else nb = slen(sb);
    for (i = 0; i < na && i < nb; i++) {
        uint16_t ca = szou_upcase16(ua ? ua[i] : (uint16_t)(uint8_t)sa[i]);
        uint16_t cb = szou_upcase16(ub ? ub[i] : (uint16_t)(uint8_t)sb[i]);
        if (ca != cb) return ca < cb ? -1 : 1;
    }
    return na == nb ? 0 : (na < nb ? -1 : 1);
}

static void key_sift(uint32_t *o, const names_ctx_t *x, size_t root, size_t n)
{
    for (;;) {
        size_t c = 2 * root + 1;
        uint32_t t;
        if (c >= n) return;
        if (c + 1 < n && key_cmp(x, o[c], o[c + 1]) < 0) c++;
        if (key_cmp(x, o[root], o[c]) >= 0) return;
        t = o[root]; o[root] = o[c]; o[c] = t;
        root = c;
    }
}

int szou_parse_names(const szou_header_t *h, const szou_names_header_t *nh, const uint8_t *records, size_t bytes,
                     const szou_entry_t *entries, const uint32_t *order, szou_name_t *out, uint32_t *scratch)
{
    sha256_ctx sc;
    uint8_t dig[32];
    names_ctx_t x;
    uint32_t i, R, E, nk = 0;
    size_t k;
    int rc;
    if (!h || !nh || !records || !entries || !order || !out || !scratch) return SZOU_E_ARG;
    if (h->version != SZOU_VERSION_NAMES) return SZOU_E_VERSION;
    R = nh->record_count; E = h->entry_count;
    if (R == 0 || R > SZOU_MAX_ENTRIES) return SZOU_E_HEADER;
    if (bytes != (size_t)R * SZLN_RECORD_BYTES) return SZOU_E_LENGTH;
    sha256_init(&sc);
    sha256_update(&sc, records, bytes);
    sha256_final(&sc, dig);
    if (memcmp(dig, nh->records_sha256, 32) != 0) return SZOU_E_TABLE_SHA;

    for (i = 0; i < R; i++) {
        const uint8_t *r = records + (size_t)i * SZLN_RECORD_BYTES;
        szou_name_t *n = &out[i];
        int is_entry;
        if ((rc = szou_validate_path(r)) != SZOU_OK) return rc;
        memset(n, 0, sizeof *n);
        memcpy(n->path, r, SZOU_PATH_FIELD);
        n->kind = r[260]; n->attributes = r[261]; n->units = rd16(r + 262);
        if (!all_zero(r + 776, 8)) return SZOU_E_RESERVED;
        if (n->units > SZLN_NAME_UNITS) return SZOU_E_NAMES;
        for (k = 0; k < 256; k++) {
            uint16_t u = rd16(r + 264 + 2 * k);
            if (k < n->units) n->name[k] = u;
            else if (u) return SZOU_E_RESERVED;            /* units after name_units must be zero */
        }
        if (n->units && (rc = szou_validate_long_name(n->name, n->units)) != SZOU_OK) return rc;
        if (i) {
            int c = szou_path_casecmp(out[i - 1].path, n->path);
            if (c == 0) return SZOU_E_DUPLICATE;
            if (c > 0) return SZOU_E_ORDER;
        }
        is_entry = find_prefix(order, entries, E, n->path, slen(n->path));
        if (n->kind == SZLN_KIND_FILE) {
            if (!is_entry) return SZOU_E_NAMES;
            if (n->attributes) return SZOU_E_ATTR;          /* the entry carries file attributes */
            if (!n->units) return SZOU_E_NAMES;
        } else if (n->kind == SZLN_KIND_DIR) {
            if (is_entry) return SZOU_E_CONFLICT;
            if (n->attributes & ~SZOU_ATTR_ALLOWED) return SZOU_E_ATTR;
        } else {
            return SZOU_E_NAMES;
        }
    }
    /* Complete directory list: every ancestor of every entry and record is a kind-2 record. */
    for (i = 0; i < E + R; i++) {
        const char *p = i < E ? entries[i].path : out[i - E].path;
        for (k = 0; p[k]; k++) {
            const szou_name_t *d;
            if (p[k] != '\\') continue;
            d = names_find_n(out, R, p, k);
            if (!d || d->kind != SZLN_KIND_DIR) return SZOU_E_NAMES;
        }
    }
    /* Sibling collisions: no short or long name may equal another child's. */
    for (i = 0; i < E; i++) scratch[nk++] = i;
    for (i = 0; i < R; i++) {
        if (out[i].kind == SZLN_KIND_DIR) scratch[nk++] = (1u << 30) | i;
        if (out[i].units) scratch[nk++] = (2u << 30) | i;
    }
    x.e = entries; x.r = out;
    for (k = nk / 2; k-- > 0;) key_sift(scratch, &x, k, nk);
    for (k = nk; k-- > 1;) {
        uint32_t t = scratch[0]; scratch[0] = scratch[k]; scratch[k] = t;
        key_sift(scratch, &x, 0, k);
    }
    for (k = 1; k < nk; k++)
        if (key_cmp(&x, scratch[k - 1], scratch[k]) == 0 &&
            szou_path_casecmp(key_path(&x, scratch[k - 1]), key_path(&x, scratch[k])) != 0)
            return SZOU_E_DUPLICATE;
    return SZOU_OK;
}
