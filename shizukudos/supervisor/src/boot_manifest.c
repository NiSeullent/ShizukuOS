/* SPDX-License-Identifier: GPL-2.0-only
 * ShizukuCore installed-target boot manifest validation and SHA-256.
 * The manifest is read-only loader input; nothing here allocates or writes it.
 * Freestanding: no console, libc or Supervisor globals, so the UEFI
 * direct-route loader may compile it unchanged and reuse shz_bman_check_table.
 */
#include "boot_manifest.h"

static const uint32_t k256[64] = {
    0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
    0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
    0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
    0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
    0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
    0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
    0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
    0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2};

#define ROR(x, n) (((x) >> (n)) | ((x) << (32 - (n))))

static void sha_block(uint32_t h[8], const uint8_t *p)
{
    uint32_t w[64], a, b, c, d, e, f, g, k, t1, t2;
    unsigned i;
    for (i = 0; i < 16; ++i)
        w[i] = (uint32_t)p[4 * i] << 24 | (uint32_t)p[4 * i + 1] << 16 | (uint32_t)p[4 * i + 2] << 8 | p[4 * i + 3];
    for (; i < 64; ++i)
        w[i] = w[i - 16] + (ROR(w[i - 15], 7) ^ ROR(w[i - 15], 18) ^ (w[i - 15] >> 3)) + w[i - 7] +
               (ROR(w[i - 2], 17) ^ ROR(w[i - 2], 19) ^ (w[i - 2] >> 10));
    a = h[0]; b = h[1]; c = h[2]; d = h[3]; e = h[4]; f = h[5]; g = h[6]; k = h[7];
    for (i = 0; i < 64; ++i) {
        t1 = k + (ROR(e, 6) ^ ROR(e, 11) ^ ROR(e, 25)) + ((e & f) ^ (~e & g)) + k256[i] + w[i];
        t2 = (ROR(a, 2) ^ ROR(a, 13) ^ ROR(a, 22)) + ((a & b) ^ (a & c) ^ (b & c));
        k = g; g = f; f = e; e = d + t1; d = c; c = b; b = a; a = t1 + t2;
    }
    h[0] += a; h[1] += b; h[2] += c; h[3] += d; h[4] += e; h[5] += f; h[6] += g; h[7] += k;
}

void shz_sha256(const void *data, uint64_t len, uint8_t out[32])
{
    uint32_t h[8] = {0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a,
                     0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19};
    const uint8_t *p = data;
    uint8_t tail[128];
    uint64_t left = len, bits = len * 8;
    unsigned i, n;
    while (left >= 64) { sha_block(h, p); p += 64; left -= 64; }
    for (i = 0; i < sizeof tail; ++i) tail[i] = i < left ? p[i] : 0;
    tail[left] = 0x80;
    n = left < 56 ? 64 : 128;
    for (i = 0; i < 8; ++i)
        tail[n - 1 - i] = (uint8_t)(bits >> (8 * i));
    sha_block(h, tail);
    if (n == 128) sha_block(h, tail + 64);
    for (i = 0; i < 8; ++i) {
        out[4 * i] = (uint8_t)(h[i] >> 24); out[4 * i + 1] = (uint8_t)(h[i] >> 16);
        out[4 * i + 2] = (uint8_t)(h[i] >> 8); out[4 * i + 3] = (uint8_t)h[i];
    }
}

/* Self-contained byte helpers: the UEFI direct-route loader may compile this
 * file without the Supervisor console/libc environment. */
static int bytes_eq(const uint8_t *a, const uint8_t *b, unsigned n)
{
    unsigned i;
    for (i = 0; i < n; ++i)
        if (a[i] != b[i]) return 0;
    return 1;
}

static void bytes_zero(void *p, unsigned n)
{
    volatile uint8_t *b = (volatile uint8_t *)p;
    unsigned i;
    for (i = 0; i < n; ++i) b[i] = 0;
}

/* "manifest: <msg>[ <name>]" truncated to err_size, always NUL terminated. */
static void bman_err(char *err, unsigned err_size, const char *msg, const char *name, unsigned name_max)
{
    static const char tag[] = "manifest: ";
    unsigned n = 0, i;
    if (!err || !err_size) return;
    for (i = 0; tag[i] && n + 1 < err_size; ++i) err[n++] = tag[i];
    for (i = 0; msg[i] && n + 1 < err_size; ++i) err[n++] = msg[i];
    if (name && n + 1 < err_size) err[n++] = ' ';
    for (i = 0; name && i < name_max && name[i] && n + 1 < err_size; ++i)
        err[n++] = (name[i] >= 0x20 && name[i] < 0x7f) ? name[i] : '?';
    err[n] = 0;
}

/* Exact NUL-terminated string within its fixed field, trailing bytes zero. */
static int field_ok(const char *f, unsigned size, int allow_empty)
{
    unsigned i = 0;
    while (i < size && f[i]) ++i;
    if (i == size || (!i && !allow_empty)) return 0;
    for (; i < size; ++i)
        if (f[i]) return 0;
    return 1;
}

static int field_eq(const char *f, unsigned size, const char *s)
{
    unsigned i;
    for (i = 0; i < size; ++i) {
        if (f[i] != s[i]) return 0;
        if (!s[i]) return 1;
    }
    return 0;
}

static int zero_bytes(const uint8_t *p, unsigned n)
{
    unsigned i;
    for (i = 0; i < n; ++i)
        if (p[i]) return 0;
    return 1;
}

static const shz_blob_t *loader_blob(const shz_info_t *info, const char *name, unsigned size)
{
    unsigned i;
    for (i = 0; i < SHZ_MAX_BLOBS; ++i)
        if (info->blobs[i].size && size && field_eq(info->blobs[i].name, sizeof info->blobs[i].name, name))
            return &info->blobs[i];
    return 0;
}

#define TFAIL(msg, name) do { bman_err(err, err_size, msg, name, 16); return -1; } while (0)

int shz_bman_check_table(const void *blob, uint64_t size, char *err, unsigned err_size)
{
    const shz_bman_header_t *h;
    const shz_bman_entry_t *e;
    uint8_t digest[32];
    uint32_t done = 0, i, j, progress;
    int stamped;
    if (err && err_size) err[0] = 0;
    if (!blob || size < sizeof *h || size > SHZ_BMAN_MAX_BYTES || ((uintptr_t)blob & 7))
        TFAIL("blob absent, misaligned or outside size bound", 0);
    h = (const shz_bman_header_t *)blob;
    e = (const shz_bman_entry_t *)((const uint8_t *)blob + sizeof *h);
    if (h->magic != SHZ_BMAN_MAGIC || h->version != SHZ_BMAN_VERSION || h->header_size != sizeof *h ||
        h->entry_size != sizeof *e || !h->entry_count || h->entry_count > SHZ_BMAN_MAX_ENTRIES ||
        h->total_size != sizeof *h + (uint32_t)h->entry_count * sizeof *e || h->total_size != size ||
        h->flags || h->reserved[0] || h->reserved[1])
        TFAIL("header rejected", 0);
    /* Installer identity: both stamped (nonzero) or both template (zero). */
    stamped = h->install_generation != 0;
    if (stamped == zero_bytes(h->install_id, 16)) {
        if (stamped) TFAIL("header install_id missing for stamped generation", 0);
        TFAIL("header install_id present without generation", 0);
    }
    shz_sha256(e, (uint64_t)h->entry_count * sizeof *e, digest);
    if (!bytes_eq(digest, h->entries_sha256, sizeof digest)) TFAIL("entry table hash mismatch", 0);

    for (i = 0; i < h->entry_count; ++i) {
        const shz_bman_entry_t *x = &e[i];
        const int has_blob = x->blob[0] != 0;
        if (!field_ok(x->component, sizeof x->component, 0) || !field_ok(x->parent, sizeof x->parent, 1) ||
            !field_ok(x->blob, sizeof x->blob, 1) || !field_ok(x->install_path, sizeof x->install_path, !has_blob) ||
            x->reserved || (x->flags & ~SHZ_BMAN_REQUIRED) || x->kind > SHZ_BMAN_KIND_RESOURCE ||
            (x->depends & (1u << i)) || (x->depends >> h->entry_count))
            TFAIL("entry malformed", x->component);
        if ((i == 0) != (x->kind == SHZ_BMAN_KIND_CORE)) TFAIL("entry 0 must be the only core entry", 0);
        if (x->kind == SHZ_BMAN_KIND_CORE &&
            (!field_eq(x->component, 16, SHZ_BMAN_ROOT_NAME) || x->parent[0] || has_blob || x->depends ||
             x->domain_id || !(x->flags & SHZ_BMAN_REQUIRED)))
            TFAIL("ShizukuCore root entry rejected", 0);
        if (x->kind == SHZ_BMAN_KIND_CHILD && !field_eq(x->parent, 16, SHZ_BMAN_ROOT_NAME))
            TFAIL("child is not parented by ShizukuCore:", x->component);
        if (x->kind == SHZ_BMAN_KIND_RESOURCE) {
            unsigned p;
            if (!has_blob || x->domain_id) TFAIL("resource rejected:", x->component);
            for (p = 1; p < h->entry_count; ++p)
                if (e[p].kind == SHZ_BMAN_KIND_CHILD && field_eq(e[p].component, 16, x->parent)) break;
            /* A resource names its owning child as parent; the child consumes it,
             * so the resource cannot depend on that child. */
            if (p == h->entry_count) TFAIL("resource parent is not a child:", x->component);
            if (x->depends & (1u << p)) TFAIL("resource depends on its owning child:", x->component);
        }
        for (j = 0; j < i; ++j)
            if (field_eq(e[j].component, 16, x->component) || (has_blob && field_eq(e[j].blob, 16, x->blob)))
                TFAIL("duplicate component or blob", x->component);
        if (!has_blob) {
            if (x->size || !zero_bytes(x->sha256, 32)) TFAIL("blob digest without blob:", x->component);
            continue;
        }
        if (field_eq(x->blob, 16, SHZ_BMAN_BLOB_NAME)) TFAIL("manifest cannot bind itself", 0);
    }
    /* Acyclic dependency graph (Kahn); entry 0 has no dependencies. */
    do {
        progress = 0;
        for (i = 0; i < h->entry_count; ++i)
            if (!(done & (1u << i)) && (e[i].depends & ~done) == 0) { done |= 1u << i; progress = 1; }
    } while (progress);
    if (done != (1u << h->entry_count) - 1) TFAIL("dependency cycle", 0);
    return stamped ? 0 : SHZ_BMAN_TEMPLATE;
}

#define FAIL(msg, name) do { bytes_zero(out, sizeof *out); bman_err(err, err_size, msg, name, 16); return -1; } while (0)

int shz_bman_parse(const shz_info_t *info, const shz_blob_t *blob, uint32_t cap_bits,
                   shz_bman_t *out, char *err, unsigned err_size)
{
    const shz_bman_header_t *h;
    const shz_bman_entry_t *e;
    uint8_t digest[32];
    uint32_t i, j;
    int table;
    bytes_zero(out, sizeof *out);
    if (!info || !blob || !blob->base) FAIL("blob absent", 0);
    table = shz_bman_check_table((const void *)(uintptr_t)blob->base, blob->size, err, err_size);
    if (table < 0) return -1;
    h = (const shz_bman_header_t *)(uintptr_t)blob->base;
    e = (const shz_bman_entry_t *)(uintptr_t)(blob->base + sizeof *h);
    if (h->loader_profile != info->loader_flags) FAIL("profile differs from loader route", 0);
    if ((h->required_caps & cap_bits) != h->required_caps) FAIL("required CPU capabilities absent", 0);
    for (i = 0; i < h->entry_count; ++i) {
        const shz_bman_entry_t *x = &e[i];
        if ((x->required_caps & cap_bits) != x->required_caps)
            FAIL("required CPU capabilities absent for", x->component);
        if (!x->blob[0]) {
            out->present |= 1u << i;
            continue;
        }
        {
            const shz_blob_t *b = loader_blob(info, x->blob, sizeof x->blob);
            if (!b) {
                if (x->flags & SHZ_BMAN_REQUIRED) FAIL("required blob absent:", x->blob);
                continue;
            }
            if (b->size != x->size) FAIL("blob size differs from installed target:", x->blob);
            shz_sha256((const void *)(uintptr_t)b->base, b->size, digest);
            if (!bytes_eq(digest, x->sha256, sizeof digest)) FAIL("blob SHA-256 differs from installed target:", x->blob);
            out->present |= 1u << i;
        }
    }
    /* No loader blob may enter the Core without manifest coverage. */
    for (i = 0; i < SHZ_MAX_BLOBS; ++i) {
        const shz_blob_t *b = &info->blobs[i];
        if (!b->size || field_eq(b->name, sizeof b->name, SHZ_BMAN_BLOB_NAME)) continue;
        for (j = 0; j < h->entry_count; ++j)
            if (e[j].blob[0] && field_eq(e[j].blob, 16, b->name)) break;
        if (j == h->entry_count) FAIL("loader blob not covered by manifest:", b->name);
    }
    out->header = h;
    out->entries = e;
    out->count = h->entry_count;
    return table;
}

const shz_bman_entry_t *shz_bman_component(const shz_bman_t *m, const char *component, unsigned *index)
{
    unsigned i;
    if (!m || !m->entries) return 0;
    for (i = 0; i < m->count; ++i)
        if (field_eq(m->entries[i].component, 16, component)) {
            if (index) *index = i;
            return &m->entries[i];
        }
    return 0;
}
