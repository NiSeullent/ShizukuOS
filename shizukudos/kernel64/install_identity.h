/* SPDX-License-Identifier: GPL-2.0-only
 * Installed-target identity of the running Kernel64 (routing02 contract C2/C3).
 *
 * Kernel64 side (install_identity.c): consumes shz_bootinfo_t.install written by
 * exactly one boot route -- ShizukuCore manifest admission (Supervisor), the UEFI
 * boot manager's mode=kernel64 or the BIOS Multiboot stub -- after that route
 * verified \SHZDOS\SHZBOOT.MAN against the bytes it actually loaded.  An all-zero
 * tail is the historical unattested route; it is reported as such, never as
 * attested.
 *
 * Direct-route verifier (SHZ_INSTID_WANT_VERIFIER): a freestanding, allocation
 * free, libc free check shared by supervisor/loader/loader.c (PE32+ EFI, MS ABI)
 * and kernel64/standalone/boot32.c (32-bit protected mode).  It applies the
 * header/entry/hierarchy rules of supervisor/src/boot_manifest.c shz_bman_parse()
 * that are meaningful without a Supervisor blob table and additionally REQUIRES
 * the Shizuku64 resource KERNEL64S.BIN (and WIN64.IMG when an initial RAM image
 * was loaded) to equal the loaded bytes by size and SHA-256.  Any mismatch is a
 * refusal: an attested target never boots a different kernel.
 */
#ifndef SHZ_K64_INSTALL_IDENTITY_H
#define SHZ_K64_INSTALL_IDENTITY_H
#include <stdint.h>
#include "../abi/shz_abi.h"

/* 0 attested, 1 absent (historical unattested route), <0 malformed (not attested). */
int k64_install_identity_init(const shz_bootinfo_t *bi);
/* Verified install generation; 0 when unattested or malformed. */
uint64_t k64_install_generation(void);
/* Kernel copy of the verified identity; NULL when unattested or malformed. */
const shz_install_identity_t *k64_install_identity(void);

#ifdef SHZ_INSTID_WANT_VERIFIER
#include "../supervisor/src/boot_manifest.h"

#define SHZ_INSTID_KERNEL_BLOB "KERNEL64S.BIN"
#define SHZ_INSTID_INITRD_BLOB "WIN64.IMG"
#define SHZ_INSTID_OWNER "Shizuku64"
#define SHZ_INSTID_KERNEL_PATH "\\SHZDOS\\KERNEL64S.BIN"   /* the exact files both direct routes load */
#define SHZ_INSTID_INITRD_PATH "\\SHZDOS\\WIN64.IMG"

static const uint32_t shz_instid_k256[64] = {
    0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
    0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
    0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
    0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
    0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
    0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
    0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
    0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2};

#define SHZ_INSTID_ROR(x, n) (((x) >> (n)) | ((x) << (32 - (n))))

static inline void shz_instid_sha_block(uint32_t h[8], const volatile uint8_t *p)
{
    uint32_t w[64], a, b, c, d, e, f, g, k, t1, t2;
    unsigned i;
    for (i = 0; i < 16; ++i)
        w[i] = (uint32_t)p[4 * i] << 24 | (uint32_t)p[4 * i + 1] << 16 | (uint32_t)p[4 * i + 2] << 8 | p[4 * i + 3];
    for (; i < 64; ++i)
        w[i] = w[i - 16] + (SHZ_INSTID_ROR(w[i - 15], 7) ^ SHZ_INSTID_ROR(w[i - 15], 18) ^ (w[i - 15] >> 3)) +
               w[i - 7] + (SHZ_INSTID_ROR(w[i - 2], 17) ^ SHZ_INSTID_ROR(w[i - 2], 19) ^ (w[i - 2] >> 10));
    a = h[0]; b = h[1]; c = h[2]; d = h[3]; e = h[4]; f = h[5]; g = h[6]; k = h[7];
    for (i = 0; i < 64; ++i) {
        t1 = k + (SHZ_INSTID_ROR(e, 6) ^ SHZ_INSTID_ROR(e, 11) ^ SHZ_INSTID_ROR(e, 25)) + ((e & f) ^ (~e & g)) +
             shz_instid_k256[i] + w[i];
        t2 = (SHZ_INSTID_ROR(a, 2) ^ SHZ_INSTID_ROR(a, 13) ^ SHZ_INSTID_ROR(a, 22)) + ((a & b) ^ (a & c) ^ (b & c));
        k = g; g = f; f = e; e = d + t1; d = c; c = b; b = a; a = t1 + t2;
    }
    h[0] += a; h[1] += b; h[2] += c; h[3] += d; h[4] += e; h[5] += f; h[6] += g; h[7] += k;
}

/* SHA-256 (FIPS 180-4), same digest as boot_manifest.c shz_sha256(); 64-bit
 * arithmetic is limited to shifts and compares so the 32-bit stub needs no libgcc. */
static inline void shz_instid_sha256(const volatile uint8_t *p, uint64_t len, uint8_t out[32])
{
    uint32_t h[8] = {0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a,
                     0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19};
    uint8_t tail[128];
    const uint64_t bits = len << 3;
    unsigned i, n, left;
    while (len >= 64) { shz_instid_sha_block(h, p); p += 64; len -= 64; }
    left = (unsigned)len;
    for (i = 0; i < sizeof tail; ++i)
        tail[i] = i < left ? p[i] : 0;
    tail[left] = 0x80;
    n = left < 56 ? 64 : 128;
    for (i = 0; i < 8; ++i)
        tail[n - 1 - i] = (uint8_t)(bits >> (8 * i));
    shz_instid_sha_block(h, tail);
    if (n == 128) shz_instid_sha_block(h, tail + 64);
    for (i = 0; i < 8; ++i) {
        out[4 * i] = (uint8_t)(h[i] >> 24); out[4 * i + 1] = (uint8_t)(h[i] >> 16);
        out[4 * i + 2] = (uint8_t)(h[i] >> 8); out[4 * i + 3] = (uint8_t)h[i];
    }
}

static inline int shz_instid_field_ok(const char *f, unsigned size, int allow_empty)
{
    unsigned i = 0;
    while (i < size && f[i]) ++i;
    if (i == size || (!i && !allow_empty)) return 0;
    for (; i < size; ++i)
        if (f[i]) return 0;
    return 1;
}

static inline int shz_instid_field_eq(const char *f, unsigned size, const char *s)
{
    unsigned i;
    for (i = 0; i < size; ++i) {
        if (f[i] != s[i]) return 0;
        if (!s[i]) return 1;
    }
    return 0;
}

static inline int shz_instid_zero(const uint8_t *p, unsigned n)
{
    unsigned i;
    for (i = 0; i < n; ++i)
        if (p[i]) return 0;
    return 1;
}

static inline int shz_instid_same(const uint8_t *a, const uint8_t *b, unsigned n)
{
    unsigned i, d = 0;
    for (i = 0; i < n; ++i) d |= (unsigned)(a[i] ^ b[i]);
    return d == 0;
}

/* True when the first 8 bytes are SHZ_BMAN_MAGIC (Multiboot module classification). */
static inline int shz_instid_is_manifest(const volatile uint8_t *p, uint64_t size)
{
    uint64_t m = 0;
    unsigned i;
    if (size < 8) return 0;
    for (i = 0; i < 8; ++i) m |= (uint64_t)p[i] << (8 * i);
    return m == SHZ_BMAN_MAGIC;
}

/* Verify a manifest snapshot (`man`, 8-byte aligned private copy, `man_size`
 * bytes) against the loaded kernel and optional initrd.  Returns 0 and fills
 * *out with exactly `route` (one SHZ_INSTID_* bit); otherwise -1, *out zeroed,
 * *why names the refused rule. */
static inline int shz_instid_verify(const void *man, uint64_t man_size,
                             const volatile uint8_t *kernel, uint64_t kernel_size,
                             const volatile uint8_t *initrd, uint64_t initrd_size,
                             uint32_t route, shz_install_identity_t *out, const char **why)
{
    const shz_bman_header_t *h = (const shz_bman_header_t *)man;
    const shz_bman_entry_t *e = (const shz_bman_entry_t *)((const uint8_t *)man + sizeof *h);
    const shz_bman_entry_t *kentry = 0, *ientry = 0;
    uint8_t digest[32];
    uint32_t i, j, done = 0, progress;
    unsigned owner = 0;

#define SHZ_INSTID_FAIL(text) do { *why = (text); return -1; } while (0)
    for (i = 0; i < sizeof *out; ++i) ((uint8_t *)out)[i] = 0;
    if (route != SHZ_INSTID_UEFI_DIRECT && route != SHZ_INSTID_MULTIBOOT && route != SHZ_INSTID_SUPERVISOR)
        SHZ_INSTID_FAIL("internal error: route flag");
    if (!man || ((uintptr_t)man & 7) || man_size < sizeof *h || man_size > SHZ_BMAN_MAX_BYTES)
        SHZ_INSTID_FAIL("manifest size outside [96, 4096] bytes");
    if (h->magic != SHZ_BMAN_MAGIC || h->version != SHZ_BMAN_VERSION || h->header_size != sizeof *h ||
        h->entry_size != sizeof *e || !h->entry_count || h->entry_count > SHZ_BMAN_MAX_ENTRIES ||
        h->total_size != sizeof *h + (uint32_t)h->entry_count * sizeof *e || h->total_size != man_size ||
        h->flags || h->reserved[0] || h->reserved[1])
        SHZ_INSTID_FAIL("manifest header rejected");
    if (!h->install_generation)
        SHZ_INSTID_FAIL("manifest install generation is zero (unstamped installer template)");
    if (shz_instid_zero(h->install_id, sizeof h->install_id))
        SHZ_INSTID_FAIL("manifest install id is zero (unstamped installer template)");
    /* Contract C1: the installed manifest is written for loader profile 0. */
    if (h->loader_profile)
        SHZ_INSTID_FAIL("manifest loader profile is not the installed profile 0");
    shz_instid_sha256((const volatile uint8_t *)e, (uint64_t)h->entry_count * sizeof *e, digest);
    if (!shz_instid_same(digest, h->entries_sha256, 32))
        SHZ_INSTID_FAIL("manifest entry table SHA-256 mismatch");

    for (i = 0; i < h->entry_count; ++i) {
        const shz_bman_entry_t *x = &e[i];
        const int has_blob = x->blob[0] != 0;
        if (!shz_instid_field_ok(x->component, sizeof x->component, 0) ||
            !shz_instid_field_ok(x->parent, sizeof x->parent, 1) || !shz_instid_field_ok(x->blob, sizeof x->blob, 1) ||
            !shz_instid_field_ok(x->install_path, sizeof x->install_path, !has_blob) || x->reserved ||
            (x->flags & ~(uint32_t)SHZ_BMAN_REQUIRED) || x->kind > SHZ_BMAN_KIND_RESOURCE ||
            (x->depends & (1u << i)) || (x->depends >> h->entry_count))
            SHZ_INSTID_FAIL("manifest entry malformed");
        if ((i == 0) != (x->kind == SHZ_BMAN_KIND_CORE))
            SHZ_INSTID_FAIL("manifest entry 0 must be the only ShizukuCore entry");
        if (x->kind == SHZ_BMAN_KIND_CORE &&
            (!shz_instid_field_eq(x->component, 16, SHZ_BMAN_ROOT_NAME) || x->parent[0] || has_blob ||
             x->depends || x->domain_id || !(x->flags & SHZ_BMAN_REQUIRED)))
            SHZ_INSTID_FAIL("manifest ShizukuCore root entry rejected");
        if (x->kind == SHZ_BMAN_KIND_CHILD && !shz_instid_field_eq(x->parent, 16, SHZ_BMAN_ROOT_NAME))
            SHZ_INSTID_FAIL("manifest child is not parented by ShizukuCore");
        if (x->kind == SHZ_BMAN_KIND_RESOURCE) {
            unsigned p;
            if (!has_blob || x->domain_id) SHZ_INSTID_FAIL("manifest resource entry rejected");
            for (p = 1; p < h->entry_count; ++p)
                if (e[p].kind == SHZ_BMAN_KIND_CHILD && shz_instid_field_eq(e[p].component, 16, x->parent)) break;
            if (p == h->entry_count) SHZ_INSTID_FAIL("manifest resource parent is not a ShizukuCore child");
            if (x->depends & (1u << p)) SHZ_INSTID_FAIL("manifest resource depends on its owning child");
        }
        for (j = 0; j < i; ++j)
            if (shz_instid_field_eq(e[j].component, 16, x->component) ||
                (has_blob && shz_instid_field_eq(e[j].blob, 16, x->blob)))
                SHZ_INSTID_FAIL("manifest duplicate component or blob");
        if (!has_blob) {
            if (x->size || !shz_instid_zero(x->sha256, 32)) SHZ_INSTID_FAIL("manifest digest without blob");
            continue;
        }
        if (shz_instid_field_eq(x->blob, 16, SHZ_BMAN_BLOB_NAME)) SHZ_INSTID_FAIL("manifest binds itself");
        if (shz_instid_field_eq(x->blob, 16, SHZ_INSTID_KERNEL_BLOB)) kentry = x;
        if (shz_instid_field_eq(x->blob, 16, SHZ_INSTID_INITRD_BLOB)) ientry = x;
    }
    for (i = 1; i < h->entry_count && !owner; ++i)
        if (e[i].kind == SHZ_BMAN_KIND_CHILD && shz_instid_field_eq(e[i].component, 16, SHZ_INSTID_OWNER)) owner = i;
    do {
        progress = 0;
        for (i = 0; i < h->entry_count; ++i)
            if (!(done & (1u << i)) && (e[i].depends & ~done) == 0) { done |= 1u << i; progress = 1; }
    } while (progress);
    if (done != (1u << h->entry_count) - 1) SHZ_INSTID_FAIL("manifest dependency cycle");

    /* Direct-route rules: Kernel64 is the Shizuku64 (SZLm) child of ShizukuCore. */
    if (!owner || e[owner].domain_id != SHZ_DOM_KERNEL64)
        SHZ_INSTID_FAIL("manifest has no Shizuku64 child for domain Kernel64");
    if (!kentry)
        SHZ_INSTID_FAIL("manifest does not bind KERNEL64S.BIN (required on the direct Kernel64 route)");
    if (kentry->kind != SHZ_BMAN_KIND_RESOURCE || !shz_instid_field_eq(kentry->parent, 16, SHZ_INSTID_OWNER))
        SHZ_INSTID_FAIL("manifest KERNEL64S.BIN is not a Shizuku64 resource");
    if (!shz_instid_field_eq(kentry->install_path, 64, SHZ_INSTID_KERNEL_PATH))
        SHZ_INSTID_FAIL("manifest KERNEL64S.BIN install path is not \\SHZDOS\\KERNEL64S.BIN");
    if (!kernel || kentry->size != kernel_size)
        SHZ_INSTID_FAIL("loaded KERNEL64S.BIN size differs from the installed target");
    shz_instid_sha256(kernel, kernel_size, digest);
    if (!shz_instid_same(digest, kentry->sha256, 32))
        SHZ_INSTID_FAIL("loaded KERNEL64S.BIN SHA-256 differs from the installed target");
    if (initrd_size) {
        if (!ientry)
            SHZ_INSTID_FAIL("an initial RAM image was loaded but the manifest does not bind WIN64.IMG");
        if (ientry->kind != SHZ_BMAN_KIND_RESOURCE || !shz_instid_field_eq(ientry->parent, 16, SHZ_INSTID_OWNER))
            SHZ_INSTID_FAIL("manifest WIN64.IMG is not a Shizuku64 resource");
        if (!shz_instid_field_eq(ientry->install_path, 64, SHZ_INSTID_INITRD_PATH))
            SHZ_INSTID_FAIL("manifest WIN64.IMG install path is not \\SHZDOS\\WIN64.IMG");
        if (!initrd || ientry->size != initrd_size)
            SHZ_INSTID_FAIL("loaded WIN64.IMG size differs from the installed target");
        shz_instid_sha256(initrd, initrd_size, digest);
        if (!shz_instid_same(digest, ientry->sha256, 32))
            SHZ_INSTID_FAIL("loaded WIN64.IMG SHA-256 differs from the installed target");
    } else if (ientry && (ientry->flags & SHZ_BMAN_REQUIRED)) {
        SHZ_INSTID_FAIL("manifest requires WIN64.IMG but no initial RAM image was loaded");
    }
#undef SHZ_INSTID_FAIL

    out->magic = SHZ_INSTID_MAGIC;
    out->flags = route;
    out->install_generation = h->install_generation;
    for (i = 0; i < 16; ++i) out->install_id[i] = h->install_id[i];
    for (i = 0; i < 32; ++i) out->entries_sha256[i] = h->entries_sha256[i];
    *why = "verified";
    return 0;
}
#endif /* SHZ_INSTID_WANT_VERIFIER */
#endif
