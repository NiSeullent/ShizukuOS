/* SPDX-License-Identifier: GPL-2.0-only
 * Host control for the direct-route installed-target manifest verifier
 * (kernel64/install_identity.h, used by supervisor/loader/loader.c k64_prepare and
 * kernel64/standalone/boot32.c) and the Kernel64 consumer (kernel64/install_identity.c).
 * Build (from the repository root):
 *   cc -std=gnu11 -Wall -Wextra -Werror -I shizukudos/supervisor/src \
 *      shizukudos/supervisor/loader/tests/test_direct_manifest.c shizukudos/kernel64/install_identity.c -o t
 * This is a host model of the verification logic only; it is not boot, VM or install evidence.
 */
#include <stdarg.h>
#include <stdio.h>
#include <string.h>
#define SHZ_INSTID_WANT_VERIFIER
#include "../../../kernel64/install_identity.h"

void kprintf(const char *fmt, ...);
void kprintf(const char *fmt, ...)
{
    va_list ap;
    va_start(ap, fmt);
    vprintf(fmt, ap);
    va_end(ap);
}

static int failures;
#define CHECK(cond, name) do { if (cond) printf("PASS %s\n", name); else { printf("FAIL %s\n", name); ++failures; } } while (0)

static uint64_t man[SHZ_BMAN_MAX_BYTES / 8];
static uint8_t kernel[70000], initrd[5000];

static void entry(shz_bman_entry_t *e, const char *component, const char *parent, const char *blob, const char *path,
                  uint32_t kind, uint32_t dom, uint32_t depends, uint32_t flags, const uint8_t *bytes, uint64_t size)
{
    memset(e, 0, sizeof *e);
    strcpy(e->component, component);
    strcpy(e->parent, parent);
    strcpy(e->blob, blob);
    strcpy(e->install_path, path);
    e->kind = kind; e->domain_id = dom; e->depends = depends; e->flags = flags; e->size = size;
    if (bytes) shz_instid_sha256(bytes, size, e->sha256);
}

/* The C1 seven-entry table; KERNEL32.BIN / KERNEL64.BIN digests are arbitrary (not loaded on this route). */
static uint32_t build(void)
{
    static const uint8_t other[3] = {1, 2, 3};
    shz_bman_header_t *h = (shz_bman_header_t *)man;
    shz_bman_entry_t *e = (shz_bman_entry_t *)(h + 1);
    memset(man, 0, sizeof man);
    entry(&e[0], "ShizukuCore", "", "", "", SHZ_BMAN_KIND_CORE, 0, 0, SHZ_BMAN_REQUIRED, 0, 0);
    entry(&e[1], "ShizukuDOS", "ShizukuCore", "", "", SHZ_BMAN_KIND_CHILD, SHZ_DOM_DOS16, 1, SHZ_BMAN_REQUIRED, 0, 0);
    entry(&e[2], "Shizuku32", "ShizukuCore", "KERNEL32.BIN", "\\SHZDOS\\KERNEL32.BIN", SHZ_BMAN_KIND_CHILD,
          SHZ_DOM_KERNEL32, 1, SHZ_BMAN_REQUIRED, other, 3);
    entry(&e[3], "Shizuku64", "ShizukuCore", "KERNEL64.BIN", "\\SHZDOS\\KERNEL64.BIN", SHZ_BMAN_KIND_CHILD,
          SHZ_DOM_KERNEL64, 1, SHZ_BMAN_REQUIRED, other, 2);
    entry(&e[4], "ShizukuOS", "ShizukuCore", "", "", SHZ_BMAN_KIND_CHILD, 5, 1u | 2u, SHZ_BMAN_REQUIRED, 0, 0);
    entry(&e[5], "Win64Runtime", "Shizuku64", "WIN64.IMG", "\\SHZDOS\\WIN64.IMG", SHZ_BMAN_KIND_RESOURCE, 0, 1,
          0, initrd, sizeof initrd);
    entry(&e[6], "Kernel64S", "Shizuku64", "KERNEL64S.BIN", "\\SHZDOS\\KERNEL64S.BIN", SHZ_BMAN_KIND_RESOURCE, 0, 1,
          0, kernel, sizeof kernel);
    h->magic = SHZ_BMAN_MAGIC; h->version = SHZ_BMAN_VERSION; h->header_size = 96; h->entry_size = 176;
    h->entry_count = 7; h->total_size = 96 + 7 * 176; h->loader_profile = 0; h->install_generation = 3;
    memset(h->install_id, 0xA5, sizeof h->install_id);
    shz_instid_sha256((const uint8_t *)e, 7 * 176, h->entries_sha256);
    return h->total_size;
}

static int verify(uint32_t size, int with_initrd, shz_install_identity_t *out, const char **why)
{
    return shz_instid_verify(man, size, kernel, sizeof kernel, with_initrd ? initrd : 0,
                             with_initrd ? sizeof initrd : 0, SHZ_INSTID_MULTIBOOT, out, why);
}

int main(void)
{
    static const uint8_t abc_digest[32] = {
        0xba, 0x78, 0x16, 0xbf, 0x8f, 0x01, 0xcf, 0xea, 0x41, 0x41, 0x40, 0xde, 0x5d, 0xae, 0x22, 0x23,
        0xb0, 0x03, 0x61, 0xa3, 0x96, 0x17, 0x7a, 0x9c, 0xb4, 0x10, 0xff, 0x61, 0xf2, 0x00, 0x15, 0xad};
    static const uint8_t two_block_digest[32] = {   /* "abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq" */
        0x24, 0x8d, 0x6a, 0x61, 0xd2, 0x06, 0x38, 0xb8, 0xe5, 0xc0, 0x26, 0x93, 0x0c, 0x3e, 0x60, 0x39,
        0xa3, 0x3c, 0xe4, 0x59, 0x64, 0xff, 0x21, 0x67, 0xf6, 0xec, 0xed, 0xd4, 0x19, 0xdb, 0x06, 0xc1};
    const char *two = "abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq";
    shz_install_identity_t id;
    shz_bootinfo_t bi;
    const char *why = 0;
    uint8_t d[32];
    uint32_t size, i;
    shz_bman_header_t *h = (shz_bman_header_t *)man;
    shz_bman_entry_t *e = (shz_bman_entry_t *)(h + 1);

    for (i = 0; i < sizeof kernel; ++i) kernel[i] = (uint8_t)(i * 7 + 1);
    for (i = 0; i < sizeof initrd; ++i) initrd[i] = (uint8_t)(i * 13 + 5);
    shz_instid_sha256((const uint8_t *)"abc", 3, d);
    CHECK(!memcmp(d, abc_digest, 32), "sha256 FIPS vector abc");
    shz_instid_sha256((const uint8_t *)two, strlen(two), d);
    CHECK(!memcmp(d, two_block_digest, 32), "sha256 FIPS two-block vector");

    size = build();
    CHECK(shz_instid_is_manifest((const uint8_t *)man, size) && !shz_instid_is_manifest(kernel, sizeof kernel),
          "module classification by SHZ_BMAN_MAGIC");
    CHECK(!verify(size, 1, &id, &why) && id.magic == SHZ_INSTID_MAGIC && id.flags == SHZ_INSTID_MULTIBOOT &&
          id.install_generation == 3 && id.install_id[0] == 0xA5 && !memcmp(id.entries_sha256, h->entries_sha256, 32),
          "valid manifest + matching kernel/initrd accepted");
    CHECK(!verify(size, 0, &id, &why), "valid manifest, no initrd loaded, WIN64.IMG not REQUIRED accepted");

    kernel[100] ^= 1;
    CHECK(verify(size, 1, &id, &why) && id.magic == 0 && strstr(why, "KERNEL64S.BIN SHA-256"), "kernel hash mismatch refused");
    printf("  why: %s\n", why);
    kernel[100] ^= 1;
    CHECK(shz_instid_verify(man, size, kernel, sizeof kernel - 1, initrd, sizeof initrd, SHZ_INSTID_MULTIBOOT, &id, &why) &&
          strstr(why, "KERNEL64S.BIN size"), "kernel size mismatch refused");
    initrd[7] ^= 0x80;
    CHECK(verify(size, 1, &id, &why) && strstr(why, "WIN64.IMG SHA-256"), "initrd hash mismatch refused");
    initrd[7] ^= 0x80;

    e[3].depends = 0;                              /* entry table edit without re-hashing */
    CHECK(verify(size, 1, &id, &why) && strstr(why, "entry table SHA-256"), "entry table hash mismatch refused");
    printf("  why: %s\n", why);

    size = build();
    h->install_generation = 0;
    CHECK(verify(size, 1, &id, &why) && strstr(why, "generation is zero"), "zero generation (unstamped template) refused");
    size = build();
    memset(h->install_id, 0, 16);
    CHECK(verify(size, 1, &id, &why) && strstr(why, "install id is zero"), "zero install id refused");

    size = build();                                /* no KERNEL64S.BIN entry: rename blob, re-hash */
    strcpy(e[6].blob, "KERNEL64X.BIN");
    shz_instid_sha256((const uint8_t *)e, 7 * 176, h->entries_sha256);
    CHECK(verify(size, 1, &id, &why) && strstr(why, "does not bind KERNEL64S.BIN"), "missing KERNEL64S.BIN entry refused");
    size = build();                                /* wrong installed path, re-hashed */
    memset(e[6].install_path, 0, sizeof e[6].install_path);
    strcpy(e[6].install_path, "\\EFI\\KERNEL64S.BIN");
    shz_instid_sha256((const uint8_t *)e, 7 * 176, h->entries_sha256);
    CHECK(verify(size, 1, &id, &why) && strstr(why, "install path"), "kernel install path mismatch refused");
    size = build();                                /* KERNEL64S.BIN parented by Shizuku32, re-hashed */
    strcpy(e[6].parent, "Shizuku32");
    shz_instid_sha256((const uint8_t *)e, 7 * 176, h->entries_sha256);
    CHECK(verify(size, 1, &id, &why) && strstr(why, "not a Shizuku64 resource"), "kernel under wrong parent refused");
    size = build();
    CHECK(verify(size - 176, 1, &id, &why) && strstr(why, "header"), "truncated manifest refused");
    size = build();
    e[5].flags = SHZ_BMAN_REQUIRED;
    shz_instid_sha256((const uint8_t *)e, 7 * 176, h->entries_sha256);
    CHECK(verify(size, 0, &id, &why) && strstr(why, "requires WIN64.IMG"), "REQUIRED WIN64.IMG absent refused");

    /* Kernel64 consumer. */
    memset(&bi, 0, sizeof bi);
    bi.size = sizeof bi;
    CHECK(k64_install_identity_init(&bi) == 1 && k64_install_generation() == 0 && !k64_install_identity(),
          "absent manifest: all-zero install tail is unattested");
    bi.size = (uint32_t)__builtin_offsetof(shz_bootinfo_t, install);
    CHECK(k64_install_identity_init(&bi) == 1 && !k64_install_identity(), "old writer without tail is unattested");
    size = build();
    CHECK(!verify(size, 1, &id, &why), "re-verify for consumer");
    bi.size = sizeof bi;
    bi.install = id;
    CHECK(k64_install_identity_init(&bi) == 0 && k64_install_generation() == 3 && k64_install_identity() &&
          k64_install_identity()->flags == SHZ_INSTID_MULTIBOOT, "verified tail attested");
    bi.install.flags = SHZ_INSTID_MULTIBOOT | SHZ_INSTID_UEFI_DIRECT;
    CHECK(k64_install_identity_init(&bi) < 0 && k64_install_generation() == 0 && !k64_install_identity(),
          "two route bits malformed, not attested");
    bi.install = id;
    bi.install.install_generation = 0;
    CHECK(k64_install_identity_init(&bi) < 0 && !k64_install_identity(), "zero generation tail malformed");
    bi.install = id;
    bi.install.magic ^= 1;
    CHECK(k64_install_identity_init(&bi) < 0, "bad magic tail malformed");

    printf("%s: %d failure(s)\n", failures ? "FAIL" : "PASS", failures);
    return failures != 0;
}
