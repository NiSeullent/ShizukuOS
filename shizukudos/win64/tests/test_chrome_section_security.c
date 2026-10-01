/* SPDX-License-Identifier: GPL-2.0-only
 * Host contracts for the production section SD parser/access checks. */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "../../kernel64/ipc_section_security.h"

static unsigned checked, failed;
#define CHECK(c) do { ++checked; if (!(c)) { ++failed; fprintf(stderr, "FAIL line %u: %s\n", __LINE__, #c); } } while (0)
typedef struct { uint8_t bytes[256]; uint32_t length; unsigned reads; } fixture;
#define BASE 0x1000u

static int read_fixture(void *ctx, uint64_t address, void *out, size_t size)
{
    fixture *f = ctx;
    ++f->reads;
    if (address < BASE || address - BASE > f->length || size > f->length - (address - BASE)) return -1;
    memcpy(out, f->bytes + (address - BASE), size);
    return 0;
}
static void put16(uint8_t *p, uint16_t v) { memcpy(p, &v, 2); }
static void put64(uint8_t *p, uint64_t v) { memcpy(p, &v, 8); }
static void empty(fixture *f, int relative)
{
    memset(f, 0, sizeof *f);
    f->length = sizeof f->bytes;
    f->bytes[0] = 1;
    put16(f->bytes + 2, SHZ_SEC_DACL_PRESENT | (relative ? SHZ_SEC_RELATIVE : 0));
    if (relative) shz_sec_put32(f->bytes + 16, 64);
    else put64(f->bytes + 32, BASE + 64);
    f->bytes[64] = 2;
    put16(f->bytes + 66, 8);
}

int main(void)
{
    fixture f;
    uint8_t *sd = malloc(SHZ_SEC_MAX), *other = malloc(SHZ_SEC_MAX);
    uint32_t n = 0, other_n = 0, seed = 0x43524f4du, i;
    CHECK(sd && other);
    if (!sd || !other) return 1;
    empty(&f, 0);
    CHECK(shz_sec_capture(&f, read_fixture, BASE, sd, &n) == 0 && n == 28);
    CHECK(sd[0] == 1 && shz_sec_u16(sd + 2) == 0x8004 && shz_sec_u32(sd + 16) == 20);
    CHECK(shz_sec_section_check(sd, n, 0x20007, 0x5) == 0); /* writable -> read-only */
    CHECK(shz_sec_section_check(sd, n, 0x5, 0x2) == SHZ_SEC_DENIED); /* Chromium's write probe */
    CHECK(shz_sec_section_check(sd, n, 0x5, 0x5) == 0); /* same access */
    CHECK(shz_sec_section_check(sd, n, 0x5, 0x1) == 0); /* query subset */
    CHECK(shz_sec_section_check(sd, n, 0, 0x4) == SHZ_SEC_DENIED); /* OpenFileMapping */
    CHECK(shz_sec_section_check(sd, n, 0x5, 0x20005) == SHZ_SEC_UNSUPPORTED); /* owner evaluation */
    empty(&f, 1);
    CHECK(shz_sec_capture(&f, read_fixture, BASE, other, &other_n) == 0 && other_n == n && !memcmp(sd, other, n));
    memset(f.bytes, 0, sizeof f.bytes);
    CHECK(shz_sec_section_check(sd, n, 0x5, 0x2) == SHZ_SEC_DENIED); /* owned snapshot */
    CHECK(shz_sec_section_access(0x80000000) == 0x20005);
    CHECK(shz_sec_section_access(0x40000000) == 0x20012);
    CHECK(shz_sec_section_access(0x20000000) == 0x20008);
    CHECK(shz_sec_section_access(0x10000000) == 0xf001f);
    CHECK(shz_sec_section_access(0xc0000000) == 0x20017);

    empty(&f, 0);
    put64(f.bytes + 32, 0); /* present NULL DACL allows newly requested rights */
    CHECK(shz_sec_capture(&f, read_fixture, BASE, sd, &n) == 0 && n == 20);
    CHECK(shz_sec_section_check(sd, n, 0x5, 0x2) == 0);
    empty(&f, 0);
    put16(f.bytes + 2, 0); /* absent DACL: pointer bytes do not matter */
    put64(f.bytes + 32, UINT64_MAX);
    CHECK(shz_sec_capture(&f, read_fixture, BASE, sd, &n) == 0 && n == 20);
    CHECK(shz_sec_section_check(sd, n, 0x5, 0x2) == 0);
    CHECK(shz_sec_capture(&f, read_fixture, 0, sd, &n) == 0 && n == 0);
    CHECK(shz_sec_section_check(0, 0, 0x5, 0x2) == 0);

    /* All four components survive absolute -> self-relative conversion. */
    empty(&f, 0);
    put16(f.bytes + 2, SHZ_SEC_DACL_PRESENT | SHZ_SEC_SACL_PRESENT);
    put64(f.bytes + 8, BASE + 80); put64(f.bytes + 16, BASE + 96); put64(f.bytes + 24, BASE + 112);
    f.bytes[80] = f.bytes[96] = 1; f.bytes[81] = f.bytes[97] = 1;
    f.bytes[87] = 5; f.bytes[103] = 1;
    shz_sec_put32(f.bytes + 88, 21); shz_sec_put32(f.bytes + 104, 0);
    f.bytes[112] = 4; put16(f.bytes + 114, 8);
    CHECK(shz_sec_capture(&f, read_fixture, BASE, sd, &n) == 0 && n == 60);
    CHECK(!memcmp(sd + shz_sec_u32(sd + 4), f.bytes + 80, 12));
    CHECK(!memcmp(sd + shz_sec_u32(sd + 8), f.bytes + 96, 12));
    CHECK(!memcmp(sd + shz_sec_u32(sd + 12), f.bytes + 112, 8));
    CHECK(!memcmp(sd + shz_sec_u32(sd + 16), f.bytes + 64, 8));
    CHECK(shz_sec_section_check(sd, n, 0x5, 0x2) == SHZ_SEC_DENIED); /* empty SACL is harmless */

    empty(&f, 1);
    put16(f.bytes + 2, SHZ_SEC_RELATIVE | SHZ_SEC_DACL_PRESENT | SHZ_SEC_SACL_PRESENT);
    shz_sec_put32(f.bytes + 12, 64); shz_sec_put32(f.bytes + 16, 0); /* NULL DACL + SACL */
    put16(f.bytes + 66, 28); put16(f.bytes + 68, 1);
    f.bytes[72] = 17; put16(f.bytes + 74, 20); /* SYSTEM_MANDATORY_LABEL_ACE */
    shz_sec_put32(f.bytes + 76, 1); f.bytes[80] = 1; f.bytes[81] = 1;
    f.bytes[87] = 16; shz_sec_put32(f.bytes + 88, 0x3000);
    CHECK(shz_sec_capture(&f, read_fixture, BASE, sd, &n) == 0);
    CHECK(shz_sec_section_check(sd, n, 0x5, 0x2) == SHZ_SEC_UNSUPPORTED);
    CHECK(shz_sec_section_check(sd, n, 0x7, 0x2) == 0); /* existing grant still preserved */

    empty(&f, 1);
    put16(f.bytes + 66, 12); put16(f.bytes + 68, 1); put16(f.bytes + 74, 4);
    CHECK(shz_sec_capture(&f, read_fixture, BASE, sd, &n) == 0);
    CHECK(shz_sec_section_check(sd, n, 0x5, 0x2) == SHZ_SEC_UNSUPPORTED); /* no ACL/token guess */
    CHECK(shz_sec_section_check(sd, n, 0x7, 0x2) == 0); /* already granted */
    put16(f.bytes + 74, 0);
    CHECK(shz_sec_capture(&f, read_fixture, BASE, sd, &n) == SHZ_SEC_BAD_ACL);
    empty(&f, 1); shz_sec_put32(f.bytes + 16, 4);
    CHECK(shz_sec_capture(&f, read_fixture, BASE, sd, &n) == SHZ_SEC_BAD_SD);
    empty(&f, 0); put64(f.bytes + 32, UINT64_MAX - 3);
    CHECK(shz_sec_capture(&f, read_fixture, BASE, sd, &n) == SHZ_SEC_AV);
    empty(&f, 0); f.length = 39;
    CHECK(shz_sec_capture(&f, read_fixture, BASE, sd, &n) == SHZ_SEC_AV);
    empty(&f, 1); f.bytes[0] = 2;
    CHECK(shz_sec_capture(&f, read_fixture, BASE, sd, &n) == SHZ_SEC_BAD_SD);
    empty(&f, 1); put16(f.bytes + 66, 7);
    CHECK(shz_sec_capture(&f, read_fixture, BASE, sd, &n) == SHZ_SEC_BAD_ACL);
    empty(&f, 1); f.bytes[64] = 3;
    CHECK(shz_sec_capture(&f, read_fixture, BASE, sd, &n) == SHZ_SEC_BAD_ACL);
    CHECK(shz_sec_section_check(sd, 3, 0x5, 0x2) == SHZ_SEC_BAD_SD);

    /* Random descriptors and stored blobs: callback bounds and sanitizer
     * instrumentation provide independent memory safety checks. */
    for (i = 0; i < 100000; ++i) {
        uint32_t j;
        int32_t st;
        memset(&f, 0, sizeof f);
        for (j = 0; j < sizeof f.bytes; ++j) { seed ^= seed << 13; seed ^= seed >> 17; seed ^= seed << 5; f.bytes[j] = seed; }
        f.length = seed % (sizeof f.bytes + 1);
        if (!(i & 3)) f.bytes[0] = 1;
        st = shz_sec_capture(&f, read_fixture, BASE, sd, &n);
        CHECK(st || (n >= 20 && n <= SHZ_SEC_MAX && sd[0] == 1 && (shz_sec_u16(sd + 2) & SHZ_SEC_RELATIVE)));
        st = shz_sec_section_check(f.bytes, f.length, 0x5, 0x2);
        CHECK(st == 0 || st == SHZ_SEC_BAD_SD || st == SHZ_SEC_BAD_ACL || st == SHZ_SEC_DENIED || st == SHZ_SEC_UNSUPPORTED);
    }
    free(sd); free(other);
    printf("section security host: %u checks, %u failed\n", checked, failed);
    return failed ? 1 : 0;
}
