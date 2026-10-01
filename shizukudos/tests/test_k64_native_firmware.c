/* SPDX-License-Identifier: GPL-2.0-only */
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#if __has_include("../kernel64/standalone/native_firmware.h")
#include "../kernel64/standalone/native_firmware.h"

static unsigned checks, failures;
#define CHECK(name, condition) do { ++checks; if (!(condition)) { ++failures; fprintf(stderr, "FAIL %s\n", name); } } while (0)
struct input { uint8_t bytes[4096]; uint32_t length, reads, invalid_reads; uint64_t pa; };
static int read_map(void *ctx, uint64_t pa, void *out, uint32_t bytes)
{
    struct input *m = ctx;
    ++m->reads;
    if (pa < m->pa || bytes > m->length || pa - m->pa > m->length - bytes) {
        ++m->invalid_reads;
        return 0;
    }
    memcpy(out, m->bytes + (size_t)(pa - m->pa), bytes);
    return 1;
}
static void init(struct input *m) { memset(m, 0, sizeof *m); m->pa = 0x9000; }
static void entry(struct input *m, uint64_t base, uint64_t length, uint32_t type, uint32_t extra)
{
    uint32_t size = 20 + extra;
    memcpy(m->bytes + m->length, &size, 4);
    memcpy(m->bytes + m->length + 4, &base, 8);
    memcpy(m->bytes + m->length + 12, &length, 8);
    memcpy(m->bytes + m->length + 20, &type, 4);
    memset(m->bytes + m->length + 24, 0x5a, extra);
    m->length += 24 + extra;
}
static int capture(shz_native_firmware_t *h, struct input *m)
{
    return shz_native_firmware_capture(h, 1, m->pa, m->length, 0x10000000, read_map, m);
}
static int cleared(const shz_native_firmware_t *h)
{
    const uint8_t *p = (const uint8_t *)h;
    for (unsigned i = 0; i < sizeof *h; ++i) if (p[i]) return 0;
    return 1;
}
static void seal(shz_native_firmware_t *h) { h->check = shz_native_firmware_sum(h); }
int main(void)
{
    struct input m;
    shz_native_firmware_t h, saved;
    init(&m);
    entry(&m, 0x100000, 0x300000, 1, 12);
    entry(&m, 0x500000, 0x1000, 3, 0);
    entry(&m, 0x600000, 0x2000, 4, 4);
    entry(&m, 0xfec00000, 0x1000, 2, 0);
    CHECK("capture complete variable-length map", capture(&h, &m) == 1);
    CHECK("retained exact base/length/type and denied rows", h.count == 4 && h.range[0].base == 0x100000 &&
          h.range[0].length == 0x300000 && h.range[1].type == 3 && h.range[2].type == 4 && h.range[3].type == 2);
    CHECK("native Multiboot record validates", shz_native_firmware_valid(&h, 1));
    CHECK("UEFI-direct cannot consume native record", !shz_native_firmware_valid(&h, 0));
    CHECK("RAM span reads admitted", shz_native_firmware_covers(&h, 0x1ffff0, 64));
    CHECK("ACPI reclaim span reads admitted", shz_native_firmware_covers(&h, 0x500000, 4096));
    CHECK("ACPI NVS span reads admitted", shz_native_firmware_covers(&h, 0x600000, 8192));
    CHECK("MMIO type2 rejected", !shz_native_firmware_covers(&h, 0xfec00000, 36));
    CHECK("gap crossing rejected", !shz_native_firmware_covers(&h, 0x3ffff0, 0x100040));
    CHECK("zero-sized read rejected", !shz_native_firmware_covers(&h, 0x100000, 0));
    CHECK("physical read overflow rejected", !shz_native_firmware_covers(&h, UINT64_MAX - 16, 36));
    saved = h;
    h.range[0].length ^= 1;
    CHECK("checksum damage rejected before coverage", !shz_native_firmware_valid(&h, 1) &&
          !shz_native_firmware_covers(&h, 0x100000, 36));
    h = saved; h.version++; seal(&h);
    CHECK("unknown version rejected", !shz_native_firmware_valid(&h, 1));
    h = saved; h.profile++; seal(&h);
    CHECK("unknown writer profile rejected", !shz_native_firmware_valid(&h, 1));
    h = saved; h.reserved = 1; seal(&h);
    CHECK("nonzero reserved header rejected", !shz_native_firmware_valid(&h, 1));
    h = saved; h.range[0].reserved = 1; seal(&h);
    CHECK("nonzero reserved row rejected", !shz_native_firmware_valid(&h, 1));
    h = saved; h.count = 65;
    CHECK("corrupt count rejected without out-of-bounds checksum", !shz_native_firmware_valid(&h, 1));
    h = saved;
    CHECK("absent map clears stale metadata", shz_native_firmware_capture(&h, 0, 0, 0, 0, NULL, NULL) == 0 && cleared(&h));
    CHECK("absent record rejects later reader", !shz_native_firmware_valid(&h, 1));

    init(&m); entry(&m, 0x200000, 4096, 1, 0); entry(&m, 0x201000, 4096, 3, 0);
    CHECK("adjacent different readable types captured", capture(&h, &m) == 1);
    CHECK("read can cross fully covered adjacent spans", shz_native_firmware_covers(&h, 0x200ff0, 64));
    init(&m); entry(&m, 0x202000, 4096, 1, 0); entry(&m, 0x200000, 8192, 4, 0);
    CHECK("unsorted coverage captured", capture(&h, &m) == 1 && shz_native_firmware_covers(&h, 0x200000, 12288));
    entry(&m, 0x201000, 128, 2, 0);
    CHECK("reserved overlap always denies", capture(&h, &m) == 1 && !shz_native_firmware_covers(&h, 0x200000, 8192));
    m.bytes[m.length - 4] = 5;
    CHECK("unusable overlap always denies", capture(&h, &m) == 1 && !shz_native_firmware_covers(&h, 0x200000, 8192));
    init(&m); entry(&m, 0x200000, 4096, 0, 0);
    CHECK("unknown type never authorizes reads", capture(&h, &m) == 1 && !shz_native_firmware_covers(&h, 0x200000, 1));
    init(&m); entry(&m, UINT64_MAX - 15, 16, 1, 0);
    CHECK("base plus length overflow clears whole map", capture(&h, &m) < 0 && cleared(&h));
    init(&m); entry(&m, 0x200000, 0, 1, 0);
    CHECK("zero length entry cannot authorize", capture(&h, &m) == 1 && !shz_native_firmware_covers(&h, 0x200000, 1));
    init(&m); entry(&m, 0x200000, 4096, 1, 0); m.length--;
    CHECK("truncated payload refused before unsafe read", capture(&h, &m) < 0 && cleared(&h) && !m.invalid_reads);
    init(&m); entry(&m, 0x200000, 4096, 1, 0); m.length = 3;
    CHECK("truncated size refused before unsafe read", capture(&h, &m) < 0 && cleared(&h) && !m.invalid_reads);
    init(&m); entry(&m, 0x200000, 4096, 1, 0); m.bytes[0] = 19;
    CHECK("short entry refused", capture(&h, &m) < 0 && cleared(&h));
    init(&m); entry(&m, 0x200000, 4096, 1, 0); memset(m.bytes, 0xff, 4);
    CHECK("size addition overflow refused", capture(&h, &m) < 0 && cleared(&h));
    init(&m); entry(&m, 0x200000, 4096, 1, 0); m.bytes[m.length++] = 0;
    CHECK("trailing incomplete entry refused", capture(&h, &m) < 0 && cleared(&h));
    init(&m);
    CHECK("present empty map refused", capture(&h, &m) < 0 && cleared(&h));
    entry(&m, 0x200000, 4096, 1, 0);
    CHECK("32-bit pointer wrap refused before read", shz_native_firmware_capture(&h, 1, 0xfffffff0, 24,
          UINT64_C(0x100000000), read_map, &m) < 0 && !m.reads && cleared(&h));
    CHECK("source beyond supplied RAM bound refused before read", shz_native_firmware_capture(&h, 1, m.pa,
          m.length, m.pa + m.length - 1, read_map, &m) < 0 && !m.reads && cleared(&h));
    CHECK("null reader refused", shz_native_firmware_capture(&h, 1, m.pa, m.length, 0x10000000, NULL, &m) < 0);
    CHECK("unavailable source refused", shz_native_firmware_capture(&h, 1, m.pa + 1, m.length,
          0x10000000, read_map, &m) < 0 && cleared(&h));
    init(&m);
    for (unsigned i = 0; i < 64; ++i) entry(&m, 0x100000 + i * 4096, 4096, 1, i & 3);
    CHECK("all 64 entries retained", capture(&h, &m) == 1 && h.count == 64 &&
          shz_native_firmware_covers(&h, 0x100000, 64 * 4096));
    entry(&m, 0x100000, 64 * 4096, 2, 0);
    CHECK("65th reserved row must not be truncated", capture(&h, &m) < 0 && cleared(&h));
    CHECK("overflow leaves no prior RAM authorization", !shz_native_firmware_covers(&h, 0x100000, 1));
    printf("%s native firmware handoff: %u checks, %u failures\n", failures ? "FAIL" : "PASS", checks, failures);
    return failures ? 1 : 0;
}
#else
int main(void) { fputs("FAIL production native firmware handoff is absent; no complete E820 ownership survives the stub\n", stderr); return 1; }
#endif
