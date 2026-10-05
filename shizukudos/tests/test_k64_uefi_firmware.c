/* SPDX-License-Identifier: GPL-2.0-only
 * Calls the actual private final-map and real-EFI selection helpers.
 */
#include "../supervisor/loader/firmware_capture.h"
#include "../kernel64/standalone/native_firmware.h"
#include "../abi/shz_abi.h"

_Static_assert(sizeof(shz_bootinfo_t) == 680, "public boot ABI: 616-byte routing01 layout + 64-byte additive install identity tail (routing02 C2)");
_Static_assert(offsetof(shz_bootinfo_t, generation) == 16, "actual boot generation");
_Static_assert(offsetof(shz_bootinfo_t, storage) == 472, "old provenance tail");
_Static_assert(offsetof(shz_uefi_firmware_t, rsdp_pa) == 32, "RSDP scalar offset");
_Static_assert(offsetof(shz_uefi_firmware_t, generation) == 40, "generation offset");
_Static_assert(offsetof(shz_uefi_firmware_t, descriptor_version) == 48, "map version offset");
_Static_assert(offsetof(shz_uefi_firmware_t, map_bytes) == 56, "source map size offset");
_Static_assert(sizeof(shz_native_firmware_t) == 1568, "BIOS record stays fixed");
_Static_assert(SHZ_NATIVE_FIRMWARE_MAGIC != SHZ_UEFI_FIRMWARE_MAGIC, "separate profile magic");

#ifdef SHZ_UEFI_FIRMWARE_OBJECT_CHECK
int shz_uefi_object_select(const EFI_SYSTEM_TABLE *st, uint64_t *pa)
{ return shz_uefi_rsdp_select(st, pa); }
int shz_uefi_object_capture(shz_uefi_firmware_t *out, const void *map, size_t bytes, size_t stride,
        uint32_t version, uint64_t rsdp, uint64_t generation, int ebs)
{ return shz_uefi_firmware_capture(out, map, bytes, stride, version, rsdp, generation, ebs); }
int shz_uefi_object_read_bound(const shz_uefi_firmware_t *h, uint64_t pa, uint32_t bytes,
        uint64_t generation)
{ return shz_uefi_firmware_valid(h, generation) && shz_uefi_firmware_covers(h, pa, bytes); }
#else
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static unsigned checks, refusals;
#define CHECK(c) do { ++checks; if (!(c)) { \
    fprintf(stderr, "FAIL line %d: %s\n", __LINE__, #c); exit(1); } } while (0)
static const uint64_t high = UINT64_C(0x100200000);
static const uint64_t generation = UINT64_C(0x100000007);

static EFI_MEMORY_DESCRIPTOR desc(uint32_t type, uint64_t pa, uint64_t pages, uint64_t attrs)
{
    EFI_MEMORY_DESCRIPTOR d = {0};
    d.type = type; d.physical_start = pa; d.pages = pages; d.attributes = attrs;
    return d;
}
static void unchanged_capture(const void *map, size_t bytes, size_t stride, uint32_t version,
        uint64_t rsdp, uint64_t gen, int ebs, int expected)
{
    shz_uefi_firmware_t out, before;
    memset(&out, 0xa5, sizeof(out)); before = out;
    CHECK(shz_uefi_firmware_capture(&out, map, bytes, stride, version, rsdp, gen, ebs) == expected);
    CHECK(memcmp(&out, &before, sizeof(out)) == 0);
    ++refusals;
}
static shz_uefi_firmware_t capture(const void *map, size_t bytes, size_t stride, uint64_t rsdp)
{
    shz_uefi_firmware_t out;
    memset(&out, 0xa5, sizeof(out));
    CHECK(shz_uefi_firmware_capture(&out, map, bytes, stride, 1, rsdp, generation, 1) == 1);
    CHECK(shz_uefi_firmware_valid(&out, generation));
    return out;
}
static void invalid_record(shz_uefi_firmware_t h, int reseal)
{
    if (reseal) h.check = shz_uefi_firmware_sum(&h);
    CHECK(!shz_uefi_firmware_valid(&h, generation));
    /* covers has no external generation parameter: an otherwise valid resealed
     * generation must be rejected by the owner's valid(record, bootinfo) gate.
     */
    if (!shz_uefi_firmware_valid(&h, h.generation)) CHECK(!shz_uefi_firmware_covers(&h, high, 20));
    ++refusals;
}

static void test_capture_and_bounds(void)
{
    EFI_MEMORY_DESCRIPTOR map[5] = {
        desc(10, high + 0x1000, 1, 8 | 0x20000),
        desc(7, 0x100000, 4, 8),
        desc(9, high, 1, 8 | 0x4000),
        desc(6, 0x200000, 1, 8 | SHZ_UEFI_FIRMWARE_RUNTIME),
        desc(11, 0xf0000000, 1, 1)
    };
    shz_uefi_firmware_t h = capture(map, sizeof(map), sizeof(map[0]), high + 0xff8), bad;
    CHECK(h.count == 2 && h.range[0].efi_type == 10 && h.range[1].efi_type == 9);
    CHECK(h.range[0].attributes == (8 | 0x20000) && h.range[1].attributes == (8 | 0x4000));
    CHECK(h.map_bytes == sizeof(map) && h.descriptor_size == 40);
    CHECK(shz_uefi_firmware_covers(&h, high, 0x2000));
    CHECK(shz_uefi_firmware_covers(&h, high + 0xff8, 20));
    CHECK(!shz_uefi_firmware_covers(&h, high - 1, 1));
    CHECK(!shz_uefi_firmware_covers(&h, high + 0x1fff, 2));
    CHECK(!shz_uefi_firmware_covers(&h, high, 0));
    CHECK(!shz_uefi_firmware_covers(&h, UINT64_MAX - 1, 4));
    CHECK(!shz_uefi_firmware_covers(&h, 0x100000, 20));
    CHECK(!shz_uefi_firmware_covers(&h, 0x200000, 20));
    CHECK(!shz_uefi_firmware_covers(&h, 0xf0000000, 20));
    CHECK(!shz_uefi_firmware_covers(NULL, high, 20));
    CHECK(!shz_uefi_firmware_valid(&h, generation + 1));
    CHECK(!shz_uefi_firmware_valid(&h, 0));
    CHECK(!shz_uefi_firmware_valid(NULL, generation));
    CHECK(shz_uefi_firmware_capture(NULL, map, sizeof(map), 40, 1, high, generation, 1) == -1);
    unchanged_capture(NULL, sizeof(map), 40, 1, high, generation, 1, -1);
    unchanged_capture(map, 0, 40, 1, high, generation, 1, -1);
    unchanged_capture(map, sizeof(map) - 1, 40, 1, high, generation, 1, -1);
    unchanged_capture(map, sizeof(map), 40, 2, high, generation, 1, -1);
    unchanged_capture(map, sizeof(map), 40, 1, high, generation, 0, -1);
    unchanged_capture(map, sizeof(map), 40, 1, high, generation, 2, -1);
    unchanged_capture(map, sizeof(map), 40, 1, high, 0, 1, -1);
    unchanged_capture(map, sizeof(map), 40, 1, 0, generation, 1, 0);
    unchanged_capture(map, sizeof(map), 40, 1, high - 8, generation, 1, -1);
    unchanged_capture(map, sizeof(map), 40, 1, high + 0x1ff8, generation, 1, -1);
    unchanged_capture(map, sizeof(map), 32, 1, high, generation, 1, -1);
    unchanged_capture(map, sizeof(map), 41, 1, high, generation, 1, -1);
    unchanged_capture(map, sizeof(map), 4104, 1, high, generation, 1, -1);
    unchanged_capture(map, SHZ_UEFI_FIRMWARE_MAP_MAX + 1u, 40, 1, high, generation, 1, -1);
    unchanged_capture((void *)(UINTPTR_MAX - 15u), 40, 40, 1, high, generation, 1, -1);

#define MUTATE(field, value, seal) do { bad = h; bad.field = (value); invalid_record(bad, seal); } while (0)
    MUTATE(magic, SHZ_NATIVE_FIRMWARE_MAGIC, 1);
    MUTATE(version, 2, 1); MUTATE(bytes, sizeof(h) - 1, 1);
    MUTATE(profile, 1, 1); MUTATE(flags, 0, 1); MUTATE(flags, 3, 1);
    MUTATE(reserved, 1, 1); MUTATE(generation, 0, 1); MUTATE(generation, generation + 1, 1);
    MUTATE(check, h.check + 1, 0); MUTATE(rsdp_pa, 0, 1);
    MUTATE(rsdp_pa, high - 8, 1); MUTATE(rsdp_pa, high + 0x1ff8, 1);
    MUTATE(descriptor_version, 0, 1); MUTATE(descriptor_size, 32, 1);
    MUTATE(descriptor_size, 41, 1); MUTATE(descriptor_size, 4104, 1);
    MUTATE(map_bytes, 0, 1); MUTATE(map_bytes, 41, 1);
    MUTATE(map_bytes, 40, 1); MUTATE(map_bytes, UINT64_C(4097) * 40, 1);
    MUTATE(map_bytes, SHZ_UEFI_FIRMWARE_MAP_MAX + UINT64_C(40), 1);
    MUTATE(count, 0, 1); MUTATE(count, 49, 1);
    MUTATE(range[0].reserved, 1, 1); MUTATE(range[0].efi_type, 7, 1);
    MUTATE(range[0].attributes, 1, 1);
    MUTATE(range[0].attributes, 8 | SHZ_UEFI_FIRMWARE_RUNTIME, 1);
    MUTATE(range[0].base, high + 1, 1); MUTATE(range[0].length, 0, 1);
    MUTATE(range[0].length, 1, 1); MUTATE(range[0].base, UINT64_MAX & ~UINT64_C(0xfff), 1);
    MUTATE(range[0].base, high, 1); /* retained overlap, even after resealing */
    MUTATE(range[2].base, high, 1); MUTATE(range[2].length, 0x1000, 1);
    MUTATE(range[2].attributes, 8, 1); MUTATE(range[2].efi_type, 9, 1);
    MUTATE(range[47].reserved, 1, 1);
#undef MUTATE
    /* Every unused byte is independently rejected, even though unused rows are
     * not checksum inputs. This includes all attributes/type/reserved fields.
     */
    for (size_t i = offsetof(shz_uefi_firmware_t, range) + h.count * sizeof(h.range[0]);
            i < sizeof(h); ++i) {
        bad = h; ((uint8_t *)&bad)[i] = 1;
        CHECK(!shz_uefi_firmware_valid(&bad, generation));
    }
    map[0].physical_start = high + 0x2000;
    unchanged_capture(map, sizeof(map), 40, 1, high + 0xff8, generation, 1, -1);
    h = capture(map, sizeof(map), 40, high);
    CHECK(!shz_uefi_firmware_covers(&h, high + 0xff8, 20));
    CHECK(shz_uefi_firmware_covers(&h, high + 0x2000, 0x1000));
}

static void test_complete_map(void)
{
    EFI_MEMORY_DESCRIPTOR map[3], saved;
    map[0] = desc(9, high, 1, 8);
    map[1] = desc(7, high + 0x2000, 1, 8);
    map[2] = desc(11, high + 0x3000, 1, 1);
    for (uint32_t type = 0; type <= 15; ++type) {
        map[1] = desc(type, high, 1, 8);
        unchanged_capture(map, sizeof(map), 40, 1, high, generation, 1, -1);
        saved = map[0]; map[0] = map[1]; map[1] = saved;
        unchanged_capture(map, sizeof(map), 40, 1, high, generation, 1, -1);
        map[0] = desc(9, high, 1, 8);
    }
    map[1] = desc(7, high + 0x2000, 2, 8);
    map[2] = desc(11, high + 0x3000, 1, 1);
    unchanged_capture(map, sizeof(map), 40, 1, high, generation, 1, -1);
    saved = map[1]; map[1] = map[2]; map[2] = saved;
    unchanged_capture(map, sizeof(map), 40, 1, high, generation, 1, -1);
    map[1] = desc(7, 0x100000, 1, 8);
    map[2] = desc(15, 0x200000, 1, 0);
    CHECK(capture(map, sizeof(map), 40, high).count == 1);
    map[2].type = 16;
    unchanged_capture(map, sizeof(map), 40, 1, high, generation, 1, -1);
    map[2].type = UINT32_MAX;
    unchanged_capture(map, sizeof(map), 40, 1, high, generation, 1, -1);
    map[2] = desc(7, 0x200001, 1, 8);
    unchanged_capture(map, sizeof(map), 40, 1, high, generation, 1, -1);
    map[2] = desc(7, 0x200000, 0, 8);
    unchanged_capture(map, sizeof(map), 40, 1, high, generation, 1, -1);
    map[2] = desc(7, 0x200000, (UINT64_MAX >> 12) + 1, 8);
    unchanged_capture(map, sizeof(map), 40, 1, high, generation, 1, -1);
    map[2] = desc(7, UINT64_MAX & ~UINT64_C(0xfff), 1, 8);
    unchanged_capture(map, sizeof(map), 40, 1, high, generation, 1, -1);
    map[2] = desc(9, 0x200000, 1, 1);
    unchanged_capture(map, sizeof(map), 40, 1, high, generation, 1, -1);
    map[2] = desc(10, 0x200000, 1, 8 | SHZ_UEFI_FIRMWARE_RUNTIME);
    unchanged_capture(map, sizeof(map), 40, 1, high, generation, 1, -1);
    /* Non-ACPI rows, including runtime/MMIO, cannot cover a selected RSDP. */
    for (uint32_t type = 0; type <= 15; ++type) {
        if (type == 9 || type == 10) continue;
        map[0] = desc(type, high, 1, 8);
        unchanged_capture(map, 40, 40, 1, high, generation, 1, -1);
    }
    map[0] = desc(7, 0, 1, 8); map[1] = desc(9, high, 1, 8);
    CHECK(capture(map, 80, 40, high).count == 1); /* physical base zero is valid */
}

static void test_strides_and_caps(void)
{
    uint8_t stream[4096 * 2 + 1];
    EFI_MEMORY_DESCRIPTOR d = desc(9, high, 1, 8), rows[49];
    for (size_t stride = 40; stride <= 4096; stride = stride == 40 ? 48 : stride == 48 ? 4096 : 8192) {
        memset(stream, 0xcd, sizeof(stream));
        memcpy(stream + 1, &d, sizeof(d));
        EFI_MEMORY_DESCRIPTOR e = desc(10, high + 0x1000, 1, 8 | 0x4000);
        memcpy(stream + 1 + stride, &e, sizeof(e));
        shz_uefi_firmware_t h = capture(stream + 1, stride * 2, stride, high + 0xff8);
        CHECK(h.descriptor_size == stride && h.map_bytes == stride * 2);
        CHECK(shz_uefi_firmware_covers(&h, high, 0x2000));
    }
    for (uint32_t i = 0; i < 49; ++i) rows[i] = desc(9, high + i * UINT64_C(0x1000), 1, 8);
    shz_uefi_firmware_t h = capture(rows, 48 * sizeof(rows[0]), sizeof(rows[0]), high);
    CHECK(h.count == 48 && shz_uefi_firmware_covers(&h, high, 48 * 0x1000));
    unchanged_capture(rows, sizeof(rows), sizeof(rows[0]), 1, high, generation, 1, -1);
    /* Identical adjacent rows are not silently merged to hide the 49th. */
    uint8_t *maximum = calloc(SHZ_UEFI_FIRMWARE_MAP_MAX, 1);
    CHECK(maximum != NULL);
    for (uint32_t i = 0; i < 4096; ++i) {
        d = desc(i == 4095 ? 9 : 7, high + i * UINT64_C(0x1000), 1, 8);
        memcpy(maximum + (size_t)i * 4096, &d, sizeof(d));
    }
    h = capture(maximum, SHZ_UEFI_FIRMWARE_MAP_MAX, 4096, high + UINT64_C(4095) * 0x1000);
    CHECK(h.count == 1 && h.map_bytes == SHZ_UEFI_FIRMWARE_MAP_MAX);
    /* Reject the count cap before dereferencing any fake source. */
    unchanged_capture((void *)(uintptr_t)0x1000, 4097u * 40u, 40, 1, high, generation, 1, -1);
    free(maximum);
    /* A final retry map is captured afresh, rather than carrying earlier rows. */
    d = desc(9, high, 1, 8); h = capture(&d, sizeof(d), sizeof(d), high);
    d.physical_start += 0x10000;
    h = capture(&d, sizeof(d), sizeof(d), d.physical_start);
    CHECK(!shz_uefi_firmware_covers(&h, high, 20));
    CHECK(shz_uefi_firmware_covers(&h, d.physical_start, 20));
}

static EFI_SYSTEM_TABLE system_table(EFI_CONFIGURATION_TABLE *rows, size_t count)
{
    EFI_SYSTEM_TABLE st = {0};
    st.header.signature = EFI_SYSTEM_TABLE_SIGNATURE;
    st.header.header_size = sizeof(st);
    st.table_count = count; st.tables = rows;
    return st;
}
static void refused_select(const EFI_SYSTEM_TABLE *st, int expected)
{
    uint64_t out = UINT64_C(0x123456789abcdef0);
    CHECK(shz_uefi_rsdp_select(st, &out) == expected);
    CHECK(out == UINT64_C(0x123456789abcdef0));
    ++refusals;
}
static void test_selection(void)
{
    const EFI_GUID acpi20 = {0x8868e871,0xe4f1,0x11d3,{0xbc,0x22,0x00,0x80,0xc7,0x3c,0x88,0x81}};
    const EFI_GUID acpi10 = {0xeb9d2d30,0x2d88,0x11d3,{0x9a,0x16,0x00,0x90,0x27,0x3f,0xc1,0x4d}};
    EFI_CONFIGURATION_TABLE rows[4] = {{acpi10, (void *)(uintptr_t)0x12340},
        {acpi20, (void *)(uintptr_t)high}, {{0}, NULL}, {{0}, NULL}};
    EFI_SYSTEM_TABLE st = system_table(rows, 2);
    uint64_t out = 0;
    CHECK(shz_uefi_rsdp_select(&st, &out) == 1 && out == high);
    EFI_CONFIGURATION_TABLE swap = rows[0]; rows[0] = rows[1]; rows[1] = swap;
    CHECK(shz_uefi_rsdp_select(&st, &out) == 1 && out == high);
    st.table_count = 1; rows[0].table = NULL;
    refused_select(&st, -1);
    st.table_count = 2; /* present bad ACPI2 with good ACPI1 never falls back */
    refused_select(&st, -1);
    rows[0].table = (void *)(uintptr_t)high; rows[2] = rows[0]; st.table_count = 3;
    refused_select(&st, -1);
    rows[2].table = NULL;
    refused_select(&st, -1);
    rows[2] = rows[1]; /* duplicate legacy GUID is malformed even with good ACPI2 */
    refused_select(&st, -1);
    rows[0].table = (void *)(UINTPTR_MAX - 15u); st.table_count = 2;
    refused_select(&st, -1);
    rows[0] = rows[1]; st.table_count = 1;
    CHECK(shz_uefi_rsdp_select(&st, &out) == 1 && out == 0x12340);
    rows[0].table = NULL; refused_select(&st, -1);
    rows[0] = rows[1]; st.table_count = 2; refused_select(&st, -1);
    rows[0] = (EFI_CONFIGURATION_TABLE){{0}, NULL}; rows[1] = rows[0];
    refused_select(&st, 0);
    rows[0].guid = acpi20; rows[0].guid.d[7] ^= 1; rows[0].table = (void *)(uintptr_t)high;
    refused_select(&st, 0); /* near-matching GUID never selects */
    st.table_count = 0; st.tables = NULL; refused_select(&st, 0);
    refused_select(NULL, -1);
    CHECK(shz_uefi_rsdp_select(&st, NULL) == -1);
    st.header.signature = 0; refused_select(&st, -1);
    st = system_table(rows, 1); st.header.header_size = sizeof(st) - 1; refused_select(&st, -1);
    st.header.header_size = SHZ_UEFI_SYSTEM_TABLE_MAX + 1; refused_select(&st, -1);
    st = system_table(rows, 1); st.header.reserved = 1; refused_select(&st, -1);
    st = system_table(NULL, 1); refused_select(&st, -1);
    st = system_table(rows, 4097); refused_select(&st, -1);
    st.table_count = SIZE_MAX; refused_select(&st, -1);
    st = system_table((EFI_CONFIGURATION_TABLE *)(UINTPTR_MAX - 7u), 1); refused_select(&st, -1);
    st = system_table((EFI_CONFIGURATION_TABLE *)((uint8_t *)rows + 1), 1); refused_select(&st, -1);
    refused_select((const EFI_SYSTEM_TABLE *)(UINTPTR_MAX - 7u), -1);
    refused_select((const EFI_SYSTEM_TABLE *)((const uint8_t *)&st + 1), -1);
    EFI_CONFIGURATION_TABLE *large = calloc(4096, sizeof(*large)); CHECK(large != NULL);
    large[4095] = (EFI_CONFIGURATION_TABLE){acpi20, (void *)(uintptr_t)high};
    st = system_table(large, 4096);
    CHECK(shz_uefi_rsdp_select(&st, &out) == 1 && out == high);
    free(large);
}

static void test_bios_control(void)
{
    shz_native_firmware_t bios = {0};
    bios.magic = SHZ_NATIVE_FIRMWARE_MAGIC; bios.version = SHZ_NATIVE_FIRMWARE_VERSION;
    bios.bytes = sizeof(bios); bios.count = 1; bios.profile = SHZ_NATIVE_FIRMWARE_MULTIBOOT;
    bios.range[0].base = 0x100000; bios.range[0].length = 0x200000; bios.range[0].type = 1;
    bios.check = shz_native_firmware_sum(&bios);
    CHECK(shz_native_firmware_valid(&bios, 1));
    CHECK(shz_native_firmware_covers(&bios, 0x100000, 0x1000));
    shz_uefi_firmware_t old = {0}; memcpy(&old, &bios, sizeof(bios));
    CHECK(!shz_uefi_firmware_valid(&old, generation));
    EFI_MEMORY_DESCRIPTOR d = desc(9, high, 1, 8);
    shz_uefi_firmware_t fresh = capture(&d, 40, 40, high);
    memcpy(&bios, &fresh, sizeof(bios));
    CHECK(!shz_native_firmware_valid(&bios, 1));
    CHECK(!shz_native_firmware_valid(&bios, 0));
}
int main(void)
{
    test_capture_and_bounds(); test_complete_map(); test_strides_and_caps(); test_selection(); test_bios_control();
    printf("PASS actual UEFI capture/GUID helpers: %u checks; %u byte-unchanged/record refusals\n", checks, refusals);
    return 0;
}
#endif
