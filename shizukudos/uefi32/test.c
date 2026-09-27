/* SPDX-License-Identifier: GPL-2.0-only */
#include "layout.h"
#include "paging.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static unsigned checks;
#define CHECK(x) do { ++checks; if (!(x)) { fprintf(stderr, "FAIL line %d: %s\n", __LINE__, #x); exit(1); } } while (0)
static uint64_t pages[5][512];
static int read_table(void *context, uint64_t address, uint64_t *entry)
{
    unsigned page = (unsigned)(address >> 12), index = (unsigned)((address & 4095) / 8);
    (void)context;
    if (!page || page > 5 || (address & 7)) return 0;
    *entry = pages[page - 1][index];
    return 1;
}

static void page_tests(void)
{
    uint64_t address = SD32_BASE;
    memset(pages, 0, sizeof(pages));
    pages[0][0] = 0x2003; pages[1][0] = 0x3003;
    pages[2][16] = UINT64_C(0x02000083); /* 2-MiB identity mapping */
    CHECK(sd32_identity_page(0x1000, address, 4, 1, 1, read_table, 0));
    CHECK(sd32_identity_page(0x1000, address + 0x1ff000, 4, 1, 1, read_table, 0));
    pages[2][16] |= 0x2000;
    CHECK(!sd32_identity_page(0x1000, address, 4, 1, 1, read_table, 0));
    pages[2][16] &= ~UINT64_C(0x2000);
    pages[2][16] |= UINT64_C(1) << 63;
    CHECK(!sd32_identity_page(0x1000, address, 4, 1, 1, read_table, 0));
    CHECK(sd32_identity_page(0x1000, address, 4, 1, 0, read_table, 0));
    pages[2][16] = UINT64_C(0x02000081);
    CHECK(!sd32_identity_page(0x1000, address, 4, 1, 0, read_table, 0));
    pages[2][16] = UINT64_C(0x04000083);
    CHECK(!sd32_identity_page(0x1000, address, 4, 0, 0, read_table, 0));
    pages[2][16] = 0x4003; pages[3][0] = 0x02000003;
    CHECK(sd32_identity_page(0x1000, address, 4, 1, 1, read_table, 0));
    pages[0][0] &= ~UINT64_C(2);
    CHECK(!sd32_identity_page(0x1000, address, 4, 1, 1, read_table, 0));
    pages[0][0] = 0x2003; pages[1][0] = 0x83; /* 1-GiB identity page */
    CHECK(sd32_identity_page(0x1000, address, 4, 1, 1, read_table, 0));
    pages[4][0] = 0x1003;
    pages[1][0] |= 0x2000;
    CHECK(!sd32_identity_page(0x1000, address, 4, 1, 1, read_table, 0));
    pages[1][0] &= ~UINT64_C(0x2000);
    CHECK(sd32_identity_page(0x5000, address, 5, 1, 1, read_table, 0));
    CHECK(!sd32_identity_page(0x5000, address, 3, 1, 1, read_table, 0));
    CHECK(!sd32_identity_page(0x5000, UINT64_C(0x100000000), 5, 1, 1, read_table, 0));
    pages[4][0] |= 128;
    CHECK(!sd32_identity_page(0x5000, address, 5, 1, 1, read_table, 0));
    CHECK(!sd32_identity_page(0, address, 4, 1, 1, read_table, 0));
}

static void abi_tests(void)
{
    SD32_BOOT b = {0}, original;
    unsigned i;
    b.magic = SD32_MAGIC; b.version = SD32_VERSION; b.size = sizeof(b);
    b.region_base = SD32_BASE; b.region_bytes = SD32_REGION_SIZE;
    b.stack_top = SD32_STACK_TOP; b.payload_bytes = 12345;
    b.memory_map = SD32_MAP; b.map_bytes = 4800; b.descriptor_bytes = 48; b.descriptor_version = 1;
    b.framebuffer = 0xc0000000; b.framebuffer_bytes = 640 * 480 * 4;
    b.width = 640; b.height = 480; b.pitch_pixels = 640; b.pixel_format = 1;
    CHECK(sd32_validate_boot(&b)); original = b;
    b.magic = 0; CHECK(!sd32_validate_boot(&b)); b = original;
    b.version = 0; CHECK(!sd32_validate_boot(&b)); b = original;
    b.size--; CHECK(!sd32_validate_boot(&b)); b = original;
    b.payload_bytes = 0xf0001; CHECK(!sd32_validate_boot(&b)); b = original;
    b.map_bytes = SD32_MAP_CAPACITY + 1; CHECK(!sd32_validate_boot(&b)); b = original;
    b.map_bytes--; CHECK(!sd32_validate_boot(&b)); b = original;
    b.framebuffer = 0xfffffff0; CHECK(!sd32_validate_boot(&b)); b = original;
    b.pitch_pixels = UINT32_MAX; CHECK(!sd32_validate_boot(&b)); b = original;
    b.framebuffer_bytes--; CHECK(!sd32_validate_boot(&b)); b = original;
    b.pixel_format = 3; CHECK(!sd32_validate_boot(&b)); b = original;
    b.cr0 = 1; b.cr4 = 0; b.efer = 0; b.cs = 0x10; b.ss = 0x18; b.esp = SD32_STACK_TOP - 8;
    CHECK(sd32_validate_mode(&b)); original = b;
    b.cr0 |= 0x80000000; CHECK(!sd32_validate_mode(&b)); b = original;
    b.cr0 = 0; CHECK(!sd32_validate_mode(&b)); b = original;
    for (i = 0; i < 3; ++i) {
        b.cr4 = i == 0 ? 0x20 : i == 1 ? 0x1000 : 0x20000;
        CHECK(!sd32_validate_mode(&b)); b = original;
    }
    b.efer = 0x100; CHECK(!sd32_validate_mode(&b)); b = original;
    b.efer = 0x400; CHECK(!sd32_validate_mode(&b)); b = original;
    b.cs = 0x13; CHECK(!sd32_validate_mode(&b)); b = original;
    b.ss = 0x1b; CHECK(!sd32_validate_mode(&b)); b = original;
    b.esp = SD32_STACK_BOTTOM - 1; CHECK(!sd32_validate_mode(&b)); b = original;
    b.esp = SD32_STACK_TOP; CHECK(!sd32_validate_mode(&b));
}

int main(void)
{
    page_tests(); abi_tests();
    printf("PASS: %u mode-transition, page-table and cross-ABI contract checks\n", checks);
    return 0;
}
