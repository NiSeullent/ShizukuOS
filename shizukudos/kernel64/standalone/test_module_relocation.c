/* SPDX-License-Identifier: GPL-2.0-only */
#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "module_relocation.h"

static void small_moves(void)
{
    unsigned src, dst, n, i;
    unsigned char actual[64], expected[64];
    for (src = 0; src < 32; ++src)
        for (dst = 0; dst < 32; ++dst)
            for (n = 0; n <= 32; ++n) {
                for (i = 0; i < 64; ++i) actual[i] = expected[i] = (unsigned char)(i * 37u + 17u);
                memmove(expected + dst, expected + src, n);
                shz_stub_move(actual + dst, actual + src, n);
                assert(!memcmp(actual, expected, sizeof actual));
            }
}

static int plan(shz_memplan_t *map, unsigned ram, unsigned stub, unsigned ks, unsigned ke,
                unsigned is, unsigned ie, int has)
{
    return shz_stub_relocation_valid(map, ram, stub, ks, ke, is, ie, has);
}

static void bounds_and_holes(void)
{
    shz_memplan_t map;
    unsigned ram = 128u << 20, stub = 0x4e0000u;
    unsigned ks = 0x4e0000u, ke = 0x4f0000u, is = 0x4f4000u, ie = is + (50u << 20);
    shz_memplan_init(&map); shz_memplan_add(&map, 0x1000u, ram);
    assert(plan(&map, ram, stub, ks, ke, is, ie, 1));
    assert(plan(&map, ram, stub, ks, ke, 0, 0, 0));
    assert(plan(&map, ram, stub, ks, ke, is, is, 1));
    assert(!plan(&map, ram, stub, ks, ks, is, ie, 1));
    assert(!plan(&map, ram, stub, ke, ks, is, ie, 1));
    assert(plan(&map, ram, stub, ks, ks + SHZ_STUB_KERNEL_FILE_MAX, 0, 0, 0));
    assert(!plan(&map, ram, stub, ks, ks + SHZ_STUB_KERNEL_FILE_MAX+1, 0, 0, 0));
    assert(!plan(&map, ram, stub, stub - 1, ke, is, ie, 1));
    assert(!plan(&map, ram, stub, ks, ke, is, is - 1, 1));
    assert(!plan(&map, ram, stub, ks, ke, stub - 1, ie, 1));
    assert(!plan(&map, ram, stub, ks, ke, ks, ke, 1));
    assert(!plan(&map, ram, stub, ks, ram + 1, is, ie, 1));
    assert(!plan(&map, ram, stub, ks, ke, is, ram + 1, 1));
    assert(!plan(&map, ram, SHZ_STUB_INITRD_GPA + 1, ks, ke, is, ie, 1));
    assert(!plan(&map, ram, 0x2f0000u, ks, ke, is, ie, 1));
    assert(!plan(&map, 64u << 20, stub, ks, ke, is, ie, 1));
    shz_memplan_remove(&map, is + 0x1000u, is + 0x2000u);
    assert(!plan(&map, ram, stub, ks, ke, is, ie, 1));
    shz_memplan_add(&map, is + 0x1000u, is + 0x2000u);
    shz_memplan_remove(&map, (70u << 20), (70u << 20) + 0x1000u);
    assert(!plan(&map, ram, stub, ks, ke, is, ie, 1));
    shz_memplan_add(&map, (70u << 20), (70u << 20) + 0x1000u);
    shz_memplan_remove(&map, SHZ_STUB_KERNEL_GPA, SHZ_STUB_KERNEL_GPA + 1);
    assert(!plan(&map, ram, stub, ks, ke, is, ie, 1));
    shz_memplan_init(&map); shz_memplan_add(&map, 0x1000u, UINT32_MAX);
    /* Wide addition must reject a destination that wraps 32-bit arithmetic. */
    assert(!plan(&map, UINT32_MAX, stub, ks, ke, is, UINT32_MAX, 1));
    puts("relocation bounds, overflow and firmware holes: PASS");
}

static void actual_installer_overlap(void)
{
    const unsigned bytes = 50u << 20, source = 0x4f4000u, destination = SHZ_STUB_INITRD_GPA;
    unsigned char *memory = calloc(1, 96u << 20);
    unsigned i;
    assert(memory);
    for (i = 0; i < bytes; ++i) memory[source + i] = (unsigned char)(i * 37u + 17u);
    memset(memory + 0x4e0000u, 0xa5, 0x10000u);
    /* Preserve a kernel source below the archive; relocate kernel first. */
    shz_stub_move(memory + SHZ_STUB_KERNEL_GPA, memory + 0x4e0000u, 0x10000u);
    shz_stub_move(memory + destination, memory + source, bytes);
    for (i = 0; i < bytes; ++i) assert(memory[destination + i] == (unsigned char)(i * 37u + 17u));
    for (i = 0; i < 0x10000u; ++i) assert(memory[SHZ_STUB_KERNEL_GPA + i] == 0xa5);
    assert(memory[destination + bytes] == 0);
    free(memory);
    puts("actual 50MiB installer overlapping relocation, kernel first: PASS");
}

int main(void)
{
    small_moves(); bounds_and_holes(); actual_installer_overlap();
    puts("MODULE_RELOCATION_HOST: PASS");
    return 0;
}
