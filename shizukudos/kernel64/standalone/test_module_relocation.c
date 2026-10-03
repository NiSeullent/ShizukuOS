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

/* Kernel64 geometry (memholes.h) unless a test asks for the Kernel32 one. */
static int plan(shz_memplan_t *map, unsigned ram, unsigned stub, unsigned ks, unsigned ke,
                unsigned is, unsigned ie, int has)
{
    return shz_stub_relocation_valid(map, ram, SHZ_K64_KERNEL_END, SHZ_K64_KERNEL_FILE_MAX, stub, ks, ke, is, ie, has);
}
static int plan32(shz_memplan_t *map, unsigned ram, unsigned stub, unsigned ks, unsigned ke)
{
    return shz_stub_relocation_valid(map, ram, SHZ_STUB_K32_KERNEL_END, SHZ_STUB_K32_FILE_MAX, stub, ks, ke, 0, 0, 0);
}

/* Window/file-size contract: K64 [1 MiB, 4 MiB) with a 3 MiB file, K32 unchanged [1 MiB, 3 MiB) with a 1 MiB file,
 * and no caller-supplied geometry that reaches into the stub image or lets the file outgrow its window. */
static void kernel_windows(void)
{
    shz_memplan_t map;
    const unsigned ram = 128u << 20, stub = 0x4e0000u, ks = 0x500000u;
    assert(SHZ_K64_KERNEL_END == 0x400000u && SHZ_K64_KERNEL_FILE_MAX == 0x300000u && SHZ_K64_HEAP_GPA == 0x400000u &&
           SHZ_K64_HEAP_BYTES == 0xB00000u && SHZ_K64_PMM_GPA == 0xF00000u && SHZ_K64_HEAP_KEEP == 0x800000u);
    shz_memplan_init(&map); shz_memplan_add(&map, 0x1000u, ram);
    assert(plan(&map, ram, stub, ks, ks + SHZ_K64_KERNEL_FILE_MAX, 0, 0, 0));          /* 3 MiB file: accepted */
    assert(!plan(&map, ram, stub, ks, ks + SHZ_K64_KERNEL_FILE_MAX + 1u, 0, 0, 0));    /* one byte past the window */
    assert(plan32(&map, ram, stub, ks, ks + 0x100000u));                               /* K32 file limit unchanged */
    assert(!plan32(&map, ram, stub, ks, ks + 0x100001u));
    assert(!shz_stub_relocation_valid(&map, ram, SHZ_STUB_IMAGE_GPA + 0x1000u, 0x300000u, stub, ks, ks + 16, 0, 0, 0));
    assert(!shz_stub_relocation_valid(&map, ram, SHZ_K64_KERNEL_END, SHZ_K64_KERNEL_WINDOW + 1u, stub, ks, ks + 16,
                                      0, 0, 0));                                       /* file larger than window */
    assert(!shz_stub_relocation_valid(&map, ram, SHZ_STUB_KERNEL_GPA, 1u, stub, ks, ks + 1, 0, 0, 0));
    assert(!shz_stub_relocation_valid(&map, ram, SHZ_K64_KERNEL_END, 0, stub, ks, ks + 1, 0, 0, 0));
    assert(!shz_stub_relocation_valid(&map, ram, 0x80000000u, 0x7ff00000u, stub, ks, ks + 1, 0, 0, 0));
    /* Firmware hole in [3 MiB, 4 MiB): inside the K64 window (refused), outside the K32 window. */
    shz_memplan_remove(&map, 0x3ff000u, 0x400000u);
    assert(!plan(&map, ram, stub, ks, ks + 16, 0, 0, 0));
    assert(plan32(&map, ram, stub, ks, ks + 16));
    puts("kernel windows (K64 [1,4) MiB 3 MiB file, K32 [1,3) MiB 1 MiB file), window/file negatives: PASS");
}

/* The stub's order on a full-size K64 image: zero the window to its exclusive end, then copy the file. Neither may
 * write the stub image at 4 MiB nor the heap/page allocator above it. */
static void zero_and_copy_bounds(void)
{
    const unsigned src = 0x500000u, file = SHZ_K64_KERNEL_FILE_MAX - 0x1000u;
    unsigned char *memory = malloc(16u << 20);
    unsigned i;
    assert(memory);
    memset(memory, 0x5a, 16u << 20);
    for (i = 0; i < file; ++i) memory[src + i] = (unsigned char)(i * 13u + 1u);
    memset(memory + SHZ_STUB_KERNEL_GPA, 0, SHZ_K64_KERNEL_END - SHZ_STUB_KERNEL_GPA);
    shz_stub_move(memory + SHZ_STUB_KERNEL_GPA, memory + src, file);
    assert(memory[SHZ_STUB_KERNEL_GPA - 1] == 0x5a && memory[SHZ_STUB_IMAGE_GPA] == 0x5a);   /* stub untouched */
    assert(memory[SHZ_K64_HEAP_GPA] == 0x5a);
    for (i = 0; i < file; ++i) assert(memory[SHZ_STUB_KERNEL_GPA + i] == (unsigned char)(i * 13u + 1u));
    for (i = SHZ_STUB_KERNEL_GPA + file; i < SHZ_K64_KERNEL_END; ++i) assert(memory[i] == 0);  /* bss reads zero */
    free(memory);
    puts("K64 zero [1 MiB, 4 MiB) + 3 MiB copy stays below the stub and heap: PASS");
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
    assert(plan(&map, ram, stub, ks, ks + 0x100001u, is + 0x200000u, ie + 0x200000u, 1));  /* > 1 MiB: K64 ok */
    assert(!plan(&map, ram, stub, ks, ks + SHZ_K64_KERNEL_FILE_MAX + 1u, is + 0x300000u, ie + 0x300000u, 1));
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
    small_moves(); bounds_and_holes(); kernel_windows(); zero_and_copy_bounds(); actual_installer_overlap();
    puts("MODULE_RELOCATION_HOST: PASS");
    return 0;
}
