/* SPDX-License-Identifier: GPL-2.0-only
 * Standalone Kernel64 boot stub, C part (32-bit protected mode, paging off, flat segments).
 * Multiboot modules: [0] KERNEL64 image (copied to 1 MiB), [1] initial RAM archive (copied to 32 MiB).
 * Diagnostics go to COM1; on error the stub reports and asks QEMU to exit (isa-debug-exit).
 */
#include <stdint.h>
#include "../../abi/shz_abi.h"
#include "memholes.h"

#ifdef STUB_K32                                    /* Kernel32: 32-bit Protected Mode, paging off, EBX = bootinfo */
#define STUB_DOMAIN SHZ_DOM_KERNEL32
#define MAX_RAM (128u << 20)                       /* Kernel32's page allocator limit (mem.c MAX_PAGES) */
#else
#define STUB_DOMAIN SHZ_DOM_KERNEL64
#define MAX_RAM (256u << 20)                       /* Kernel64's page allocator limit (mem.c MAX_PAGES) */
#endif
#define KERNEL_GPA 0x100000u
#define INITRD_GPA 0x2000000u
#define FIXED_END 0x600000u                        /* Kernel64 mem.c: kernel image and heap at fixed addresses below 6 MiB */
#define MB_MAGIC 0x2BADB002u
#define MB_INFO_MEM_MAP 0x40u
#define MAX_RANGES 64

extern char stub_end[];                            /* boot.ld: end of the stub image including its stack */

struct mbi {
    uint32_t flags, mem_lower, mem_upper, boot_device, cmdline, mods_count, mods_addr, syms[4];
    uint32_t mmap_length, mmap_addr;
};
struct mod { uint32_t start, end, string, reserved; };
struct mmap_entry { uint32_t size; uint64_t base, length; uint32_t type; } __attribute__((packed));

static inline void outb(uint16_t p, uint8_t v) { __asm__ volatile("outb %0, %1" : : "a"(v), "Nd"(p)); }
static void say(const char *s) { while (*s) outb(0x3f8, (uint8_t)*s++); }
static void hex(uint32_t v)
{
    int i;
    for (i = 28; i >= 0; i -= 4) outb(0x3f8, (uint8_t)"0123456789abcdef"[(v >> i) & 15]);
}
static void __attribute__((noreturn)) fail(const char *msg, uint32_t value)
{
    say("SHZ-STUB: "); say(msg); say(" "); hex(value); say("\nSHZ-EXIT:fe\n");
    outb(0xf4, 0x7f);
    for (;;) __asm__ volatile("cli; hlt");
}
static void copy(uint32_t dst, uint32_t src, uint32_t n)
{
    __asm__ volatile("rep movsb" : "+D"(dst), "+S"(src), "+c"(n) : : "memory");
}
static void zero(uint32_t dst, uint32_t n)
{
    __asm__ volatile("rep stosb" : "+D"(dst), "+c"(n) : "a"(0) : "memory");
}

static uint64_t hole_gpa[SHZ_MEMHOLES_MAX], hole_size[SHZ_MEMHOLES_MAX];
static uint32_t hole_count;

/* RAM size and the non-RAM holes below it, from the Multiboot memory map (the firmware's E820).
 * Without a map: the classic mem_upper (contiguous RAM from 1 MiB), no holes. With one: RAM ends where the
 * highest usable range below 4 GiB ends; the gaps between usable ranges above 1 MiB are holes. Under legacy
 * BIOS/QEMU there are none; under UEFI + CSMWrap the map keeps e.g. OVMF's ACPI NVS at 8-9 MiB. */
static uint32_t memory_layout(const struct mbi *mbi, uint32_t isize)
{
    static uint64_t base[MAX_RANGES], end[MAX_RANGES];
    uint32_t n = 0, i, j, off, ram;
    uint64_t top = 0, cursor;

    if (!(mbi->flags & MB_INFO_MEM_MAP) || !mbi->mmap_length) {
        ram = (mbi->mem_upper + 1024u) << 10;      /* bytes of RAM below 4 GiB */
        ram &= ~0x1fffffu;
        return ram > MAX_RAM ? MAX_RAM : ram;
    }
    for (off = 0; off + 24 <= mbi->mmap_length; off += ((const struct mmap_entry *)(mbi->mmap_addr + off))->size + 4) {
        const struct mmap_entry *e = (const struct mmap_entry *)(mbi->mmap_addr + off);
        uint64_t b = e->base, x = e->base + e->length;
        if (e->type != 1 || !e->length || b >= (1ull << 32))
            continue;
        if (x > (1ull << 32)) x = 1ull << 32;
        if (n == MAX_RANGES) fail("too many memory map entries, max", MAX_RANGES);
        for (i = n++; i > 0 && base[i - 1] > b; --i) {    /* insertion sort by base */
            base[i] = base[i - 1];
            end[i] = end[i - 1];
        }
        base[i] = b;
        end[i] = x;
        if (x > top) top = x;
    }
    if (top > MAX_RAM) top = MAX_RAM;
    ram = (uint32_t)top & ~0x1fffffu;
    /* Gaps in [1 MiB, ram) not covered by any usable range. */
    cursor = KERNEL_GPA;
    for (i = 0; i <= n && cursor < ram; ++i) {
        uint64_t next = i < n ? base[i] : ram;
        if (next > ram) next = ram;
        if (next > cursor) {
            uint64_t a = cursor & ~0xfffull, z = (next + 0xfff) & ~0xfffull;
            if (hole_count == SHZ_MEMHOLES_MAX) fail("too many holes in the memory map, max", SHZ_MEMHOLES_MAX);
#ifdef STUB_K32
            fail("Kernel32 needs contiguous RAM from 1 MiB; hole at", (uint32_t)a);
#endif
            if (a < FIXED_END) fail("hole in the fixed kernel/heap area below 6 MiB at", (uint32_t)a);
            if (a < INITRD_GPA + isize && z > INITRD_GPA) fail("hole where the initrd goes, at", (uint32_t)a);
            hole_gpa[hole_count] = a;
            hole_size[hole_count++] = z - a;
            say("SHZ-STUB: firmware hole "); hex((uint32_t)a); say(" size "); hex((uint32_t)(z - a)); say(" kept out of the page allocator\n");
        }
        if (i < n && end[i] > cursor) cursor = end[i];
    }
    for (j = 0; j < 3; ++j) {                      /* page tables 0x1000-0x5000, holes 0x6000, bootinfo 0x7000 */
        uint64_t need = j == 2 ? SHZ_BOOTINFO_GPA : j ? SHZ_MEMHOLES_GPA : 0x1000;
        for (i = 0; i < n && !(base[i] <= need && end[i] >= need + 0x1000); ++i)
            ;
        if (i == n) fail("low boot page is not RAM:", (uint32_t)need);
    }
    return ram;
}

void stub_prepare(uint32_t magic, const struct mbi *mbi)
{
    const struct mod *mods;
    uint32_t ksize, isize = 0, ram, i;
    volatile shz_bootinfo_t *bi = (volatile shz_bootinfo_t *)SHZ_BOOTINFO_GPA;
    volatile uint32_t *pml4 = (volatile uint32_t *)0x1000, *pdpt_lo = (volatile uint32_t *)0x2000,
                      *pd = (volatile uint32_t *)0x3000, *pdpt_hi = (volatile uint32_t *)0x4000;

    if (magic != MB_MAGIC) fail("not entered by a Multiboot loader, eax=", magic);
    if (!(mbi->flags & 1)) fail("no memory info", mbi->flags);
    if (!(mbi->flags & 8) || mbi->mods_count < 1) fail("need module 0 = KERNEL64 image, flags=", mbi->flags);
    mods = (const struct mod *)mbi->mods_addr;
    ksize = mods[0].end - mods[0].start;
    if (mbi->mods_count > 1) isize = mods[1].end - mods[1].start;
    ram = memory_layout(mbi, isize);
    if (ram < (64u << 20)) fail("need at least 64 MiB, have ", ram);
    for (i = 0; i < mbi->mods_count && i < 2; ++i) {
        if (mods[i].start < (uint32_t)stub_end || mods[i].end > INITRD_GPA)
            fail("module placed where the copy would corrupt it: start=", mods[i].start);
    }
    if (ksize == 0 || ksize > 0x100000u) fail("kernel image size (file + bss must stay below 3 MiB), ", ksize);
    if (INITRD_GPA + isize > ram) fail("initrd does not fit in RAM, size=", isize);

    zero(KERNEL_GPA, 0x300000u - KERNEL_GPA);      /* bss of the kernel image reads as zero, as after the Supervisor's memset */
    copy(KERNEL_GPA, mods[0].start, ksize);
    if (isize) copy(INITRD_GPA, mods[1].start, isize);

#ifndef STUB_K32
    zero(0x1000, 0x4000);
    pml4[0] = 0x2000 | 3;                          /* PML4[0]   -> PDPT_LO */
    pml4[2 * 511] = 0x4000 | 3;                    /* PML4[511] -> PDPT_HI (64-bit entries: low dword index *2) */
    pdpt_lo[0] = 0x3000 | 3;                       /* 0 GiB     -> PD */
    pdpt_hi[2 * 510] = 0x3000 | 3;                 /* 0xFFFFFFFF80000000 -> PD (physical 0) */
    for (i = 0; i < 512 && ((uint64_t)i << 21) < ram; ++i)
        pd[2 * i] = (i << 21) | 0x83;              /* present, writable, 2 MiB */
    {                                              /* after every read of the Multiboot data, which may sit in low memory */
        volatile shz_memholes_t *holes = (volatile shz_memholes_t *)SHZ_MEMHOLES_GPA;
        zero(SHZ_MEMHOLES_GPA, sizeof(shz_memholes_t));
        holes->magic = SHZ_MEMHOLES_MAGIC;
        holes->count = hole_count;
        for (i = 0; i < hole_count; ++i) {
            holes->hole[i].gpa = hole_gpa[i];
            holes->hole[i].size = hole_size[i];
        }
        holes->check = shz_memholes_sum(holes);
    }
#else
    (void)pml4; (void)pdpt_lo; (void)pd; (void)pdpt_hi;
#endif

    zero(SHZ_BOOTINFO_GPA, sizeof(shz_bootinfo_t));
    bi->magic = SHZ_BOOTINFO_MAGIC;
    bi->abi_major = SHZ_ABI_MAJOR;
    bi->abi_minor = SHZ_ABI_MINOR;
    bi->size = sizeof(shz_bootinfo_t);
    bi->domain_id = STUB_DOMAIN;
    bi->generation = 1;
    bi->ram_size = ram;
    bi->kernel_gpa = KERNEL_GPA;
    bi->kernel_size = ksize;
    if (isize) {
        bi->initrd_gpa = INITRD_GPA;
        bi->initrd_size = isize;
    }
    bi->tsc_hz = 1000000000u;                      /* nominal; QEMU TCG's TSC runs at 1 GHz. Only logged by Kernel64. */
    say("SHZ-STUB: kernel ");  hex(ksize);
    say(" initrd ");           hex(isize);
    say(" ram ");              hex(ram);
    say("\n");
}
