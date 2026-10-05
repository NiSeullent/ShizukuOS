/* SPDX-License-Identifier: GPL-2.0-only
 * Standalone Kernel64 boot stub, C part (32-bit protected mode, paging off, flat segments).
 * Multiboot modules: [0] KERNEL64 image (copied to 1 MiB), [1] initial RAM archive (copied to 32 MiB).
 * Kernel64 only: a module among the first three whose first 8 bytes are SHZ_BMAN_MAGIC is the installed-target
 * manifest \SHZDOS\SHZBOOT.MAN (syslinux `--- /SHZDOS/SHZBOOT.MAN`, routing02 C3). It is never the initrd; it is
 * snapshotted (<= 4096 bytes) before any copy and verified against the relocated kernel and initrd bytes. Any
 * mismatch refuses the boot; without it the historical unattested route continues and `install` stays zero.
 * Diagnostics go to COM1; on error the stub reports and asks QEMU to exit (isa-debug-exit).
 */
#include <stdint.h>
#include "../../abi/shz_abi.h"
#include "memholes.h"
#include "native_firmware.h"
#include "module_relocation.h"
#ifdef STUB_K32
#include "k32_cmdline.h"
#else
#define SHZ_INSTID_WANT_VERIFIER
#include "../install_identity.h"
#define STUB_MAX_MODS 3u                           /* kernel, initrd, manifest; later modules keep being ignored */
#endif
#ifndef STUB_MAX_MODS
#define STUB_MAX_MODS 2u
#endif

#ifdef STUB_K32                                    /* Kernel32: 32-bit Protected Mode, paging off, EBX = bootinfo */
#define STUB_DOMAIN SHZ_DOM_KERNEL32
#define MAX_RAM (128u << 20)                       /* Kernel32's page allocator limit (mem.c MAX_PAGES) */
#else
#define STUB_DOMAIN SHZ_DOM_KERNEL64
#define MAX_RAM 0xE0000000u                        /* 3.5 GiB: the most a QEMU pc guest has below 4 GiB; mem.c manages up to 4 GiB */
#endif
#define KERNEL_GPA 0x100000u
#define INITRD_GPA 0x2000000u
#define MB_MAGIC 0x2BADB002u
#define MB_INFO_MEM_MAP 0x40u

extern char stub_end[];                            /* boot.ld: end of the stub image including its stack */

struct mbi {
    uint32_t flags, mem_lower, mem_upper, boot_device, cmdline, mods_count, mods_addr, syms[4];
    uint32_t mmap_length, mmap_addr;
    uint32_t drives_length, drives_addr, config_table, boot_loader_name;
};
_Static_assert(__builtin_offsetof(struct mbi, boot_loader_name)==64, "Multiboot1 boot-loader offset");
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
    shz_stub_move((volatile uint8_t *)dst, (const volatile uint8_t *)src, n);
}
static void zero(uint32_t dst, uint32_t n)
{
    __asm__ volatile("rep stosb" : "+D"(dst), "+c"(n) : "a"(0) : "memory");
}

static shz_memplan_result_t plan;
static shz_native_firmware_t native_firmware;
static shz_memplan_t runs;

static int loader_read(void *unused, uint64_t pa, void *out, uint32_t bytes)
{
    uint8_t *dst = out;
    const volatile uint8_t *src = (const volatile uint8_t *)(uint32_t)pa;
    uint32_t i;
    (void)unused;
    for (i = 0; i < bytes; ++i) dst[i] = src[i];
    return 1;
}

/* RAM size and the firmware holes below it (memholes.h: the same plan the UEFI boot manager uses for its direct
 * Kernel64 boot). Without a Multiboot memory map: the classic mem_upper, contiguous RAM from 1 MiB, no holes. */
static void memory_ranges(const struct mbi *mbi)
{
    uint32_t ram, i;

    shz_memplan_init(&runs);
    if (!(mbi->flags & MB_INFO_MEM_MAP) || !mbi->mmap_length) {
        /* mem_upper: KiB of contiguous RAM above 1 MiB (below 4 GiB); low memory as on every PC */
        ram = mbi->mem_upper >= 0x3FFC00u ? 0xFFF00000u : (mbi->mem_upper + 1024u) << 10;
        shz_memplan_add(&runs, 0, (uint64_t)mbi->mem_lower << 10);
        shz_memplan_add(&runs, KERNEL_GPA, ram);
    } else {
        for (i = 0; i < native_firmware.count; ++i) {
            const shz_native_firmware_range_t *e = &native_firmware.range[i];
            uint64_t b = e->base, x = e->base + e->length;
            if (e->type != 1 || !e->length || b >= (1ull << 32))
                continue;
            if (x > (1ull << 32)) x = 1ull << 32;
            shz_memplan_add(&runs, b, x);
        }
        /* A reservation overlapping RAM wins, as for the UEFI map reader. */
        for (i = 0; i < native_firmware.count; ++i) {
            const shz_native_firmware_range_t *e = &native_firmware.range[i];
            if (e->type != 1 && e->length)
                shz_memplan_remove(&runs, e->base, e->base + e->length);
        }
    }
}

static uint32_t memory_layout(uint32_t isize)
{
    uint32_t i;
    if (!shz_memplan_solve(&runs, MAX_RAM, 64u << 20, INITRD_GPA, isize, &plan))
        fail(plan.why, (uint32_t)plan.at);
#ifdef STUB_K32
    if (plan.count) fail("Kernel32 needs contiguous RAM from 1 MiB; firmware hole at", (uint32_t)plan.gpa[0]);
#endif
    for (i = 0; i < plan.count; ++i) {
        say("SHZ-STUB: firmware hole "); hex((uint32_t)plan.gpa[i]); say(" size "); hex((uint32_t)plan.size[i]);
        say(plan.gpa[i] < SHZ_K64_PMM_GPA ? " fenced off in the kernel heap\n" : " kept out of the page allocator\n");
    }
    if (plan.cut) {
        say("SHZ-STUB: more than 16 firmware holes; RAM ends below the hole at "); hex((uint32_t)plan.cut); say("\n");
    }
    if (runs.dropped) {
        say("SHZ-STUB: memory map has more than 64 separate usable ranges; ignored above the 64th: "); hex(runs.dropped);
        say("\n");
    }
    return (uint32_t)plan.ram;
}

void stub_prepare(uint32_t magic, const struct mbi *mbi)
{
    static char cmdline[SHZ_CMDLINE_MAX];          /* stub .bss (above 4 MiB), untouched by the copies below */
    struct mod mods[STUB_MAX_MODS];               /* Snapshot descriptors before kernel zero/initrd relocation. */
    uint32_t ksize, isize = 0, ram, i, cmdline_len = 0, has_initrd, nmods;
#ifndef STUB_K32
    static uint64_t manifest[SHZ_BMAN_MAX_BYTES / 8];  /* stub .bss snapshot of SHZBOOT.MAN */
    static shz_install_identity_t install;
    uint32_t msize = 0, manifest_index = 0;
#endif
    volatile shz_bootinfo_t *bi = (volatile shz_bootinfo_t *)SHZ_BOOTINFO_GPA;
    volatile uint32_t *pml4 = (volatile uint32_t *)0x1000, *pdpt_lo = (volatile uint32_t *)0x2000,
                      *pd = (volatile uint32_t *)0x3000, *pdpt_hi = (volatile uint32_t *)0x4000;

    if (magic != MB_MAGIC) fail("not entered by a Multiboot loader, eax=", magic);
    if (!(mbi->flags & 1)) fail("no memory info", mbi->flags);
    {
        const uint64_t source_limit = mbi->mem_upper >= 0x3FFC00u ? UINT64_C(0xffffffff) :
                                      ((uint64_t)mbi->mem_upper + 1024u) << 10;
        const int captured = shz_native_firmware_capture(&native_firmware, !!(mbi->flags & MB_INFO_MEM_MAP),
                mbi->mmap_addr, mbi->mmap_length, source_limit, loader_read, 0);
        if (captured < 0) fail("malformed or incomplete firmware map", mbi->mmap_length);
    }
    if (!(mbi->flags & 8) || mbi->mods_count < 1) fail("need module 0 = KERNEL64 image, flags=", mbi->flags);
    memory_ranges(mbi);
    nmods = mbi->mods_count < STUB_MAX_MODS ? mbi->mods_count : STUB_MAX_MODS;
    {
        const uint64_t descriptors_end = (uint64_t)mbi->mods_addr + nmods * sizeof(struct mod);
        const volatile struct mod *source = (const volatile struct mod *)mbi->mods_addr;
        if (!mbi->mods_addr || descriptors_end > UINT32_MAX ||
            !shz_memplan_covers(&runs, mbi->mods_addr, descriptors_end))
            fail("module descriptors outside usable RAM", mbi->mods_addr);
        for (i = 0; i < nmods; ++i) {
            mods[i].start = source[i].start; mods[i].end = source[i].end;
            mods[i].string = source[i].string; mods[i].reserved = source[i].reserved;
        }
    }
#ifndef STUB_K32
    /* Classify modules 1..2 by content, before any copy can overwrite them. Exactly one manifest at most. */
    for (i = 1; i < nmods; ++i) {
        const uint32_t n = mods[i].end > mods[i].start ? mods[i].end - mods[i].start : 0;
        uint32_t k;
        if (n < 8 || !shz_memplan_covers(&runs, mods[i].start, (uint64_t)mods[i].start + 8u) ||
            !shz_instid_is_manifest((const volatile uint8_t *)mods[i].start, n))
            continue;
        if (manifest_index) fail("more than one SHZBOOT.MAN module, second at", mods[i].start);
        if (n > SHZ_BMAN_MAX_BYTES || mods[i].start < (uint32_t)stub_end ||
            !shz_memplan_covers(&runs, mods[i].start, mods[i].end))
            fail("SHZBOOT.MAN module outside the 4096-byte bound or usable RAM, size", n);
        for (k = 0; k < n; ++k)
            ((uint8_t *)manifest)[k] = ((const volatile uint8_t *)mods[i].start)[k];
        msize = n;
        manifest_index = i;
    }
    has_initrd = nmods > 1 && manifest_index != 1;  /* the manifest is never the initial RAM image */
#else
    has_initrd = nmods > 1;
#endif
    if (mods[0].end <= mods[0].start || (has_initrd && mods[1].end < mods[1].start))
        fail("reversed or empty kernel module extent", mods[0].start);
    ksize = mods[0].end - mods[0].start;
    if (has_initrd) isize = mods[1].end - mods[1].start;
    ram = memory_layout(isize);
    if (ram < (64u << 20)) fail("need at least 64 MiB, have ", ram);
    if (ksize == 0 || ksize > SHZ_STUB_KERNEL_FILE_MAX) fail("kernel image size (file + bss must stay below 3 MiB), ", ksize);
    if (!shz_stub_relocation_valid(&runs, ram, (uint32_t)stub_end, mods[0].start, mods[0].end,
                has_initrd ? mods[1].start : 0, has_initrd ? mods[1].end : 0, has_initrd))
        fail("module relocation outside safe usable RAM", mods[0].start);
    if (mbi->flags & 4) {                          /* Capture before module copies. K64 retains its historical raw,
                                                      sanitized/truncated line; K32 uses a bounded adapter only for
                                                      the exact advertised QEMU image-name prefix. */
        const volatile char *src = (const volatile char *)mbi->cmdline;
#ifdef STUB_K32
        int image_prefix=0;
        if (mbi->flags & (1u<<9)) {
            if (!mbi->boot_loader_name || mbi->boot_loader_name > ram-5)
                fail("K32 boot-loader name outside RAM", mbi->boot_loader_name);
            image_prefix=shz_mb1_loader_is_qemu((const volatile char *)mbi->boot_loader_name);
        }
        const int copied=shz_mb1_k32_cmdline(cmdline,sizeof cmdline,src,image_prefix);
        if (copied<0) fail("K32 command line malformed or truncated", 0);
        cmdline_len=(uint32_t)copied;
#else
        for (cmdline_len = 0; cmdline_len < SHZ_CMDLINE_MAX - 1 && src[cmdline_len]; ++cmdline_len)
            cmdline[cmdline_len] = (src[cmdline_len] >= 0x20 && src[cmdline_len] < 0x7f) ? src[cmdline_len] : '?';
#endif
    }

    zero(KERNEL_GPA, 0x300000u - KERNEL_GPA);      /* bss of the kernel image reads as zero, as after the Supervisor's memset */
    copy(KERNEL_GPA, mods[0].start, ksize);
    if (isize) copy(INITRD_GPA, mods[1].start, isize);
#ifndef STUB_K32
    if (msize) {                                   /* hash the relocated bytes Kernel64 will actually run */
        const char *why = 0;
        if (shz_instid_verify(manifest, msize, (const volatile uint8_t *)KERNEL_GPA, ksize,
                              isize ? (const volatile uint8_t *)INITRD_GPA : 0, isize,
                              SHZ_INSTID_MULTIBOOT, &install, &why)) {
            say("SHZ-STUB: SHZBOOT.MAN binds this installed target and verification failed: "); say(why);
            say("\nSHZ-STUB: an attested target never boots a different kernel or RAM image\n");
            fail("installed-target manifest refused, module", manifest_index);
        }
        say("SHZ-STUB: installed target attested by SHZBOOT.MAN, generation ");
        hex((uint32_t)(install.install_generation >> 32)); hex((uint32_t)install.install_generation); say("\n");
    } else {
        say("SHZ-STUB: no SHZBOOT.MAN module; historical unattested route\n");
    }
#endif

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
        shz_memholes_write(holes, &plan);
    }
    /* Captured before copies: the loader's map may itself have occupied low memory.
     * An absent map writes an explicit zero record rather than retaining stale bytes. */
    copy(SHZ_NATIVE_FIRMWARE_GPA, (uint32_t)&native_firmware, sizeof(native_firmware));
    say("SHZ-STUB: native firmware ranges "); hex(native_firmware.count); say("\n");
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
    for (i = 0; i < cmdline_len; ++i)              /* ABI 1.1 tail; the framebuffer fields stay zero (no GOP here) */
        bi->cmdline[i] = cmdline[i];
    bi->cmdline_size = cmdline_len;
#ifndef STUB_K32
    for (i = 0; i < sizeof install; ++i)           /* zero unless verified above; bi->size covers it */
        ((volatile uint8_t *)&bi->install)[i] = ((const uint8_t *)&install)[i];
#endif
    say("SHZ-STUB: kernel ");  hex(ksize);
    say(" initrd ");           hex(isize);
    say(" ram ");              hex(ram);
    say(" cmdline ");          hex(bi->cmdline_size);
    say("\n");
}
