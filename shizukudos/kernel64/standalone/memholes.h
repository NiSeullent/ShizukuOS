/* SPDX-License-Identifier: GPL-2.0-only
 * Firmware memory-map holes for the standalone Kernel64 (built with SHZ_STANDALONE), and the one RAM plan that
 * both of its boot paths use:
 *   - the Multiboot stub (boot32.c) from the E820 map it is given (legacy BIOS, or SeaBIOS inside CSMWrap), and
 *   - the UEFI boot manager's direct Kernel64 boot (supervisor/loader/loader.c) from the UEFI memory map.
 * Not part of the inter-kernel ABI: a Supervisor domain has flat RAM and never sees it.
 *
 * Why: OVMF with S3 enabled (QEMU's default) reserves its SEC/PEI scratch RAM at 8-9 MiB as EfiACPIMemoryNVS for
 * S3 resume; UEFI hands it to CSMWrap's E820 as ACPI NVS too. An OS must not overwrite ACPI NVS, so Kernel64's RAM
 * is not one run from 1 MiB. Kernel64's layout is fixed: boot structures [0x1000, 0x8000), kernel image + bss
 * [1 MiB, 4 MiB), heap [4 MiB, 15 MiB), page allocator above 15 MiB, initial RAM image at 32 MiB. The plan:
 *   - boot structures, the kernel window and the initial RAM image must be usable RAM (else: refused);
 *   - a hole in the heap window is fenced off in the heap's block list (mem.c heap_init), as long as at least
 *     SHZ_K64_HEAP_KEEP bytes of the heap stay usable (else: refused);
 *   - a hole above the heap is kept out of the page allocator;
 *   - RAM ends at the highest usable address below the caller's cap, 2 MiB aligned, with its top page usable
 *     (mem.c probes it); when there are more holes than SHZ_MEMHOLES_MAX, RAM ends below the first one that does
 *     not fit (the boot continues with less RAM instead of failing).
 * The result goes to physical 0x6000 as shz_memholes_t, which mem.c reads (magic + checksum; absent = no holes).
 */
#ifndef SHZ_MEMHOLES_H
#define SHZ_MEMHOLES_H
#include <stdint.h>

#define SHZ_MEMHOLES_GPA 0x6000u        /* free low page: stub page tables 0x1000-0x4FFF, loader trampoline/GDT
                                           0x5000-0x5FFF, bootinfo 0x7000 */
#define SHZ_MEMHOLES_MAGIC 0x454c4f48u  /* "HOLE" */
#define SHZ_MEMHOLES_MAX 16

/* Kernel64's fixed guest-physical layout: the one checked contract for every Kernel64 loader (Multiboot stub
 * boot32.c, UEFI direct boot supervisor/loader/loader.c, Supervisor kdom.c) and for mem.c, which includes this
 * header in every build. kernel64/link.ld repeats SHZ_K64_KERNEL_END as a literal in its ASSERT (a linker script
 * cannot include C); test_memplan.py checks that the two agree. Kernel32 has its own geometry (boot32.c STUB_K32). */
#define SHZ_K64_LOW_GPA 0x1000u         /* boot page tables, loader trampoline, holes, boot info: [0x1000, 0x8000) */
#define SHZ_K64_LOW_END 0x8000u
#define SHZ_K64_KERNEL_GPA 0x100000u    /* kernel image + bss: [1 MiB, 4 MiB); every loader zeroes all of it */
#define SHZ_K64_KERNEL_END 0x400000u
#define SHZ_K64_KERNEL_WINDOW (SHZ_K64_KERNEL_END - SHZ_K64_KERNEL_GPA)
#define SHZ_K64_KERNEL_FILE_MAX SHZ_K64_KERNEL_WINDOW  /* KERNEL64*.BIN bytes; link.ld bounds file + bss */
#define SHZ_K64_HEAP_GPA SHZ_K64_KERNEL_END              /* heap: [4 MiB, 15 MiB) */
#define SHZ_K64_PMM_GPA 0xF00000u       /* page allocator from 15 MiB */
#define SHZ_K64_HEAP_BYTES (SHZ_K64_PMM_GPA - SHZ_K64_HEAP_GPA)   /* 11 MiB */
#define SHZ_K64_HEAP_KEEP 0x800000u     /* at least 8 MiB of the 11 MiB heap window must be usable RAM */
_Static_assert(SHZ_K64_LOW_END <= SHZ_K64_KERNEL_GPA && SHZ_K64_KERNEL_GPA < SHZ_K64_KERNEL_END &&
               SHZ_K64_KERNEL_END == SHZ_K64_HEAP_GPA && SHZ_K64_HEAP_GPA < SHZ_K64_PMM_GPA &&
               SHZ_K64_HEAP_KEEP <= SHZ_K64_HEAP_BYTES && !(SHZ_K64_KERNEL_END & 0xfffu) &&
               !(SHZ_K64_PMM_GPA & 0xfffu), "Kernel64 guest-physical layout");

typedef struct {
    uint32_t magic;                     /* SHZ_MEMHOLES_MAGIC */
    uint32_t count;                     /* <= SHZ_MEMHOLES_MAX */
    struct {
        uint64_t gpa, size;
    } hole[SHZ_MEMHOLES_MAX];
    uint32_t check;                     /* ~(magic + count + every 32-bit word of hole[0..count)) */
    uint32_t reserved;
} shz_memholes_t;

static inline uint32_t shz_memholes_sum(const volatile shz_memholes_t *h)
{
    uint32_t sum = h->magic + h->count, i;
    for (i = 0; i < h->count && i < SHZ_MEMHOLES_MAX; ++i)
        sum += (uint32_t)h->hole[i].gpa + (uint32_t)(h->hole[i].gpa >> 32) + (uint32_t)h->hole[i].size +
               (uint32_t)(h->hole[i].size >> 32);
    return ~sum;
}

/* ---------------------------------------------------------------- RAM plan (no libc, no 64-bit division) */
#define SHZ_MEMPLAN_RUNS 64

typedef struct {
    uint32_t n;                         /* usable runs: sorted, disjoint, not touching */
    uint32_t dropped;                   /* runs lost because more than SHZ_MEMPLAN_RUNS were distinct (the highest) */
    uint64_t base[SHZ_MEMPLAN_RUNS], end[SHZ_MEMPLAN_RUNS];
} shz_memplan_t;

typedef struct {
    uint64_t ram;                       /* Kernel64 ram_size: guest RAM is [0, ram), 2 MiB aligned; 0 = refused */
    uint32_t count;                     /* holes in [4 MiB, ram), page aligned outward */
    uint64_t gpa[SHZ_MEMHOLES_MAX], size[SHZ_MEMHOLES_MAX];
    uint64_t heap_hole_bytes;           /* bytes of the heap window [4 MiB, 15 MiB) inside holes */
    uint64_t cut;                       /* nonzero: RAM ends early below this hole (hole budget exhausted) */
    uint64_t top;                       /* highest usable address below the cap */
    const char *why;                    /* refusal reason when ram == 0 */
    uint64_t at;                        /* the address the refusal is about (a byte count when at_is_size) */
    uint32_t at_is_size;
} shz_memplan_result_t;

static inline void shz_memplan_init(shz_memplan_t *p)
{
    p->n = 0;
    p->dropped = 0;
}

/* Adds usable RAM [b, e). Overlapping or touching runs merge; the map need not be sorted. */
static inline void shz_memplan_add(shz_memplan_t *p, uint64_t b, uint64_t e)
{
    uint32_t i, j, k;
    if (e <= b)
        return;
    for (i = 0; i < p->n && p->end[i] < b; ++i)
        ;
    for (j = i; j < p->n && p->base[j] <= e; ++j) {
        if (p->base[j] < b) b = p->base[j];
        if (p->end[j] > e) e = p->end[j];
    }
    if (j > i) {                        /* runs [i, j) and the new range become run i */
        p->base[i] = b;
        p->end[i] = e;
        for (k = i + 1; j < p->n; ++k, ++j) {
            p->base[k] = p->base[j];
            p->end[k] = p->end[j];
        }
        p->n = k;
        return;
    }
    if (p->n == SHZ_MEMPLAN_RUNS) {     /* full: the highest run is treated as not usable (safe, only loses RAM) */
        ++p->dropped;
        if (i == p->n)
            return;
        --p->n;
    }
    for (k = p->n; k > i; --k) {
        p->base[k] = p->base[k - 1];
        p->end[k] = p->end[k - 1];
    }
    p->base[i] = b;
    p->end[i] = e;
    ++p->n;
}

/* Removes [b, e) from the usable runs: a firmware map may list an unusable range overlapping a usable one, and
 * the unusable one wins. */
static inline void shz_memplan_remove(shz_memplan_t *p, uint64_t b, uint64_t e)
{
    uint32_t i = 0, k;
    if (e <= b)
        return;
    while (i < p->n) {
        if (p->end[i] <= b || p->base[i] >= e) {
            ++i;
        } else if (p->base[i] < b && p->end[i] > e) {   /* strictly inside run i: split it */
            if (p->n == SHZ_MEMPLAN_RUNS) {             /* no room for the upper part: lose the highest run */
                ++p->dropped;
                if (i == p->n - 1) {
                    p->end[i] = b;
                    return;
                }
                --p->n;
            }
            for (k = p->n; k > i + 1; --k) {
                p->base[k] = p->base[k - 1];
                p->end[k] = p->end[k - 1];
            }
            p->base[i + 1] = e;
            p->end[i + 1] = p->end[i];
            p->end[i] = b;
            ++p->n;
            return;                                     /* runs are disjoint: no other run meets [b, e) */
        } else if (p->base[i] >= b && p->end[i] <= e) { /* covered: delete run i */
            for (k = i; k + 1 < p->n; ++k) {
                p->base[k] = p->base[k + 1];
                p->end[k] = p->end[k + 1];
            }
            --p->n;
        } else {
            if (p->base[i] < b)
                p->end[i] = b;
            else
                p->base[i] = e;
            ++i;
        }
    }
}

static inline int shz_memplan_covers(const shz_memplan_t *p, uint64_t b, uint64_t e)
{
    uint32_t i;
    for (i = 0; i < p->n; ++i)
        if (p->base[i] <= b && p->end[i] >= e)
            return 1;
    return 0;
}

static inline int shz_memplan_refuse(shz_memplan_result_t *r, const char *why, uint64_t at)
{
    r->ram = 0;
    r->why = why;
    r->at = at;
    r->at_is_size = 0;
    return 0;
}

/* Plans Kernel64's RAM below `cap` (bytes, 2 MiB aligned). Returns 1 with r->ram set, or 0 with r->why/r->at. */
static inline int shz_memplan_solve(const shz_memplan_t *p, uint64_t cap, uint64_t min_ram, uint64_t initrd_gpa,
                                    uint64_t initrd_size, shz_memplan_result_t *r)
{
    const uint64_t initrd_end = initrd_gpa + initrd_size;
    uint64_t ram = 0, cursor, lower;
    uint32_t i, kept;

    r->ram = r->heap_hole_bytes = r->cut = r->top = r->at = 0;
    r->count = r->at_is_size = 0;
    r->why = 0;
    if (!shz_memplan_covers(p, SHZ_K64_LOW_GPA, SHZ_K64_LOW_END))
        return shz_memplan_refuse(r, "the boot pages [0x1000, 0x8000) are not usable RAM", SHZ_K64_LOW_GPA);
    if (!shz_memplan_covers(p, SHZ_K64_KERNEL_GPA, SHZ_K64_KERNEL_END)) {
        for (i = 0; i < p->n && !(p->base[i] <= SHZ_K64_KERNEL_GPA && p->end[i] > SHZ_K64_KERNEL_GPA); ++i)
            ;
        return shz_memplan_refuse(r, "firmware hole in the kernel window [1 MiB, 4 MiB) at",
                                  i < p->n ? p->end[i] : SHZ_K64_KERNEL_GPA);
    }
    for (i = 0; i < p->n; ++i)          /* highest usable address below the cap */
        if (p->base[i] < cap)
            r->top = p->end[i] < cap ? p->end[i] : cap;
    ram = r->top & ~0x1fffffull;

    /* Gaps between usable runs in [4 MiB, ram). The kernel window is covered, so they start at or above 4 MiB. */
    cursor = SHZ_K64_HEAP_GPA;
    for (i = 0; i < p->n && cursor < ram; ++i) {
        if (p->end[i] <= cursor)
            continue;
        if (p->base[i] > cursor) {
            const uint64_t a = cursor & ~0xfffull;
            const uint64_t z = ((p->base[i] < ram ? p->base[i] : ram) + 0xfff) & ~0xfffull;
            if (initrd_size && a < initrd_end && z > initrd_gpa)
                return shz_memplan_refuse(r, "firmware hole where the initial RAM image goes (32 MiB), at", a);
            if (r->count == SHZ_MEMHOLES_MAX) {
                r->cut = a;
                ram = a & ~0x1fffffull;
                break;
            }
            r->gpa[r->count] = a;
            r->size[r->count++] = z - a;
        }
        cursor = p->end[i];
    }

    /* mem.c writes the top page of RAM: it must be usable. Lower RAM to the 2 MiB boundary below any gap there. */
    while (ram >= min_ram && !shz_memplan_covers(p, ram - 0x1000, ram)) {
        lower = 0;
        for (i = 0; i < p->n; ++i)
            if (p->base[i] < ram && (p->end[i] < ram ? p->end[i] : ram) > lower)
                lower = p->end[i] < ram ? p->end[i] : ram;
        if (lower >= ram)               /* a run starting inside the top page: step below it */
            lower = ram - 1;
        ram = lower & ~0x1fffffull;
    }
    for (i = kept = 0; i < r->count; ++i)       /* holes above the final RAM end do not matter */
        if (r->gpa[i] < ram) {
            r->gpa[kept] = r->gpa[i];
            r->size[kept] = r->gpa[i] + r->size[i] > ram ? ram - r->gpa[i] : r->size[i];
            ++kept;
        }
    r->count = kept;
    for (i = 0; i < r->count; ++i) {
        const uint64_t a = r->gpa[i] > SHZ_K64_HEAP_GPA ? r->gpa[i] : SHZ_K64_HEAP_GPA;
        const uint64_t z = r->gpa[i] + r->size[i] < SHZ_K64_PMM_GPA ? r->gpa[i] + r->size[i] : SHZ_K64_PMM_GPA;
        if (z > a)
            r->heap_hole_bytes += z - a;
    }
    if (r->heap_hole_bytes > SHZ_K64_HEAP_BYTES || SHZ_K64_HEAP_BYTES - r->heap_hole_bytes < SHZ_K64_HEAP_KEEP) {
        shz_memplan_refuse(r, "firmware holes leave less than 8 MiB of the kernel heap [4 MiB, 15 MiB); "
                              "hole bytes there:", r->heap_hole_bytes);
        r->at_is_size = 1;
        return 0;
    }
    if (ram < min_ram)
        return shz_memplan_refuse(r, "usable RAM (after firmware holes) ends too low for Kernel64, at", ram);
    if (initrd_size && initrd_end > ram)
        return shz_memplan_refuse(r, "the initial RAM image does not fit below the end of usable RAM, which is",
                                  ram);
    r->ram = ram;
    return 1;
}

/* Writes the plan's holes where mem.c looks for them (callers own that page and zero it first). */
static inline void shz_memholes_write(volatile shz_memholes_t *h, const shz_memplan_result_t *r)
{
    uint32_t i;
    h->magic = SHZ_MEMHOLES_MAGIC;
    h->count = r->count;
    for (i = 0; i < r->count; ++i) {
        h->hole[i].gpa = r->gpa[i];
        h->hole[i].size = r->size[i];
    }
    h->reserved = 0;
    h->check = shz_memholes_sum(h);
}
#endif
