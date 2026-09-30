/* SPDX-License-Identifier: GPL-2.0-only
 * Kernel64 memory management.
 *
 * Address space (kernel half is shared by every process):
 *   0xFFFFFFFF80000000  kernel image alias (physical 0, first 1 GiB, 2 MiB pages)
 *   0xFFFF800000000000  direct map of all guest-physical memory this kernel owns or may touch
 *   0x0000000000010000..0x00007FFFFFFEEFFF  user space (per process)
 * Guest-physical layout: 0..1 MiB boot structures, 1..3 MiB kernel image + bss (every loader zeroes exactly this
 * window; link.ld refuses an image that outgrows it), 3..15 MiB heap, 15 MiB.. page allocator (initrd range excluded). RAM up to MAX_PAGES (4 GiB of guest-physical) is managed;
 * the standalone stub caps what it reports below 4 GiB (boot32.c MAX_RAM), 256 MiB configurations still work.
 * The direct map is built for all of RAM with 2 MiB pages (a 3.5 GiB guest costs 4 page directories).
 * Standalone builds (SHZ_STANDALONE) also take firmware memory holes from standalone/memholes.h: their pages stay
 * out of the page allocator, and holes inside the heap window are fenced off in the heap block list.
 */
#include "k64.h"
#ifdef SHZ_STANDALONE
#include "standalone/memholes.h"
#endif

#define HEAP_PA 0x300000ull                    /* = end of the kernel window [1 MiB, 3 MiB) */
#define HEAP_BYTES 0xC00000ull
#define PMM_BASE 0xF00000ull
#define MAX_PAGES (4096ull * 1024 * 1024 / PAGE_SIZE)

#ifdef SHZ_STANDALONE
_Static_assert(HEAP_PA == SHZ_K64_HEAP_GPA && PMM_BASE == SHZ_K64_PMM_GPA && HEAP_PA + HEAP_BYTES == PMM_BASE,
               "standalone/memholes.h plans holes for this layout");
static uint64_t hole_gpa[SHZ_MEMHOLES_MAX], hole_end[SHZ_MEMHOLES_MAX];
static unsigned hole_count;
#endif

static uint8_t page_map[MAX_PAGES / 8];
static uint64_t pmm_pages, pmm_free_pages, pmm_hint;
static uint64_t kpml4;
static uint64_t ram_top;
extern int mem_probe_ok;

uint64_t kernel_pml4(void) { return kpml4; }

static int bit_get(uint64_t i) { return page_map[i >> 3] & (1u << (i & 7)); }
static void bit_set(uint64_t i) { page_map[i >> 3] |= (uint8_t)(1u << (i & 7)); }
static void bit_clr(uint64_t i) { page_map[i >> 3] &= (uint8_t)~(1u << (i & 7)); }

uint64_t pmm_alloc(void)
{
    uint64_t f = irq_save(), n, i;
    for (n = 0; n < pmm_pages; ++n) {
        i = (pmm_hint + n) % pmm_pages;
        if (!bit_get(i)) {
            bit_set(i);
            pmm_hint = i + 1;
            --pmm_free_pages;
            irq_restore(f);
            memset((void *)p2v(PMM_BASE + i * PAGE_SIZE), 0, PAGE_SIZE);
            return PMM_BASE + i * PAGE_SIZE;
        }
    }
    irq_restore(f);
    return 0;
}

void pmm_free(uint64_t pa)
{
    uint64_t f = irq_save(), i;
    KASSERT(pa >= PMM_BASE && !(pa & 0xfff));
    i = (pa - PMM_BASE) / PAGE_SIZE;
    KASSERT(i < pmm_pages && bit_get(i));       /* double free or foreign page */
    bit_clr(i);
    ++pmm_free_pages;
    irq_restore(f);
}

/* A run of n physically contiguous zeroed pages (kernel stacks, the scheduler's thread table), searched top-down so the runs stay
 * clear of the single pages pmm_alloc() hands out from the bottom of the map. contig_hint is the exclusive upper bound of the next
 * search: it follows the last run handed out and is lifted again by pmm_free_contig(), so thread churn recycles the same slots. */
static uint64_t contig_hint;

uint64_t pmm_alloc_contig(unsigned n)
{
    uint64_t f, i, run, start, base = 0;
    unsigned pass;
    if (!n) return 0;
    f = irq_save();
    for (pass = 0; pass < 2 && !base; ++pass) {
        start = (!pass && contig_hint && contig_hint <= pmm_pages) ? contig_hint : pmm_pages;
        run = 0;
        for (i = start; i > 0;) {
            --i;
            if ((i & 7) == 7 && page_map[i >> 3] == 0xff) { i -= 7; run = 0; continue; }     /* a fully used byte of the map */
            if (bit_get(i)) { run = 0; continue; }
            if (++run == n) { base = i + 1; break; }                                        /* base is stored +1: 0 means none */
        }
    }
    if (!base) { irq_restore(f); return 0; }
    --base;
    for (i = 0; i < n; ++i) bit_set(base + i);
    pmm_free_pages -= n;
    contig_hint = base;
    irq_restore(f);
    memset((void *)p2v(PMM_BASE + base * PAGE_SIZE), 0, (size_t)n * PAGE_SIZE);
    return PMM_BASE + base * PAGE_SIZE;
}

void pmm_free_contig(uint64_t pa, unsigned n)
{
    uint64_t f, i;
    KASSERT(pa >= PMM_BASE && !(pa & 0xfff));
    f = irq_save();
    i = (pa - PMM_BASE) / PAGE_SIZE;
    KASSERT(i + n <= pmm_pages);
    for (; n; --n, ++i) {
        KASSERT(bit_get(i));
        bit_clr(i);
        ++pmm_free_pages;
    }
    if (i > contig_hint) contig_hint = i;
    irq_restore(f);
}

uint64_t pmm_free_count(void) { return pmm_free_pages; }
uint64_t pmm_total_count(void) { return pmm_pages; }

/* ---------------------------------------------------------------- paging */
static uint64_t *table_at(uint64_t pa) { return (uint64_t *)p2v(pa); }

static uint64_t *walk(uint64_t pml4, uint64_t va, int create, uint64_t user)
{
    uint64_t *t = table_at(pml4);
    int level;
    for (level = 3; level > 0; --level) {
        const unsigned idx = (va >> (12 + 9 * level)) & 511;
        if (!(t[idx] & PT_P)) {
            uint64_t pa;
            if (!create)
                return 0;
            pa = pmm_alloc();
            if (!pa)
                return 0;
            t[idx] = pa | PT_P | PT_W | (user ? PT_U : 0);
        } else if (user && !(t[idx] & PT_U)) {
            t[idx] |= PT_U;
        }
        t = table_at(t[idx] & 0x000ffffffffff000ull);
    }
    return &t[(va >> 12) & 511];
}

int vm_map(uint64_t pml4, uint64_t va, uint64_t pa, uint64_t flags)
{
    uint64_t *pte = walk(pml4, va, 1, flags & PT_U);
    if (!pte)
        return -1;
    *pte = (pa & 0x000ffffffffff000ull) | (flags & (PT_W | PT_U | PT_NX | PT_PWT | PT_PCD)) | PT_P;
    invlpg(va);
    return 0;
}

int vm_unmap(uint64_t pml4, uint64_t va, uint64_t *pa_out)
{
    uint64_t *pte = walk(pml4, va, 0, 0);
    if (!pte || !(*pte & PT_P))
        return -1;
    if (pa_out)
        *pa_out = *pte & 0x000ffffffffff000ull;
    *pte = 0;
    invlpg(va);
    return 0;
}

int vm_protect(uint64_t pml4, uint64_t va, uint64_t flags)
{
    uint64_t *pte = walk(pml4, va, 0, 0);
    if (!pte || !(*pte & PT_P))
        return -1;
    *pte = (*pte & 0x000ffffffffff000ull) | (flags & (PT_W | PT_U | PT_NX)) | PT_P;
    invlpg(va);
    return 0;
}

uint64_t vm_lookup(uint64_t pml4, uint64_t va, uint64_t *flags_out)
{
    uint64_t *pte = walk(pml4, va, 0, 0);
    if (!pte || !(*pte & PT_P))
        return 0;
    if (flags_out)
        *flags_out = *pte & (PT_W | PT_U | PT_NX);
    return (*pte & 0x000ffffffffff000ull) | (va & 0xfff);
}

uint64_t vm_new_space(void)
{
    const uint64_t pa = pmm_alloc();
    unsigned i;
    if (!pa)
        return 0;
    for (i = 256; i < 512; ++i)                 /* share the kernel half */
        table_at(pa)[i] = table_at(kpml4)[i];
    return pa;
}

static void free_level(uint64_t table_pa, int level)
{
    uint64_t *t = table_at(table_pa);
    unsigned i;
    for (i = 0; i < (level == 4 ? 256u : 512u); ++i) {
        if (!(t[i] & PT_P))
            continue;
        if (level == 1)
            pmm_free(t[i] & 0x000ffffffffff000ull);
        else
            free_level(t[i] & 0x000ffffffffff000ull, level - 1);
    }
    pmm_free(table_pa);
}

void vm_free_space(uint64_t pml4) { free_level(pml4, 4); }

static uint64_t count_level(uint64_t table_pa, int level)
{
    const uint64_t *t = table_at(table_pa);
    uint64_t n = 0;
    unsigned i;
    for (i = 0; i < (level == 4 ? 256u : 512u); ++i) {
        if (!(t[i] & PT_P) || !(t[i] & PT_U))
            continue;
        n += level == 1 ? 1 : count_level(t[i] & 0x000ffffffffff000ull, level - 1);
    }
    return n;
}

uint64_t vm_count_user_pages(uint64_t pml4) { return count_level(pml4, 4); }

/* ---------------------------------------------------------------- heap */
struct hblock { uint64_t size; uint64_t used; struct hblock *next; uint64_t magic; };
#define HMAGIC 0x4b48454150363421ull
static struct hblock *heap_head;
static size_t heap_used_bytes, heap_total_bytes;

/* One free block per usable segment of the heap window [HEAP_PA, HEAP_PA + HEAP_BYTES). Firmware holes (standalone
 * builds only) split the window: each segment before a hole ends in a used, never-freed sentinel block (header
 * only, size 0), so kfree's merging of neighbouring free blocks never reaches across the hole, and nothing is ever
 * written inside it. Without holes this is the single block it always was. */
static void heap_init(void)
{
    const uint64_t window_end = HEAP_PA + HEAP_BYTES, hdr = sizeof(struct hblock);
    uint64_t seg = HEAP_PA;
    struct hblock *prev = 0;

    heap_head = 0;
    while (seg < window_end) {
        uint64_t stop = window_end, resume = window_end;
        struct hblock *b, *sentinel = 0;
#ifdef SHZ_STANDALONE
        unsigned h;
        for (h = 0; h < hole_count; ++h)        /* the nearest hole at or after seg */
            if (hole_end[h] > seg && hole_gpa[h] < stop) {
                stop = hole_gpa[h] > seg ? hole_gpa[h] : seg;
                resume = hole_end[h];
            }
#endif
        if (stop - seg >= 2 * hdr + 64) {
            b = (struct hblock *)p2v(seg);
            b->used = 0;
            b->magic = HMAGIC;
            b->next = 0;
            b->size = stop - seg - hdr;
            if (stop < window_end) {
                sentinel = (struct hblock *)p2v(stop - hdr);
                sentinel->size = 0;
                sentinel->used = 1;
                sentinel->next = 0;
                sentinel->magic = HMAGIC;
                b->size -= hdr;
                b->next = sentinel;
            }
            if (prev)
                prev->next = b;
            else
                heap_head = b;
            prev = sentinel ? sentinel : b;
            heap_total_bytes += b->size;
        }
        seg = stop < window_end ? resume : window_end;
    }
    KASSERT(heap_head);
}

void *kmalloc(size_t n)
{
    uint64_t f = irq_save();
    struct hblock *b;
    n = (n + 15) & ~(size_t)15;
    for (b = heap_head; b; b = b->next) {
        KASSERT(b->magic == HMAGIC);
        if (!b->used && b->size >= n) {
            if (b->size >= n + sizeof *b + 32) {
                struct hblock *rest = (struct hblock *)((uint8_t *)(b + 1) + n);
                rest->size = b->size - n - sizeof *b;
                rest->used = 0;
                rest->next = b->next;
                rest->magic = HMAGIC;
                b->size = n;
                b->next = rest;
            }
            b->used = 1;
            heap_used_bytes += b->size;
            irq_restore(f);
            return b + 1;
        }
    }
    irq_restore(f);
    return 0;
}

void *kzalloc(size_t n)
{
    void *p = kmalloc(n);
    if (p) memset(p, 0, n);
    return p;
}

void kfree(void *p)
{
    uint64_t f = irq_save();
    struct hblock *b, *n;
    if (!p) { irq_restore(f); return; }
    b = (struct hblock *)p - 1;
    KASSERT(b->magic == HMAGIC && b->used);
    b->used = 0;
    heap_used_bytes -= b->size;
    for (n = heap_head; n; n = n->next)
        while (!n->used && n->next && !n->next->used) {
            n->size += sizeof *n + n->next->size;
            n->next = n->next->next;
        }
    irq_restore(f);
}

size_t kheap_used(void) { return heap_used_bytes; }
size_t kheap_total(void) { return heap_total_bytes; }   /* HEAP_BYTES minus block headers and fenced firmware holes */

/* ---------------------------------------------------------------- init */
static void map_2m(uint64_t pml4, uint64_t va, uint64_t pa, uint64_t flags)
{
    /* Kernel-only large-page mapping (used for the image alias and the direct map). */
    uint64_t *t = table_at(pml4);
    int level;
    for (level = 3; level > 1; --level) {
        const unsigned idx = (va >> (12 + 9 * level)) & 511;
        if (!(t[idx] & PT_P)) {
            const uint64_t n = pmm_alloc();
            KASSERT(n);
            t[idx] = n | PT_P | PT_W;
        }
        t = table_at(t[idx] & 0x000ffffffffff000ull);
    }
    t[(va >> 21) & 511] = pa | flags | PT_P | (1ull << 7);
}

void mem_init(const shz_bootinfo_t *bi)
{
    uint64_t off, first_initrd_page, last_initrd_page, i;
    unsigned c;

    ram_top = bi->ram_size;
    KASSERT(ram_top > (16ull << 20) && ram_top <= MAX_PAGES * PAGE_SIZE && !(ram_top & 0x1fffff));
    pmm_pages = (ram_top - PMM_BASE) / PAGE_SIZE;
    pmm_free_pages = pmm_pages;
    memset(page_map, 0, sizeof page_map);
    if (bi->initrd_size) {                      /* keep the initial RAM image out of the allocator */
        first_initrd_page = (bi->initrd_gpa - PMM_BASE) / PAGE_SIZE;
        last_initrd_page = (bi->initrd_gpa + bi->initrd_size - 1 - PMM_BASE) / PAGE_SIZE;
        for (i = first_initrd_page; i <= last_initrd_page && i < pmm_pages; ++i) {
            bit_set(i);
            --pmm_free_pages;
        }
    }
#ifdef SHZ_STANDALONE
    {   /* Firmware ranges that are not RAM (standalone/memholes.h: e.g. OVMF's S3 ACPI NVS at 8 MiB), written by the
         * Multiboot stub or by the UEFI boot manager's direct boot; both refuse holes below the heap window or over
         * the initrd. Read through the boot mapping (physical memory below 1 GiB at K64_VIRT_BASE). */
        const shz_memholes_t *h = (const shz_memholes_t *)(K64_VIRT_BASE + SHZ_MEMHOLES_GPA);
        if (h->magic == SHZ_MEMHOLES_MAGIC && h->count <= SHZ_MEMHOLES_MAX && h->check == shz_memholes_sum(h)) {
            const uint64_t before = pmm_free_pages;
            uint64_t heap_fenced = 0;
            for (c = 0; c < h->count; ++c) {
                const uint64_t a = h->hole[c].gpa, z = h->hole[c].gpa + h->hole[c].size;
                KASSERT(a >= HEAP_PA && z > a && !(a & 0xfff) && !(z & 0xfff));
                hole_gpa[hole_count] = a;
                hole_end[hole_count++] = z;
                if (a < PMM_BASE)
                    heap_fenced += (z < PMM_BASE ? z : PMM_BASE) - a;
                for (off = a > PMM_BASE ? a : PMM_BASE; off < z && off < ram_top; off += PAGE_SIZE) {
                    i = (off - PMM_BASE) / PAGE_SIZE;
                    if (!bit_get(i)) {
                        bit_set(i);
                        --pmm_free_pages;
                    }
                }
            }
            if (h->count)
                kprintf("K64: %u firmware memory hole(s): %u page(s) kept out of the page allocator, "
                        "%u KiB of the heap fenced off\n", h->count, (uint32_t)(before - pmm_free_pages),
                        (uint32_t)(heap_fenced >> 10));
        }
    }
#endif
    /* Build the final tables while still running on the Supervisor's boot mapping, through
     * which physical memory below 1 GiB is reachable at K64_VIRT_BASE (phys_base_va). */
    kpml4 = pmm_alloc();
    KASSERT(kpml4);
    for (off = 0; off < ram_top && off < (1ull << 30); off += 0x200000)
        map_2m(kpml4, K64_VIRT_BASE + off, off, PT_W);              /* kernel image alias (RWX) */
    for (off = 0; off < ram_top; off += 0x200000)
        map_2m(kpml4, DIRECT_MAP + off, off, PT_W | PT_NX);         /* direct map of RAM */
    for (c = 0; c < bi->channel_count; ++c)                          /* IPC windows above RAM */
        for (off = 0; off < bi->channel[c].size; off += PAGE_SIZE)
            KASSERT(vm_map(kpml4, DIRECT_MAP + bi->channel[c].gpa + off, bi->channel[c].gpa + off, PT_W | PT_NX) == 0);
    /* Kernel windows (kwin.c: lazily populated file views and large kernel buffers) live in their own PML4 slot.
     * Its PDPT must exist now: every process PML4 copies the kernel half at creation (vm_new_space) and would
     * otherwise miss a slot created later, faulting on window pages while running on that process's tables. */
    KASSERT(walk(kpml4, KWIN_BASE, 1, 0));
    /* NT driver host image window (NTDRV_VA_BASE, its own PML4 slot 448): reserved here for the same reason, so a
     * .sys loaded after a process exists (NtLoadDriver from user mode) is mapped in that process's tables too. */
    KASSERT(walk(kpml4, NTDRV_VA_BASE, 1, 0));
    write_cr3(kpml4);
    phys_base_va = DIRECT_MAP;
    heap_init();
    /* Probe the top of RAM through the direct map (exercises page directories beyond 1 GiB on big guests). */
    {
        volatile uint64_t *top = (volatile uint64_t *)p2v(ram_top - PAGE_SIZE);
        const uint64_t pattern = 0x5348495a554b3634ull ^ ram_top;
        uint64_t saved = top[0];
        top[0] = pattern;
        mem_probe_ok = top[0] == pattern;
        top[0] = saved;
        shz_evidence(10, (ram_top >> 20) | ((uint64_t)mem_probe_ok << 32) | (pmm_free_pages << 33));
    }
}

int mem_probe_ok;
uint64_t mem_ram_top(void) { return ram_top; }

uint64_t phys_base_va = K64_VIRT_BASE;
