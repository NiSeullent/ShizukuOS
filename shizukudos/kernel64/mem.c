/* SPDX-License-Identifier: GPL-2.0-only
 * Kernel64 memory management.
 *
 * Address space (kernel half is shared by every process):
 *   0xFFFFFFFF80000000  kernel image alias (physical 0, first 1 GiB, 2 MiB pages)
 *   0xFFFF800000000000  direct map of all guest-physical memory this kernel owns or may touch
 *   0x0000000000010000..0x00007FFFFFFEEFFF  user space (per process)
 * Guest-physical layout: 0..1 MiB boot structures, 1 MiB kernel, 2..6 MiB heap,
 * 6 MiB.. page allocator (initrd range and firmware holes from bootinfo excluded).
 */
#include "k64.h"
#ifdef SHZ_STANDALONE
#include "standalone/memholes.h"
#endif

#define HEAP_PA 0x200000ull
#define HEAP_BYTES 0x400000ull
#define PMM_BASE 0x600000ull
#define MAX_PAGES (256ull * 1024 * 1024 / PAGE_SIZE)

static uint8_t page_map[MAX_PAGES / 8];
static uint64_t pmm_pages, pmm_free_pages, pmm_hint;
static uint64_t kpml4;
static uint64_t ram_top;

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

uint64_t pmm_free_count(void) { return pmm_free_pages; }

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

/* ---------------------------------------------------------------- heap */
struct hblock { uint64_t size; uint64_t used; struct hblock *next; uint64_t magic; };
#define HMAGIC 0x4b48454150363421ull
static struct hblock *heap_head;
static size_t heap_used_bytes;

static void heap_init(void)
{
    heap_head = (struct hblock *)p2v(HEAP_PA);
    heap_head->size = HEAP_BYTES - sizeof *heap_head;
    heap_head->used = 0;
    heap_head->next = 0;
    heap_head->magic = HMAGIC;
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
    {   /* Firmware ranges that are not RAM (standalone/memholes.h: e.g. OVMF's ACPI NVS under UEFI + CSMWrap).
         * The Multiboot stub guarantees they lie above PMM_BASE; still read through the boot mapping here. */
        const shz_memholes_t *h = (const shz_memholes_t *)(K64_VIRT_BASE + SHZ_MEMHOLES_GPA);
        if (h->magic == SHZ_MEMHOLES_MAGIC && h->count <= SHZ_MEMHOLES_MAX && h->check == shz_memholes_sum(h)) {
            const uint64_t before = pmm_free_pages;
            for (c = 0; c < h->count; ++c) {
                KASSERT(h->hole[c].gpa >= PMM_BASE);
                for (off = h->hole[c].gpa; off < h->hole[c].gpa + h->hole[c].size && off < ram_top; off += PAGE_SIZE) {
                    i = (off - PMM_BASE) / PAGE_SIZE;
                    if (!bit_get(i)) {
                        bit_set(i);
                        --pmm_free_pages;
                    }
                }
            }
            if (h->count)
                kprintf("K64: %u firmware memory hole(s), %u page(s) kept out of the page allocator\n",
                        h->count, (uint32_t)(before - pmm_free_pages));
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
    write_cr3(kpml4);
    phys_base_va = DIRECT_MAP;
    heap_init();
}

uint64_t phys_base_va = K64_VIRT_BASE;
