/* SPDX-License-Identifier: GPL-2.0-only */
#include "ept.h"
#include "cpu.h"
#include "pool.h"

#define LARGE (1ull << 7)
#define ADDR_MASK 0x000ffffffffff000ull

static uint64_t *next_level(uint64_t *table, unsigned index, int create)
{
    uint64_t e = table[index];
    if (e & EPT_RWX) {
        if (e & LARGE)
            return 0;                       /* caller must split first */
        return (uint64_t *)(uintptr_t)(e & ADDR_MASK);
    }
    if (!create)
        return 0;
    {
        uint64_t *t = pool_alloc_pages(1);
        if (!t)
            return 0;
        table[index] = (uint64_t)(uintptr_t)t | EPT_RWX;
        return t;
    }
}

int ept_init(ept_t *e)
{
    e->pml4 = pool_alloc_pages(1);
    if (!e->pml4)
        return -1;
    e->pml4_pa = (uint64_t)(uintptr_t)e->pml4;
    e->mapped_bytes = 0;
    return 0;
}

static uint64_t *walk_to_pd(ept_t *e, uint64_t gpa)
{
    uint64_t *pdpt = next_level(e->pml4, (gpa >> 39) & 511, 1);
    return pdpt ? next_level(pdpt, (gpa >> 30) & 511, 1) : 0;
}

int ept_map(ept_t *e, uint64_t gpa, uint64_t hpa, uint64_t size, uint64_t perms, int force_4k)
{
    if ((gpa | hpa | size) & 0xfff)
        return -1;
    while (size) {
        uint64_t *pd = walk_to_pd(e, gpa);
        unsigned pdi = (gpa >> 21) & 511;
        if (!pd)
            return -1;
        if (!force_4k && !((gpa | hpa) & 0x1fffff) && size >= 0x200000) {
            if (pd[pdi])
                return -1;
            pd[pdi] = hpa | perms | LARGE;
            gpa += 0x200000; hpa += 0x200000; size -= 0x200000; e->mapped_bytes += 0x200000;
            continue;
        }
        {
            uint64_t *pt = next_level(pd, pdi, 1);
            unsigned pti = (gpa >> 12) & 511;
            if (!pt || pt[pti])
                return -1;
            pt[pti] = hpa | perms;
            gpa += 0x1000; hpa += 0x1000; size -= 0x1000; e->mapped_bytes += 0x1000;
        }
    }
    return 0;
}

int ept_remap_page(ept_t *e, uint64_t gpa, uint64_t hpa, uint64_t perms)
{
    uint64_t *pd = walk_to_pd(e, gpa);
    unsigned pdi = (gpa >> 21) & 511, i;
    uint64_t *pt;
    if (!pd)
        return -1;
    if ((pd[pdi] & EPT_RWX) && (pd[pdi] & LARGE)) {         /* split the 2 MiB leaf */
        const uint64_t base = pd[pdi] & ADDR_MASK, attrs = pd[pdi] & ~ADDR_MASK & ~LARGE;
        uint64_t *n = pool_alloc_pages(1);
        if (!n)
            return -1;
        for (i = 0; i < 512; ++i)
            n[i] = (base + ((uint64_t)i << 12)) | attrs;
        pd[pdi] = (uint64_t)(uintptr_t)n | EPT_RWX;
    }
    pt = next_level(pd, pdi, 1);
    if (!pt)
        return -1;
    pt[(gpa >> 12) & 511] = hpa | perms;
    return 0;
}

uint64_t ept_pointer(const ept_t *e) { return e->pml4_pa | (3ull << 3) | 6ull; }

void ept_invalidate(void) { invept_all(); }
