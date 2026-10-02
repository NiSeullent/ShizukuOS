/* SPDX-License-Identifier: GPL-2.0-only
 * Kernel32 memory management: physical page allocator (bitmap), 32-bit two-level
 * paging with kernel/user separation, and a first-fit kernel heap.
 *
 * Guest-physical map (this kernel's own view, not the Supervisor's):
 *   0x00000000..0x000fffff  boot structures (kept mapped)
 *   0x00100000..0x001fffff  kernel image and bss
 *   0x00200000..0x003fffff  kernel heap (2 MiB)
 *   0x00400000..ram_size    page allocator
 * User address spaces live at 0x40000000 and above; kernel mappings are shared.
 */
#include "k32.h"
#include "../kcommon/pma_sync.h"

#define HEAP_BASE 0x00200000u
#define HEAP_SIZE 0x00200000u
#define PMM_BASE 0x00400000u
#define MAX_PAGES (128u * 1024u * 1024u / PAGE_SIZE)

static uint8_t page_map[MAX_PAGES / 8];
static uint32_t pmm_first, pmm_pages, pmm_free_pages, pmm_hint;
static uint32_t kernel_pd;
static uint32_t ipc_lo, ipc_hi;

/* Normal-context allocator ownership. Disable local IRQs before joining the
 * existing ticket protocol; no NMI use, recursion, blocking/callback, nested
 * PMM/heap ownership or context transfer is permitted. Page zeroing happens
 * only after reserving unique ownership and releasing the PMM ticket. Paging
 * mutation/root reclamation is not made concurrent by these allocator locks. */
static pma_ticketlock_t pmm_lock __attribute__((aligned(64)));
static pma_ticketlock_t heap_lock __attribute__((aligned(64)));
typedef struct { uint32_t flags, ticket; } memory_guard_t;
static memory_guard_t memory_enter(pma_ticketlock_t *lock)
{
    memory_guard_t g;
    g.flags = irq_save();
    g.ticket = pma_ticket_lock(lock);
    return g;
}
static void memory_leave(pma_ticketlock_t *lock, memory_guard_t g)
{
    KASSERT(pma_ticket_unlock(lock, g.ticket));
    irq_restore(g.flags);
}

static int bit_get(uint32_t i) { return page_map[i >> 3] & (1u << (i & 7)); }
static void bit_set(uint32_t i) { page_map[i >> 3] |= (uint8_t)(1u << (i & 7)); }
static void bit_clr(uint32_t i) { page_map[i >> 3] &= (uint8_t)~(1u << (i & 7)); }

uint32_t pmm_alloc(void)
{
    memory_guard_t g = memory_enter(&pmm_lock);
    uint32_t n, i;
    for (n = 0; n < pmm_pages; ++n) {
        i = (pmm_hint + n) % pmm_pages;
        if (!bit_get(i)) {
            bit_set(i);
            pmm_hint = i + 1;
            --pmm_free_pages;
            memory_leave(&pmm_lock, g);
            memset((void *)(PMM_BASE + i * PAGE_SIZE), 0, PAGE_SIZE);
            return PMM_BASE + i * PAGE_SIZE;
        }
    }
    memory_leave(&pmm_lock, g);
    return 0;
}

void pmm_free(uint32_t pa)
{
    memory_guard_t g = memory_enter(&pmm_lock);
    uint32_t i;
    KASSERT(pa >= PMM_BASE && !(pa & 0xfff));
    i = (pa - PMM_BASE) / PAGE_SIZE;
    KASSERT(i < pmm_pages && bit_get(i));       /* double free or foreign page */
    bit_clr(i);
    ++pmm_free_pages;
    memory_leave(&pmm_lock, g);
}

uint32_t kernel_space(void) { return kernel_pd; }
uint32_t pmm_free_count(void)
{
    memory_guard_t g = memory_enter(&pmm_lock);
    uint32_t n = pmm_free_pages;
    memory_leave(&pmm_lock, g);
    return n;
}
uint32_t pmm_total_count(void)
{
    memory_guard_t g = memory_enter(&pmm_lock);
    uint32_t n = pmm_pages;
    memory_leave(&pmm_lock, g);
    return n;
}

/* ---------------------------------------------------------------- paging */
static uint32_t *pde_of(uint32_t pd, uint32_t va) { return (uint32_t *)pd + (va >> 22); }

int vm_map(uint32_t pd, uint32_t va, uint32_t pa, uint32_t flags)
{
    uint32_t *pde = pde_of(pd, va), *pt;
    if (!(*pde & PTE_P)) {
        const uint32_t page = pmm_alloc();
        if (!page)
            return -1;
        *pde = page | PTE_P | PTE_W | PTE_U;    /* the PTE decides user access */
    }
    pt = (uint32_t *)(*pde & ~0xfffu);
    pt[(va >> 12) & 0x3ff] = (pa & ~0xfffu) | (flags & 7) | PTE_P;
    invlpg(va);
    return 0;
}

int vm_map_range(uint32_t pd, uint32_t va, uint32_t bytes, uint32_t flags)
{
    uint32_t off;
    for (off = 0; off < bytes; off += PAGE_SIZE) {
        const uint32_t pa = pmm_alloc();
        if (!pa || vm_map(pd, va + off, pa, flags))
            return -1;
    }
    return 0;
}

uint32_t vm_translate(uint32_t pd, uint32_t va)
{
    const uint32_t pde = *pde_of(pd, va);
    uint32_t pte;
    if (!(pde & PTE_P))
        return 0;
    pte = ((uint32_t *)(pde & ~0xfffu))[(va >> 12) & 0x3ff];
    if (!(pte & PTE_P))
        return 0;
    return (pte & ~0xfffu) | (va & 0xfff);
}

uint32_t vm_new_space(void)
{
    const uint32_t pd = pmm_alloc();
    unsigned i;
    if (!pd)
        return 0;
    for (i = 0; i < 256; ++i)                   /* below 0x40000000: shared kernel mappings */
        ((uint32_t *)pd)[i] = ((uint32_t *)kernel_pd)[i];
    for (i = ipc_lo >> 22; i <= ipc_hi >> 22 && ipc_hi; ++i)
        ((uint32_t *)pd)[i] = ((uint32_t *)kernel_pd)[i];
    return pd;
}

void vm_free_space(uint32_t pd)
{
    unsigned i, j;
    for (i = 256; i < 1024; ++i) {
        const uint32_t pde = ((uint32_t *)pd)[i];
        if (!(pde & PTE_P) || (i >= (ipc_lo >> 22) && i <= (ipc_hi >> 22) && ipc_hi))
            continue;
        for (j = 0; j < 1024; ++j) {
            const uint32_t pte = ((uint32_t *)(pde & ~0xfffu))[j];
            if (pte & PTE_P)
                pmm_free(pte & ~0xfffu);
        }
        pmm_free(pde & ~0xfffu);
    }
    pmm_free(pd);
}

/* ---------------------------------------------------------------- heap */
struct hblock { uint32_t size; uint32_t used; struct hblock *next; uint32_t magic; };
#define HMAGIC 0x4b48454a
static struct hblock *heap_head;
static size_t heap_used_bytes;

static void heap_init(void)
{
    heap_head = (struct hblock *)HEAP_BASE;
    heap_head->size = HEAP_SIZE - sizeof *heap_head;
    heap_head->used = 0;
    heap_head->next = 0;
    heap_head->magic = HMAGIC;
}

void *kmalloc(size_t n)
{
    if (!n || n > HEAP_SIZE - sizeof(struct hblock)) return 0;
    n = (n + 15) & ~(size_t)15;
    if (n > HEAP_SIZE - sizeof(struct hblock)) return 0;
    memory_guard_t g = memory_enter(&heap_lock);
    struct hblock *b;
    for (b = heap_head; b; b = b->next) {
        KASSERT(b->magic == HMAGIC);
        if (!b->used && b->size >= n) {
            if (b->size >= n + sizeof *b + 32) {          /* split */
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
            memory_leave(&heap_lock, g);
            return b + 1;
        }
    }
    memory_leave(&heap_lock, g);
    return 0;
}

void kfree(void *p)
{
    if (!p) return;
    memory_guard_t g = memory_enter(&heap_lock);
    struct hblock *b, *n;
    const uintptr_t address = (uintptr_t)p;
    KASSERT(address >= HEAP_BASE + sizeof(struct hblock) && address < HEAP_BASE + HEAP_SIZE);
    /* Only a published block boundary owns an allocation. A forged header
     * inside payload bytes must not release or alter real heap accounting. */
    for (b = heap_head; b && (void *)(b + 1) != p; b = b->next) { }
    KASSERT(b && b->magic == HMAGIC && b->used);
    b->used = 0;
    heap_used_bytes -= b->size;
    for (n = heap_head; n; n = n->next)                     /* coalesce forward */
        while (!n->used && n->next && !n->next->used) {
            n->size += sizeof *n + n->next->size;
            n->next = n->next->next;
        }
    memory_leave(&heap_lock, g);
}

size_t kheap_used(void)
{
    memory_guard_t g = memory_enter(&heap_lock);
    size_t n = heap_used_bytes;
    memory_leave(&heap_lock, g);
    return n;
}

/* ---------------------------------------------------------------- init */
void mem_init(const shz_bootinfo_t *bi)
{
    const uint32_t ram = (uint32_t)bi->ram_size;
    uint32_t off, i, pd;
    unsigned c;

    pma_ticket_init(&pmm_lock);
    pma_ticket_init(&heap_lock);
    KASSERT(ram > PMM_BASE + 0x100000 && ram <= MAX_PAGES * PAGE_SIZE);
    pmm_first = PMM_BASE;
    pmm_pages = (ram - PMM_BASE) / PAGE_SIZE;
    pmm_free_pages = pmm_pages;
    memset(page_map, 0, sizeof page_map);
    heap_init();

    pd = pmm_alloc();
    KASSERT(pd);
    kernel_pd = pd;
    /* Identity map all of RAM, supervisor-only, writable. */
    for (off = 0; off < ram; off += PAGE_SIZE)
        KASSERT(vm_map(pd, off, off, PTE_W) == 0);
    /* IPC channel windows are ordinary guest-physical addresses above RAM. */
    for (c = 0; c < bi->channel_count; ++c) {
        const uint32_t base = (uint32_t)bi->channel[c].gpa;
        if (!ipc_lo || base < ipc_lo) ipc_lo = base;
        if (base + (uint32_t)bi->channel[c].size - 1 > ipc_hi) ipc_hi = base + (uint32_t)bi->channel[c].size - 1;
        for (i = 0; i < bi->channel[c].size; i += PAGE_SIZE)
            KASSERT(vm_map(pd, base + i, base + i, PTE_W) == 0);
    }
    write_cr3(pd);
    write_cr0(read_cr0() | 0x80010000u);                    /* PG | WP */
}
