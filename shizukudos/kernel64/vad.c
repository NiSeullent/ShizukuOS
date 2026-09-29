/* SPDX-License-Identifier: GPL-2.0-only
 * Kernel64 user virtual memory: a sorted set of address descriptors with Windows-style
 * reserve / commit / decommit / release / protect / query semantics, demand-zero page
 * population and user-memory copy helpers that validate against the descriptors.
 *
 * Concurrency: the kernel is preemptible and the threads of one process (and, for cross-process memory access, other
 * processes) use one descriptor set, so every public entry point below runs its descriptor and page-table work with
 * interrupts disabled (the uniprocessor kernel's lock; nothing in here sleeps). Unserialised, two threads calling
 * NtAllocateVirtualMemory / NtFreeVirtualMemory at once corrupted the set - a live thread stack's descriptor vanished and
 * the thread faulted on its own stack. A torn-down address space (process_teardown) is never touched again.
 */
#include "proc_internal.h"

#define PAGE_MASK (~(PAGE_SIZE - 1))
static inline uint64_t up(uint64_t v) { return (v + PAGE_SIZE - 1) & PAGE_MASK; }

void vad_init(process_t *p)
{
    p->vads.cap = 64;
    p->vads.count = 0;
    p->vads.v = kzalloc(sizeof(vad_t) * p->vads.cap);
    KASSERT(p->vads.v);
}

void vad_destroy(process_t *p)
{
    kfree(p->vads.v);
    p->vads.v = 0;
    p->vads.count = p->vads.cap = 0;
}

static int vad_insert_at(process_t *p, unsigned idx, const vad_t *n)
{
    vad_set_t *s = &p->vads;
    if (s->count == s->cap) {
        vad_t *bigger = kzalloc(sizeof(vad_t) * s->cap * 2);
        if (!bigger)
            return -1;
        memcpy(bigger, s->v, sizeof(vad_t) * s->count);
        kfree(s->v);
        s->v = bigger;
        s->cap *= 2;
    }
    memmove(&s->v[idx + 1], &s->v[idx], sizeof(vad_t) * (s->count - idx));
    s->v[idx] = *n;
    ++s->count;
    return 0;
}

static void vad_remove_at(process_t *p, unsigned idx)
{
    vad_set_t *s = &p->vads;
    memmove(&s->v[idx], &s->v[idx + 1], sizeof(vad_t) * (s->count - idx - 1));
    --s->count;
}

/* Index of the first descriptor with end > addr. */
static unsigned vad_lower(process_t *p, uint64_t addr)
{
    unsigned lo = 0, hi = p->vads.count;
    while (lo < hi) {
        const unsigned mid = (lo + hi) / 2;
        if (p->vads.v[mid].end <= addr) lo = mid + 1; else hi = mid;
    }
    return lo;
}

vad_t *vad_find(process_t *p, uint64_t addr)
{
    const unsigned i = vad_lower(p, addr);
    return i < p->vads.count && p->vads.v[i].start <= addr ? &p->vads.v[i] : 0;
}

/* Split so that `at` (page aligned) is a descriptor boundary. */
static int vad_split(process_t *p, uint64_t at)
{
    const unsigned i = vad_lower(p, at);
    vad_t right;
    if (i >= p->vads.count || p->vads.v[i].start >= at || p->vads.v[i].end <= at)
        return 0;
    right = p->vads.v[i];
    right.start = at;
    p->vads.v[i].end = at;
    return vad_insert_at(p, i + 1, &right);
}

static void vad_coalesce(process_t *p)
{
    unsigned i = 0;
    while (i + 1 < p->vads.count) {
        vad_t *a = &p->vads.v[i], *b = &p->vads.v[i + 1];
        if (a->end == b->start && a->state == b->state && a->prot == b->prot && a->kind == b->kind &&
            a->alloc_base == b->alloc_base && a->alloc_prot == b->alloc_prot)
            { a->end = b->end; vad_remove_at(p, i + 1); }
        else
            ++i;
    }
}

static int range_free(process_t *p, uint64_t start, uint64_t end)
{
    const unsigned i = vad_lower(p, start);
    return !(i < p->vads.count && p->vads.v[i].start < end);
}

uint64_t prot_to_ptflags(uint32_t prot)
{
    uint64_t f = PT_U;
    switch (prot & 0xff) {
    case PAGE_READONLY: f |= PT_NX; break;
    case PAGE_READWRITE: case PAGE_WRITECOPY: f |= PT_W | PT_NX; break;
    case PAGE_EXECUTE: case PAGE_EXECUTE_READ: break;
    case PAGE_EXECUTE_READWRITE: case PAGE_EXECUTE_WRITECOPY: f |= PT_W; break;
    default: f = 0; break;              /* NOACCESS: never mapped user-accessible */
    }
    if (prot & 0x200) f |= PT_PCD;
    return f;
}

static int prot_valid(uint32_t prot)
{
    const uint32_t base = prot & 0xff;
    return base == PAGE_NOACCESS || base == PAGE_READONLY || base == PAGE_READWRITE || base == PAGE_WRITECOPY ||
           base == PAGE_EXECUTE || base == PAGE_EXECUTE_READ || base == PAGE_EXECUTE_READWRITE ||
           base == PAGE_EXECUTE_WRITECOPY;
}

/* Free the physical pages and unmap [start, end). */
static void unmap_pages(process_t *p, uint64_t start, uint64_t end)
{
    uint64_t a, pa;
    for (a = start; a < end; a += PAGE_SIZE)
        if (vm_unmap(p->pml4, a, &pa) == 0)
            pmm_free(pa);
}

static int32_t vad_alloc_locked(process_t *p, uint64_t *base, uint64_t *size, uint32_t type, uint32_t prot, uint32_t kind)
{
    uint64_t start, end, len;
    const int commit = (type & MEM_COMMIT) != 0;
    int reserve = (type & MEM_RESERVE) != 0;
    if (!(commit || reserve) || !size || !*size || !base || !prot_valid(prot))
        return STATUS_INVALID_PARAMETER;
    if (!*base)
        reserve = 1;                                    /* commit with no base implies a fresh reservation */
    if ((type & ~(uint32_t)(MEM_COMMIT | MEM_RESERVE | MEM_TOP_DOWN)))
        return STATUS_INVALID_PARAMETER;
    len = up(*size + (*base & (PAGE_SIZE - 1)));
    if (len == 0 || len > USER_TOP)
        return STATUS_INVALID_PARAMETER;
    if (*base) {
        start = reserve ? (*base & PAGE_MASK) : (*base & PAGE_MASK);
        if (reserve && (start & 0xffff))
            start &= ~0xffffull;                        /* reservations are 64 KiB granular */
        end = start + len;
        if (start < USER_MIN || end > USER_TOP || end < start)
            return STATUS_INVALID_PARAMETER;
        if (reserve) {
            vad_t n;
            if (!range_free(p, start, end))
                return STATUS_CONFLICTING_ADDRESSES;
            n.start = start; n.end = end;
            n.state = commit ? VAD_COMMITTED : VAD_RESERVED;
            n.prot = prot; n.kind = kind; n.alloc_prot = prot; n.alloc_base = start;
            if (vad_insert_at(p, vad_lower(p, start), &n))
                return STATUS_NO_MEMORY;
        } else {
            /* commit inside an existing reservation */
            uint64_t a;
            for (a = start; a < end; a = vad_find(p, a)->end)
                if (!vad_find(p, a))
                    return STATUS_INVALID_PARAMETER;
            if (vad_split(p, start) || vad_split(p, end))
                return STATUS_NO_MEMORY;
            for (a = start; a < end; a = vad_find(p, a)->end) {
                vad_t *v = vad_find(p, a);
                v->state = VAD_COMMITTED;
                v->prot = prot;
            }
        }
    } else {
        /* choose an address: top-down or first-fit from the mmap hint, 64 KiB aligned */
        uint64_t cand = (type & MEM_TOP_DOWN) ? (USER_TOP - len) & ~0xffffull : (p->mmap_hint + 0xffff) & ~0xffffull;
        unsigned tries = 0;
        if (!reserve)
            return STATUS_INVALID_PARAMETER;
        for (;;) {
            unsigned i;
            if (cand < USER_MIN || cand + len > USER_TOP)
                return STATUS_NO_MEMORY;
            i = vad_lower(p, cand);
            if (!(i < p->vads.count && p->vads.v[i].start < cand + len))
                break;
            cand = (type & MEM_TOP_DOWN) ? (p->vads.v[i].start - len) & ~0xffffull : (p->vads.v[i].end + 0xffff) & ~0xffffull;
            if (++tries > 4096)
                return STATUS_NO_MEMORY;
        }
        {
            vad_t n;
            n.start = cand; n.end = cand + len;
            n.state = commit ? VAD_COMMITTED : VAD_RESERVED;
            n.prot = prot; n.kind = kind; n.alloc_prot = prot; n.alloc_base = cand;
            if (vad_insert_at(p, vad_lower(p, cand), &n))
                return STATUS_NO_MEMORY;
        }
        start = cand;
        end = cand + len;
        if (!(type & MEM_TOP_DOWN))
            p->mmap_hint = end;
    }
    vad_coalesce(p);
    *base = start;
    *size = end - start;
    return STATUS_SUCCESS;
}

/* Inserts a descriptor at a fixed address with an explicit allocation base (image sections
 * belong to one allocation whose base is the image base). */
static int32_t vad_insert_fixed_locked(process_t *p, uint64_t start, uint64_t size, uint32_t state, uint32_t prot, uint32_t kind,
                         uint64_t alloc_base)
{
    vad_t n;
    const uint64_t end = start + up(size);
    if ((start & (PAGE_SIZE - 1)) || start < USER_MIN || end > USER_TOP || end <= start)
        return STATUS_INVALID_PARAMETER;
    if (!range_free(p, start, end))
        return STATUS_CONFLICTING_ADDRESSES;
    n.start = start; n.end = end; n.state = state; n.prot = prot; n.kind = kind;
    n.alloc_prot = prot; n.alloc_base = alloc_base;
    return vad_insert_at(p, vad_lower(p, start), &n) ? STATUS_NO_MEMORY : STATUS_SUCCESS;
}

int vad_range_is_free(process_t *p, uint64_t start, uint64_t size)
{
    const uint64_t f = irq_save();
    const int r = range_free(p, start, start + up(size));
    irq_restore(f);
    return r;
}

static int32_t vad_free_locked(process_t *p, uint64_t *base, uint64_t *size, uint32_t type)
{
    uint64_t start, end;
    vad_t *v;
    if (!base || !size || !*base)
        return STATUS_INVALID_PARAMETER;
    if (type == MEM_RELEASE) {
        v = vad_find(p, *base);
        if (!v)
            return STATUS_UNABLE_TO_FREE_VM;
        if (v->alloc_base != *base)
            return STATUS_FREE_VM_NOT_AT_BASE;
        if (*size != 0)
            return STATUS_INVALID_PARAMETER;
        start = v->start;
        end = start;
        {
            unsigned i;
            for (i = vad_lower(p, start); i < p->vads.count && p->vads.v[i].alloc_base == *base;)
                { end = p->vads.v[i].end; unmap_pages(p, p->vads.v[i].start, p->vads.v[i].end); vad_remove_at(p, i); }
        }
        *size = end - start;
        return STATUS_SUCCESS;
    }
    if (type == MEM_DECOMMIT) {
        uint64_t a;
        start = *base & PAGE_MASK;
        end = up(*base + *size);
        if (!*size || end <= start)
            return STATUS_INVALID_PARAMETER;
        for (a = start; a < end; a = vad_find(p, a)->end)
            if (!vad_find(p, a))
                return STATUS_INVALID_PARAMETER;
        if (vad_split(p, start) || vad_split(p, end))
            return STATUS_NO_MEMORY;
        for (a = start; a < end; a = vad_find(p, a)->end) {
            vad_t *w = vad_find(p, a);
            if (w->state == VAD_COMMITTED)
                unmap_pages(p, w->start, w->end);
            w->state = VAD_RESERVED;
        }
        vad_coalesce(p);
        *base = start;
        *size = end - start;
        return STATUS_SUCCESS;
    }
    return STATUS_INVALID_PARAMETER;
}

static int32_t vad_protect_locked(process_t *p, uint64_t *base, uint64_t *size, uint32_t new_prot, uint32_t *old_prot)
{
    uint64_t start = *base & PAGE_MASK, end = up(*base + *size), a;
    vad_t *v;
    if (!*size || end <= start || !prot_valid(new_prot))
        return STATUS_INVALID_PARAMETER;
    for (a = start; a < end; ) {
        v = vad_find(p, a);
        if (!v)
            return STATUS_INVALID_PARAMETER;
        if (v->state != VAD_COMMITTED)
            return STATUS_INVALID_PARAMETER;    /* NT: protecting uncommitted memory is an error */
        a = v->end;
    }
    v = vad_find(p, start);
    if (old_prot)
        *old_prot = v->prot;
    if (vad_split(p, start) || vad_split(p, end))
        return STATUS_NO_MEMORY;
    for (a = start; a < end; a = vad_find(p, a)->end) {
        vad_t *w = vad_find(p, a);
        uint64_t va;
        w->prot = new_prot;
        for (va = w->start; va < w->end; va += PAGE_SIZE)
            if (vm_lookup(p->pml4, va, 0)) {
                if ((new_prot & 0xff) == PAGE_NOACCESS || (new_prot & 0x100)) {
                    uint64_t pa;
                    if (vm_unmap(p->pml4, va, &pa) == 0) {     /* NOACCESS/GUARD: re-fault on touch */
                        /* keep the data: park it by remapping without user access */
                        vm_map(p->pml4, va, pa, 0);
                    }
                } else {
                    uint64_t pa = vm_lookup(p->pml4, va, 0) & ~0xfffull;
                    vm_map(p->pml4, va, pa, prot_to_ptflags(new_prot));
                }
            }
    }
    vad_coalesce(p);
    return STATUS_SUCCESS;
}

static int32_t vad_query_locked(process_t *p, uint64_t addr, uint64_t *base, uint64_t *alloc_base, uint32_t *alloc_prot,
                  uint64_t *size, uint32_t *state, uint32_t *prot, uint32_t *type)
{
    vad_t *v;
    if (addr >= USER_TOP)
        return STATUS_INVALID_PARAMETER;
    v = vad_find(p, addr & PAGE_MASK);
    if (!v) {
        const unsigned i = vad_lower(p, addr);
        const uint64_t start = addr & PAGE_MASK;
        const uint64_t end = i < p->vads.count ? p->vads.v[i].start : USER_TOP;
        *base = start; *alloc_base = 0; *alloc_prot = 0; *size = end - start;
        *state = MEM_FREE; *prot = PAGE_NOACCESS; *type = 0;
        return STATUS_SUCCESS;
    }
    *base = v->start; *alloc_base = v->alloc_base; *alloc_prot = v->alloc_prot; *size = v->end - v->start;
    *state = v->state == VAD_COMMITTED ? MEM_COMMIT : MEM_RESERVE;
    *prot = v->state == VAD_COMMITTED ? v->prot : 0;
    *type = v->kind == VK_IMAGE ? MEM_IMAGE : MEM_PRIVATE;
    return STATUS_SUCCESS;
}

/* Demand-zero population of one committed page. Returns 0 when the access is legitimate
 * and the page is now mapped, nonzero (an NTSTATUS) otherwise. */
static int user_fault_in_locked(process_t *p, uint64_t addr, int write, int exec)
{
    vad_t *v = vad_find(p, addr & PAGE_MASK);
    uint64_t pa, flags = 0;
    const uint32_t base = v ? v->prot & 0xff : 0;
    if (p->teardown)
        return STATUS_ACCESS_VIOLATION;         /* the address space is being (or has been) released */
    if (addr < USER_MIN || addr >= USER_TOP || !v || v->state != VAD_COMMITTED)
        return STATUS_ACCESS_VIOLATION;
    if (base == PAGE_NOACCESS)
        return STATUS_ACCESS_VIOLATION;
    if (v->prot & 0x100) {                      /* PAGE_GUARD: one-shot, then normal protection */
        v->prot &= ~0x100u;
        return STATUS_GUARD_PAGE_VIOLATION;
    }
    if (write && !(base == PAGE_READWRITE || base == PAGE_WRITECOPY || base == PAGE_EXECUTE_READWRITE ||
                   base == PAGE_EXECUTE_WRITECOPY))
        return STATUS_ACCESS_VIOLATION;
    if (exec && !(base >= PAGE_EXECUTE))
        return STATUS_ACCESS_VIOLATION;
    if (vm_lookup(p->pml4, addr, &flags))
        return 0;                               /* already present (spurious or racing fault) */
    pa = pmm_alloc();
    if (!pa)
        return STATUS_NO_MEMORY;
    if (vm_map(p->pml4, addr & PAGE_MASK, pa, prot_to_ptflags(v->prot))) {
        pmm_free(pa);
        return STATUS_NO_MEMORY;
    }
    return 0;
}

static int user_page(process_t *p, uint64_t uva, int write, uint64_t *kva)
{
    uint64_t flags = 0, pa;
    if (uva < USER_MIN || uva >= USER_TOP || p->teardown)
        return -1;
    pa = vm_lookup(p->pml4, uva, &flags);
    if (!pa || !(flags & PT_U) || (write && !(flags & PT_W))) {
        if (user_fault_in_locked(p, uva, write, 0))
            return -1;
        pa = vm_lookup(p->pml4, uva, &flags);
        if (!pa || !(flags & PT_U) || (write && !(flags & PT_W)))
            return -1;
    }
    *kva = p2v(pa);
    return 0;
}

int copy_from_user(process_t *p, void *dst, uint64_t uva, uint64_t n)
{
    uint8_t *d = dst;
    if (uva + n < uva)
        return -1;
    while (n) {
        uint64_t kva, chunk = PAGE_SIZE - (uva & 0xfff);
        if (chunk > n) chunk = n;
        const uint64_t f = irq_save();
        if (user_page(p, uva, 0, &kva)) { irq_restore(f); return -1; }
        memcpy(d, (void *)kva, chunk);
        irq_restore(f);
        d += chunk; uva += chunk; n -= chunk;
    }
    return 0;
}

int copy_to_user(process_t *p, uint64_t uva, const void *src, uint64_t n)
{
    const uint8_t *s = src;
    if (uva + n < uva)
        return -1;
    while (n) {
        uint64_t kva, chunk = PAGE_SIZE - (uva & 0xfff);
        if (chunk > n) chunk = n;
        const uint64_t f = irq_save();
        if (user_page(p, uva, 1, &kva)) { irq_restore(f); return -1; }
        memcpy((void *)kva, s, chunk);
        irq_restore(f);
        s += chunk; uva += chunk; n -= chunk;
    }
    return 0;
}

int user_string_len(process_t *p, uint64_t uva, uint64_t max, uint64_t *len)
{
    uint64_t n = 0;
    while (n < max) {
        uint64_t kva;
        const uint64_t f = irq_save();
        char c;
        if (user_page(p, uva + n, 0, &kva)) { irq_restore(f); return -1; }
        c = *(char *)kva;
        irq_restore(f);
        if (c == 0) {
            *len = n;
            return 0;
        }
        ++n;
    }
    return -1;
}

/* ---------------------------------------------------------------- serialised entry points (see the header comment) */
int32_t vad_alloc(process_t *p, uint64_t *base, uint64_t *size, uint32_t type, uint32_t prot, uint32_t kind)
{
    const uint64_t f = irq_save();
    const int32_t st = vad_alloc_locked(p, base, size, type, prot, kind);
    irq_restore(f);
    return st;
}

int32_t vad_insert_fixed(process_t *p, uint64_t start, uint64_t size, uint32_t state, uint32_t prot, uint32_t kind,
                         uint64_t alloc_base)
{
    const uint64_t f = irq_save();
    const int32_t st = vad_insert_fixed_locked(p, start, size, state, prot, kind, alloc_base);
    irq_restore(f);
    return st;
}

int32_t vad_free(process_t *p, uint64_t *base, uint64_t *size, uint32_t type)
{
    const uint64_t f = irq_save();
    const int32_t st = vad_free_locked(p, base, size, type);
    irq_restore(f);
    return st;
}

int32_t vad_protect(process_t *p, uint64_t *base, uint64_t *size, uint32_t new_prot, uint32_t *old_prot)
{
    const uint64_t f = irq_save();
    const int32_t st = vad_protect_locked(p, base, size, new_prot, old_prot);
    irq_restore(f);
    return st;
}

int32_t vad_query(process_t *p, uint64_t addr, uint64_t *base, uint64_t *alloc_base, uint32_t *alloc_prot,
                  uint64_t *size, uint32_t *state, uint32_t *prot, uint32_t *type)
{
    const uint64_t f = irq_save();
    const int32_t st = vad_query_locked(p, addr, base, alloc_base, alloc_prot, size, state, prot, type);
    irq_restore(f);
    return st;
}

int user_fault_in(process_t *p, uint64_t addr, int write, int exec)
{
    const uint64_t f = irq_save();
    const int st = user_fault_in_locked(p, addr, write, exec);
    irq_restore(f);
    return st;
}
