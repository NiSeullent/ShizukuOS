/* SPDX-License-Identifier: GPL-2.0-only
 * Kernel file views ("kernel windows"): a file of any size appears read-only at a kernel virtual address in the
 * KWIN slot (PML4 slot 386, 512 GiB, shared by every address space because its PDPT exists before the first
 * process), and its pages are read from the file system on first touch through a kernel-mode page fault.
 *
 * Used by the PE loader for disk-backed images: pe_parse()/imports/exports/relocation blocks read the file through
 * the view, so parsing a 334 MB DLL reads only the headers and directory pages it really touches. The view pages
 * are a cache owned by the view (read-only, NX, kernel-only); a view lives as long as its file node and is never
 * evicted or released (documented limit). While a node has a view, writes to the file are refused (disk.c).
 *
 * Fault context: isr_dispatch() calls kwin_fault() for a not-present kernel-mode fault inside the slot. The handler
 * reads the page with fs_read() (which may block on the volume mutex and polls the AHCI device), so a view must
 * only be touched from thread context that holds no file-system lock. An I/O error maps a zero page and is
 * counted in view->io_errors; callers check it after parsing (STATUS_IN_PAGE_ERROR).
 */
#include "kwin.h"

#define KWIN_GUARD (2ull << 20)                 /* unmapped gap after every view */

static kview_t *views;
static uint64_t next_va = KWIN_BASE + KWIN_GUARD;
static kmutex_t view_lock;
static int lock_ready;
static uint64_t total_faults;

kview_t *kview_get(fsnode_t *n)
{
    kview_t *v;
    uint64_t span;
    if (!lock_ready) { mutex_init(&view_lock); lock_ready = 1; }
    if (!n || n->is_dir) return 0;
    if (n->view) return n->view;
    span = (n->size + KWIN_GUARD + KWIN_GUARD - 1) & ~(KWIN_GUARD - 1);
    if (!n->size || next_va + span > KWIN_BASE + KWIN_SIZE) return 0;
    v = kzalloc(sizeof *v);
    if (!v) return 0;
    v->node = n;
    v->base = next_va;
    v->size = n->size;
    v->npages = (n->size + PAGE_SIZE - 1) / PAGE_SIZE;
    next_va += span;
    v->next = views;
    views = v;
    n->view = v;
    return v;
}

static kview_t *view_at(uint64_t addr)
{
    kview_t *v;
    for (v = views; v; v = v->next)
        if (addr >= v->base && addr < v->base + v->npages * PAGE_SIZE) return v;
    return 0;
}

/* Loads the page of `v` containing `addr` (no-op when already present). 0 = mapped. */
static int load_page(kview_t *v, uint64_t addr)
{
    const uint64_t va = addr & ~(PAGE_SIZE - 1), off = va - v->base;
    uint64_t pa, done = 0, want;
    int rc;
    mutex_lock(&view_lock);
    if (vm_lookup(kernel_pml4(), va, 0)) { mutex_unlock(&view_lock); return 0; }
    pa = pmm_alloc();                           /* zeroed: the tail past EOF reads as zero */
    if (!pa) { mutex_unlock(&view_lock); kprintf("K64 kwin: out of memory for %s page %llu\n", v->node->name, off / PAGE_SIZE); return -1; }
    want = v->size - off < PAGE_SIZE ? v->size - off : PAGE_SIZE;
    rc = fs_read(v->node, off, (void *)p2v(pa), want, &done);
    if (rc || done != want) {
        ++v->io_errors;
        memset((void *)p2v(pa), 0, PAGE_SIZE);
        kprintf("K64 kwin: %s: read of page %llu failed (rc %d, %llu of %llu bytes)\n", v->node->name, off / PAGE_SIZE, rc,
                done, want);
    }
    if (vm_map(kernel_pml4(), va, pa, PT_NX)) {             /* read-only, kernel-only */
        pmm_free(pa);
        mutex_unlock(&view_lock);
        return -1;
    }
    ++v->resident;
    ++total_faults;
    mutex_unlock(&view_lock);
    return 0;
}

int kwin_fault(uint64_t addr)
{
    kview_t *v = view_at(addr);
    return v && load_page(v, addr) == 0;
}

int kview_read(kview_t *v, uint64_t off, void *buf, uint64_t len)
{
    if (!v || off > v->size || len > v->size - off) return -1;
    memcpy(buf, (const void *)(v->base + off), len);        /* faults the pages in */
    return v->io_errors ? -1 : 0;
}

uint64_t kwin_total_faults(void) { return total_faults; }

/* Physical address of view page `page` (loaded on first use), for mapping it into a process read-only (section.c);
 * 0 when the page is outside the file or could not be produced. */
uint64_t kview_page_pa(kview_t *v, uint64_t page)
{
    uint64_t va;
    if (!v || page >= v->npages) return 0;
    va = v->base + page * PAGE_SIZE;
    if (!vm_lookup(kernel_pml4(), va, 0) && load_page(v, va)) return 0;
    return vm_lookup(kernel_pml4(), va, 0) & ~(PAGE_SIZE - 1);
}
