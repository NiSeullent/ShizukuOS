/* SPDX-License-Identifier: GPL-2.0-only
 * Kernel64 sections (file mappings) and mapped views: what CreateFileMapping / OpenFileMapping / MapViewOfFile(Ex) /
 * UnmapViewOfFile / FlushViewOfFile need, with NT semantics.
 *
 *  - A section is either backed by the paging file (INVALID_HANDLE_VALUE: zero-filled memory shared by every view)
 *    or by a file. Its pages live in a three-level radix of physical pages owned by the section and are produced on
 *    first touch: demand-zero for paging-file sections, read from the file for file sections. A read-only file section
 *    whose file already has a kernel file view (kwin.c; e.g. an image the loader mapped) maps that view's pages
 *    instead, so the bytes exist once.
 *  - Every view of a section maps the same physical pages: a write through one view is seen by every other view, in
 *    this and in other processes (shared memory). Copy-on-write views (FILE_MAP_COPY, PAGE_WRITECOPY) map the pages
 *    read-only and give the process a private copy on its first write (marked with the PT_SW_PRIV software bit so
 *    that unmapping frees exactly the private copies).
 *  - A view holds a reference on the section object, so the section (and its pages) lives until the last handle is
 *    closed AND the last view is unmapped, as on NT. A file section keeps its file node open.
 *  - SEC_RESERVE sections map reserved views whose pages are committed with VirtualAlloc(MEM_COMMIT); SEC_COMMIT
 *    (the default) views are committed. SEC_IMAGE sections are not supported (STATUS_INVALID_PARAMETER): images are
 *    mapped by the loader.
 *  - FlushViewOfFile writes the resident pages of a writable file section back to the file (the kernel does not track
 *    dirty pages, so every resident page of the flushed range is written). A file that has a kernel file view refuses
 *    writes (kwin.c), which fails the flush with STATUS_MEDIA_WRITE_PROTECTED.
 * Limits: sections up to 512 GiB; no large pages; a file write through NtWriteFile after a page was produced is not
 * reflected in existing views of a copied (radix) file section.
 */
#include "kwin.h"

#define SEC_IMAGE 0x1000000u
#define SEC_RESERVE 0x4000000u
#define SEC_COMMIT 0x8000000u
#define SEC_NOCACHE 0x10000000u
#define SEC_WRITECOMBINE 0x40000000u
#define SEC_LARGE_PAGES 0x80000000u

#define STATUS_SECTION_TOO_BIG ((int32_t)0xC0000040)
#define STATUS_SECTION_PROTECTION ((int32_t)0xC000004E)
#define STATUS_MAPPED_FILE_SIZE_ZERO ((int32_t)0xC000011E)
#define STATUS_MAPPED_ALIGNMENT ((int32_t)0xC0000220)
#define STATUS_INVALID_VIEW_SIZE ((int32_t)0xC000001F)
#define STATUS_NOT_MAPPED_VIEW ((int32_t)0xC0000019)
#define STATUS_INVALID_PAGE_PROTECTION ((int32_t)0xC0000045)
#define STATUS_INVALID_FILE_FOR_SECTION ((int32_t)0xC0000020)
#define STATUS_MEDIA_WRITE_PROTECTED ((int32_t)0xC00000A2)
#define STATUS_NOT_MAPPED_DATA ((int32_t)0xC0000088)

#define RADIX_MAX_PAGES (1ull << 27)                        /* 512 GiB */

typedef struct section {
    uint64_t size, npages;
    uint32_t prot;                  /* page protection of the section (the most a view may get) */
    uint32_t attrs;                 /* SEC_* */
    fsnode_t *node;                 /* file section: its file (open_count held) */
    kview_t *kv;                    /* read-only file section over an existing kernel file view */
    uint64_t root;                  /* radix root page (physical), 0 = empty */
    uint64_t resident;              /* pages produced */
    unsigned views;
    kmutex_t lock;
} section_t;

typedef struct sview {
    section_t *s;
    kobject_t *obj;                 /* the section object, referenced while mapped */
    process_t *p;
    uint64_t base, size;            /* user range of the view */
    uint64_t first_page;            /* section page mapped at base */
    uint32_t prot;
} sview_t;

static uint64_t sections_live, views_live;

/* ---------------------------------------------------------------- radix of physical pages */
static uint64_t *radix_slot(section_t *s, uint64_t idx, int create)
{
    uint64_t *t;
    int lvl;
    if (!s->root) {
        if (!create) return 0;
        s->root = pmm_alloc();
        if (!s->root) return 0;
    }
    t = (uint64_t *)p2v(s->root);
    for (lvl = 2; lvl > 0; --lvl) {
        const unsigned i = (unsigned)(idx >> (9 * lvl)) & 511;
        if (!t[i]) {
            if (!create) return 0;
            t[i] = pmm_alloc();
            if (!t[i]) return 0;
        }
        t = (uint64_t *)p2v(t[i]);
    }
    return &t[idx & 511];
}

static void radix_free(uint64_t table, int lvl)
{
    uint64_t *t = (uint64_t *)p2v(table);
    unsigned i;
    for (i = 0; i < 512; ++i)
        if (t[i]) {
            if (lvl == 0) pmm_free(t[i]);
            else radix_free(t[i], lvl - 1);
        }
    pmm_free(table);
}

static uint64_t prot_base(uint32_t prot) { return prot & 0xff; }
static int prot_writes(uint32_t prot)
{
    const uint64_t b = prot_base(prot);
    return b == PAGE_READWRITE || b == PAGE_EXECUTE_READWRITE;
}
static int prot_cow(uint32_t prot)
{
    const uint64_t b = prot_base(prot);
    return b == PAGE_WRITECOPY || b == PAGE_EXECUTE_WRITECOPY;
}
static int prot_execs(uint32_t prot) { return prot_base(prot) >= PAGE_EXECUTE; }

/* Physical page holding section page `idx`, produced on first use; 0 on failure. */
static uint64_t section_page(section_t *s, uint64_t idx)
{
    uint64_t *slot, pa;
    if (idx >= s->npages) return 0;
    if (s->kv) {
        extern uint64_t kview_page_pa(kview_t *v, uint64_t page);
        return kview_page_pa(s->kv, idx);
    }
    mutex_lock(&s->lock);
    slot = radix_slot(s, idx, 1);
    if (!slot) { mutex_unlock(&s->lock); return 0; }
    if (!*slot) {
        pa = pmm_alloc();                                   /* zeroed */
        if (pa && s->node && idx * PAGE_SIZE < s->node->size) {
            const uint64_t off = idx * PAGE_SIZE;
            const uint64_t want = s->node->size - off < PAGE_SIZE ? s->node->size - off : PAGE_SIZE;
            uint64_t done = 0;
            if (fs_read(s->node, off, (void *)p2v(pa), want, &done) || done != want) {
                kprintf("K64 section: read of %s page %llu failed (%llu of %llu bytes)\n", s->node->name, idx, done, want);
                pmm_free(pa);
                pa = 0;
            }
        }
        *slot = pa;
        if (pa) ++s->resident;
    }
    pa = *slot;
    mutex_unlock(&s->lock);
    return pa;
}

/* ---------------------------------------------------------------- objects */
void section_object_free(kobject_t *o)
{
    section_t *s = o->u.section.s;
    if (!s) return;
    o->u.section.s = 0;
    if (s->root) radix_free(s->root, 2);
    if (s->node) {
        if (s->node->open_count) --s->node->open_count;
        if (s->node->delete_pending && !s->node->open_count) fs_remove(s->node);
    }
    kfree(s);
    --sections_live;
}

static int prot_valid_section(uint32_t prot)
{
    const uint32_t b = prot & 0xff;
    return (prot & ~0xffu) == 0 && (b == PAGE_READONLY || b == PAGE_READWRITE || b == PAGE_WRITECOPY || b == PAGE_EXECUTE_READ ||
                                     b == PAGE_EXECUTE_READWRITE || b == PAGE_EXECUTE_WRITECOPY);
}

/* Creates a section. file == NULL: paging-file backed (max_size required). Returns the object (one reference). */
int32_t section_create(file_t *file, uint64_t max_size, uint32_t prot, uint32_t attrs, const char *name, kobject_t **out)
{
    section_t *s;
    kobject_t *o;
    const uint32_t kind = attrs & (SEC_IMAGE | SEC_RESERVE | SEC_COMMIT);
    if (!prot_valid_section(prot)) return STATUS_INVALID_PAGE_PROTECTION;
    if ((attrs & SEC_IMAGE) || (attrs & SEC_LARGE_PAGES)) return STATUS_INVALID_PARAMETER;
    if (kind == (SEC_RESERVE | SEC_COMMIT)) return STATUS_INVALID_PARAMETER;
    if (file) {
        fsnode_t *n = file->node;
        const uint32_t acc = file->access;
        const int can_read = (acc & (0x80000000u | 0x10000000u | 1u)) != 0;          /* GENERIC_READ/ALL, FILE_READ_DATA */
        const int can_write = (acc & (0x40000000u | 0x10000000u | 2u)) != 0;         /* GENERIC_WRITE/ALL, FILE_WRITE_DATA */
        if (!n || n->is_dir || file->pipe || file->console) return STATUS_INVALID_FILE_FOR_SECTION;
        if (!can_read || (prot_writes(prot) && !can_write)) return STATUS_ACCESS_DENIED;
        if (attrs & SEC_RESERVE) return STATUS_INVALID_PARAMETER;                     /* NT: SEC_RESERVE is for paging-file sections */
        if (!max_size) {
            if (!n->size) return STATUS_MAPPED_FILE_SIZE_ZERO;
            max_size = n->size;
        } else if (max_size > n->size) {
            if (!prot_writes(prot)) return STATUS_SECTION_TOO_BIG;
            if (n->readonly || fs_truncate(n, max_size)) return STATUS_DISK_FULL;     /* the file grows to the section size */
        }
    } else if (!max_size) {
        return STATUS_INVALID_PARAMETER;
    }
    if ((max_size + PAGE_SIZE - 1) / PAGE_SIZE > RADIX_MAX_PAGES) return STATUS_SECTION_TOO_BIG;
    s = kzalloc(sizeof *s);
    o = s ? ob_create(OB_SECTION, name) : 0;
    if (!o) { kfree(s); return STATUS_NO_MEMORY; }
    s->size = max_size;
    s->npages = (max_size + PAGE_SIZE - 1) / PAGE_SIZE;
    s->prot = prot;
    s->attrs = kind ? kind : SEC_COMMIT;
    mutex_init(&s->lock);
    if (file) {
        s->node = file->node;
        ++s->node->open_count;
        if (s->node->view && !prot_writes(prot)) s->kv = s->node->view;             /* share the pages of the existing view */
    }
    o->u.section.s = s;
    ++sections_live;
    *out = o;
    return STATUS_SUCCESS;
}

uint64_t section_size(kobject_t *o) { section_t *s = o->u.section.s; return s ? s->size : 0; }
uint32_t section_attrs(kobject_t *o) { section_t *s = o->u.section.s; return s ? s->attrs | (s->node ? 0x800000u : 0) : 0; }

/* Whether a view with `vprot` may be mapped from a section created with `sprot`. */
static int view_prot_allowed(uint32_t sprot, uint32_t vprot)
{
    const uint32_t v = vprot & 0xff;
    if (!prot_valid_section(vprot & 0xff) && v != PAGE_NOACCESS) return 0;
    if (v == PAGE_NOACCESS || v == PAGE_READONLY || v == PAGE_WRITECOPY) return 1;           /* any section can be read / copied */
    if (v == PAGE_READWRITE) return prot_writes(sprot);
    if (v == PAGE_EXECUTE_READ || v == PAGE_EXECUTE_WRITECOPY) return prot_execs(sprot);
    if (v == PAGE_EXECUTE_READWRITE) return prot_base(sprot) == PAGE_EXECUTE_READWRITE;
    return 0;
}

extern int32_t vad_attach_view(process_t *p, uint64_t base, void *view);

/* NtMapViewOfSection core: maps `*size` bytes (0 = to the end) at section byte `offset` (64 KiB aligned) into `p` at
 * `*base` (0 = anywhere; MEM_TOP_DOWN in alloc_type). */
int32_t section_map(kobject_t *o, process_t *p, uint64_t *base, uint64_t offset, uint64_t *size, uint32_t alloc_type, uint32_t prot)
{
    section_t *s = o->u.section.s;
    sview_t *w;
    uint64_t b = *base, len = *size;
    int32_t st;
    uint32_t type;
    if (!s) return STATUS_INVALID_HANDLE;
    if (offset & 0xffff) return STATUS_MAPPED_ALIGNMENT;
    if (b & 0xffff) return STATUS_MAPPED_ALIGNMENT;
    if (alloc_type & ~(uint32_t)(MEM_TOP_DOWN | MEM_RESERVE)) return STATUS_INVALID_PARAMETER;
    if (offset >= s->size) return STATUS_INVALID_VIEW_SIZE;
    if (!len) len = s->size - offset;
    if (len > s->size - offset) return STATUS_INVALID_VIEW_SIZE;
    if (!view_prot_allowed(s->prot, prot)) return STATUS_SECTION_PROTECTION;
    w = kzalloc(sizeof *w);
    if (!w) return STATUS_NO_MEMORY;
    len = (len + PAGE_SIZE - 1) & ~(PAGE_SIZE - 1);
    type = MEM_RESERVE | ((s->attrs & SEC_RESERVE) ? 0 : MEM_COMMIT) | (alloc_type & MEM_TOP_DOWN);
    st = vad_alloc(p, &b, &len, type, prot, VK_SECTION);
    if (st) { kfree(w); return st; }
    w->s = s;
    w->obj = o;
    w->p = p;
    w->base = b;
    w->size = len;
    w->first_page = offset / PAGE_SIZE;
    w->prot = prot;
    if (vad_attach_view(p, b, w)) {                          /* cannot fail for a descriptor just created */
        uint64_t zero = 0;
        (void)zero;
        kfree(w);
        return STATUS_NO_MEMORY;
    }
    ob_ref(o);
    ++s->views;
    ++views_live;
    *base = b;
    *size = len;
    return STATUS_SUCCESS;
}

/* The view's pages leave the address space: private copy-on-write copies are freed, section pages stay with the
 * section (vad.c calls this for every descriptor of the view). */
void section_unmap_pages(process_t *p, uint64_t start, uint64_t end)
{
    uint64_t a;
    for (a = start; a < end; a += PAGE_SIZE) {
        uint64_t flags = 0, pa = vm_lookup(p->pml4, a, &flags);
        if (!pa) continue;
        vm_unmap(p->pml4, a, 0);
        if (flags & PT_SW_PRIV) pmm_free(pa & ~(PAGE_SIZE - 1));
    }
}

/* Called by vad.c once the descriptors of a view are gone. */
void section_view_released(void *view)
{
    sview_t *w = view;
    kobject_t *o;
    if (!w) return;
    o = w->obj;
    if (w->s && w->s->views) --w->s->views;
    --views_live;
    kfree(w);
    ob_deref(o);
}

/* Page fault inside a view (from user_fault_in / image_kpage); protection checks were done by the caller. */
int section_fault(process_t *p, vad_t *v, uint64_t addr, int write)
{
    sview_t *w = v->img;
    const uint64_t page = addr & ~(PAGE_SIZE - 1);
    const int cow = prot_cow(v->prot);
    uint64_t flags = 0, cur, pa, idx;
    if (!w || !w->s) return STATUS_ACCESS_VIOLATION;
    cur = vm_lookup(p->pml4, page, &flags);
    if (cur && (flags & PT_U)) {
        if (!write || (flags & PT_W)) return 0;                 /* present and sufficient: a racing fault */
        if (!cow || (flags & PT_SW_PRIV)) return STATUS_ACCESS_VIOLATION;
        pa = pmm_alloc();
        if (!pa) return STATUS_NO_MEMORY;
        memcpy((void *)p2v(pa), (const void *)p2v(cur & ~(PAGE_SIZE - 1)), PAGE_SIZE);
        if (vm_map(p->pml4, page, pa, prot_to_ptflags(v->prot) | PT_SW_PRIV)) { pmm_free(pa); return STATUS_NO_MEMORY; }
        return 0;
    }
    idx = w->first_page + (page - w->base) / PAGE_SIZE;
    if (idx >= w->s->npages) return STATUS_ACCESS_VIOLATION;
    pa = section_page(w->s, idx);
    if (!pa) return w->s->node ? (int32_t)0xC0000006 : STATUS_NO_MEMORY;   /* STATUS_IN_PAGE_ERROR / no memory */
    if (cur) {                                                   /* parked (NOACCESS/GUARD) mapping: replace it */
        vm_unmap(p->pml4, page, 0);
        if (flags & PT_SW_PRIV) pmm_free(cur & ~(PAGE_SIZE - 1));
    }
    if (cow && write) {
        const uint64_t copy = pmm_alloc();
        if (!copy) return STATUS_NO_MEMORY;
        memcpy((void *)p2v(copy), (const void *)p2v(pa), PAGE_SIZE);
        if (vm_map(p->pml4, page, copy, prot_to_ptflags(v->prot) | PT_SW_PRIV)) { pmm_free(copy); return STATUS_NO_MEMORY; }
        return 0;
    }
    flags = prot_to_ptflags(v->prot);
    if (cow || w->s->kv) flags &= ~PT_W;
    if (vm_map(p->pml4, page, pa, flags)) return STATUS_NO_MEMORY;
    return 0;
}

/* The page (kernel address) a view shows at `page`: used by image_kpage() for kernel access to a view. */
int section_kpage(process_t *p, vad_t *v, uint64_t page)
{
    return section_fault(p, v, page, 0);
}

/* FlushViewOfFile: writes the resident pages of [addr, addr+len) back to the section's file. */
int32_t section_flush(process_t *p, uint64_t addr, uint64_t len, uint64_t *base_out, uint64_t *len_out)
{
    vad_t *v = vad_find(p, addr & ~(PAGE_SIZE - 1));
    sview_t *w;
    section_t *s;
    uint64_t start, end, a;
    int32_t st = STATUS_SUCCESS;
    if (!v || v->kind != VK_SECTION || !(w = v->img)) return STATUS_NOT_MAPPED_VIEW;
    s = w->s;
    start = addr & ~(PAGE_SIZE - 1);
    end = len ? (addr + len + PAGE_SIZE - 1) & ~(PAGE_SIZE - 1) : w->base + w->size;
    if (end > w->base + w->size) end = w->base + w->size;
    if (base_out) *base_out = start;
    if (len_out) *len_out = end - start;
    if (!s->node || s->kv || !prot_writes(s->prot)) return STATUS_SUCCESS;          /* nothing that could be dirty */
    for (a = start; a < end; a += PAGE_SIZE) {
        const uint64_t idx = w->first_page + (a - w->base) / PAGE_SIZE;
        uint64_t *slot, off, n;
        if (idx >= s->npages) break;
        mutex_lock(&s->lock);
        slot = radix_slot(s, idx, 0);
        if (!slot || !*slot) { mutex_unlock(&s->lock); continue; }
        off = idx * PAGE_SIZE;
        n = s->size - off < PAGE_SIZE ? s->size - off : PAGE_SIZE;
        if (off + n > s->node->size) n = s->node->size > off ? s->node->size - off : 0;
        if (n && fs_write(s->node, off, (const void *)p2v(*slot), n)) st = STATUS_MEDIA_WRITE_PROTECTED;
        mutex_unlock(&s->lock);
        if (st) break;
    }
    if (!st) fs_flush(s->node);
    return st;
}

/* Section information for NtQuerySection(SectionBasicInformation): {BaseAddress 0, Attributes, MaximumSize}. */
int32_t section_query(kobject_t *o, uint64_t out[3])
{
    section_t *s = o->u.section.s;
    if (!s) return STATUS_INVALID_HANDLE;
    out[0] = 0;
    out[1] = s->attrs | (s->node ? 0x800000u : 0);                                   /* SEC_FILE */
    out[2] = s->size;
    return STATUS_SUCCESS;
}

void section_stats(uint64_t *sections, uint64_t *views) { *sections = sections_live; *views = views_live; }
