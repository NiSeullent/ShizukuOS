/* SPDX-License-Identifier: GPL-2.0-only
 * Kernel64 sections and views (NtCreateSection / NtOpenSection / NtMapViewOfSection / NtUnmapViewOfSection /
 * NtQuerySection / NtFlushVirtualMemory): the memory behind CreateFileMapping / MapViewOfFile, shared between every
 * process that maps the same section object (by name, inherited or duplicated handle).
 *
 * Anonymous sections own their physical pages. File sections hold references to resident pages keyed by the retained
 * file node and page index, so independent sections on the same local file see each other's mapped writes. Pages are
 * created on first touch and released when their last section dies, after its last handle AND view are gone (each view
 * holds an object reference). Process page tables never own a view page: views are unmapped before process_teardown()
 * frees the address space, and NtFreeVirtualMemory refuses views.
 *
 *   - pagefile-backed sections (no file) are zero-filled;
 *   - file-backed sections share lazily read resident pages; writable sections write them back on FlushViewOfFile,
 *     on unmap and when the section dies. Direct ReadFile/WriteFile accesses remain outside this mapped-page cache;
 *   - PAGE_WRITECOPY / PAGE_EXECUTE_WRITECOPY views share pages until the first write, which gives that view (only) a
 *     private copy;
 *   - SEC_RESERVE sections map as reserved and are committed with VirtualAlloc(MEM_COMMIT) inside the view.
 * Page lookup tables live in physical pages (two levels, 512 entries each), so big sections cost almost no kernel heap.
 */
#include "ipc.h"
#include "auth_policy.h"
#include "ipc_section_security.h"

#define SEC_FILE 0x800000u
#define SEC_IMAGE 0x1000000u
#define SEC_RESERVE 0x4000000u
#define SEC_COMMIT 0x8000000u
#define SEC_NOCACHE 0x10000000u
#define SEC_LARGE_PAGES 0x80000000u
#define STATUS_SECTION_PROTECTION ((int32_t)0xC000004E)
#define STATUS_SECTION_NOT_IMAGE ((int32_t)0xC0000049)
#define STATUS_INVALID_PARAMETER_4 ((int32_t)0xC00000F2)
#define OBJ_OPENIF_ATTR 0x80u
#define MAX_SECTION_BYTES (4ull << 30)

typedef struct {
    uint64_t size, npages;
    uint64_t *dir;                      /* ceil(npages / 512) entries: physical address of a leaf of 512 page addresses */
    uint32_t prot, attrs;
    fsnode_t *node;                     /* backing file (its open_count is held), 0 for pagefile-backed */
    int file_writable;
    uint64_t resident;
} section_t;

typedef struct cow_page { struct cow_page *next; uint64_t index, pa; } cow_page_t;

struct view {
    view_t *next;
    uint64_t base, size;                /* mapped range in the process */
    kobject_t *sec;                     /* referenced section object */
    uint64_t first;                     /* section page index of `base` */
    cow_page_t *cow;                    /* private copies made by writes to a copy-on-write view */
};

static int prot_writable(uint32_t p) { p &= 0xff; return p == PAGE_READWRITE || p == PAGE_EXECUTE_READWRITE; }
static int prot_cow(uint32_t p) { p &= 0xff; return p == PAGE_WRITECOPY || p == PAGE_EXECUTE_WRITECOPY; }
static int prot_exec(uint32_t p) { p &= 0xff; return p >= PAGE_EXECUTE && p <= PAGE_EXECUTE_WRITECOPY; }

static int section_security_read(void *p, uint64_t addr, void *out, size_t n)
{
    return copy_from_user(p, out, addr, n);
}

/* Capture creation attributes before allocating the section. The object owns
 * the returned descriptor, using its existing sd lifetime/query support. */
static int32_t section_security_capture(process_t *p, uint64_t oa, void **sd, uint32_t *len)
{
    struct ipc_objattr a;
    uint8_t *scratch, *saved;
    int32_t st;
    *sd = 0; *len = 0;
    if (!oa) return 0;
    if (copy_from_user(p, &a, oa, sizeof a)) return STATUS_ACCESS_VIOLATION;
    if (!a.sd) return 0;
    scratch = kmalloc(SHZ_SEC_MAX);
    if (!scratch) return STATUS_INSUFFICIENT_RESOURCES;
    st = shz_sec_capture(p, section_security_read, a.sd, scratch, len);
    saved = !st ? kmalloc(*len) : 0;
    if (!st && !saved) st = STATUS_INSUFFICIENT_RESOURCES;
    if (!st) { memcpy(saved, scratch, *len); *sd = saved; }
    kfree(scratch);
    return st;
}

int32_t ipc_section_duplicate_access(kobject_t *o, uint32_t granted, uint32_t *desired)
{
    const uint64_t f = irq_save();
    int32_t st;
    *desired = shz_sec_section_access(*desired);
    st = shz_sec_section_check(o->sd, o->sd_len, granted, *desired);
    irq_restore(f);
    return st;
}

static int32_t sys_open_section(process_t *p, uint64_t ph, uint64_t access, uint64_t oa)
{
    char name[48];
    uint32_t oattrs = 0, a = (uint32_t)access;
    kobject_t *o;
    uint64_t f;
    int32_t st = ipc_name_from_oa(p, oa, name, sizeof name, &oattrs);
    if (st) return st;
    if (!name[0]) return STATUS_OBJECT_NAME_INVALID;
    f = irq_save();
    o = ob_find_named(OB_SECTION, name);
    if (o) ob_ref(o);
    irq_restore(f);
    if (!o) return STATUS_OBJECT_NAME_NOT_FOUND;
    if (o->type != OB_SECTION) { ob_deref(o); return STATUS_OBJECT_TYPE_MISMATCH; }
    st = ipc_section_duplicate_access(o, 0, &a);
    if (st) { ob_deref(o); return st; }
    return ipc_give_handle(p, o, a, (oattrs & OBJ_INHERIT_ATTR) != 0, ph, 0);
}

/* ---------------------------------------------------------------- section pages (interrupts off) */
/* The node's open_count is held by each section until its page references have
 * been released. Do not retain bare node pointers after the last reference.
 * A separate cache lock serializes independent sections' acquisitions; existing
 * per-section/view mutation still follows the caller's interrupt-off contract. */
#define FILE_PAGE_BUCKETS 256u
typedef struct file_page {
    struct file_page *next;
    fsnode_t *node;
    uint64_t index, pa, refs;
} file_page_t;
static file_page_t *file_pages[FILE_PAGE_BUCKETS];
static uint64_t file_page_epochs[FILE_PAGE_BUCKETS];
static uint32_t file_pages_lock;

static unsigned file_page_bucket(fsnode_t *node, uint64_t index)
{
    return (unsigned)(((uint64_t)node >> 4) ^ index ^ (index >> 8)) & (FILE_PAGE_BUCKETS - 1);
}

static uint64_t file_page_lock(void)
{
    const uint64_t f = irq_save();
    while (__atomic_exchange_n(&file_pages_lock, 1, __ATOMIC_ACQUIRE)) __asm__ volatile("pause");
    return f;
}

static void file_page_unlock(uint64_t f)
{
    __atomic_store_n(&file_pages_lock, 0, __ATOMIC_RELEASE);
    irq_restore(f);
}

static uint64_t file_page_acquire(fsnode_t *node, uint64_t index)
{
    const unsigned bucket = file_page_bucket(node, index);
    file_page_t *p, *candidate;
    uint64_t f, pa, epoch;
    for (;;) {
        uint64_t done = 0;
        f = file_page_lock();
        for (p = file_pages[bucket]; p; p = p->next) {
            if (p->node != node || p->index != index) continue;
            pa = p->refs == UINT64_MAX ? 0 : p->pa;
            if (pa) ++p->refs;
            file_page_unlock(f);
            return pa;
        }
        epoch = file_page_epochs[bucket];
        file_page_unlock(f);
        /* Allocators and VFS may take other locks: keep them outside the cache
         * lock. A second lookup publishes only one page if faults race. */
        candidate = kzalloc(sizeof *candidate);
        if (!candidate) return 0;
        pa = pmm_alloc();
        if (!pa || fs_read(node, index * PAGE_SIZE, (void *)p2v(pa), PAGE_SIZE, &done)) {
            if (pa) pmm_free(pa);
            kfree(candidate);
            return 0;
        }
        candidate->node = node; candidate->index = index;
        candidate->pa = pa; candidate->refs = 1;
        f = file_page_lock();
        for (p = file_pages[bucket]; p; p = p->next) {
            if (p->node != node || p->index != index) continue;
            const uint64_t existing = p->refs == UINT64_MAX ? 0 : p->pa;
            if (existing) ++p->refs;
            file_page_unlock(f);
            pmm_free(pa);
            kfree(candidate);
            return existing;
        }
        if (epoch != file_page_epochs[bucket]) {
            /* An intervening page could have been published, changed, written
             * back and finally released. Never publish our older read snapshot. */
            file_page_unlock(f);
            pmm_free(pa);
            kfree(candidate);
            continue;
        }
        candidate->next = file_pages[bucket]; file_pages[bucket] = candidate;
        ++file_page_epochs[bucket];
        file_page_unlock(f);
        return pa;
    }
}

static void file_page_release(fsnode_t *node, uint64_t index, uint64_t pa)
{
    const unsigned bucket = file_page_bucket(node, index);
    file_page_t **pp, *p;
    const uint64_t f = file_page_lock();
    for (pp = &file_pages[bucket]; (p = *pp) != 0; pp = &p->next) {
        if (p->node != node || p->index != index || p->pa != pa) continue;
        if (--p->refs) { file_page_unlock(f); return; }
        *pp = p->next;
        ++file_page_epochs[bucket];
        file_page_unlock(f);
        pmm_free(pa);
        kfree(p);
        return;
    }
    file_page_unlock(f);
}

static uint64_t *leaf_of(section_t *s, uint64_t idx, int create)
{
    uint64_t *d = &s->dir[idx >> 9];
    if (!*d) {
        if (!create) return 0;
        *d = pmm_alloc();
        if (!*d) return 0;
    }
    return (uint64_t *)p2v(*d);
}

/* Physical page `idx` of the section, created (zeroed, or read from the file) when `create` is set. */
static uint64_t section_page(section_t *s, uint64_t idx, int create)
{
    uint64_t *leaf, pa;
    if (idx >= s->npages) return 0;
    leaf = leaf_of(s, idx, create);
    if (!leaf) return 0;
    if (leaf[idx & 511] || !create) return leaf[idx & 511];
    pa = s->node ? file_page_acquire(s->node, idx) : pmm_alloc();
    if (!pa) return 0;
    leaf[idx & 511] = pa;
    ++s->resident;
    return pa;
}

/* Writes the resident pages of [first, first + count) back to the backing file (interrupts on). */
static void section_write_back(section_t *s, uint64_t first, uint64_t count)
{
    uint64_t i;
    if (!s->node || !s->file_writable) return;
    for (i = first; i < first + count && i < s->npages; ++i) {
        uint64_t pa, off = i * PAGE_SIZE, len;
        const uint64_t f = irq_save();
        pa = section_page(s, i, 0);
        irq_restore(f);
        if (!pa || off >= s->size) continue;
        len = s->size - off < PAGE_SIZE ? s->size - off : PAGE_SIZE;
        if (off + len > s->node->size) {                   /* never grow the file past what the section covers */
            if (off >= s->node->size) continue;
            len = s->node->size - off;
        }
        fs_write(s->node, off, (void *)p2v(pa), len);
    }
}

void section_free(kobject_t *o)
{
    section_t *s = o->u.file.file;
    uint64_t d;
    if (!s) return;
    o->u.file.file = 0;
    section_write_back(s, 0, s->npages);
    for (d = 0; d < (s->npages + 511) / 512; ++d) {
        uint64_t *leaf, i;
        if (!s->dir[d]) continue;
        leaf = (uint64_t *)p2v(s->dir[d]);
        for (i = 0; i < 512; ++i) if (leaf[i]) {
            if (s->node) file_page_release(s->node, d * 512 + i, leaf[i]);
            else pmm_free(leaf[i]);
        }
        pmm_free(s->dir[d]);
    }
    if (s->node) {
        if (s->node->open_count) --s->node->open_count;
        if (s->node->delete_pending && s->node->open_count == 0) fs_remove(s->node);
    }
    kfree(s->dir);
    kfree(s);
    --ipc_stat_sections;
}

/* ---------------------------------------------------------------- views */
static view_t *view_at(process_t *p, uint64_t addr)
{
    ipc_proc_t *ip = p->ipc;
    view_t *v;
    for (v = ip ? ip->views : 0; v; v = v->next)
        if (addr >= v->base && addr < v->base + v->size) return v;
    return 0;
}

static uint64_t cow_lookup(view_t *v, uint64_t idx)
{
    cow_page_t *c;
    for (c = v->cow; c; c = c->next) if (c->index == idx) return c->pa;
    return 0;
}

/* Page fault inside a view (vad.c, interrupts off): maps the section page, or makes the private copy of a copy-on-write
 * page on its first write. Returns 0 when the access may be retried, an NTSTATUS otherwise. */
int view_fault(process_t *p, vad_t *d, uint64_t addr, int write, int exec)
{
    view_t *v = view_at(p, addr);
    section_t *s;
    const uint32_t prot = d->prot, base = prot & 0xff;
    uint64_t idx, pa, flags = 0, page = addr & ~(PAGE_SIZE - 1), cur;
    if (!v || !(s = v->sec->u.file.file)) return STATUS_ACCESS_VIOLATION;
    if (base == PAGE_NOACCESS) return STATUS_ACCESS_VIOLATION;
    if (prot & 0x100) { d->prot &= ~0x100u; return STATUS_GUARD_PAGE_VIOLATION; }
    if (write && !prot_writable(base) && !prot_cow(base)) return STATUS_ACCESS_VIOLATION;
    if (exec && !prot_exec(base)) return STATUS_ACCESS_VIOLATION;
    idx = v->first + (page - v->base) / PAGE_SIZE;
    cur = vm_lookup(p->pml4, page, &flags);
    if (cur && (!write || (flags & PT_W))) return 0;                     /* already mapped well enough (racing fault) */
    pa = cow_lookup(v, idx);
    if (!pa) {
        const uint64_t spa = section_page(s, idx, 1);
        if (!spa) return idx >= s->npages ? STATUS_ACCESS_VIOLATION : STATUS_NO_MEMORY;
        if (prot_cow(base) && write) {                                   /* first write: this view's own copy */
            cow_page_t *c = kzalloc(sizeof *c);
            pa = pmm_alloc();
            if (!c || !pa) { kfree(c); if (pa) pmm_free(pa); return STATUS_NO_MEMORY; }
            memcpy((void *)p2v(pa), (void *)p2v(spa), PAGE_SIZE);
            c->index = idx; c->pa = pa; c->next = v->cow; v->cow = c;
        } else {
            pa = spa;
        }
    }
    flags = prot_to_ptflags(prot);
    if (prot_cow(base) && pa != cow_lookup(v, idx)) flags &= ~PT_W;     /* shared page of a COW view: read-only */
    if (cur) vm_unmap(p->pml4, page, 0);
    return vm_map(p->pml4, page, pa, flags) ? STATUS_NO_MEMORY : 0;
}

/* Unmaps a view's pages (none of them is freed except its private copies) and unlinks it; interrupts off. */
static void view_detach(process_t *p, view_t *v)
{
    ipc_proc_t *ip = p->ipc;
    view_t **pp;
    uint64_t va;
    cow_page_t *c, *n;
    for (pp = &ip->views; *pp; pp = &(*pp)->next)
        if (*pp == v) { *pp = v->next; break; }
    if (!p->teardown || p->pml4 != kernel_pml4())
        for (va = v->base; va < v->base + v->size; va += PAGE_SIZE) vm_unmap(p->pml4, va, 0);
    for (c = v->cow; c; c = n) { n = c->next; pmm_free(c->pa); kfree(c); }
    v->cow = 0;
    --ipc_stat_views;
}

/* After view_detach (interrupts on): the descriptor goes, dirty file pages are written back, the section reference drops. */
static void view_release(process_t *p, view_t *v, int remove_vad)
{
    section_t *s = v->sec->u.file.file;
    if (remove_vad) vad_remove_view(p, v->base);
    if (s && s->file_writable) section_write_back(s, v->first, v->size / PAGE_SIZE);
    ob_deref(v->sec);
    kfree(v);
}

/* Process teardown: every view goes before the address space is freed (vm_free_space would free section pages). */
void views_teardown(process_t *p)
{
    for (;;) {
        ipc_proc_t *ip = p->ipc;
        view_t *v;
        const uint64_t f = irq_save();
        v = ip ? ip->views : 0;
        if (v) view_detach(p, v);
        irq_restore(f);
        if (!v) break;
        view_release(p, v, 0);                          /* the descriptor set is destroyed with the process object */
    }
}

/* ---------------------------------------------------------------- system calls */
static int32_t get_section(process_t *p, uint64_t h, kobject_t **o, uint32_t *access)
{
    int32_t st = ipc_ref_handle(p, h, OB_SECTION, o, access);
    return st == STATUS_OBJECT_TYPE_MISMATCH ? STATUS_OBJECT_TYPE_MISMATCH : st;
}

/* NtCreateSection(PHANDLE, ACCESS_MASK, POBJECT_ATTRIBUTES, PLARGE_INTEGER MaximumSize, ULONG SectionPageProtection,
 *                 ULONG AllocationAttributes, HANDLE FileHandle) */
static int32_t sys_create_section(process_t *p, struct regs *r, uint64_t ph, uint64_t access, uint64_t oa, uint64_t psize)
{
    const uint32_t prot = (uint32_t)stack_arg(p, r, 5);
    uint32_t attrs = (uint32_t)stack_arg(p, r, 6), oattrs = 0;
    const uint64_t fh = (uint64_t)stack_arg(p, r, 7);
    char name[48];
    int64_t size = 0;
    kobject_t *o, *fobj = 0;
    section_t *s;
    int32_t st;
    const uint32_t pb = prot & 0xff;
    if (pb != PAGE_READONLY && pb != PAGE_READWRITE && pb != PAGE_WRITECOPY && pb != PAGE_EXECUTE_READ &&
        pb != PAGE_EXECUTE_READWRITE && pb != PAGE_EXECUTE_WRITECOPY)
        return STATUS_INVALID_PAGE_PROTECTION;
    if (attrs & (SEC_IMAGE | SEC_LARGE_PAGES)) return STATUS_NOT_SUPPORTED;        /* image sections, large pages: no */
    if (attrs & ~(SEC_FILE | SEC_RESERVE | SEC_COMMIT | SEC_NOCACHE)) return STATUS_INVALID_PARAMETER;
    if ((attrs & SEC_RESERVE) && (attrs & SEC_COMMIT)) return STATUS_INVALID_PARAMETER;
    if (!(attrs & (SEC_RESERVE | SEC_COMMIT))) attrs |= SEC_COMMIT;
    if (psize && copy_from_user(p, &size, psize, 8)) return STATUS_ACCESS_VIOLATION;
    if (size < 0) return STATUS_INVALID_PARAMETER_4;
    st = ipc_name_from_oa(p, oa, name, sizeof name, &oattrs);
    if (st) return st;
    if (name[0]) {
        const uint64_t f = irq_save();
        kobject_t *ex = ob_find_named(OB_SECTION, name);
        if (ex) ob_ref(ex);
        irq_restore(f);
        if (ex) {
            if (ex->type != OB_SECTION) { ob_deref(ex); return STATUS_OBJECT_TYPE_MISMATCH; }
            if (!(oattrs & OBJ_OPENIF_ATTR)) { ob_deref(ex); return STATUS_OBJECT_NAME_COLLISION; }
            uint32_t a = (uint32_t)access;
            st = ipc_section_duplicate_access(ex, 0, &a);
            if (st) { ob_deref(ex); return st; }
            st = ipc_give_handle(p, ex, a, (oattrs & OBJ_INHERIT_ATTR) != 0, ph, 0);
            return st ? st : STATUS_OBJECT_NAME_EXISTS;
        }
    }
    s = kzalloc(sizeof *s);
    if (!s) return STATUS_INSUFFICIENT_RESOURCES;
    void *sd = 0;
    uint32_t sd_len = 0;
    st = section_security_capture(p, oa, &sd, &sd_len);
    if (st) { kfree(s); return st; }
    if (fh) {
        uint32_t faccess = 0;
        file_t *file;
        st = ipc_ref_handle(p, fh, OB_FILE, &fobj, &faccess);
        if (st) { kfree(sd); kfree(s); return st == STATUS_OBJECT_TYPE_MISMATCH ? STATUS_INVALID_HANDLE : st; }
        file = fobj->u.file.file;
        if (!file || !file->node || file->node->is_dir) { ob_deref(fobj); kfree(sd); kfree(s); return STATUS_INVALID_PARAMETER; }
        if(!shz_auth_node_access(p,file->node,prot_writable(pb))){ob_deref(fobj);kfree(sd);kfree(s);return STATUS_ACCESS_DENIED;}
        if (!(faccess & (GENERIC_READ_ACCESS | GENERIC_ALL_ACCESS | FILE_READ_DATA_ACCESS)) && !(faccess & 0x120089)) {
            ob_deref(fobj); kfree(sd); kfree(s); return STATUS_ACCESS_DENIED;
        }
        s->file_writable = (faccess & (GENERIC_WRITE_ACCESS | GENERIC_ALL_ACCESS | FILE_WRITE_DATA_ACCESS)) != 0;
        if (prot_writable(pb) && !s->file_writable) { ob_deref(fobj); kfree(sd); kfree(s); return STATUS_ACCESS_DENIED; }
        if (!prot_writable(pb)) s->file_writable = 0;                   /* only a writable section writes the file */
        if (size == 0) size = (int64_t)file->node->size;
        if (size == 0) { ob_deref(fobj); kfree(sd); kfree(s); return STATUS_MAPPED_FILE_SIZE_ZERO; }
        if ((uint64_t)size > file->node->size) {
            if (!prot_writable(pb) || fs_truncate(file->node, (uint64_t)size)) {   /* Windows extends the file */
                ob_deref(fobj); kfree(sd); kfree(s); return STATUS_SECTION_TOO_BIG;
            }
        }
        s->node = file->node;
        ++s->node->open_count;                           /* the file stays until the section dies */
        ob_deref(fobj);
    } else if (size == 0) {
        kfree(sd); kfree(s);
        return STATUS_INVALID_PARAMETER_4;
    }
    if ((uint64_t)size > MAX_SECTION_BYTES) {
        if (s->node) --s->node->open_count;
        kfree(sd); kfree(s);
        return STATUS_SECTION_TOO_BIG;
    }
    s->size = (uint64_t)size;
    s->npages = (s->size + PAGE_SIZE - 1) / PAGE_SIZE;
    s->prot = prot;
    s->attrs = attrs | (s->node ? SEC_FILE : 0);
    s->dir = kzalloc(((s->npages + 511) / 512) * sizeof(uint64_t));
    o = s->dir ? ob_create(OB_SECTION, name) : 0;
    if (!o) {
        if (s->node) --s->node->open_count;
        kfree(s->dir); kfree(sd); kfree(s);
        return STATUS_INSUFFICIENT_RESOURCES;
    }
    o->u.file.file = s;
    o->sd = sd; o->sd_len = sd_len;
    ++ipc_stat_sections;
    return ipc_give_handle(p, o, shz_sec_section_access((uint32_t)access), (oattrs & OBJ_INHERIT_ATTR) != 0, ph, 0);
}

/* NtMapViewOfSection(Section, Process, PVOID *Base, ULONG_PTR ZeroBits, SIZE_T CommitSize, PLARGE_INTEGER Offset,
 *                    PSIZE_T ViewSize, SECTION_INHERIT, ULONG AllocationType, ULONG Win32Protect) */
static int32_t sys_map_view(process_t *p, struct regs *r, uint64_t hsec, uint64_t hproc, uint64_t pbase, uint64_t zero_bits)
{
    const uint64_t poffset = (uint64_t)stack_arg(p, r, 6), psize = (uint64_t)stack_arg(p, r, 7);
    const uint32_t alloc_type = (uint32_t)stack_arg(p, r, 9), prot = (uint32_t)stack_arg(p, r, 10);
    const uint32_t pb = prot & 0xff;
    kobject_t *so, *po;
    process_t *target;
    section_t *s;
    uint32_t access = 0;
    uint64_t base = 0, size = 0, offset = 0, delta;
    view_t *v;
    int32_t st;
    (void)zero_bits;
    if (copy_from_user(p, &base, pbase, 8) || copy_from_user(p, &size, psize, 8)) return STATUS_ACCESS_VIOLATION;
    if (poffset && copy_from_user(p, &offset, poffset, 8)) return STATUS_ACCESS_VIOLATION;
    if (alloc_type & ~(uint32_t)(MEM_TOP_DOWN | MEM_RESERVE | 0x20000000u /* MEM_LARGE_PAGES */)) return STATUS_INVALID_PARAMETER;
    if (pb != PAGE_READONLY && pb != PAGE_READWRITE && pb != PAGE_WRITECOPY && pb != PAGE_EXECUTE_READ &&
        pb != PAGE_EXECUTE_READWRITE && pb != PAGE_EXECUTE_WRITECOPY && pb != PAGE_NOACCESS && pb != PAGE_EXECUTE)
        return STATUS_INVALID_PAGE_PROTECTION;
    st = get_section(p, hsec, &so, &access);
    if (st) return st;
    s = so->u.file.file;
    if(s->node&&!shz_auth_node_access(p,s->node,prot_writable(pb))){ob_deref(so);return STATUS_ACCESS_DENIED;}
    /* The handle's rights and the section's protection bound the view's protection (MapViewOfFile table): a writable view
     * needs a writable section, an executable view an executable one; copy-on-write works on any section. */
    if ((prot_writable(pb) && !(access & SECTION_MAP_WRITE)) || (prot_exec(pb) && !(access & SECTION_MAP_EXECUTE)) ||
        (!prot_writable(pb) && !(access & (SECTION_MAP_READ | SECTION_MAP_WRITE)))) {
        ob_deref(so);
        return STATUS_ACCESS_DENIED;
    }
    if ((prot_writable(pb) && !prot_writable(s->prot)) || (prot_exec(pb) && !prot_exec(s->prot))) {
        ob_deref(so);
        return STATUS_SECTION_PROTECTION;
    }
    st = ipc_ref_process(p, hproc, PROCESS_VM_OPERATION, &target, &po);
    if (st) { ob_deref(so); return st; }
    if (target->terminated || target->teardown) { ob_deref(po); ob_deref(so); return STATUS_PROCESS_IS_TERMINATING; }
    delta = offset & 0xffffull;                          /* the offset is rounded down to the allocation granularity */
    offset -= delta;
    if (offset >= s->npages * PAGE_SIZE) { ob_deref(po); ob_deref(so); return STATUS_INVALID_VIEW_SIZE; }
    if (size == 0) size = s->npages * PAGE_SIZE - offset;
    else size += delta;
    size = (size + PAGE_SIZE - 1) & ~(PAGE_SIZE - 1);
    if (offset + size > s->npages * PAGE_SIZE || offset + size < offset) {
        ob_deref(po); ob_deref(so);
        return STATUS_INVALID_VIEW_SIZE;
    }
    if (base) {
        if (base & 0xffff) { ob_deref(po); ob_deref(so); return STATUS_MAPPED_ALIGNMENT; }
    }
    v = kzalloc(sizeof *v);
    if (!v || !ipc_proc(target, 1)) { kfree(v); ob_deref(po); ob_deref(so); return STATUS_INSUFFICIENT_RESOURCES; }
    st = vad_alloc(target, &base, &size, MEM_RESERVE | ((s->attrs & SEC_RESERVE) ? 0 : MEM_COMMIT) | (alloc_type & MEM_TOP_DOWN),
                   pb == PAGE_NOACCESS ? PAGE_NOACCESS : prot, VK_VIEW);
    if (st) { kfree(v); ob_deref(po); ob_deref(so); return st; }
    v->base = base;
    v->size = size;
    v->sec = so;                                         /* the handle reference becomes the view's reference */
    v->first = offset / PAGE_SIZE;
    {
        const uint64_t f = irq_save();
        ipc_proc_t *ip = ipc_proc(target, 1);
        v->next = ip->views;
        ip->views = v;
        ++ipc_stat_views;
        irq_restore(f);
    }
    ob_deref(po);
    if (copy_to_user(p, pbase, &base, 8) || copy_to_user(p, psize, &size, 8) ||
        (poffset && copy_to_user(p, poffset, &offset, 8)))
        return STATUS_ACCESS_VIOLATION;                  /* the view stays mapped, as on NT */
    return STATUS_SUCCESS;
}

/* NtUnmapViewOfSection(Process, BaseAddress): any address inside the view identifies it. */
static int32_t sys_unmap_view(process_t *p, uint64_t hproc, uint64_t addr)
{
    process_t *target;
    kobject_t *po;
    view_t *v;
    uint64_t f;
    int32_t st = ipc_ref_process(p, hproc, PROCESS_VM_OPERATION, &target, &po);
    if (st) return st;
    f = irq_save();
    v = target->teardown ? 0 : view_at(target, addr);
    if (v) view_detach(target, v);
    irq_restore(f);
    if (v) view_release(target, v, 1);
    ob_deref(po);
    return v ? STATUS_SUCCESS : STATUS_NOT_MAPPED_VIEW;
}

/* NtQuerySection(Section, SectionBasicInformation = 0, SECTION_BASIC_INFORMATION *, Length, PSIZE_T ResultLength) */
static int32_t sys_query_section(process_t *p, struct regs *r, uint64_t h, uint64_t cls, uint64_t buf, uint64_t len)
{
    const uint64_t pret = (uint64_t)stack_arg(p, r, 5);
    struct { uint64_t base; uint32_t attrs, pad; int64_t size; } b;
    kobject_t *o;
    uint32_t access = 0;
    int32_t st;
    if (cls == 1) return STATUS_SECTION_NOT_IMAGE;
    if (cls != 0) return STATUS_INVALID_INFO_CLASS;
    if (len < sizeof b) return STATUS_INFO_LENGTH_MISMATCH;
    st = get_section(p, h, &o, &access);
    if (st) return st;
    if (!(access & SECTION_QUERY)) { ob_deref(o); return STATUS_ACCESS_DENIED; }
    memset(&b, 0, sizeof b);
    b.attrs = ((section_t *)o->u.file.file)->attrs;
    b.size = (int64_t)((section_t *)o->u.file.file)->size;
    ob_deref(o);
    if (copy_to_user(p, buf, &b, sizeof b)) return STATUS_ACCESS_VIOLATION;
    if (pret) { const uint64_t n = sizeof b; if (copy_to_user(p, pret, &n, 8)) return STATUS_ACCESS_VIOLATION; }
    return STATUS_SUCCESS;
}

/* NtFlushVirtualMemory(Process, PVOID *Base, PSIZE_T Size, PIO_STATUS_BLOCK): FlushViewOfFile. */
static int32_t sys_flush_vm(process_t *p, uint64_t hproc, uint64_t pbase, uint64_t psize, uint64_t piosb)
{
    process_t *target;
    kobject_t *po, *so = 0;
    uint64_t base, size, f, first = 0, count = 0;
    view_t *v;
    int32_t st;
    if (copy_from_user(p, &base, pbase, 8) || copy_from_user(p, &size, psize, 8)) return STATUS_ACCESS_VIOLATION;
    st = ipc_ref_process(p, hproc, PROCESS_VM_OPERATION, &target, &po);
    if (st) return st;
    f = irq_save();
    v = target->teardown ? 0 : view_at(target, base);
    if (v) {
        const uint64_t start = base & ~(PAGE_SIZE - 1);
        uint64_t end = size ? (base + size + PAGE_SIZE - 1) & ~(PAGE_SIZE - 1) : v->base + v->size;
        if (end > v->base + v->size) end = v->base + v->size;
        first = v->first + (start - v->base) / PAGE_SIZE;
        count = (end - start) / PAGE_SIZE;
        so = v->sec;
        ob_ref(so);
        base = start;
        size = end - start;
    }
    irq_restore(f);
    ob_deref(po);
    if (!so) return STATUS_NOT_MAPPED_VIEW;
    {section_t *s=so->u.file.file;if(s->node&&!shz_auth_node_access(target,s->node,1)){ob_deref(so);return STATUS_ACCESS_DENIED;}}
    section_write_back(so->u.file.file, first, count);
    ob_deref(so);
    if (copy_to_user(p, pbase, &base, 8) || copy_to_user(p, psize, &size, 8)) return STATUS_ACCESS_VIOLATION;
    if (piosb) { struct ipc_iosb io = { 0, 0 }; if (copy_to_user(p, piosb, &io, sizeof io)) return STATUS_ACCESS_VIOLATION; }
    return STATUS_SUCCESS;
}

int32_t ipc_section_syscall(process_t *p, struct regs *r, uint32_t num, uint64_t a1, uint64_t a2, uint64_t a3,
                            uint64_t a4, int *handled)
{
    *handled = 1;
    switch (num) {
    case SYS_NtCreateSection: return sys_create_section(p, r, a1, a2, a3, a4);
    case SYS_NtOpenSection: return sys_open_section(p, a1, a2, a3);
    case SYS_NtMapViewOfSection: return sys_map_view(p, r, a1, a2, a3, a4);
    case SYS_NtUnmapViewOfSection: return sys_unmap_view(p, a1, a2);
    case SYS_NtQuerySection: return sys_query_section(p, r, a1, a2, a3, a4);
    case SYS_NtFlushVirtualMemory: return sys_flush_vm(p, a1, a2, a3, a4);
    default: break;
    }
    *handled = 0;
    return 0;
}
