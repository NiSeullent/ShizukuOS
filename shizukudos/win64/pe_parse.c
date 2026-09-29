/* SPDX-License-Identifier: GPL-2.0-only */
#include "pe_parse.h"

static uint16_t rd16(const uint8_t *p) { return (uint16_t)(p[0] | (p[1] << 8)); }
static uint32_t rd32(const uint8_t *p) { return (uint32_t)p[0] | ((uint32_t)p[1] << 8) | ((uint32_t)p[2] << 16) | ((uint32_t)p[3] << 24); }
static uint64_t rd64(const uint8_t *p) { return (uint64_t)rd32(p) | ((uint64_t)rd32(p + 4) << 32); }
static int in_range(uint64_t off, uint64_t len, uint64_t limit) { return off <= limit && len <= limit - off; }
static int pow2(uint32_t v) { return v && !(v & (v - 1)); }
static uint32_t align_up(uint32_t v, uint32_t a) { return (uint32_t)(((uint64_t)v + a - 1) & ~(uint64_t)(a - 1)); }

int pe_parse(const uint8_t *f, uint64_t size, pe_info_t *o)
{
    uint64_t nt, opt, sec;
    uint32_t i, j, hdr_end, opt_size, nrva;
    uint16_t nsec;
    *o = (pe_info_t){0};
    if (size < 64) return PE_E_TRUNCATED;
    if (f[0] != 'M' || f[1] != 'Z') return PE_E_DOS;
    nt = rd32(f + 0x3c);
    if (nt < 64 || !in_range(nt, 24, size)) return PE_E_TRUNCATED;
    if (f[nt] != 'P' || f[nt + 1] != 'E' || f[nt + 2] || f[nt + 3]) return PE_E_NT_SIG;
    if (rd16(f + nt + 4) != 0x8664) return PE_E_MACHINE;            /* AMD64 only: not ARM64, not x86 */
    nsec = rd16(f + nt + 6);
    opt_size = rd16(f + nt + 20);
    o->characteristics = rd16(f + nt + 22);
    if (!nsec || nsec > PE_MAX_SECTIONS) return PE_E_SECTIONS;
    if (!(o->characteristics & 0x0002)) return PE_E_HEADERS;        /* not IMAGE_FILE_EXECUTABLE_IMAGE */
    opt = nt + 24;
    if (opt_size < 112 || !in_range(opt, opt_size, size)) return PE_E_OPT_SIZE;
    if (rd16(f + opt) != 0x20b) return PE_E_MAGIC;
    o->entry_rva = rd32(f + opt + 16);
    o->image_base = rd64(f + opt + 24);
    o->section_alignment = rd32(f + opt + 32);
    o->file_alignment = rd32(f + opt + 36);
    o->major_os = rd16(f + opt + 40);
    o->minor_os = rd16(f + opt + 42);
    o->size_of_image = rd32(f + opt + 56);
    o->size_of_headers = rd32(f + opt + 60);
    o->checksum = rd32(f + opt + 64);
    o->subsystem = rd16(f + opt + 68);
    o->dll_characteristics = rd16(f + opt + 70);
    o->stack_reserve = rd64(f + opt + 72);
    o->stack_commit = rd64(f + opt + 80);
    o->heap_reserve = rd64(f + opt + 88);
    o->heap_commit = rd64(f + opt + 96);
    nrva = rd32(f + opt + 108);
    if (nrva > 16) nrva = 16;
    if (opt_size < 112 + nrva * 8) return PE_E_OPT_SIZE;
    for (i = 0; i < nrva; ++i) {
        o->dir_rva[i] = rd32(f + opt + 112 + i * 8);
        o->dir_size[i] = rd32(f + opt + 116 + i * 8);
    }
    if (!pow2(o->section_alignment) || !pow2(o->file_alignment) || o->file_alignment < 512 || o->file_alignment > 65536 ||
        o->section_alignment < o->file_alignment)
        return PE_E_ALIGN;
    if (o->section_alignment < 4096) {
        /* Low-alignment image: only valid when sections sit in the file exactly where they sit in memory. */
        if (o->section_alignment != o->file_alignment) return PE_E_ALIGN;
        o->low_alignment = 1;
    }
    if (o->image_base & 0xffff) return PE_E_ALIGN;
    if (o->image_base >= (1ull << 47) || o->image_base + o->size_of_image > (1ull << 47)) return PE_E_ALIGN;
    sec = opt + opt_size;
    o->nt_offset = (uint32_t)nt;
    o->section_table_offset = (uint32_t)sec;
    o->nsections = nsec;
    if (!in_range(sec, (uint64_t)nsec * 40, size)) return PE_E_SECTIONS;
    hdr_end = (uint32_t)(sec + (uint64_t)nsec * 40);
    if (o->size_of_headers < hdr_end || o->size_of_headers > size || o->size_of_headers > o->size_of_image ||
        o->size_of_image == 0)
        return PE_E_HEADERS;
    if (o->size_of_image % o->section_alignment) return PE_E_IMAGE_SIZE;
    if (o->size_of_image > (1u << 30)) return PE_E_IMAGE_SIZE;
    for (i = 0; i < nsec; ++i) {
        pe_section_t s;
        int rc = pe_get_section(f, o, i, &s);
        if (rc) return rc;
        if (s.rva % o->section_alignment || s.rva < align_up(o->size_of_headers, o->section_alignment))
            return PE_E_SECTION_RANGE;
        if (!in_range(s.rva, s.vsize ? s.vsize : 1, o->size_of_image)) return PE_E_SECTION_RANGE;
        if (s.raw_size) {
            if (s.raw_off % o->file_alignment && s.raw_off % 512) return PE_E_SECTION_RANGE;
            if (!in_range(s.raw_off, s.raw_size, size)) return PE_E_SECTION_RANGE;
            if (s.raw_off < o->size_of_headers) return PE_E_SECTION_RANGE;
            if (o->low_alignment && s.raw_off != s.rva) return PE_E_SECTION_RANGE;
        }
        for (j = 0; j < i; ++j) {                                   /* virtual ranges must not overlap */
            pe_section_t t;
            pe_get_section(f, o, j, &t);
            {
                const uint64_t a0 = s.rva, a1 = a0 + (s.vsize ? align_up(s.vsize, o->section_alignment) : o->section_alignment);
                const uint64_t b0 = t.rva, b1 = b0 + (t.vsize ? align_up(t.vsize, o->section_alignment) : o->section_alignment);
                if (a0 < b1 && b0 < a1) return PE_E_OVERLAP;
            }
        }
    }
    for (i = 0; i < 16; ++i) {
        if (o->dir_rva[i] || o->dir_size[i]) {
            if (i == 4) continue;                                   /* security directory holds a file offset, not an RVA */
            if (!in_range(o->dir_rva[i], o->dir_size[i], o->size_of_image)) return PE_E_DIR;
        }
    }
    if (o->dir_rva[14]) return PE_E_CLR;                            /* managed images need a CLR host, not this loader */
    if (o->entry_rva && o->entry_rva >= o->size_of_image) return PE_E_ENTRY;
    return PE_OK;
}

int pe_get_section(const uint8_t *f, const pe_info_t *o, unsigned index, pe_section_t *out)
{
    const uint8_t *p;
    unsigned k;
    if (index >= o->nsections) return PE_E_SECTIONS;
    p = f + o->section_table_offset + (uint64_t)index * 40;
    for (k = 0; k < 8; ++k) out->name[k] = (char)p[k];
    out->name[8] = 0;
    out->vsize = rd32(p + 8);
    out->rva = rd32(p + 12);
    out->raw_size = rd32(p + 16);
    out->raw_off = rd32(p + 20);
    out->characteristics = rd32(p + 36);
    return PE_OK;
}

int pe_rva_to_offset(const uint8_t *f, uint64_t size, const pe_info_t *o, uint32_t rva, uint64_t *off, uint64_t *avail)
{
    unsigned i;
    if (rva < o->size_of_headers) {
        *off = rva;
        *avail = o->size_of_headers - rva;
        return PE_OK;
    }
    for (i = 0; i < o->nsections; ++i) {
        pe_section_t s;
        uint32_t backed;
        pe_get_section(f, o, i, &s);
        backed = s.raw_size < (s.vsize ? s.vsize : s.raw_size) ? s.raw_size : (s.vsize ? s.vsize : s.raw_size);
        if (rva >= s.rva && rva - s.rva < backed) {
            *off = (uint64_t)s.raw_off + (rva - s.rva);
            if (*off >= size) return PE_E_RVA;
            *avail = backed - (rva - s.rva);
            if (*avail > size - *off) *avail = size - *off;
            return PE_OK;
        }
    }
    return PE_E_RVA;
}

int pe_read_string(const uint8_t *f, uint64_t size, const pe_info_t *o, uint32_t rva, char *out, unsigned cap)
{
    uint64_t off, avail, n;
    if (pe_rva_to_offset(f, size, o, rva, &off, &avail)) return PE_E_STRING;
    for (n = 0; n < avail && n + 1 < cap; ++n) {
        out[n] = (char)f[off + n];
        if (!out[n]) return PE_OK;
        if ((unsigned char)out[n] < 0x20 || (unsigned char)out[n] > 0x7e) return PE_E_STRING;
    }
    return PE_E_STRING;
}

int pe_find_export(const uint8_t *f, uint64_t size, const pe_info_t *o, const char *name, int ordinal, uint32_t *rva,
                   char *forward, unsigned forward_cap)
{
    uint64_t off, avail;
    uint32_t nfunc, nnames, base, fn_rva, names_rva, ords_rva, i;
    const uint32_t exp_rva = o->dir_rva[0], exp_size = o->dir_size[0];
    if (!exp_rva || exp_size < 40) return PE_E_NOT_FOUND;
    if (pe_rva_to_offset(f, size, o, exp_rva, &off, &avail) || avail < 40) return PE_E_EXPORT;
    base = rd32(f + off + 16);
    nfunc = rd32(f + off + 20);
    nnames = rd32(f + off + 24);
    fn_rva = rd32(f + off + 28);
    names_rva = rd32(f + off + 32);
    ords_rva = rd32(f + off + 36);
    if (nfunc > 65536 || nnames > 65536) return PE_E_EXPORT;
    if (ordinal >= 0) {
        i = (uint32_t)ordinal - base;
        if ((uint32_t)ordinal < base || i >= nfunc) return PE_E_NOT_FOUND;
    } else {
        for (i = 0; i < nnames; ++i) {
            uint64_t noff, navail, ooff, oavail;
            uint32_t name_rva;
            char cand[128];
            unsigned k;
            if (pe_rva_to_offset(f, size, o, names_rva + i * 4, &noff, &navail) || navail < 4) return PE_E_EXPORT;
            name_rva = rd32(f + noff);
            if (pe_read_string(f, size, o, name_rva, cand, sizeof cand)) return PE_E_EXPORT;
            for (k = 0; cand[k] && name[k] && cand[k] == name[k]; ++k) { }
            if (cand[k] || name[k]) continue;
            if (pe_rva_to_offset(f, size, o, ords_rva + i * 2, &ooff, &oavail) || oavail < 2) return PE_E_EXPORT;
            i = rd16(f + ooff);
            if (i >= nfunc) return PE_E_EXPORT;
            goto found;
        }
        return PE_E_NOT_FOUND;
    }
found:
    {
        uint64_t foff, favail;
        uint32_t target;
        if (pe_rva_to_offset(f, size, o, fn_rva + i * 4, &foff, &favail) || favail < 4) return PE_E_EXPORT;
        target = rd32(f + foff);
        if (!target) return PE_E_NOT_FOUND;
        if (target >= exp_rva && target - exp_rva < exp_size) {
            if (!forward || pe_read_string(f, size, o, target, forward, forward_cap)) return PE_E_FORWARD;
            *rva = 0;
            return PE_OK;
        }
        if (target >= o->size_of_image) return PE_E_EXPORT;
        *rva = target;
        if (forward) forward[0] = 0;
        return PE_OK;
    }
}

int pe_walk_imports(const uint8_t *f, uint64_t size, const pe_info_t *o, pe_import_fn fn, void *ctx)
{
    uint32_t desc_rva = o->dir_rva[1];
    unsigned guard = 0;
    if (!desc_rva) return PE_OK;
    for (;; desc_rva += 20) {
        uint64_t off, avail;
        uint32_t ilt, name_rva, iat, idx;
        char dll[128];
        if (++guard > 512) return PE_E_IMPORT;
        if (pe_rva_to_offset(f, size, o, desc_rva, &off, &avail) || avail < 20) return PE_E_IMPORT;
        ilt = rd32(f + off);
        name_rva = rd32(f + off + 12);
        iat = rd32(f + off + 16);
        if (!ilt && !name_rva && !iat) return PE_OK;
        if (!name_rva || !iat) return PE_E_IMPORT;
        if (pe_read_string(f, size, o, name_rva, dll, sizeof dll)) return PE_E_IMPORT;
        if (!ilt) ilt = iat;
        for (idx = 0;; ++idx) {
            uint64_t toff, tavail, thunk;
            int rc;
            if (idx > 16384) return PE_E_IMPORT;
            if (pe_rva_to_offset(f, size, o, ilt + idx * 8, &toff, &tavail) || tavail < 8) return PE_E_IMPORT;
            thunk = rd64(f + toff);
            if (!thunk) break;
            if (!in_range(iat + idx * 8, 8, o->size_of_image)) return PE_E_IMPORT;
            if (thunk >> 63) {
                rc = fn(ctx, dll, 0, (uint16_t)(thunk & 0xffff), 1, iat + idx * 8);
            } else {
                char sym[160];
                uint64_t hoff, havail;
                if ((thunk >> 31) || pe_rva_to_offset(f, size, o, (uint32_t)thunk, &hoff, &havail) || havail < 3) return PE_E_IMPORT;
                if (pe_read_string(f, size, o, (uint32_t)thunk + 2, sym, sizeof sym)) return PE_E_IMPORT;
                rc = fn(ctx, dll, sym, rd16(f + hoff), 0, iat + idx * 8);
            }
            if (rc) return rc;
        }
    }
}

static unsigned reloc_width(unsigned type)
{
    switch (type) {
    case 1: case 2: case 4: return 2;                               /* HIGH, LOW, HIGHADJ: one 16-bit half */
    case 3: return 4;                                               /* HIGHLOW */
    case 10: return 8;                                              /* DIR64 */
    default: return 0;                                              /* MIPS/ARM/RISC-V specific types: not on AMD64 */
    }
}

int pe_walk_relocs(const uint8_t *f, uint64_t size, const pe_info_t *o, pe_reloc_fn fn, void *ctx)
{
    uint32_t rva = o->dir_rva[5], remaining = o->dir_size[5];
    if (!rva || !remaining) return PE_OK;
    while (remaining >= 8) {
        uint64_t off, avail;
        uint32_t page, block, count, i;
        if (pe_rva_to_offset(f, size, o, rva, &off, &avail) || avail < 8) return PE_E_RELOC;
        page = rd32(f + off);
        block = rd32(f + off + 4);
        if (block < 8 || block > remaining || (block & 1) || page >= o->size_of_image || (page & 0xfff)) return PE_E_RELOC;
        if (avail < block) return PE_E_RELOC;
        count = (block - 8) / 2;
        for (i = 0; i < count; ++i) {
            const uint16_t e = rd16(f + off + 8 + i * 2);
            unsigned type = e >> 12;
            const uint32_t at = page + (e & 0xfff);
            const unsigned width = reloc_width(type);
            int rc;
            if (type == 0) continue;
            if (!width || !in_range(at, width, o->size_of_image)) return PE_E_RELOC;
            if (type == 4) {                                        /* HIGHADJ: the next entry is the low half */
                if (++i >= count) return PE_E_RELOC;
                type |= (unsigned)rd16(f + off + 8 + i * 2) << 16;
            }
            rc = fn(ctx, at, type);
            if (rc) return rc;
        }
        rva += block;
        remaining -= block;
    }
    return remaining ? PE_E_RELOC : PE_OK;
}

/* ---------------------------------------------------------------- relocation */
struct apply_ctx {
    pe_page_fn page;
    void *ctx;
    uint64_t delta, applied;
    uint32_t cur_rva, next_rva;
    uint8_t *cur, *next;
    int failed;
};

/* Byte `i` (0..4095+8) relative to the current page: the fixup may run into the following page. */
static uint8_t *fix_byte(struct apply_ctx *a, uint32_t rva)
{
    const uint32_t pg = rva & ~0xfffu;
    if (pg == a->cur_rva && a->cur) return a->cur + (rva & 0xfff);
    if (!a->next || a->next_rva != pg) {
        a->next = a->page(a->ctx, pg);
        a->next_rva = pg;
        if (!a->next) return 0;
    }
    return a->next + (rva & 0xfff);
}

static int apply_one(void *c, uint32_t rva, unsigned type)
{
    struct apply_ctx *a = c;
    const unsigned width = reloc_width(type & 15);
    uint8_t *p[8];
    uint64_t v = 0;
    unsigned k;
    if ((rva & ~0xfffu) != a->cur_rva) {                            /* new block page (blocks are per page) */
        a->cur_rva = rva & ~0xfffu;
        a->cur = a->page(a->ctx, a->cur_rva);
        if (!a->cur) { a->failed = 1; return PE_E_RELOC; }
    }
    for (k = 0; k < width; ++k) {
        p[k] = fix_byte(a, rva + k);
        if (!p[k]) { a->failed = 1; return PE_E_RELOC; }
        v |= (uint64_t)*p[k] << (8 * k);
    }
    switch (type & 15) {
    case 10: v += a->delta; break;
    case 3: v = (uint32_t)((uint32_t)v + (uint32_t)a->delta); break;
    case 1: v = (uint16_t)((uint16_t)v + (uint16_t)(a->delta >> 16)); break;
    case 2: v = (uint16_t)((uint16_t)v + (uint16_t)a->delta); break;
    case 4: {                                                       /* HIGHADJ: high half of a 32-bit value, rounded */
        int64_t t = (int64_t)(int16_t)(uint16_t)v * 65536 + (int16_t)(uint16_t)(type >> 16);
        t += (int32_t)(uint32_t)a->delta;
        t += 0x8000;
        v = (uint16_t)((uint64_t)t >> 16);
        break;
    }
    default: return PE_E_RELOC;
    }
    for (k = 0; k < width; ++k) *p[k] = (uint8_t)(v >> (8 * k));
    ++a->applied;
    return 0;
}

int pe_apply_relocs(const uint8_t *f, uint64_t size, const pe_info_t *o, uint64_t delta, pe_page_fn page, void *ctx,
                    uint64_t *applied)
{
    struct apply_ctx a;
    int rc;
    a.page = page; a.ctx = ctx; a.delta = delta; a.applied = 0;
    a.cur_rva = a.next_rva = 0xffffffffu; a.cur = a.next = 0; a.failed = 0;
    rc = pe_walk_relocs(f, size, o, apply_one, &a);
    if (applied) *applied = a.applied;
    return rc || a.failed ? PE_E_RELOC : PE_OK;
}

/* ---------------------------------------------------------------- delay-load imports */
int pe_walk_delay_imports(const uint8_t *f, uint64_t size, const pe_info_t *o, pe_delay_fn fn, void *ctx)
{
    uint32_t d = o->dir_rva[13];
    unsigned guard = 0;
    if (!d) return PE_OK;
    for (;; d += 32) {
        uint64_t off, avail;
        pe_delay_desc_t dd;
        uint32_t idx;
        if (++guard > 1024) return PE_E_DELAY;
        if (pe_rva_to_offset(f, size, o, d, &off, &avail) || avail < 32) return PE_E_DELAY;
        dd.attributes = rd32(f + off);
        dd.name_rva = rd32(f + off + 4);
        dd.module_handle_rva = rd32(f + off + 8);
        dd.iat_rva = rd32(f + off + 12);
        dd.int_rva = rd32(f + off + 16);
        dd.bound_iat_rva = rd32(f + off + 20);
        dd.unload_iat_rva = rd32(f + off + 24);
        dd.timestamp = rd32(f + off + 28);
        if (!dd.name_rva && !dd.iat_rva && !dd.int_rva) return PE_OK;       /* terminator */
        if (!(dd.attributes & 1)) {
            /* Legacy VA-based descriptor (Visual C++ 6): fields hold VAs. Converted when they fit the image. */
            uint32_t *fields[] = { &dd.name_rva, &dd.module_handle_rva, &dd.iat_rva, &dd.int_rva, &dd.bound_iat_rva, &dd.unload_iat_rva };
            unsigned k;
            for (k = 0; k < 6; ++k)
                if (*fields[k]) {
                    const uint64_t va = *fields[k];
                    if (va < o->image_base || va - o->image_base >= o->size_of_image) return PE_E_DELAY;
                    *fields[k] = (uint32_t)(va - o->image_base);
                }
        }
        if (!dd.name_rva || !dd.iat_rva || !dd.int_rva || !dd.module_handle_rva) return PE_E_DELAY;
        if (!in_range(dd.module_handle_rva, 8, o->size_of_image)) return PE_E_DELAY;
        if (pe_read_string(f, size, o, dd.name_rva, dd.dll, sizeof dd.dll)) return PE_E_DELAY;
        for (idx = 0;; ++idx) {
            uint64_t toff, tavail, thunk;
            int rc;
            if (idx > 65536) return PE_E_DELAY;
            if (pe_rva_to_offset(f, size, o, dd.int_rva + idx * 8, &toff, &tavail) || tavail < 8) return PE_E_DELAY;
            thunk = rd64(f + toff);
            if (!thunk) break;
            if (!in_range((uint64_t)dd.iat_rva + idx * 8, 8, o->size_of_image)) return PE_E_DELAY;
            if (thunk >> 63) {
                rc = fn(ctx, &dd, 0, (uint16_t)(thunk & 0xffff), 1, dd.iat_rva + idx * 8);
            } else {
                char sym[160];
                uint64_t hoff, havail;
                uint32_t hn = (uint32_t)thunk;
                if (!(dd.attributes & 1)) {
                    if (thunk < o->image_base || thunk - o->image_base >= o->size_of_image) return PE_E_DELAY;
                    hn = (uint32_t)(thunk - o->image_base);
                } else if (thunk >> 31) {
                    return PE_E_DELAY;
                }
                if (pe_rva_to_offset(f, size, o, hn, &hoff, &havail) || havail < 3) return PE_E_DELAY;
                if (pe_read_string(f, size, o, hn + 2, sym, sizeof sym)) return PE_E_DELAY;
                rc = fn(ctx, &dd, sym, rd16(f + hoff), 0, dd.iat_rva + idx * 8);
            }
            if (rc) return rc;
        }
    }
}

/* ---------------------------------------------------------------- load configuration */
int pe_load_config(const uint8_t *f, uint64_t size, const pe_info_t *o, pe_load_config_t *c)
{
    uint64_t off, avail;
    uint32_t n;
    *c = (pe_load_config_t){0};
    if (!o->dir_rva[10]) return PE_OK;
    if (pe_rva_to_offset(f, size, o, o->dir_rva[10], &off, &avail) || avail < 4) return PE_E_LOADCFG;
    n = rd32(f + off);
    if (n < 4 || n > avail || n > 0x10000) return PE_E_LOADCFG;
#define LC64(at) ((at) + 8 <= n ? rd64(f + off + (at)) : 0)
#define LC32(at) ((at) + 4 <= n ? rd32(f + off + (at)) : 0)
#define LC16(at) ((at) + 2 <= n ? rd16(f + off + (at)) : 0)
    c->size = n;
    c->dependent_load_flags = (uint16_t)LC16(0x4e);
    c->security_cookie = LC64(0x58);
    c->se_handler_table = LC64(0x60);
    c->se_handler_count = LC64(0x68);
    c->guard_cf_check_fptr = LC64(0x70);
    c->guard_cf_dispatch_fptr = LC64(0x78);
    c->guard_cf_function_table = LC64(0x80);
    c->guard_cf_function_count = LC64(0x88);
    c->guard_flags = LC32(0x90);
    c->guard_iat_table = LC64(0xa0);
    c->guard_iat_count = LC64(0xa8);
    c->guard_longjump_table = LC64(0xb0);
    c->guard_longjump_count = LC64(0xb8);
    c->dynamic_value_reloc_table = LC64(0xc0);
    c->guard_rf_failure_fptr = LC64(0xd8);
    c->dynamic_value_reloc_offset = LC32(0xe0);
    c->dynamic_value_reloc_section = (uint16_t)LC16(0xe4);
    c->guard_rf_verify_sp_fptr = LC64(0xe8);
    c->guard_ehcont_table = LC64(0x108);
    c->guard_ehcont_count = LC64(0x110);
    c->guard_xfg_check_fptr = LC64(0x118);
    c->guard_xfg_dispatch_fptr = LC64(0x120);
    c->guard_xfg_table_dispatch_fptr = LC64(0x128);
    c->guard_memcpy_fptr = LC64(0x138);
#undef LC64
#undef LC32
#undef LC16
    {
        /* every pointer the loader may write through must be an 8-byte slot inside the image */
        const uint64_t lo = o->image_base, hi = o->image_base + o->size_of_image;
        const uint64_t slots[] = { c->security_cookie, c->guard_cf_check_fptr, c->guard_cf_dispatch_fptr,
                                   c->guard_xfg_check_fptr, c->guard_xfg_dispatch_fptr, c->guard_xfg_table_dispatch_fptr,
                                   c->guard_rf_failure_fptr, c->guard_rf_verify_sp_fptr, c->guard_memcpy_fptr };
        unsigned k;
        for (k = 0; k < sizeof slots / sizeof slots[0]; ++k)
            if (slots[k] && (slots[k] < lo || slots[k] > hi - 8 || (slots[k] & 7))) return PE_E_LOADCFG;
        /* tables (read by the CFG/EH-continuation checks): entries of 4 bytes + the stride byte count in GuardFlags */
        {
            const uint64_t stride = 4 + ((c->guard_flags & PE_GUARD_CF_FUNCTION_TABLE_SIZE_MASK) >> PE_GUARD_CF_FUNCTION_TABLE_SIZE_SHIFT);
            const uint64_t tabs[][2] = { { c->guard_cf_function_table, c->guard_cf_function_count },
                                         { c->guard_iat_table, c->guard_iat_count },
                                         { c->guard_longjump_table, c->guard_longjump_count },
                                         { c->guard_ehcont_table, c->guard_ehcont_count } };
            for (k = 0; k < 4; ++k) {
                if (!tabs[k][0] && !tabs[k][1]) continue;
                if (!tabs[k][0] || tabs[k][0] < lo || tabs[k][0] >= hi || tabs[k][1] > (1ull << 32) ||
                    tabs[k][1] * stride > hi - tabs[k][0])
                    return PE_E_LOADCFG;
            }
        }
    }
    return PE_OK;
}
