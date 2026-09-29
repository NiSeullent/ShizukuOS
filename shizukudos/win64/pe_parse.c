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
        o->section_alignment < o->file_alignment || o->section_alignment < 4096)
        return PE_E_ALIGN;                                          /* page-aligned sections only: no legacy <4K images */
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
            const unsigned type = e >> 12;
            const uint32_t at = page + (e & 0xfff);
            int rc;
            if (type == 0) continue;
            if (type != 3 && type != 10) return PE_E_RELOC;          /* HIGHLOW and DIR64 only on AMD64 */
            if (!in_range(at, type == 10 ? 8 : 4, o->size_of_image)) return PE_E_RELOC;
            rc = fn(ctx, at, type);
            if (rc) return rc;
        }
        rva += block;
        remaining -= block;
    }
    return remaining ? PE_E_RELOC : PE_OK;
}
