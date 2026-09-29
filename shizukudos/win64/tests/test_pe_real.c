/* SPDX-License-Identifier: GPL-2.0-only
 * Host driver for pe_parse.c on real images (driven by test_pe_real.py, which compares every answer with pefile):
 *
 *   test_pe_real info <image>                 parse result, load configuration, delay imports, relocation census
 *   test_pe_real map <image> <new base> <out> map the image the way Kernel64 does (headers + sections, zero fill),
 *                                             apply its base relocations for <new base> with pe_apply_relocs and
 *                                             write the mapped image; prints the relocation count and time
 */
#define _POSIX_C_SOURCE 199309L
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include "../pe_parse.h"

static uint8_t *slurp(const char *path, size_t *n)
{
    FILE *f = fopen(path, "rb");
    uint8_t *b;
    if (!f) { perror(path); exit(2); }
    fseek(f, 0, SEEK_END); *n = (size_t)ftell(f); fseek(f, 0, SEEK_SET);
    b = malloc(*n ? *n : 1);
    if (!b || fread(b, 1, *n, f) != *n) exit(2);
    fclose(f);
    return b;
}

struct dctx { unsigned descs, thunks, ordinals; char last[128]; };
static int delay_cb(void *c, const pe_delay_desc_t *d, const char *name, uint16_t ord, int by_ord, uint32_t slot)
{
    struct dctx *x = c;
    (void)name; (void)ord; (void)slot;
    if (strcmp(x->last, d->dll)) { ++x->descs; strncpy(x->last, d->dll, sizeof x->last - 1); printf("delay-dll %s %u\n", d->dll, d->attributes & 1); }
    ++x->thunks;
    if (by_ord) ++x->ordinals;
    return 0;
}

struct rctx { unsigned long n[16]; };
static int reloc_cb(void *c, uint32_t rva, unsigned type) { (void)rva; ((struct rctx *)c)->n[type & 15]++; return 0; }

static int info(const char *path)
{
    size_t n;
    uint8_t *f = slurp(path, &n);
    pe_info_t pi;
    pe_load_config_t lc;
    struct dctx dc = {0, 0, 0, ""};
    struct rctx rc;
    int r = pe_parse(f, n, &pi);
    printf("parse %d\n", r);
    if (r) { free(f); return 0; }
    printf("image_base %#llx size_of_image %#x low_alignment %d\n", (unsigned long long)pi.image_base, pi.size_of_image, pi.low_alignment);
    r = pe_load_config(f, n, &pi, &lc);
    printf("loadcfg %d size %u dependent_load_flags %#x cookie %#llx guard_flags %#x check %#llx dispatch %#llx cf_table %#llx cf_count %llu "
           "se_table %#llx dvrt %#llx xfg_check %#llx ehcont %llu\n",
           r, lc.size, lc.dependent_load_flags, (unsigned long long)lc.security_cookie, lc.guard_flags,
           (unsigned long long)lc.guard_cf_check_fptr, (unsigned long long)lc.guard_cf_dispatch_fptr,
           (unsigned long long)lc.guard_cf_function_table, (unsigned long long)lc.guard_cf_function_count,
           (unsigned long long)lc.se_handler_table, (unsigned long long)lc.dynamic_value_reloc_table,
           (unsigned long long)lc.guard_xfg_check_fptr, (unsigned long long)lc.guard_ehcont_count);
    r = pe_walk_delay_imports(f, n, &pi, delay_cb, &dc);
    printf("delay %d descs %u thunks %u ordinals %u\n", r, dc.descs, dc.thunks, dc.ordinals);
    memset(&rc, 0, sizeof rc);
    r = pe_walk_relocs(f, n, &pi, reloc_cb, &rc);
    printf("relocs %d dir64 %lu highlow %lu other %lu\n", r, rc.n[10], rc.n[3], rc.n[1] + rc.n[2] + rc.n[4]);
    free(f);
    return 0;
}

struct mapctx { uint8_t *img; uint32_t size; };
static uint8_t *page_of(void *c, uint32_t rva)
{
    struct mapctx *m = c;
    return rva < m->size ? m->img + rva : 0;
}

static int map(const char *path, const char *base_text, const char *out)
{
    size_t n;
    uint8_t *f = slurp(path, &n), *img;
    pe_info_t pi;
    unsigned i;
    uint64_t new_base = strtoull(base_text, 0, 0), applied = 0;
    struct timespec t0, t1;
    struct mapctx mc;
    FILE *o;
    int r = pe_parse(f, n, &pi);
    if (r) { printf("parse %d\n", r); return 1; }
    img = calloc(1, pi.size_of_image);
    if (!img) return 2;
    memcpy(img, f, pi.size_of_headers);
    for (i = 0; i < pi.nsections; ++i) {
        pe_section_t s;
        uint32_t len;
        pe_get_section(f, &pi, i, &s);
        len = s.raw_size < (s.vsize ? s.vsize : s.raw_size) ? s.raw_size : (s.vsize ? s.vsize : s.raw_size);
        memcpy(img + s.rva, f + s.raw_off, len);
    }
    mc.img = img;
    mc.size = pi.size_of_image;
    clock_gettime(CLOCK_MONOTONIC, &t0);
    r = pe_apply_relocs(f, n, &pi, new_base - pi.image_base, page_of, &mc, &applied);
    clock_gettime(CLOCK_MONOTONIC, &t1);
    printf("relocate %d applied %llu ms %.3f\n", r, (unsigned long long)applied,
           (double)(t1.tv_sec - t0.tv_sec) * 1e3 + (double)(t1.tv_nsec - t0.tv_nsec) / 1e6);
    o = fopen(out, "wb");
    if (!o || fwrite(img, 1, pi.size_of_image, o) != pi.size_of_image) return 2;
    fclose(o);
    free(img);
    free(f);
    return r ? 1 : 0;
}

int main(int argc, char **argv)
{
    if (argc == 3 && !strcmp(argv[1], "info")) return info(argv[2]);
    if (argc == 5 && !strcmp(argv[1], "map")) return map(argv[2], argv[3], argv[4]);
    fprintf(stderr, "usage: test_pe_real info <image> | map <image> <new base> <out>\n");
    return 2;
}
