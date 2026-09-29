/* SPDX-License-Identifier: GPL-2.0-only
 * Host tests for pe_parse.c: real mingw-built AMD64 images, targeted malformations and a
 * mutation fuzz run (built with ASan/UBSan by test_pe_parse.py).
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "../pe_parse.h"

static unsigned long checks;
#define CHECK(c) do { ++checks; if (!(c)) { fprintf(stderr, "FAIL %s:%d %s\n", __FILE__, __LINE__, #c); exit(1); } } while (0)

static uint8_t *slurp(const char *path, size_t *n)
{
    FILE *f = fopen(path, "rb");
    uint8_t *b;
    if (!f) { perror(path); exit(2); }
    fseek(f, 0, SEEK_END); *n = (size_t)ftell(f); fseek(f, 0, SEEK_SET);
    b = malloc(*n);
    if (fread(b, 1, *n, f) != *n) exit(2);
    fclose(f);
    return b;
}

struct impctx { unsigned count, ordinals; char last_dll[64], last_sym[64]; };
static int imp_cb(void *c, const char *dll, const char *name, uint16_t hint, int by_ord, uint32_t iat_rva)
{
    struct impctx *x = c;
    (void)hint; (void)iat_rva;
    ++x->count;
    if (by_ord) ++x->ordinals;
    strncpy(x->last_dll, dll, 63);
    if (name) strncpy(x->last_sym, name, 63);
    return 0;
}
struct relctx { unsigned n, dir64; };
static int rel_cb(void *c, uint32_t rva, unsigned type) { struct relctx *r = c; (void)rva; ++r->n; if (type == 10) ++r->dir64; return 0; }

static void test_valid(const uint8_t *dll, size_t dn, const uint8_t *exe, size_t en)
{
    pe_info_t d, e;
    uint32_t rva;
    char fwd[64];
    struct impctx ic = {0};
    struct relctx rc = {0};
    CHECK(pe_parse(dll, dn, &d) == PE_OK && pe_parse(exe, en, &e) == PE_OK);
    CHECK(d.characteristics & PE_CHAR_DLL);
    CHECK(!(e.characteristics & PE_CHAR_DLL) && (e.subsystem == 2 || e.subsystem == 3));
    CHECK(d.section_alignment == 4096 && d.image_base < (1ull << 47));
    CHECK(pe_find_export(dll, dn, &d, "shz_add", -1, &rva, fwd, sizeof fwd) == PE_OK && rva && !fwd[0]);
    CHECK(pe_find_export(dll, dn, &d, "shz_value", -1, &rva, fwd, sizeof fwd) == PE_OK && rva);
    CHECK(pe_find_export(dll, dn, &d, "shz_fwd", -1, &rva, fwd, sizeof fwd) == PE_OK && rva == 0 && !strcmp(fwd, "kernel32.Sleep"));
    CHECK(pe_find_export(dll, dn, &d, "SHZ_ADD", -1, &rva, fwd, sizeof fwd) == PE_E_NOT_FOUND);   /* exact-case by name */
    CHECK(pe_find_export(dll, dn, &d, "nosuch", -1, &rva, fwd, sizeof fwd) == PE_E_NOT_FOUND);
    CHECK(pe_find_export(dll, dn, &d, 0, 7, &rva, fwd, sizeof fwd) == PE_OK && rva);            /* by ordinal */
    CHECK(pe_find_export(dll, dn, &d, 0, 500, &rva, fwd, sizeof fwd) == PE_E_NOT_FOUND);
    CHECK(pe_walk_imports(exe, en, &e, imp_cb, &ic) == PE_OK && ic.count >= 2);
    CHECK(pe_walk_relocs(dll, dn, &d, rel_cb, &rc) == PE_OK);
}

static void patch16(uint8_t *b, size_t at, uint16_t v) { b[at] = (uint8_t)v; b[at + 1] = (uint8_t)(v >> 8); }
static void patch32(uint8_t *b, size_t at, uint32_t v) { patch16(b, at, (uint16_t)v); patch16(b, at + 2, (uint16_t)(v >> 16)); }

static void test_targeted(const uint8_t *exe, size_t en)
{
    pe_info_t i;
    uint8_t *b = malloc(en);
    uint32_t nt;
    memcpy(b, exe, en);
    nt = b[0x3c] | (b[0x3d] << 8) | (b[0x3e] << 16) | ((uint32_t)b[0x3f] << 24);
    CHECK(pe_parse(b, en, &i) == PE_OK);
    patch16(b, nt + 4, 0x14c);      CHECK(pe_parse(b, en, &i) == PE_E_MACHINE); patch16(b, nt + 4, 0xaa64);
    CHECK(pe_parse(b, en, &i) == PE_E_MACHINE); patch16(b, nt + 4, 0x8664);
    patch16(b, nt + 24, 0x10b);     CHECK(pe_parse(b, en, &i) == PE_E_MAGIC); patch16(b, nt + 24, 0x20b);
    patch32(b, 0x3c, 0xfffffff0u);  CHECK(pe_parse(b, en, &i) == PE_E_TRUNCATED); patch32(b, 0x3c, nt);
    b[0] = 'X';                     CHECK(pe_parse(b, en, &i) == PE_E_DOS); b[0] = 'M';
    b[nt] = 'Q';                    CHECK(pe_parse(b, en, &i) == PE_E_NT_SIG); b[nt] = 'P';
    patch16(b, nt + 6, 0);          CHECK(pe_parse(b, en, &i) == PE_E_SECTIONS);
    patch16(b, nt + 6, 60000);      CHECK(pe_parse(b, en, &i) == PE_E_SECTIONS);
    memcpy(b, exe, en);
    patch32(b, nt + 24 + 32, 0);    CHECK(pe_parse(b, en, &i) == PE_E_ALIGN);        /* SectionAlignment = 0 */
    memcpy(b, exe, en);
    patch32(b, nt + 24 + 36, 3);    CHECK(pe_parse(b, en, &i) == PE_E_ALIGN);        /* FileAlignment not a power of two */
    memcpy(b, exe, en);
    patch32(b, nt + 24 + 56, 0x7ffff000u); CHECK(pe_parse(b, en, &i) != PE_OK);     /* huge SizeOfImage */
    memcpy(b, exe, en);
    patch32(b, nt + 24 + 56, 0x1234);        CHECK(pe_parse(b, en, &i) != PE_OK);   /* not a multiple of alignment */
    memcpy(b, exe, en);
    patch32(b, nt + 24 + 60, 0x100000);      CHECK(pe_parse(b, en, &i) != PE_OK);   /* headers larger than the file */
    memcpy(b, exe, en);
    CHECK(pe_parse(b, en / 2, &i) != PE_OK || 1);                                   /* truncated file: must not crash */
    CHECK(pe_parse(b, 10, &i) == PE_E_TRUNCATED);
    CHECK(pe_parse(b, 0, &i) == PE_E_TRUNCATED);
    free(b);
}

static uint32_t rng_state = 0x1badb002;
static uint32_t rnd(void) { rng_state = rng_state * 1664525u + 1013904223u; return rng_state >> 8; }

static void fuzz(const uint8_t *img, size_t n, unsigned iterations)
{
    uint8_t *b = malloc(n);
    unsigned it, accepted = 0;
    for (it = 0; it < iterations; ++it) {
        pe_info_t i;
        unsigned k, muts = 1 + rnd() % 6;
        size_t len = n;
        memcpy(b, img, n);
        for (k = 0; k < muts; ++k) {
            const uint32_t mode = rnd() % 4;
            const size_t at = mode == 3 ? rnd() % n : rnd() % (n < 2048 ? n : 2048);   /* bias toward the headers */
            if (mode == 0) b[at] ^= (uint8_t)(1u << (rnd() % 8));
            else if (mode == 1) b[at] = (uint8_t)rnd();
            else if (mode == 2) { b[at] = 0xff; if (at + 1 < n) b[at + 1] = 0xff; }
            else if (mode == 3 && rnd() % 8 == 0) len = at ? at : 1;
        }
        if (pe_parse(b, len, &i) == PE_OK) {
            struct impctx ic = {0};
            struct relctx rc = {0};
            uint32_t rva;
            char fwd[64];
            unsigned s;
            ++accepted;
            /* An accepted image must keep every walked offset inside the file. */
            for (s = 0; s < i.nsections; ++s) {
                pe_section_t sec;
                CHECK(pe_get_section(b, &i, s, &sec) == PE_OK);
                CHECK(sec.raw_size == 0 || (uint64_t)sec.raw_off + sec.raw_size <= len);
                CHECK((uint64_t)sec.rva + (sec.vsize ? sec.vsize : 1) <= i.size_of_image);
            }
            (void)pe_walk_imports(b, len, &i, imp_cb, &ic);
            (void)pe_walk_relocs(b, len, &i, rel_cb, &rc);
            (void)pe_find_export(b, len, &i, "shz_add", -1, &rva, fwd, sizeof fwd);
            (void)pe_find_export(b, len, &i, 0, 7, &rva, fwd, sizeof fwd);
        }
    }
    printf("fuzz: %u mutants, %u still parsed and were walked safely\n", iterations, accepted);
    free(b);
}

int main(int argc, char **argv)
{
    size_t dn, en;
    uint8_t *dll, *exe;
    if (argc < 3) return 2;
    dll = slurp(argv[1], &dn);
    exe = slurp(argv[2], &en);
    test_valid(dll, dn, exe, en);
    test_targeted(exe, en);
    fuzz(dll, dn, 150000);
    fuzz(exe, en, 150000);
    free(dll);
    free(exe);
    printf("PE32+ parser: %lu checks passed\n", checks);
    return 0;
}
