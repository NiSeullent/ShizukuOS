/* SPDX-License-Identifier: GPL-2.0-only
 * Link the exact production pe_parse.c. Exercise export names through the
 * real PE tables, including the unchanged publisher MSVCP140 image supplied
 * as argv[1]. No generated compatibility DLL or replacement export table.
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "../pe_parse.h"

static unsigned long checks;
#define CHECK(c) do { ++checks; if (!(c)) { fprintf(stderr, "FAIL %s:%d %s\n", __FILE__, __LINE__, #c); exit(1); } } while (0)

static void wr16(uint8_t *p, uint16_t v) { p[0] = (uint8_t)v; p[1] = (uint8_t)(v >> 8); }
static void wr32(uint8_t *p, uint32_t v) { wr16(p, (uint16_t)v); wr16(p + 2, (uint16_t)(v >> 16)); }
static uint16_t rd16(const uint8_t *p) { return (uint16_t)(p[0] | (p[1] << 8)); }
static uint32_t rd32(const uint8_t *p) { return p[0] | ((uint32_t)p[1] << 8) | ((uint32_t)p[2] << 16) | ((uint32_t)p[3] << 24); }

static void make_image(uint8_t *b, pe_info_t *info, char *a, char *z)
{
    const unsigned nt = 0x80, opt = nt + 24, sec = opt + 240;
    memset(b, 0, 0x4000);
    b[0] = 'M'; b[1] = 'Z'; wr32(b + 0x3c, nt);
    b[nt] = 'P'; b[nt + 1] = 'E'; wr16(b + nt + 4, 0x8664);
    wr16(b + nt + 6, 1); wr16(b + nt + 20, 240); wr16(b + nt + 22, 0x2002);
    wr16(b + opt, 0x20b); wr32(b + opt + 28, 1);
    wr32(b + opt + 32, 4096); wr32(b + opt + 36, 4096);
    wr32(b + opt + 56, 0x4000); wr32(b + opt + 60, 0x1000);
    wr16(b + opt + 68, 3); wr32(b + opt + 108, 16);
    wr32(b + opt + 112, 0x1000); wr32(b + opt + 116, 0x100);
    memcpy(b + sec, ".edata", 6); wr32(b + sec + 8, 0x3000);
    wr32(b + sec + 12, 0x1000); wr32(b + sec + 16, 0x3000); wr32(b + sec + 20, 0x1000);
    wr32(b + sec + 36, 0x40000040);
    wr32(b + 0x1010, 1); wr32(b + 0x1014, 3); wr32(b + 0x1018, 3);
    wr32(b + 0x101c, 0x1100); wr32(b + 0x1020, 0x1200); wr32(b + 0x1024, 0x1300);
    wr32(b + 0x1100, 0x3000); wr32(b + 0x1104, 0x3010); wr32(b + 0x1108, 0x3020);
    wr32(b + 0x1200, 0x1f80); wr32(b + 0x1204, 0x2100); wr32(b + 0x1208, 0x2300);
    wr16(b + 0x1300, 0); wr16(b + 0x1302, 1); wr16(b + 0x1304, 2);
    memset(a, 'A', 159); a[159] = 0; memset(z, 'Z', 183); z[183] = 0;
    memcpy(b + 0x1f80, a, 160); memcpy(b + 0x2100, z, 184);
    memcpy(b + 0x2300, "name_after_long", sizeof "name_after_long");
    CHECK(pe_parse(b, 0x4000, info) == PE_OK);
}

static void synthetic(void)
{
    uint8_t b[0x4000]; pe_info_t i; char a[160], z[184], fwd[128]; uint32_t rva;
    make_image(b, &i, a, z);
    CHECK(pe_find_export(b, sizeof b, &i, a, -1, &rva, fwd, sizeof fwd) == PE_OK && rva == 0x3000);
    CHECK(pe_find_export(b, sizeof b, &i, z, -1, &rva, fwd, sizeof fwd) == PE_OK && rva == 0x3010);
    CHECK(pe_find_export(b, sizeof b, &i, "name_after_long", -1, &rva, fwd, sizeof fwd) == PE_OK && rva == 0x3020);
    CHECK(pe_find_export(b, sizeof b, &i, "A", -1, &rva, fwd, sizeof fwd) == PE_E_NOT_FOUND);
    CHECK(pe_find_export(b, sizeof b, &i, "a", -1, &rva, fwd, sizeof fwd) == PE_E_NOT_FOUND);
    {
        char longer[161]; memset(longer, 'A', 160); longer[160] = 0;
        CHECK(pe_find_export(b, sizeof b, &i, longer, -1, &rva, fwd, sizeof fwd) == PE_E_NOT_FOUND);
    }
    CHECK(pe_find_export(b, sizeof b, &i, 0, 3, &rva, fwd, sizeof fwd) == PE_OK && rva == 0x3020);
    /* File-backed extent, not a fixed cap: NUL at its last byte is valid. */
    wr32(b + 0x1018, 1); wr32(b + 0x1200, 0x4000 - 160);
    memcpy(b + 0x4000 - 160, a, 160);
    CHECK(pe_find_export(b, sizeof b, &i, a, -1, &rva, fwd, sizeof fwd) == PE_OK && rva == 0x3000);
    b[0x3fff] = 'A';
    CHECK(pe_find_export(b, sizeof b, &i, a, -1, &rva, fwd, sizeof fwd) == PE_E_EXPORT);
    CHECK(pe_find_export(b, sizeof b, &i, "unrelated", -1, &rva, fwd, sizeof fwd) == PE_E_EXPORT);
    b[0x3fff] = 0; b[0x3ffe] = 0x80;
    CHECK(pe_find_export(b, sizeof b, &i, "unrelated", -1, &rva, fwd, sizeof fwd) == PE_E_EXPORT);
    b[0x3ffe] = 0x1f;
    CHECK(pe_find_export(b, sizeof b, &i, "unrelated", -1, &rva, fwd, sizeof fwd) == PE_E_EXPORT);
    wr32(b + 0x1200, 0x4000);
    CHECK(pe_find_export(b, sizeof b, &i, a, -1, &rva, fwd, sizeof fwd) == PE_E_EXPORT);
    wr32(b + 0x1200, 0xffffffffu);
    CHECK(pe_find_export(b, sizeof b, &i, a, -1, &rva, fwd, sizeof fwd) == PE_E_EXPORT);
    /* Ordinal lookup deliberately does not scan malformed unused names. */
    CHECK(pe_find_export(b, sizeof b, &i, 0, 1, &rva, fwd, sizeof fwd) == PE_OK && rva == 0x3000);
    make_image(b, &i, a, z);
    wr32(b + 0x1108, 0x10a0); memcpy(b + 0x10a0, "kernel32.Sleep", sizeof "kernel32.Sleep");
    CHECK(pe_find_export(b, sizeof b, &i, "name_after_long", -1, &rva, fwd, sizeof fwd) == PE_OK && !rva && !strcmp(fwd, "kernel32.Sleep"));
    CHECK(pe_find_export(b, sizeof b, &i, "name_after_long", -1, &rva, fwd, 8) == PE_E_FORWARD);
    memset(b + 0x10a0, 'F', 140); b[0x112c] = 0;
    /* The forwarder overlaps the function table, so reset that entry. */
    wr32(b + 0x1108, 0x10a0);
    CHECK(pe_find_export(b, sizeof b, &i, "name_after_long", -1, &rva, fwd, sizeof fwd) == PE_E_FORWARD);
}

static void publisher(const char *path)
{
    FILE *f = fopen(path, "rb"); long len; uint8_t *b; pe_info_t info;
    uint64_t off, avail, noff, navail, ooff, oavail; uint32_t count, names, ords, base, n, flush = 0, longest = 0, long_count = 0;
    const char *wanted = "?flush@?$basic_ostream@DU?$char_traits@D@std@@@std@@QEAAAEAV12@XZ";
    CHECK(f != 0); CHECK(!fseek(f, 0, SEEK_END)); len = ftell(f); CHECK(len > 0);
    CHECK(!fseek(f, 0, SEEK_SET)); b = malloc((size_t)len); CHECK(b != 0);
    CHECK(fread(b, 1, (size_t)len, f) == (size_t)len); CHECK(!fclose(f));
    CHECK(pe_parse(b, (uint64_t)len, &info) == PE_OK);
    CHECK(pe_rva_to_offset(b, (uint64_t)len, &info, info.dir_rva[0], &off, &avail) == PE_OK && avail >= 40);
    count = rd32(b + off + 24); names = rd32(b + off + 32); ords = rd32(b + off + 36); base = rd32(b + off + 16);
    for (n = 0; n < count; ++n) {
        char name[2048], fwd[128]; uint32_t named_rva, ordinal_rva, nrva, ordinal; size_t length;
        CHECK(pe_rva_to_offset(b, (uint64_t)len, &info, names + n * 4, &noff, &navail) == PE_OK && navail >= 4);
        nrva = rd32(b + noff);
        CHECK(pe_read_string(b, (uint64_t)len, &info, nrva, name, sizeof name) == PE_OK);
        length = strlen(name); if (length > longest) longest = (uint32_t)length;
        if (length < 128 && strcmp(name, wanted)) continue;
        CHECK(pe_rva_to_offset(b, (uint64_t)len, &info, ords + n * 2, &ooff, &oavail) == PE_OK && oavail >= 2);
        ordinal = base + rd16(b + ooff);
        CHECK(pe_find_export(b, (uint64_t)len, &info, name, -1, &named_rva, fwd, sizeof fwd) == PE_OK && !fwd[0]);
        CHECK(pe_find_export(b, (uint64_t)len, &info, 0, (int)ordinal, &ordinal_rva, fwd, sizeof fwd) == PE_OK && named_rva == ordinal_rva);
        if (length >= 128) ++long_count;
        if (!strcmp(name, wanted)) { CHECK(ordinal == 873 && named_rva == 0xb540); ++flush; }
    }
    CHECK(count == 1515 && longest == 183 && long_count > 0 && flush == 1);
    printf("publisher: %u exports, %u names >=128 bytes, maximum %u; actual flush name/ordinal agree\n", count, long_count, longest);
    free(b);
}

int main(int argc, char **argv)
{
    if (argc != 2) { fprintf(stderr, "usage: %s unchanged-publisher-msvcp140.dll\n", argv[0]); return 2; }
    synthetic(); publisher(argv[1]);
    printf("PE export name contract: %lu checks passed\n", checks);
    return 0;
}
