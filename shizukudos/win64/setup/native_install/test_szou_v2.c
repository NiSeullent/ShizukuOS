/* SPDX-License-Identifier: GPL-2.0-only
 * Host test: SZOU v2 + SZLN parse (positive/negative), VFAT LFN staging into a
 * real mkfs.fat FAT32 image, commit interrupted after K device writes, cold
 * roll-forward from the marker, long-name readback. Usage: test_szou_v2 IMG K */
#include "szou_fat32.h"
#include "../../../accounts/sha256.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <fcntl.h>
#include <unistd.h>
static int fails, fd, wlimit = -1;
#define CHECK(x) do { if (!(x)) { fails++; printf("FAIL %s:%d %s\n", __FILE__, __LINE__, #x); } } while (0)
static int b_rd(void *c, uint64_t l, uint32_t n, void *b) { (void)c; return pread(fd, b, n * 512ull, (off_t)(l * 512)) == (ssize_t)(n * 512ull) ? 0 : -1; }
static int b_wr(void *c, uint64_t l, uint32_t n, const void *b) { (void)c; if (wlimit == 0) return -1; if (wlimit > 0) wlimit--; return pwrite(fd, b, n * 512ull, (off_t)(l * 512)) == (ssize_t)(n * 512ull) ? 0 : -1; }
static int b_fl(void *c) { (void)c; return wlimit == 0 ? -1 : fsync(fd); }
static void *m_alloc(void *c, size_t n) { (void)c; return calloc(1, n); }
static void m_free(void *c, void *p) { (void)c; free(p); }
static int mount(szou_fat32_t *fs)
{
    szou_blkdev_t d = { 0, 512, (uint64_t)lseek(fd, 0, SEEK_END) / 512, 64, b_rd, b_wr, b_fl };
    return szou_fat32_mount(fs, &d, m_alloc, m_free, 0, 0, 0);
}
typedef struct { const char *path; uint32_t size, attr; } ent_t;
static const ent_t E[] = { { "PROGRA~1\\ACCESS~1\\WORDPAD.EXE", 70001, 0x20 }, { "WINDOWS\\SYSTEM\\EMPTY.TXT", 0, 0x21 },
                           { "WINDOWS\\WIN.INI", 777, 0x20 } };
typedef struct { const char *path; uint8_t kind, attr; const char *u8; } rec_t;
static const rec_t R[] = { { "PROGRA~1", 2, 0, "Program Files" }, { "PROGRA~1\\ACCESS~1", 2, 0x01, "Accessories" },
                           { "PROGRA~1\\ACCESS~1\\WORDPAD.EXE", 1, 0, "WordPad \xed\x95\x9c\xea\xb5\xad\xec\x96\xb4 \xf0\x9f\x98\x80 long name.exe" },
                           { "WINDOWS", 2, 0, "" }, { "WINDOWS\\FONTS", 2, 0x04, "Fonts" }, { "WINDOWS\\SYSTEM", 2, 0, "" } };
#define NE 3u
#define NR 6u
static uint32_t utf16(const char *s, uint16_t *u)
{
    const uint8_t *p = (const uint8_t *)s; uint32_t n = 0, cp;
    while (*p) {
        if (*p < 0x80) cp = *p++;
        else if (*p < 0xE0) { cp = ((p[0] & 31u) << 6) | (p[1] & 63u); p += 2; }
        else if (*p < 0xF0) { cp = ((p[0] & 15u) << 12) | ((p[1] & 63u) << 6) | (p[2] & 63u); p += 3; }
        else { cp = ((p[0] & 7u) << 18) | ((p[1] & 63u) << 12) | ((p[2] & 63u) << 6) | (p[3] & 63u); p += 4; }
        if (cp >= 0x10000) { cp -= 0x10000; u[n++] = (uint16_t)(0xD800 | (cp >> 10)); u[n++] = (uint16_t)(0xDC00 | (cp & 1023)); }
        else u[n++] = (uint16_t)cp;
    }
    return n;
}
static void w32(uint8_t *p, uint64_t v, int n) { int i; for (i = 0; i < n; i++) p[i] = (uint8_t)(v >> (8 * i)); }
static uint8_t *img; static size_t img_len, pay, ext;
static void sha(const uint8_t *p, size_t n, uint8_t *o) { sha256_ctx c; sha256_init(&c); sha256_update(&c, p, n); sha256_final(&c, o); }
static void build(void)
{
    uint64_t total = 0, off = 0; uint32_t i, k;
    for (i = 0; i < NE; i++) total += E[i].size;
    pay = 64 + 320 * NE; ext = pay + total;
    img_len = ext + 48 + 784 * NR; img = calloc(1, img_len);
    memcpy(img, "SZOU", 4); w32(img + 4, 2, 2); w32(img + 6, 64, 2); w32(img + 8, NE, 4); w32(img + 12, 1, 4); w32(img + 16, total, 8);
    for (i = 0; i < NE; i++) {
        uint8_t *r = img + 64 + 320 * i;
        strcpy((char *)r, E[i].path); w32(r + 260, E[i].attr, 4); w32(r + 264, E[i].size, 8); w32(r + 272, off, 8);
        for (k = 0; k < E[i].size; k++) img[pay + off + k] = (uint8_t)(i * 37 + k * 11 + (k >> 8));
        sha(img + pay + off, E[i].size, r + 280); off += E[i].size;
    }
    sha(img + 64, 320 * NE, img + 24);
    memcpy(img + ext, "SZLN", 4); w32(img + ext + 4, 1, 2); w32(img + ext + 6, 48, 2); w32(img + ext + 8, NR, 4);
    for (i = 0; i < NR; i++) {
        uint8_t *r = img + ext + 48 + 784 * i; uint16_t u[300]; uint32_t n = utf16(R[i].u8, u);
        strcpy((char *)r, R[i].path); r[260] = R[i].kind; r[261] = R[i].attr; w32(r + 262, n, 2);
        for (k = 0; k < n; k++) w32(r + 264 + 2 * k, u[k], 2);
    }
    sha(img + ext + 48, 784 * NR, img + ext + 16);
}
static int src_read(void *c, uint64_t o, void *b, uint32_t n) { (void)c; memcpy(b, img + o, n); return 0; }
static szou_header_t h; static szou_entry_t ents[NE]; static uint32_t ord[NE], scr[NE + 2 * NR];
static szou_names_header_t nh; static szou_name_t names[NR];
/* Mutate one record field set, re-seal the record sha, parse. */
static int neg(int rec, int off, const void *bytes, int n)
{
    uint8_t *raw = malloc(784 * NR); szou_names_header_t x = nh; int rc;
    memcpy(raw, img + ext + 48, 784 * NR); memcpy(raw + 784 * rec + off, bytes, (size_t)n);
    sha(raw, 784 * NR, x.records_sha256);
    rc = szou_parse_names(&h, &x, raw, 784 * NR, ents, ord, names, scr);
    free(raw);
    return rc;
}
int main(int argc, char **argv)
{
    szou_fat32_t fs; szou_sink_ops_t s; szou_stage_result_t res;
    szou_plan_opts_t o = { "", "SZSTAGE.NEW" };
    static uint8_t buf[65536]; uint16_t got[256], want[300]; uint32_t n, i;
    szou_header_t h1;
    if (argc < 3) return 2;
    build();
    CHECK(szou_parse_header(img, img_len, &h) == 0 && h.version == 2 && h.names_offset == ext);
    CHECK(szou_parse_header(img, img_len + 1, &h1) == 0);  /* header alone defers exact v2 length */
    CHECK(szou_parse_table(&h, img + 64, 320 * NE, ents, ord) == 0);
    CHECK(szou_parse_names_header(&h, img + ext, img_len + 1, &nh) == SZOU_E_LENGTH);
    CHECK(szou_parse_names_header(&h, img + ext, img_len, &nh) == 0 && nh.record_count == NR);
    CHECK(szou_parse_names(&h, &nh, img + ext + 48, 784 * NR, ents, ord, names, scr) == 0);
    img[12] = 0; CHECK(szou_parse_header(img, img_len, &h1) == SZOU_E_HEADER); img[12] = 1;   /* v2 needs flags 1 */
    { uint16_t lone = 0xD800, bad = '/', big = 256; uint8_t k1 = 1, at = 1, z = 0;
      CHECK(neg(0, 264, &lone, 2) == SZOU_E_NAMES);                       /* unpaired high surrogate at end */
      CHECK(neg(0, 264 + 2 * 12, &bad, 2) == SZOU_E_NAMES);
      CHECK(neg(0, 262, &big, 2) == SZOU_E_NAMES);
      CHECK(neg(5, 0, "WINDOWS\\SYSTEX", 14) == SZOU_E_NAMES);             /* EMPTY.TXT parent dir record missing */
      CHECK(neg(0, 0, "..\\X\0\0\0\0", 8) == SZOU_E_PATH);
      CHECK(neg(3, 0, "ZZ", 2) == SZOU_E_ORDER);
      CHECK(neg(5, 260, &k1, 1) == SZOU_E_NAMES);                         /* kind 1 for a non-entry */
      CHECK(neg(2, 261, &at, 1) == SZOU_E_ATTR);
      { uint16_t f[5] = { 'f', 'O', 'n', 'T', 's' }, u5 = 5;               /* SYSTEM long "fOnTs" vs sibling FONTS */
        uint8_t raw[12]; memcpy(raw, &u5, 2); memcpy(raw + 2, f, 10);
        CHECK(neg(5, 262, raw, 12) == SZOU_E_DUPLICATE); }
      CHECK(neg(1, 776, &k1, 1) == SZOU_E_RESERVED); (void)z; }
    CHECK(szou_parse_names(&h, &nh, img + ext + 48, 784 * NR, ents, ord, names, scr) == 0);

    fd = open(argv[1], O_RDWR); CHECK(fd >= 0);
    if (mount(&fs) != 0) { printf("FAIL mount (image not FAT32 >= 65525 clusters)\n"); return 1; }
    szou_fat32_sink(&fs, &s);
    CHECK(szou_stage(&o, &h, ents, src_read, 0, &s, buf, sizeof buf, &res) == SZOU_E_VERSION);   /* never drop LFN */
    CHECK(szou_stage_named(&o, &h, ents, names, NR, src_read, 0, &s, buf, sizeof buf, &res) == 0 && res.marker_written);
    CHECK(szou_fat32_unmount(&fs) == 0);
    wlimit = atoi(argv[2]);
    if (wlimit > 0) {                                  /* interrupted commit: device dies after K writes */
        CHECK(mount(&fs) == 0); szou_fat32_sink(&fs, &s);
        CHECK(szou_commit_pending(&s, buf, sizeof buf, &res) != 0);
        wlimit = -1;
    }
    wlimit = -1;
    if (mount(&fs) != 0) { printf("FAIL remount\n"); return 1; }
    szou_fat32_sink(&fs, &s);   /* cold boot: marker only */
    CHECK(szou_commit_pending(&s, buf, sizeof buf, &res) == 0 && res.committed);
    CHECK(szou_commit_pending(&s, buf, sizeof buf, &res) == SZOU_ABSENT);
    for (i = 0; i < NE; i++) {
        void *f; uint64_t sz; sha256_ctx c; uint8_t d[32];
        CHECK(s.open(s.ctx, E[i].path, &f, &sz) == 0 && sz == E[i].size);
        sha256_init(&c);
        { uint64_t o2; for (o2 = 0; o2 < sz; o2 += 4096) { uint32_t m = sz - o2 < 4096 ? (uint32_t)(sz - o2) : 4096u;
            CHECK(s.read(s.ctx, f, o2, buf, m) == 0); sha256_update(&c, buf, m); } }
        sha256_final(&c, d); CHECK(memcmp(d, ents[i].sha256, 32) == 0); s.close(s.ctx, f);
    }
    for (i = 0; i < NR; i++) {
        uint32_t wn = utf16(R[i].u8, want);
        CHECK(szou_fat32_long_name(&fs, R[i].path, got, &n) == 0 && n == wn && !memcmp(got, want, 2 * wn));
    }
    CHECK(s.mkdir_named(s.ctx, "WINDOWS\\FONTS", 0, 0, 0x04) == SZOU_E_CONFLICT);   /* different long name */
    CHECK(s.open(s.ctx, "SZOUPEND.SYS", (void **)&n, (uint64_t *)buf) == SZOU_ABSENT);
    CHECK(szou_fat32_unmount(&fs) == 0);
    close(fd);
    printf("v2 K=%s %s (%d failures)\n", argv[2], fails ? "FAILED" : "ok", fails);
    return fails != 0;
}
