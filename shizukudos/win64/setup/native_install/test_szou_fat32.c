/* SPDX-License-Identifier: GPL-2.0-only
 * Host test: szou_fat32 writer as the szou_stage file authority on a real
 * mkfs.fat FAT32 image (file-backed sector device; host-only evidence).
 * Usage: test_szou_fat32 stage|commit|verify|refuse <fat32.img> [fat16.img]
 */
#define _XOPEN_SOURCE 700
#include "szou_fat32.h"
#include "../../../accounts/sha256.h"
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

static int fails;
#define CHECK(c) do { if (!(c)) { fprintf(stderr, "FAIL %s:%d %s\n", __FILE__, __LINE__, #c); fails++; } } while (0)

static int fd;
static int b_rd(void *c, uint64_t l, uint32_t n, void *b) { (void)c; return pread(fd, b, n * 512ull, (off_t)(l * 512)) == (ssize_t)(n * 512ull) ? 0 : -1; }
static int b_wr(void *c, uint64_t l, uint32_t n, const void *b) { (void)c; return pwrite(fd, b, n * 512ull, (off_t)(l * 512)) == (ssize_t)(n * 512ull) ? 0 : -1; }
static int b_fl(void *c) { (void)c; return fsync(fd); }
static void *m_alloc(void *c, size_t n) { (void)c; return calloc(1, n); }
static void m_free(void *c, void *p) { (void)c; free(p); }

static int mount(szou_fat32_t *fs, const char *path)
{
    szou_blkdev_t d = { 0, 512, 0, 128, b_rd, b_wr, b_fl };
    fd = open(path, O_RDWR);
    if (fd < 0) return -99;
    d.sectors = (uint64_t)lseek(fd, 0, SEEK_END) / 512;
    return szou_fat32_mount(fs, &d, m_alloc, m_free, 0, 0x5B43, 0);
}

/* ---- SZOU image ---- */
typedef struct { const char *path; uint32_t len, attr; } spec_t;
static const spec_t spec[] = {
    {"WINDOWS\\EXPLORER.EXE", 300001, 0x20},
    {"WINDOWS\\SYSTEM\\USER.EXE", 4097, 0x21},
    {"WINDOWS\\WIN.INI", 13, 0x20},
    {"WINDOWS\\EMPTY.TXT", 0, 0x20},
    {"io.sys", 1024, 0x07},
};
#define NS 5u
static uint8_t data_byte(uint32_t i, uint32_t k) { return (uint8_t)(i * 131 + k * 7 + (k >> 9)); }
static void put32(uint8_t *p, uint32_t v) { p[0] = v; p[1] = v >> 8; p[2] = v >> 16; p[3] = v >> 24; }
static uint8_t *img; static size_t img_len;
static void build(void)
{
    size_t total = 0, off = 0, i, k;
    uint8_t *tab, *pay;
    for (i = 0; i < NS; i++) total += spec[i].len;
    img_len = 64 + 320 * NS + total;
    img = calloc(1, img_len); tab = img + 64; pay = tab + 320 * NS;
    memcpy(img, "SZOU", 4); img[4] = 1; img[6] = 64; put32(img + 8, NS); put32(img + 16, (uint32_t)total);
    for (i = 0; i < NS; i++) {
        uint8_t *r = tab + 320 * i; sha256_ctx c;
        strcpy((char *)r, spec[i].path); put32(r + 260, spec[i].attr); put32(r + 264, spec[i].len); put32(r + 272, (uint32_t)off);
        for (k = 0; k < spec[i].len; k++) pay[off + k] = data_byte((uint32_t)i, (uint32_t)k);
        sha256_init(&c); sha256_update(&c, pay + off, spec[i].len); sha256_final(&c, r + 280);
        off += spec[i].len;
    }
    { sha256_ctx c; sha256_init(&c); sha256_update(&c, tab, 320 * NS); sha256_final(&c, img + 24); }
}
static int src_read(void *c, uint64_t o, void *b, uint32_t n) { (void)c; memcpy(b, img + o, n); return 0; }

static int check_file(szou_sink_ops_t *s, const char *p, uint32_t i)
{
    void *f; uint64_t sz; uint8_t *b; uint32_t k; int ok = 1;
    if (s->open(s->ctx, p, &f, &sz)) return 0;
    b = malloc(spec[i].len + 1);
    if (sz != spec[i].len || (sz && s->read(s->ctx, f, 0, b, (uint32_t)sz))) ok = 0;
    for (k = 0; ok && k < sz; k++) if (b[k] != data_byte(i, k)) ok = 0;
    s->close(s->ctx, f); free(b);
    return ok;
}

int main(int argc, char **argv)
{
    static szou_fat32_t fs;
    szou_sink_ops_t s; szou_header_t h; szou_entry_t e[NS]; uint32_t ord[NS]; szou_stage_result_t r;
    static uint8_t buf[65536];
    szou_plan_opts_t o = { "", "SZSTAGE.NEW" };
    if (argc < 3) return 2;
    build();
    CHECK(szou_parse_header(img, img_len, &h) == 0 && szou_parse_table(&h, img + 64, 320 * NS, e, ord) == 0);
    CHECK(mount(&fs, argv[2]) == 0);
    szou_fat32_sink(&fs, &s);
    if (!strcmp(argv[1], "stage")) {
        CHECK(szou_stage(&o, &h, e, src_read, 0, &s, buf, sizeof buf, &r) == 0);
        CHECK(r.marker_written && r.files_staged == NS && r.bytes_read_back == h.total_payload_bytes);
        CHECK(check_file(&s, "SZSTAGE.NEW\\WINDOWS\\SYSTEM\\USER.EXE", 1));
        /* simulate an interrupted commit: one file already moved */
        CHECK(s.mkdir(s.ctx, "WINDOWS") == 0);
        CHECK(s.rename_replace(s.ctx, "SZSTAGE.NEW\\WINDOWS\\WIN.INI", "WINDOWS\\WIN.INI") == 0);
    } else if (!strcmp(argv[1], "commit")) {
        CHECK(szou_commit_pending(&s, buf, sizeof buf, &r) == 0);
        CHECK(r.committed && r.files_committed == NS - 1 && r.files_already_final == 1);
        CHECK(szou_commit_pending(&s, buf, sizeof buf, &r) == SZOU_ABSENT);
    } else if (!strcmp(argv[1], "verify")) {
        uint32_t i; void *f; uint64_t sz;
        for (i = 0; i < NS; i++) CHECK(check_file(&s, spec[i].path, i));
        CHECK(s.open(s.ctx, "SZSTAGE.NEW", &f, &sz) == SZOU_ABSENT);
        CHECK(s.open(s.ctx, SZOU_MARKER_NAME, &f, &sz) == SZOU_ABSENT);
        /* replace semantics + delete */
        CHECK(s.create(s.ctx, "WINDOWS\\NEW.INI", 5, &f) == 0 && s.write(s.ctx, f, 0, "hello", 5) == 0 && s.close(s.ctx, f) == 0);
        CHECK(s.rename_replace(s.ctx, "WINDOWS\\NEW.INI", "WINDOWS\\WIN.INI") == 0);
        CHECK(s.open(s.ctx, "WINDOWS\\WIN.INI", &f, &sz) == 0 && sz == 5 && s.close(s.ctx, f) == 0);
        CHECK(s.remove(s.ctx, "WINDOWS\\WIN.INI") == 0 && s.remove(s.ctx, "WINDOWS\\WIN.INI") == SZOU_ABSENT);
        CHECK(s.rmdir(s.ctx, "WINDOWS") == SZOU_E_STATE);           /* not empty */
    } else if (!strcmp(argv[1], "refuse")) {
        void *f; szou_fat32_t f16; uint32_t fc = fs.free_count;
        CHECK(s.mkdir(s.ctx, "LongDirectoryName") == SZOU_E_UNSUPPORTED);
        CHECK(s.create(s.ctx, "A B.TXT", 1, &f) == SZOU_E_UNSUPPORTED);
        CHECK(s.create(s.ctx, "HUGE.BIN", (uint64_t)(fs.free_count + 1) * fs.cb, &f) == SZOU_E_FULL);
        CHECK(s.create(s.ctx, "BIG.BIN", 0x100000000ull, &f) == SZOU_E_UNSUPPORTED);
        CHECK(s.create(s.ctx, "NOPE\\X.TXT", 1, &f) == SZOU_E_IO);
        CHECK(fs.free_count == fc);
        { szou_plan_opts_t lo = { "", "SZSTAGE.NEW" }; szou_entry_t le = e[2]; szou_header_t h1 = h;
          h1.entry_count = 1;
          strcpy(le.path, "Program Files\\x.ini");
          CHECK(szou_stage(&lo, &h1, &le, src_read, 0, &s, buf, sizeof buf, &r) != 0); /* LFN dir refused */
          CHECK(s.open(s.ctx, "SZSTAGE.NEW", &f, &(uint64_t){0}) == SZOU_ABSENT); }
        if (argc > 3) { close(fd); CHECK(mount(&f16, argv[3]) == SZOU_E_UNSUPPORTED); }
    }
    CHECK(argc > 3 || szou_fat32_unmount(&fs) == 0);
    close(fd);
    printf("%s %s (%d failures)\n", argv[1], fails ? "FAILED" : "ok", fails);
    return fails ? 1 : 0;
}
