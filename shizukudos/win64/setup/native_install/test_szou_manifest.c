/* SPDX-License-Identifier: GPL-2.0-only
 * Host unit test for the SZOU v1 parser and staging/commit protocol.
 * The in-memory sink below is a test fixture only; it is NOT a runtime
 * file authority and is never linked into the installer.
 *
 * cc -std=c99 -Wall -Wextra -Werror test_szou_manifest.c szou_manifest.c szou_stage.c \
 *    ../../../accounts/sha256.c -o /tmp/test_szou
 */
#include "szou_stage.h"
#include "../../../accounts/sha256.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>

static int fails;
#define CHECK(c) do { if (!(c)) { fprintf(stderr, "FAIL %s:%d %s\n", __FILE__, __LINE__, #c); fails++; } } while (0)

/* ---- image builder ---- */
typedef struct { const char *path; const char *data; uint32_t attr; } spec_t;

static void put32(uint8_t *p, uint32_t v) { p[0] = v; p[1] = v >> 8; p[2] = v >> 16; p[3] = v >> 24; }
static void put64(uint8_t *p, uint64_t v) { put32(p, (uint32_t)v); put32(p + 4, (uint32_t)(v >> 32)); }
static void sha(const void *d, size_t n, uint8_t o[32]) { sha256_ctx c; sha256_init(&c); sha256_update(&c, d, n); sha256_final(&c, o); }

static uint8_t *build(const spec_t *s, uint32_t n, size_t *len)
{
    size_t total = 0, i, off = 0;
    uint8_t *img, *tab, *pay;
    for (i = 0; i < n; i++) total += strlen(s[i].data);
    *len = 64 + 320 * (size_t)n + total;
    img = calloc(1, *len);
    tab = img + 64;
    pay = tab + 320 * (size_t)n;
    memcpy(img, "SZOU", 4);
    img[4] = 1; img[6] = 64;
    put32(img + 8, n);
    put64(img + 16, total);
    for (i = 0; i < n; i++) {
        uint8_t *r = tab + 320 * i;
        size_t dl = strlen(s[i].data);
        strncpy((char *)r, s[i].path, 259);
        put32(r + 260, s[i].attr);
        put64(r + 264, dl);
        put64(r + 272, off);
        sha(s[i].data, dl, r + 280);
        memcpy(pay + off, s[i].data, dl);
        off += dl;
    }
    sha(tab, 320 * (size_t)n, img + 24);
    return img;
}
static void reseal(uint8_t *img) { uint32_t n = img[8] | img[9] << 8; sha(img + 64, 320 * (size_t)n, img + 24); }

static int parse(const uint8_t *img, size_t len, szou_header_t *h, szou_entry_t *e, uint32_t *ord)
{
    int rc = szou_parse_header(img, len, h);
    if (rc) return rc;
    return szou_parse_table(h, img + 64, 320 * (size_t)h->entry_count, e, ord);
}

static const spec_t base[] = {
    {"WINDOWS\\EXPLORER.EXE", "explorer-bytes", 0x20},
    {"WINDOWS\\SYSTEM\\USER.EXE", "user16", 0x21},
    {"WINDOWS\\WIN.INI", "[windows]\r\n", 0x20},
    {"CONFIG.SYS", "", 0},
};
#define NB 4u

typedef struct { const uint8_t *img; } src_t;
static int src_read(void *c, uint64_t off, void *b, uint32_t n) { memcpy(b, ((src_t *)c)->img + off, n); return 0; }

/* ---- in-memory sink fixture ---- */
typedef struct { char path[260]; int dir, used; uint8_t *data; uint64_t size; uint32_t attr; } node_t;
typedef struct { node_t n[64]; int fail_rename_after; int renames; } mem_t;
static node_t *look(mem_t *m, const char *p) { int i; for (i = 0; i < 64; i++) if (m->n[i].used && !strcasecmp(m->n[i].path, p)) return &m->n[i]; return 0; }
static node_t *add(mem_t *m, const char *p) { int i; for (i = 0; i < 64; i++) if (!m->n[i].used) { memset(&m->n[i], 0, sizeof m->n[i]); m->n[i].used = 1; strcpy(m->n[i].path, p); return &m->n[i]; } return 0; }
static int parent_ok(mem_t *m, const char *p) { char t[260]; char *s; strcpy(t, p); s = strrchr(t, '\\'); if (!s) return 1; *s = 0; node_t *d = look(m, t); return d && d->dir; }
static void *m_alloc(void *c, size_t n) { (void)c; return calloc(1, n); }
static void m_free(void *c, void *p) { (void)c; free(p); }
static int m_mkdir(void *c, const char *p) { mem_t *m = c; if (look(m, p)) return SZOU_E_EXISTS; if (!parent_ok(m, p)) return SZOU_E_IO; add(m, p)->dir = 1; return 0; }
static int m_rmdir(void *c, const char *p)
{
    mem_t *m = c; node_t *d = look(m, p); size_t l = strlen(p); int i;
    if (!d) return SZOU_ABSENT;
    for (i = 0; i < 64; i++) if (m->n[i].used && !strncasecmp(m->n[i].path, p, l) && m->n[i].path[l] == '\\') return SZOU_E_IO;
    d->used = 0; return 0;
}
static int m_create(void *c, const char *p, uint64_t sz, void **f)
{ mem_t *m = c; node_t *x; if (look(m, p)) return SZOU_E_EXISTS; if (!parent_ok(m, p)) return SZOU_E_IO; x = add(m, p); x->data = calloc(1, sz + 1); x->size = sz; *f = x; return 0; }
static int m_open(void *c, const char *p, void **f, uint64_t *sz) { node_t *x = look(c, p); if (!x || x->dir) return SZOU_ABSENT; *f = x; *sz = x->size; return 0; }
static int m_read(void *c, void *f, uint64_t o, void *b, uint32_t n) { node_t *x = f; (void)c; if (o + n > x->size) return SZOU_E_IO; memcpy(b, x->data + o, n); return 0; }
static int m_write(void *c, void *f, uint64_t o, const void *b, uint32_t n) { node_t *x = f; (void)c; if (o + n > x->size) return SZOU_E_IO; memcpy(x->data + o, b, n); return 0; }
static int m_close(void *c, void *f) { (void)c; (void)f; return 0; }
static int m_rename(void *c, const char *a, const char *b)
{
    mem_t *m = c; node_t *x = look(m, a), *y;
    if (m->fail_rename_after >= 0 && m->renames >= m->fail_rename_after) return SZOU_E_IO;
    if (!x || !parent_ok(m, b)) return SZOU_E_IO;
    if ((y = look(m, b))) { free(y->data); y->used = 0; }
    strcpy(x->path, b); m->renames++; return 0;
}
static int m_remove(void *c, const char *p) { node_t *x = look(c, p); if (!x) return SZOU_ABSENT; free(x->data); x->used = 0; return 0; }
static int m_attr(void *c, const char *p, uint32_t a) { node_t *x = look(c, p); if (!x) return SZOU_E_IO; x->attr = a; return 0; }
static int m_flush(void *c) { (void)c; return 0; }

static szou_sink_ops_t sink_for(mem_t *m)
{
    szou_sink_ops_t s = { m, m_alloc, m_free, m_mkdir, m_rmdir, m_create, m_open, m_read, m_write,
                          m_close, m_rename, m_remove, m_attr, m_flush, 0, 0 };
    return s;
}

static int expect_table(const spec_t *s, uint32_t n, void (*mut)(uint8_t *), int want)
{
    size_t len; szou_header_t h; szou_entry_t e[8]; uint32_t ord[8]; int rc;
    uint8_t *img = build(s, n, &len);
    if (mut) { mut(img); reseal(img); }
    rc = parse(img, len, &h, e, ord);
    free(img);
    if (rc != want) fprintf(stderr, "  got %d (%s) want %d\n", rc, szou_strerror(rc), want);
    return rc == want;
}
static void m_overlap(uint8_t *img) { put64(img + 64 + 320 + 272, 3); }
static void m_gap(uint8_t *img) { put64(img + 64 + 320 + 264, 3); }
static void m_zero_back(uint8_t *img) { put64(img + 64 + 320 + 272, 2); }
static void m_oob(uint8_t *img) { put64(img + 64 + 640 + 264, 9); }
static void m_resv(uint8_t *img) { img[64 + 312] = 1; }
static void m_pad(uint8_t *img) { img[64 + 258] = 'X'; }
static void m_attrbad(uint8_t *img) { put32(img + 64 + 260, 0x10); }

static int one_path(const char *p, int want)
{
    spec_t s[1] = {{p, "x", 0}};
    return expect_table(s, 1, 0, want);
}

int main(void)
{
    size_t len; uint8_t *img; szou_header_t h; szou_entry_t e[8]; uint32_t ord[8];
    uint8_t buf[512]; src_t src; mem_t m; szou_sink_ops_t sk; szou_stage_result_t r;
    szou_plan_opts_t o = { "SHIZUKU", "SZSTAGE.NEW" };
    uint32_t i;

    /* valid image */
    img = build(base, NB, &len);
    CHECK(parse(img, len, &h, e, ord) == SZOU_OK);
    src.img = img;
    for (i = 0; i < NB; i++) CHECK(szou_verify_entry(&h, &e[i], src_read, &src, buf, sizeof buf) == SZOU_OK);

    /* malformed headers */
    { uint8_t t[64]; szou_header_t hh;
      memcpy(t, img, 64); t[3] = 'X'; CHECK(szou_parse_header(t, len, &hh) == SZOU_E_MAGIC);
      memcpy(t, img, 64); t[4] = 3; CHECK(szou_parse_header(t, len, &hh) == SZOU_E_VERSION);
      memcpy(t, img, 64); t[4] = 2; CHECK(szou_parse_header(t, len, &hh) == SZOU_E_HEADER); /* v2 needs flags 1 */
      memcpy(t, img, 64); t[6] = 63; CHECK(szou_parse_header(t, len, &hh) == SZOU_E_HEADER);
      memcpy(t, img, 64); t[12] = 1; CHECK(szou_parse_header(t, len, &hh) == SZOU_E_HEADER);
      memcpy(t, img, 64); t[60] = 1; CHECK(szou_parse_header(t, len, &hh) == SZOU_E_HEADER);
      memcpy(t, img, 64); put32(t + 8, 0); CHECK(szou_parse_header(t, len, &hh) == SZOU_E_HEADER);
      memcpy(t, img, 64); put64(t + 16, ~0ull); CHECK(szou_parse_header(t, len, &hh) == SZOU_E_LENGTH);
      CHECK(szou_parse_header(img, len - 1, &hh) == SZOU_E_LENGTH);
      CHECK(szou_parse_header(img, len + 1, &hh) == SZOU_E_LENGTH);
      CHECK(szou_parse_header(img, 10, &hh) == SZOU_E_LENGTH); }
    /* entry table hash */
    img[64 + 5] ^= 1;
    CHECK(parse(img, len, &h, e, ord) == SZOU_E_TABLE_SHA);
    img[64 + 5] ^= 1;

    /* path traversal / malformed paths */
    CHECK(one_path("..\\WIN.INI", SZOU_E_PATH));
    CHECK(one_path("A\\..\\B", SZOU_E_PATH));
    CHECK(one_path("A\\.\\B", SZOU_E_PATH));
    CHECK(one_path("C:WIN.INI", SZOU_E_PATH));
    CHECK(one_path("\\WIN.INI", SZOU_E_PATH));
    CHECK(one_path("A/B", SZOU_E_PATH));
    CHECK(one_path("A\\\\B", SZOU_E_PATH));
    CHECK(one_path("A\\", SZOU_E_PATH));
    CHECK(one_path("A.\\B", SZOU_E_PATH));
    CHECK(one_path("A\tB", SZOU_E_PATH));
    CHECK(one_path("WINDOWS\\Desktop\\My Files.txt", SZOU_OK));
    CHECK(expect_table(base, NB, m_pad, SZOU_E_RESERVED));

    /* duplicates and file/dir conflicts */
    { spec_t d[2] = {{"WINDOWS\\USER.EXE", "a", 0}, {"windows\\user.exe", "b", 0}};
      CHECK(expect_table(d, 2, 0, SZOU_E_DUPLICATE)); }
    { spec_t d[2] = {{"WINDOWS\\SYSTEM", "a", 0}, {"windows\\system\\x.dll", "b", 0}};
      CHECK(expect_table(d, 2, 0, SZOU_E_CONFLICT)); }
    { spec_t d[3] = {{"A\\B\\C", "a", 0}, {"A\\B.TXT", "b", 0}, {"a\\b\\D", "c", 0}};
      CHECK(expect_table(d, 3, 0, SZOU_OK)); }

    /* layout: zero-length entries share offset == previous end (producer packing) */
    { spec_t z[3] = {{"A.TXT", "abc", 0}, {"EMPTY.TXT", "", 0}, {"B.TXT", "de", 0}};
      CHECK(expect_table(z, 3, 0, SZOU_OK));
      CHECK(expect_table(z, 3, m_zero_back, SZOU_E_LAYOUT));
      CHECK(expect_table(z, 3, m_oob, SZOU_E_LAYOUT)); }
    CHECK(expect_table(base, NB, m_overlap, SZOU_E_LAYOUT));
    CHECK(expect_table(base, NB, m_gap, SZOU_E_LAYOUT));
    CHECK(expect_table(base, NB, m_resv, SZOU_E_RESERVED));
    CHECK(expect_table(base, NB, m_attrbad, SZOU_E_ATTR));

    /* payload sha mismatch: verify and stage both refuse, stage leaves nothing */
    img[len - 3] ^= 0x40; /* inside WIN.INI payload */
    CHECK(szou_verify_entry(&h, &e[2], src_read, &src, buf, sizeof buf) == SZOU_E_SHA);
    memset(&m, 0, sizeof m); m.fail_rename_after = -1; sk = sink_for(&m);
    CHECK(szou_stage(&o, &h, e, src_read, &src, &sk, buf, sizeof buf, &r) == SZOU_E_SHA);
    CHECK(r.failed_index == 2 && !look(&m, "SZSTAGE.NEW") && !look(&m, SZOU_MARKER_NAME));
    img[len - 3] ^= 0x40;

    /* no authority bound */
    { szou_sink_ops_t none; memset(&none, 0, sizeof none);
      CHECK(szou_stage(&o, &h, e, src_read, &src, &none, buf, sizeof buf, &r) == SZOU_E_NO_AUTHORITY);
      CHECK(szou_commit_pending(&none, buf, sizeof buf, &r) == SZOU_E_NO_AUTHORITY); }

    /* plan conflicts */
    { szou_plan_opts_t bad = { "", "WINDOWS" };
      CHECK(szou_plan_check(&bad, e, NB) == SZOU_E_CONFLICT);
      bad.stage_root = "..";
      CHECK(szou_plan_check(&bad, e, NB) == SZOU_E_PATH); }

    /* stage, interrupted commit, cold-boot roll-forward */
    memset(&m, 0, sizeof m); m.fail_rename_after = -1; sk = sink_for(&m);
    CHECK(szou_commit_pending(&sk, buf, sizeof buf, &r) == SZOU_ABSENT);
    CHECK(szou_stage(&o, &h, e, src_read, &src, &sk, buf, sizeof buf, &r) == SZOU_OK);
    CHECK(r.marker_written && r.files_staged == NB && r.bytes_read_back == h.total_payload_bytes);
    CHECK(look(&m, SZOU_MARKER_NAME) && !look(&m, SZOU_MARKER_TMP));
    CHECK(szou_stage(&o, &h, e, src_read, &src, &sk, buf, sizeof buf, &r) == SZOU_E_STATE);
    m.renames = 0; m.fail_rename_after = 2;
    CHECK(szou_commit_pending(&sk, buf, sizeof buf, &r) == SZOU_E_IO);
    CHECK(look(&m, SZOU_MARKER_NAME) != 0);
    m.fail_rename_after = -1;
    CHECK(szou_commit_pending(&sk, buf, sizeof buf, &r) == SZOU_OK);
    CHECK(r.committed && r.files_already_final == 2 && r.files_committed == NB - 2);
    CHECK(!look(&m, SZOU_MARKER_NAME) && !look(&m, "SZSTAGE.NEW") && !look(&m, "SZSTAGE.NEW\\WINDOWS"));
    { node_t *x = look(&m, "shizuku\\windows\\system\\user.exe");
      CHECK(x && x->size == 6 && !memcmp(x->data, "user16", 6) && x->attr == 0x21); }
    CHECK(look(&m, "SHIZUKU\\CONFIG.SYS") && look(&m, "SHIZUKU\\CONFIG.SYS")->size == 0);
    CHECK(szou_commit_pending(&sk, buf, sizeof buf, &r) == SZOU_ABSENT);

    /* corrupted marker refuses */
    memset(&m, 0, sizeof m); m.fail_rename_after = -1; sk = sink_for(&m);
    CHECK(szou_stage(&o, &h, e, src_read, &src, &sk, buf, sizeof buf, &r) == SZOU_OK);
    look(&m, SZOU_MARKER_NAME)->data[700] ^= 1;
    CHECK(szou_commit_pending(&sk, buf, sizeof buf, &r) == SZOU_E_STATE);

    free(img);
    printf("%s (%d failures)\n", fails ? "FAILED" : "szou: all checks passed", fails);
    return fails ? 1 : 0;
}
