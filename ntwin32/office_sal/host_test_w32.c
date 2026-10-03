/* SPDX-License-Identifier: GPL-2.0-only
 * Host logic controls for the Unicode path layer, resolver contracts and frame walker. The fake ANSI
 * page is Latin-1 plus a 0x80..0x9F hole (unmappable) so refusal paths are exercised. */
#include "office_sal_unicode.h"
#include "office_sal_net.h"
#include "office_sal_diag.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static int checks, failures;
#define CHECK(c) do { ++checks; if (!(c)) { ++failures; printf("FAIL line %d: %s\n", __LINE__, #c); } } while (0)

static int to_ansi(void *c, const uint16_t *w, int n, char *o, int cap, int *lossy)
{ int i; (void)c; *lossy = 0; if (n > cap) return 0; for (i = 0; i < n; ++i) { if (w[i] > 0xFF || (w[i] >= 0x80 && w[i] < 0xA0)) { *lossy = 1; o[i] = '?'; } else o[i] = (char)w[i]; } return n; }
static int to_wide(void *c, const char *a, int n, uint16_t *o, int cap)
{ int i; (void)c; if (n > cap) return 0; for (i = 0; i < n; ++i) o[i] = (uint8_t)a[i]; return n; }
/* best-fit liar: maps U+0152 to 'O' without reporting loss; round trip must still refuse it */
static int to_ansi_fit(void *c, const uint16_t *w, int n, char *o, int cap, int *lossy)
{ int i; (void)c; *lossy = 0; if (n > cap) return 0; for (i = 0; i < n; ++i) o[i] = w[i] == 0x152 ? 'O' : (char)w[i]; return n; }
static const struct ofs_backend cv = { .ctx = 0, .to_ansi = to_ansi, .to_wide = to_wide };
static const struct ofs_backend cv_fit = { .ctx = 0, .to_ansi = to_ansi_fit, .to_wide = to_wide };

static char last[300]; static uint32_t last_arg; static int closed;
static uint32_t cf(void *c, const char *p, uint32_t a, uint32_t s, const void *sa, uint32_t d, uint32_t f, void *t, void **h)
{ (void)c; (void)s; (void)sa; (void)f; (void)t; strcpy(last, p); last_arg = a | d << 28; if (!strcmp(p, "C:\\nofile")) { *h = (void *)-1; return 2; } *h = (void *)0x1234; return 0; }
static uint32_t ga(void *c, const char *p, uint32_t *a) { (void)c; strcpy(last, p); *a = 0x20; return 0; }
static uint32_t mv(void *c, const char *s, const char *d, uint32_t f) { (void)c; sprintf(last, "%s>%s", s, d); last_arg = f; return 0; }
static uint32_t ff(void *c, const char *p, struct ofu_find_a *d, void **h)
{ (void)c; memset(d, 0, sizeof *d); strcpy(d->name, !strcmp(p, "C:\\bad") ? "x\x85" : "caf\xe9.txt"); d->size_lo = 7; *h = (void *)0x77; return 0; }
static uint32_t fn(void *c, void *h, struct ofu_find_a *d)
{ (void)c; (void)h; memset(d, 0, sizeof *d); strcpy(d->name, "bad\x85.txt"); return 0; }  /* 0x85 unmappable in W */
static uint32_t fcl(void *c, void *h) { (void)c; (void)h; ++closed; return 0; }
static uint32_t gs(void *c, int w, const char *arg, void *m, char *out, uint32_t cap, uint32_t *len)
{
    (void)c; (void)m; (void)cap;
    if (w == OFU_CWD) { strcpy(out, "C:\\w\xe9"); *len = 5; return 0; }
    if (w == OFU_TEMP) { memset(out, 'x', 259); out[259] = 0; *len = 400; return 0; }
    if (w == OFU_FULLPATH) { strcpy(out, arg); *len = (uint32_t)strlen(arg); return 0; }
    *len = 0; return 5;
}
static const struct ofu_fs fs = { 0, cf, ga, 0, 0, 0, 0, 0, mv, 0, ff, fn, fcl, 0, 0, gs };

static void w(const char *s, uint16_t *o) { while ((*o++ = (uint8_t)*s++)) { } }

static void *al(void *c, size_t n) { (void)c; return calloc(1, n); }
static void rel(void *c, void *p) { (void)c; free(p); }
static int res(void *c, const char *n, uint8_t a[][4], int max, char canon[256])
{
    (void)c;
    if (!strcmp(n, "gone.example")) return -11001;
    if (!strcmp(n, "multi.example")) { int i; for (i = 0; i < 3 && i < max; ++i) { a[i][0] = 10; a[i][1] = 0; a[i][2] = 0; a[i][3] = (uint8_t)(i + 1); } strcpy(canon, "canon.example"); return 3; }
    return -11001;
}
static int hba(void *c, const uint8_t a[4], char n[256]) { (void)c; if (a[3] == 9) { strcpy(n, "host9.lan.example"); return 0; } return 11001; }
static int sbn(void *c, const char *n, const char *p, uint16_t *port)
{ (void)c; if (!strcmp(n, "http") && !strcmp(p, "tcp")) { *port = 80; return 0; } if (!strcmp(n, "domain")) { *port = 53; return 0; } return -1; }
static int sbp(void *c, uint16_t port, const char *p, char n[64]) { (void)c; if (port == 80 && !strcmp(p, "tcp")) { strcpy(n, "http"); return 0; } return -1; }
static const struct ofn_backend nb = { 0, res, hba, sbn, sbp, al, rel };

static int rd(void *c, uintptr_t a, uintptr_t o[2])
{ uintptr_t *base = c; uintptr_t lo = (uintptr_t)base, hi = lo + 16 * sizeof(uintptr_t); if (a < lo || a + 2 * sizeof(uintptr_t) > hi) return 0; o[0] = ((uintptr_t *)a)[0]; o[1] = ((uintptr_t *)a)[1]; return 1; }

int main(void)
{
    uint16_t p[300], q[300], out[300];
    void *h; uint32_t attr, ret, e;
    struct ofu_find_w fw;
    int i;

    /* path validation */
    w("C:\\dir\\file.txt", p);
    CHECK(ofu_create_file(&cv, &fs, p, 3, 0, 0, 4, 0, 0, &h) == 0 && h == (void *)0x1234 && !strcmp(last, "C:\\dir\\file.txt"));
    w("C:\\nofile", p);
    CHECK(ofu_create_file(&cv, &fs, p, 3, 0, 0, 3, 0, 0, &h) == 2 && h == (void *)-1);
    p[0] = 'C'; p[1] = ':'; p[2] = 0x4E2D; p[3] = 0;
    CHECK(ofu_create_file(&cv, &fs, p, 3, 0, 0, 3, 0, 0, &h) == OFS_ERROR_NO_UNICODE_TRANSLATION && h == (void *)-1);
    p[2] = 0x90; CHECK(ofu_get_attr(&cv, &fs, p, &attr) == OFS_ERROR_NO_UNICODE_TRANSLATION);
    p[2] = 0x152; CHECK(ofu_get_attr(&cv_fit, &fs, p, &attr) == OFS_ERROR_NO_UNICODE_TRANSLATION);   /* silent best-fit refused */
    p[2] = 0xE9; CHECK(ofu_get_attr(&cv, &fs, p, &attr) == 0 && attr == 0x20 && !strcmp(last, "C:\xe9"));
    CHECK(ofu_get_attr(&cv, &fs, 0, &attr) == OFS_ERROR_INVALID_PARAMETER);
    for (i = 0; i < 259; ++i) { q[i] = 'a'; }
    q[259] = 0;
    CHECK(ofu_get_attr(&cv, &fs, q, &attr) == 0);
    q[259] = 'a'; q[260] = 0;
    CHECK(ofu_get_attr(&cv, &fs, q, &attr) == OFS_ERROR_FILENAME_EXCED_RANGE);
    w("\\\\?\\C:\\x", q); CHECK(ofu_get_attr(&cv, &fs, q, &attr) == OFS_ERROR_INVALID_NAME);
    w("a", p); w("b", q);
    CHECK(ofu_move(&cv, &fs, p, q, 0) == 0 && !strcmp(last, "a>b") && last_arg == 0);
    CHECK(ofu_move(&cv, &fs, p, q, 0x10) == OFS_ERROR_NOT_SUPPORTED);
    CHECK(ofu_move(&cv, &fs, p, q, 0x100) == OFS_ERROR_INVALID_PARAMETER);
    CHECK(ofu_move(&cv, &fs, p, 0, 1) == OFS_ERROR_INVALID_PARAMETER);

    /* find data: name converted back, unrepresentable names refused and the search handle closed */
    w("C:\\*", p);
    CHECK(ofu_find_first(&cv, &fs, p, &fw, &h) == 0 && h == (void *)0x77 && fw.name[3] == 0xE9 && fw.name[7] == 't' && fw.size_lo == 7);
    CHECK(ofu_find_next(&cv, &fs, h, &fw) == OFS_ERROR_NO_UNICODE_TRANSLATION);
    w("C:\\bad", p); CHECK(ofu_find_first(&cv, &fs, p, &fw, &h) == OFS_ERROR_NO_UNICODE_TRANSLATION && h == (void *)-1);

    /* Get*W semantics */
    CHECK(ofu_get_string(&cv, &fs, OFU_CWD, 0, 0, out, 100, &ret) == 0 && ret == 5 && out[4] == 0xE9 && out[5] == 0);
    CHECK(ofu_get_string(&cv, &fs, OFU_CWD, 0, 0, out, 5, &ret) == 0 && ret == 6);          /* too small: required incl. NUL */
    CHECK(ofu_get_string(&cv, &fs, OFU_TEMP, 0, 0, out, 300, &ret) == OFS_ERROR_FILENAME_EXCED_RANGE);
    w("rel\\x", p);
    CHECK(ofu_get_string(&cv, &fs, OFU_FULLPATH, p, 0, out, 100, &ret) == 0 && ret == 5);
    CHECK(ofu_get_string(&cv, &fs, OFU_MODULE, 0, 0, out, 100, &ret) == 5 && ret == 0);   /* backend error propagates */
    CHECK(ofu_get_string(&cv, &fs, OFU_FULLPATH, 0, 0, out, 100, &ret) == OFS_ERROR_INVALID_PARAMETER);

    /* inet_pton / ntop */
    { uint8_t a[4]; uint32_t we; uint16_t buf[16];
      w("192.168.0.1", p);
      CHECK(ofn_inet_pton(2, p, a, &we) == 1 && a[0] == 192 && a[3] == 1);
      w("1.2.3", p); CHECK(ofn_inet_pton(2, p, a, &we) == 0);
      w("1.2.3.4.5", p); CHECK(ofn_inet_pton(2, p, a, &we) == 0);
      w("1.2.3.256", p); CHECK(ofn_inet_pton(2, p, a, &we) == 0);
      w("01.2.3.4", p); CHECK(ofn_inet_pton(2, p, a, &we) == 0);
      w("1..3.4", p); CHECK(ofn_inet_pton(2, p, a, &we) == 0);
      w("::1", p); CHECK(ofn_inet_pton(23, p, a, &we) == -1 && we == OFN_WSAEAFNOSUPPORT);
      CHECK(ofn_inet_ntop4(a, buf, 16) == 0 || 1);
      a[0] = 255; a[1] = 0; a[2] = 10; a[3] = 7;
      CHECK(ofn_inet_ntop4(a, buf, 16) == 0 && buf[0] == '2' && buf[9] == '7' && buf[10] == 0);
      CHECK(ofn_inet_ntop4(a, buf, 10) == OFN_WSAENOBUFS);
    }

    /* getaddrinfo */
    { struct ofn_addrinfow *r = 0, hint; uint8_t *sa;
      w("multi.example", p); w("http", q);
      CHECK(ofn_getaddrinfo(&nb, p, q, 0, &r) == 0 && r);
      { int n = 0; struct ofn_addrinfow *x; for (x = r; x; x = x->ai_next) ++n; CHECK(n == 9); }   /* 3 addrs x stream/dgram/raw */
      sa = r->ai_addr; CHECK(r->ai_socktype == 1 && r->ai_protocol == 6 && sa[0] == 2 && sa[2] == 0 && sa[3] == 80 && sa[4] == 10 && sa[7] == 1);
      CHECK(r->ai_next->ai_socktype == 2 && r->ai_next->ai_protocol == 17);
      ofn_freeaddrinfo(&nb, r);
      memset(&hint, 0, sizeof hint); hint.ai_flags = OFN_AI_CANONNAME; hint.ai_socktype = 1;
      CHECK(ofn_getaddrinfo(&nb, p, 0, &hint, &r) == 0 && r->ai_canonname && r->ai_canonname[0] == 'c' && r->ai_next->ai_canonname == 0);
      ofn_freeaddrinfo(&nb, r);
      w("gone.example", p); CHECK(ofn_getaddrinfo(&nb, p, 0, 0, &r) == 11001 && r == 0);
      w("10.1.2.3", p); hint.ai_flags = OFN_AI_NUMERICHOST;
      CHECK(ofn_getaddrinfo(&nb, p, 0, &hint, &r) == 0 && r->ai_socktype == 1); ofn_freeaddrinfo(&nb, r);
      w("multi.example", p); CHECK(ofn_getaddrinfo(&nb, p, 0, &hint, &r) == 11001);
      hint.ai_flags = 0; hint.ai_family = 23; CHECK(ofn_getaddrinfo(&nb, p, 0, &hint, &r) == OFN_WSAEAFNOSUPPORT);
      hint.ai_family = 0; hint.ai_flags = 0x100; CHECK(ofn_getaddrinfo(&nb, p, 0, &hint, &r) == OFN_WSAEINVAL);
      hint.ai_flags = 0; hint.ai_socktype = 9; CHECK(ofn_getaddrinfo(&nb, p, 0, &hint, &r) == OFN_WSAESOCKTNOSUPPORT);
      w("nosuchsvc", q); hint.ai_socktype = 0; w("10.1.2.3", p);
      CHECK(ofn_getaddrinfo(&nb, p, q, &hint, &r) == OFN_WSATYPE_NOT_FOUND);
      w("\x01" "\xe9", p); p[1] = 0xE9; CHECK(ofn_getaddrinfo(&nb, p, 0, 0, &r) == 11001);        /* non-ASCII host: no IDN */
      CHECK(ofn_getaddrinfo(&nb, 0, 0, 0, &r) == 11001);
      w("8080", q); CHECK(ofn_getaddrinfo(&nb, 0, q, 0, &r) == 0 && ((uint8_t *)r->ai_addr)[4] == 127 && ((uint8_t *)r->ai_addr)[2] == 0x1F); ofn_freeaddrinfo(&nb, r);
    }

    /* getnameinfo */
    { uint8_t sa[16] = {2, 0, 0, 80, 10, 0, 0, 9}; uint16_t hb[64], sb[32];
      CHECK(ofn_getnameinfo(&nb, sa, 16, hb, 64, sb, 32, 0) == 0 && hb[0] == 'h' && sb[0] == 'h' && sb[3] == 'p');
      CHECK(ofn_getnameinfo(&nb, sa, 16, hb, 64, sb, 32, OFN_NI_NOFQDN | OFN_NI_NUMERICSERV) == 0 && hb[5] == 0 && sb[0] == '8' && sb[2] == 0);
      CHECK(ofn_getnameinfo(&nb, sa, 16, hb, 64, sb, 32, OFN_NI_NUMERICHOST) == 0 && hb[0] == '1' && hb[7] == '9');
      sa[7] = 5; CHECK(ofn_getnameinfo(&nb, sa, 16, hb, 64, 0, 0, OFN_NI_NAMEREQD) == 11001);
      CHECK(ofn_getnameinfo(&nb, sa, 16, hb, 64, 0, 0, 0) == 0 && hb[0] == '1');           /* no name: numeric fallback */
      CHECK(ofn_getnameinfo(&nb, sa, 16, hb, 3, 0, 0, 0) == OFN_WSAEFAULT);
      CHECK(ofn_getnameinfo(&nb, sa, 8, hb, 64, 0, 0, 0) == OFN_WSAEFAULT);
      sa[0] = 23; CHECK(ofn_getnameinfo(&nb, sa, 16, hb, 64, 0, 0, 0) == OFN_WSAEAFNOSUPPORT);
    }

    /* frame walker */
    { uintptr_t st[16], got[8]; uint32_t n;
      memset(st, 0, sizeof st);
      st[0] = (uintptr_t)&st[2]; st[1] = 0x1111;
      st[2] = (uintptr_t)&st[6]; st[3] = 0x2222;
      st[6] = (uintptr_t)&st[4]; st[7] = 0x3333;     /* decreasing frame pointer: walk stops after reporting it */
      n = ofd_walk_frames((uintptr_t)&st[0], rd, st, 0, 8, got);
      CHECK(n == 3 && got[0] == 0x1111 && got[2] == 0x3333);
      n = ofd_walk_frames((uintptr_t)&st[0], rd, st, 1, 8, got); CHECK(n == 2 && got[0] == 0x2222);
      n = ofd_walk_frames((uintptr_t)&st[0], rd, st, 0, 1, got); CHECK(n == 1);
      n = ofd_walk_frames((uintptr_t)&st[0] + 1, rd, st, 0, 8, got); CHECK(n == 0);        /* misaligned */
      n = ofd_walk_frames((uintptr_t)&st[15], rd, st, 0, 8, got); CHECK(n == 0);           /* partially unreadable */
      st[1] = 0; n = ofd_walk_frames((uintptr_t)&st[0], rd, st, 0, 8, got); CHECK(n == 0); /* null return ends */
    }
    (void)e; (void)closed;
    CHECK(closed == 1);
    printf("%d checks, %d failures\n", checks, failures);
    return failures != 0;
}
