/* SPDX-License-Identifier: GPL-2.0-only
 * Host controls for gdi_noto.c (the production adapter core gdi32.dll runs for ExtTextOutW, GetTextExtent*, ABC and
 * metrics), over the real NotoProvider + FreeType. Host Noto files stand in for the guest assets (different bytes, so the
 * pins here are the HOST file hashes). NOT a guest, visual or strict-build proof.
 *   cc -std=c11 -Wall -Wextra -Werror -fsanitize=address,undefined -g -I.. -I$FONT -I$FT $FONT/noto_provider.c \
 *      $BCRYPT/hashes.c ../gdi_noto.c gdi_noto_host.c -lfreetype */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "gdi_noto.h"
static int fails, checks;
#define CHECK(c) do { ++checks; if (!(c)) { printf("FAIL %d: %s\n", __LINE__, #c); ++fails; } } while (0)
#define LATIN_PATH "/usr/share/fonts/google-noto-vf/NotoSans[wght].ttf"
#define KR_PATH "/usr/share/fonts/google-noto-sans-cjk-vf-fonts/NotoSansCJK-VF.ttc"
#define LATIN_PIN "8b23d6341a12454e68e35c2c0917f0504104ded6aa3024d18e9d462da06fadd3"
#define KR_PIN "d3d8256cdec8dbcb3552284bc6b20c734dd60c2ee9df83b5758e34807c4bac32"
static uint8_t lpin[32], kpin[32], zpin[32];
static const char *lpath = LATIN_PATH;
static long live, allocs, fail_at;
static void *xa(void *c, size_t n) { (void)c; if (fail_at && ++allocs >= fail_at) return NULL; void *p = malloc(n); if (p) ++live; return p; }
static void xf(void *c, void *p) { (void)c; if (p) { --live; free(p); } }
static NotoConfig cfg = { xa, xf, NULL, 0 };
static void rel(void *c, const void *d) { (void)c; free((void *)d); }
static int load(const char *path, long idx, const uint8_t *pin, NotoFontSource *s)
{
    FILE *f = fopen(path, "rb"); long n;
    memset(s, 0, sizeof *s); s->face_index = idx; s->release = rel; s->expected_sha256 = pin;
    if (!f) return 0;
    fseek(f, 0, SEEK_END); n = ftell(f); fseek(f, 0, SEEK_SET);
    s->data = malloc((size_t)n); s->size = fread((void *)s->data, 1, (size_t)n, f); fclose(f);
    return 1;
}
static const uint8_t *cur_kpin = kpin;
static NotoStatus opener(void *ctx, NotoProvider **out)
{
    NotoFontSource l, k; (void)ctx;
    if (!load(lpath, 0, lpin, &l)) return NOTO_E_UNAVAILABLE;
    load(KR_PATH, 1, cur_kpin, &k);
    return noto_create_ex(&cfg, &l, &k, out);
}
static uint64_t clock_ms;
static uint64_t now(void) { return clock_ms; }

static uint32_t *mk(int w, int h, uint32_t v) { uint32_t *b = malloc((size_t)w * h * 4); for (int i = 0; i < w * h; ++i) b[i] = v; return b; }
static int runs_n, runs_bad, abort_after;
static int runfn(void *c, int x, int y, int n) { (void)c; ++runs_n; if (x < 0 || y < 0 || n <= 0) ++runs_bad; return abort_after && runs_n >= abort_after; }

int main(void)
{
    GdiNoto g; NotoProvider *p; NotoStatus st; int px, cx, cy, i, fit;
    noto_pin_from_hex(LATIN_PIN, lpin); noto_pin_from_hex(KR_PIN, kpin);
    /* ---- lifetime: missing asset, wrong hash, retry, release */
    lpath = "/nonexistent/NotoSans.ttf"; clock_ms = 100;
    gdi_noto_init(&g, opener, NULL, now);
    CHECK(gdi_noto_get(&g, &st) == NULL && st == NOTO_E_UNAVAILABLE);
    CHECK(gdi_noto_get(&g, &st) == NULL && st == NOTO_E_UNAVAILABLE && g.open_failures == 1);   /* cached inside the window */
    clock_ms += GDI_NOTO_RETRY_MS + 1; lpath = LATIN_PATH;
    p = gdi_noto_get(&g, &st); CHECK(p && st == NOTO_OK && g.opens == 1);
    CHECK(gdi_noto_get(&g, &st) == p);
    CHECK(gdi_noto_release(&g) == NOTO_OK && live == 0 && g.p == NULL);
    cur_kpin = zpin; gdi_noto_init(&g, opener, NULL, now);
    CHECK(gdi_noto_get(&g, &st) == NULL && st == NOTO_E_HASH && live == 0);
    clock_ms += 10 * GDI_NOTO_RETRY_MS; cur_kpin = kpin;
    CHECK(gdi_noto_get(&g, &st) == NULL && st == NOTO_E_HASH);          /* a hash failure is never silently retried */
    for (int k = 1; k <= 6; ++k) {                                      /* allocator failure injection: no leak, visible error */
        gdi_noto_init(&g, opener, NULL, NULL); allocs = 0; fail_at = k;
        p = gdi_noto_get(&g, &st);
        fail_at = 0;
        if (!p) { if (st != NOTO_E_NOMEM || live) printf("inject k=%d st=%s live=%ld\n", k, noto_status_str(st), live); CHECK(live == 0 && st != NOTO_OK && st != NOTO_E_HASH); } else gdi_noto_release(&g);
    }
    CHECK(live == 0);
    gdi_noto_init(&g, opener, NULL, NULL);
    p = gdi_noto_get(&g, &st); CHECK(p != NULL);
    if (!p) { printf("provider unavailable, abort\n"); return 1; }

    /* ---- height resolution and metrics */
    CHECK(gdi_noto_resolve_px(p, -16, &px) == NOTO_OK && px == 16);
    CHECK(gdi_noto_resolve_px(p, -128, &px) == NOTO_OK && px == 128);
    CHECK(gdi_noto_resolve_px(p, -129, &px) == NOTO_E_RANGE);
    CHECK(gdi_noto_resolve_px(p, INT32_MIN, &px) == NOTO_E_RANGE);
    CHECK(gdi_noto_resolve_px(p, 100000, &px) == NOTO_E_RANGE);
    { GdiNotoTM t; int pxc;
      CHECK(gdi_noto_resolve_px(p, 16, &pxc) == NOTO_OK && gdi_noto_text_metrics(p, pxc, &t) == NOTO_OK && t.height <= 16 && t.height >= 14);
      CHECK(gdi_noto_resolve_px(p, 0, &pxc) == NOTO_OK && pxc >= 10 && pxc <= 13);
      CHECK(gdi_noto_text_metrics(p, 16, &t) == NOTO_OK && t.ascent > 12 && t.descent > 3 && t.height == t.ascent + t.descent);
      CHECK(t.avg_width >= 6 && t.avg_width <= 10 && t.max_width >= t.avg_width);
      CHECK(gdi_noto_text_metrics(p, 0, &t) != NOTO_OK && gdi_noto_text_metrics(p, 129, &t) != NOTO_OK); }

    /* ---- measuring: extent, extent_ex, char width and ABC agree */
    { uint16_t t[] = { 'H', 'e', 'l', 'l', 'o', ' ', 0xAC00, 0xD55C, 0xD83D, 0xDE00, 'x' }; int dxv[11]; int cx2, cy2; size_t n = 11;
      CHECK(gdi_noto_extent(p, t, n, 16, &cx, &cy, NULL) == NOTO_OK && cx > 40 && cy >= 16);
      CHECK(gdi_noto_extent_ex(p, t, n, 16, -1, &fit, dxv, &cx2, &cy2) == NOTO_OK && cx2 == cx && cy2 == cy && fit == 11 && dxv[10] == cx);
      for (i = 1; i < 11; ++i) CHECK(dxv[i] >= dxv[i - 1]);
      CHECK(dxv[8] == dxv[9]);                                           /* both units of the surrogate pair */
      CHECK(gdi_noto_extent_ex(p, t, n, 16, dxv[8] - 1, &fit, NULL, NULL, NULL) == NOTO_OK && fit == 8);   /* pair not split */
      CHECK(gdi_noto_extent_ex(p, t, n, 16, 0, &fit, NULL, NULL, NULL) == NOTO_OK && fit == 0);
      CHECK(gdi_noto_extent(p, t, NOTO_MAX_TEXT + 1, 16, &cx, &cy, NULL) != NOTO_OK);
      CHECK(gdi_noto_extent(p, t, n, 0, &cx, &cy, NULL) != NOTO_OK && gdi_noto_extent(p, t, n, 129, &cx, &cy, NULL) != NOTO_OK);
      for (uint32_t c = 0x20; c < 0x7f; ++c) { int w; GdiNotoABC a;
          CHECK(gdi_noto_char_width(p, c, 24, &w) == NOTO_OK && gdi_noto_abc(p, c, 24, &a) == NOTO_OK && a.a + a.b + a.c == w && a.b >= 0); }
      { int w1, w2; uint16_t one[1] = { 'W' };
        CHECK(gdi_noto_char_width(p, 'W', 20, &w1) == NOTO_OK && gdi_noto_extent(p, one, 1, 20, &w2, &cy, NULL) == NOTO_OK && w1 == w2); }
      { int wi, wW; gdi_noto_char_width(p, 'i', 16, &wi); gdi_noto_char_width(p, 'W', 16, &wW); CHECK(wW > wi + 4); }   /* variable pitch: not 8x16 */
      CHECK(gdi_noto_char_width(p, 0xD800, 16, &cx) == NOTO_E_PARAM); }

    /* ---- drawing: real AA coverage into the actual destination */
    { enum { W = 96, H = 40 };
      uint16_t t[] = { 'H', 'g', 'a', 0xAC00 };
      uint32_t *a = mk(W, H, 0xAAF0F0F0u), *b = mk(W, H, 0xAAF0F0F0u), *c2 = mk(W, H, 0xAAF0F0F0u);
      GdiNotoSurface sa = { a, W, H, 1 }, sb = { b, W, H, 1 };
      GdiNotoDirty da, db, dc2; NotoRect full = { 0, 0, W, H }, part = { 10, 0, 30, 20 };
      memset(&da, 0, sizeof da); memset(&db, 0, sizeof db); memset(&dc2, 0, sizeof dc2);
      CHECK(gdi_noto_draw(p, &sa, &full, 1, t, 4, 16, 4, 4, NULL, 0x00102030u, &da) == NOTO_OK && da.valid);
      int partial = 0, full_cov = 0, changed = 0, alpha_ok = 1, out_dirty = 0;
      for (int y = 0; y < H; ++y) for (int x = 0; x < W; ++x) {
          uint32_t v = a[y * W + x];
          if ((v >> 24) != 0xAA) alpha_ok = 0;
          if (v != 0xAAF0F0F0u) { ++changed; if (x < da.r.left || x >= da.r.right || y < da.r.top || y >= da.r.bottom) ++out_dirty; }
          if (v != 0xAAF0F0F0u && v != 0xAA102030u) ++partial;
          if (v == 0xAA102030u) ++full_cov; }
      CHECK(changed > 60 && partial > 20 && full_cov > 5 && alpha_ok && out_dirty == 0);       /* AA, not 1 bit */
      { int wide = 0; for (int y = 0; y < H; ++y) for (int x = 62; x < W; ++x) if (a[y * W + x] != 0xAAF0F0F0u) wide = 1; CHECK(wide || da.r.right > 30); }
      /* clip: pixels outside untouched, inside identical to the unclipped draw */
      CHECK(gdi_noto_draw(p, &sb, &part, 1, t, 4, 16, 4, 4, NULL, 0x00102030u, &db) == NOTO_OK);
      { int bad = 0, any = 0; for (int y = 0; y < H; ++y) for (int x = 0; x < W; ++x) {
            int in = x >= 10 && x < 30 && y < 20;
            if (in && b[y * W + x] != a[y * W + x]) ++bad;
            if (!in && b[y * W + x] != 0xAAF0F0F0u) ++bad;
            if (in && b[y * W + x] != 0xAAF0F0F0u) any = 1; }
        CHECK(bad == 0 && any && db.r.left >= 10 && db.r.right <= 30 && db.r.bottom <= 20); }
      /* two disjoint rectangles == the union, nothing doubly blended */
      { NotoRect two[2] = { { 0, 0, 20, H }, { 20, 0, W, H } }; GdiNotoSurface sc = { c2, W, H, 1 };
        CHECK(gdi_noto_draw(p, &sc, two, 2, t, 4, 16, 4, 4, NULL, 0x00102030u, &dc2) == NOTO_OK && memcmp(c2, a, (size_t)W * H * 4) == 0); }
      /* negative control: a second blend over the same pixels changes them, so the equality checks above can fail */
      { uint32_t *d2 = malloc((size_t)W * H * 4); GdiNotoDirty dd; GdiNotoSurface sd = { d2, W, H, 1 }; memset(&dd, 0, sizeof dd);
        memcpy(d2, a, (size_t)W * H * 4);
        CHECK(gdi_noto_draw(p, &sd, &full, 1, t, 4, 16, 4, 4, NULL, 0x00102030u, &dd) == NOTO_OK && memcmp(d2, a, (size_t)W * H * 4) != 0);
        free(d2); }
      /* bottom-up surface mirrors top-down */
      { uint32_t *u = mk(W, H, 0xAAF0F0F0u); GdiNotoSurface su = { u, W, H, 0 }; GdiNotoDirty du; int bad = 0; memset(&du, 0, sizeof du);
        CHECK(gdi_noto_draw(p, &su, &full, 1, t, 4, 16, 4, 4, NULL, 0x00102030u, &du) == NOTO_OK);
        for (int y = 0; y < H; ++y) for (int x = 0; x < W; ++x) if (u[(H - 1 - y) * W + x] != a[y * W + x]) ++bad;
        CHECK(bad == 0); free(u); }
      /* explicit dx: pen follows the caller advances */
      { int dxv[4] = { 20, 20, 20, 20 }; uint32_t *e = mk(W, H, 0xAAF0F0F0u); GdiNotoSurface se = { e, W, H, 1 }; GdiNotoDirty de; int neg[4] = { 5, -1, 5, 5 };
        memset(&de, 0, sizeof de);
        CHECK(gdi_noto_draw(p, &se, &full, 1, t, 4, 16, 2, 4, dxv, 0x00102030u, &de) == NOTO_OK && de.valid && de.r.right > 60 && de.r.right <= 2 + 80 + 16);
        CHECK(gdi_noto_draw(p, &se, &full, 1, t, 4, 16, 2, 4, neg, 0x00102030u, &de) == NOTO_E_PARAM);
        free(e); }
      /* Hangul comes from the KR face, no .notdef */
      { uint16_t k[1] = { 0xD55C }; NotoExtent ex; CHECK(noto_measure_px(p, k, 1, 24, &ex) == NOTO_OK && ex.missing == 0 && ex.glyphs == 1); }
      /* bounds: tiny exact-size surface (ASan flags any overrun), huge/offscreen coordinates, bad args */
      { uint32_t *s1 = mk(1, 1, 0x00ffffffu); GdiNotoSurface s1s = { s1, 1, 1, 1 }; NotoRect all = { -1000, -1000, 1000, 1000 }; GdiNotoDirty d1;
        memset(&d1, 0, sizeof d1);
        CHECK(gdi_noto_draw(p, &s1s, &all, 1, t, 4, 40, -3, -10, NULL, 0, &d1) == NOTO_OK);
        CHECK(gdi_noto_draw(p, &s1s, &all, 1, t, 4, 40, 1 << 30, 0, NULL, 0, &d1) != NOTO_OK);
        CHECK(gdi_noto_draw(p, &s1s, &all, 1, t, 4, 200, 0, 0, NULL, 0, &d1) != NOTO_OK);
        CHECK(gdi_noto_draw(p, &s1s, NULL, 1, t, 4, 16, 0, 0, NULL, 0, &d1) == NOTO_E_PARAM);
        CHECK(gdi_noto_draw(p, &s1s, &all, GDI_NOTO_MAX_RECTS + 1, t, 4, 16, 0, 0, NULL, 0, &d1) == NOTO_E_PARAM);
        CHECK(gdi_noto_draw(p, &s1s, &all, 1, t, NOTO_MAX_TEXT + 1, 16, 0, 0, NULL, 0, &d1) == NOTO_E_PARAM);
        CHECK(gdi_noto_draw(p, &s1s, &all, 1, NULL, 0, 16, 0, 0, NULL, 0, &d1) == NOTO_OK);
        free(s1); }
      /* path runs: bounded, abortable */
      { runs_n = runs_bad = 0; abort_after = 0;
        CHECK(gdi_noto_runs(p, t, 4, 16, 4, 4, NULL, runfn, NULL) == NOTO_OK && runs_n > 10 && runs_bad == 0);
        runs_n = 0; abort_after = 3; CHECK(gdi_noto_runs(p, t, 4, 16, 4, 4, NULL, runfn, NULL) == NOTO_E_ABORT && runs_n == 3);
        abort_after = 0; CHECK(gdi_noto_runs(p, t, 4, 16, 4, 4, NULL, NULL, NULL) == NOTO_E_PARAM); }
      free(a); free(b); free(c2); }
    CHECK(gdi_noto_blend(0xAA000000u, 0x00ffffffu, 255) == 0xAAffffffu && gdi_noto_blend(0x11223344u, 0, 0) == 0x11223344u);
    CHECK(gdi_noto_blend(0xFF000000u, 0x00ffffffu, 128) == 0xFF808080u);
    CHECK(gdi_noto_release(&g) == NOTO_OK && live == 0);
    printf("gdi_noto host: %d checks, %d failed\n", checks, fails);
    return fails ? 1 : 0;
}
