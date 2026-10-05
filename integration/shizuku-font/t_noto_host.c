/* Host control: real FreeType (host libfreetype stands in for the COFF archive), real Noto bytes read
 * read-only from the installed original fonts. Not a guest test. Every CHECK can fail; the harness also
 * runs negative controls proving the image comparison detects a double-blend. */
#include <limits.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "noto_provider.h"
static int fails, rel_calls;
#define CHECK(c) do { if (!(c)) { printf("FAIL %d: %s\n", __LINE__, #c); ++fails; } } while (0)
#define LATIN_PATH "/usr/share/fonts/google-noto-vf/NotoSans[wght].ttf"
#define KR_PATH "/usr/share/fonts/google-noto-sans-cjk-vf-fonts/NotoSansCJK-VF.ttc"
#define LATIN_PIN "8b23d6341a12454e68e35c2c0917f0504104ded6aa3024d18e9d462da06fadd3"
#define KR_PIN "d3d8256cdec8dbcb3552284bc6b20c734dd60c2ee9df83b5758e34807c4bac32"
static uint8_t lpin[32], kpin[32], zpin[32];

static void rel(void *ctx, const void *d) { (void)ctx; ++rel_calls; free((void *)d); }
static NotoFontSource load(const char *path, long idx, const uint8_t *pin)
{
    NotoFontSource s; FILE *f = fopen(path, "rb"); long n;
    memset(&s, 0, sizeof s); s.face_index = idx; s.release = rel; s.expected_sha256 = pin;
    if (!f) return s;
    fseek(f, 0, SEEK_END); n = ftell(f); fseek(f, 0, SEEK_SET);
    s.data = malloc((size_t)n); s.size = fread((void *)s.data, 1, (size_t)n, f); fclose(f);
    return s;
}

/* counting allocator */
typedef struct { long allocs, frees; size_t live; } Acct;
static void *a_alloc(void *c, size_t n) { Acct *a = c; void *p = malloc(n); if (p) { ++a->allocs; a->live += n; } return p; }
static void a_free(void *c, void *p) { Acct *a = c; if (p) { ++a->frees; } free(p); }

typedef struct {
    int w, h; unsigned char *px; int calls, abort_every, abort_at, clipviol, nospan_after_commit; NotoRect clip;
    int commit_then_fail; int reenter; NotoProvider *p; int busy_ok, destroy_busy;
} Img;
static int blend(Img *m, int x, int y, const uint8_t *cov, int n)
{
    int i;
    if (x < m->clip.left || y < m->clip.top || x + n > m->clip.right || y >= m->clip.bottom) ++m->clipviol;
    for (i = 0; i < n; ++i) if (x + i >= 0 && x + i < m->w && y >= 0 && y < m->h) {
        unsigned char *d = &m->px[y * m->w + x + i];
        *d = (unsigned char)((*d * (255 - cov[i]) + 127) / 255);   /* black over destination: NOT idempotent */
    }
    return 0;
}
static int cb(void *c, int x, int y, const uint8_t *cov, int n)
{
    Img *m = c; int fail = 0;
    ++m->calls;
    if (m->abort_at && m->calls == m->abort_at) { m->abort_at = 0; fail = 1; }
    if (m->abort_every && m->calls % m->abort_every == 0) fail = 1;
    if (fail && m->commit_then_fail) blend(m, x, y, cov, n);   /* BROKEN callback used as negative control */
    if (fail) return 1;
    return blend(m, x, y, cov, n);
}
static int cb_reenter(void *c, int x, int y, const uint8_t *cov, int n)
{
    Img *m = c; NotoExtent e; uint16_t t = 'a'; NotoMetrics mt; NotoGlyph g; int pres;
    if (!m->reenter) { m->reenter = 1;
        m->busy_ok = noto_measure(m->p, &t, 1, 1, &e) == NOTO_E_BUSY && noto_metrics(m->p, 1, &mt) == NOTO_E_BUSY &&
                     noto_glyph(m->p, 'a', 1, &g) == NOTO_E_BUSY && noto_query_glyph(m->p, 'a', &pres) == NOTO_E_BUSY &&
                     noto_has_glyph(m->p, 'a') == 0 && noto_draw(m->p, &t, 1, 1, 0, 0, NULL, cb, m, NULL) == NOTO_E_BUSY &&
                     noto_family(m->p, 0) != NULL;
        m->destroy_busy = noto_destroy(m->p) == NOTO_E_BUSY;   /* must not free: we keep drawing below */
    }
    return blend(m, x, y, cov, n);
}
static void w16(uint16_t *o, const char *s) { while ((*o++ = (unsigned char)*s++)) { } }
static void img_init(Img *m, int w, int h, const NotoRect *clip)
{
    memset(m, 0, sizeof *m); m->w = w; m->h = h; m->px = malloc((size_t)w * h); memset(m->px, 255, (size_t)w * h);
    m->clip.left = clip ? clip->left : 0; m->clip.top = clip ? clip->top : 0;
    m->clip.right = clip ? clip->right : w; m->clip.bottom = clip ? clip->bottom : h;
}
/* draw with periodic aborts, resuming until done; returns number of aborts, -1 on error */
static int draw_resumed(NotoProvider *p, const uint16_t *t, size_t n, int px, int x, int y, const NotoRect *clip, Img *m, NotoPen *pen)
{
    int aborts = 0, guard = 0;
    for (;;) {
        NotoStatus st = noto_draw_px(p, t, n, px, x, y, clip, cb, m, pen);
        if (st == NOTO_OK) return aborts;
        if (st != NOTO_E_ABORT || ++guard > 100000) return -1;
        ++aborts;
    }
}

int main(void)
{
    NotoProvider *p = NULL; uint16_t a[64], b[64]; NotoExtent e1, e2; NotoGlyph g; Img im;
    NotoStatus st; unsigned u, hangul = 0, jamo = 0, grey = 0, full = 0, i; NotoRect clip = {2, 2, 30, 20};
    NotoFontSource L, K;
    CHECK(noto_pin_from_hex(LATIN_PIN, lpin) == NOTO_OK && noto_pin_from_hex(KR_PIN, kpin) == NOTO_OK);
    CHECK(noto_pin_from_hex("zz", zpin) == NOTO_E_PARAM && noto_pin_from_hex(LATIN_PIN "0", zpin) == NOTO_E_PARAM);
    { uint8_t d[32], pe[32]; noto_sha256("abc", 3, d);   /* FIPS 180-4 vector */
      noto_pin_from_hex("ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad", pe);
      CHECK(memcmp(d, pe, 32) == 0); }

    /* --- negative identity controls, before the good create --- */
    L = load(LATIN_PATH, 0, lpin); K = load(KR_PATH, 1, kpin); rel_calls = 0;
    L.expected_sha256 = NULL; CHECK(noto_create(&L, &K, &p) == NOTO_E_PARAM && !p && rel_calls == 2);   /* no pin */
    L = load(LATIN_PATH, 0, lpin); K = load(KR_PATH, 1, zpin); rel_calls = 0;
    CHECK(noto_create(&L, &K, &p) == NOTO_E_HASH && !p && rel_calls == 2);                                /* wrong pin */
    L = load(LATIN_PATH, 0, lpin); K = load(KR_PATH, 1, kpin); rel_calls = 0;
    ((unsigned char *)K.data)[K.size / 2] ^= 1;                                                           /* corrupt byte */
    CHECK(noto_create(&L, &K, &p) == NOTO_E_HASH && !p && rel_calls == 2);
    L = load(LATIN_PATH, 0, lpin); K = load(KR_PATH, 1, kpin); rel_calls = 0;                              /* swapped roles */
    { NotoFontSource t2 = L; L = K; K = t2; }
    CHECK(noto_create(&L, &K, &p) != NOTO_OK && !p && rel_calls == 2);
    { uint8_t spin[32]; NotoFontSource S, S2;      /* correct hash of a different Noto family: identity by hash AND family */
      FILE *f = fopen("/usr/share/fonts/google-noto-vf/NotoSerif[wght].ttf", "rb");
      if (f) { fclose(f); S = load("/usr/share/fonts/google-noto-vf/NotoSerif[wght].ttf", 0, spin);
               noto_sha256(S.data, S.size, spin); S.expected_sha256 = spin;
               S2 = load(KR_PATH, 1, kpin); rel_calls = 0;
               CHECK(noto_create(&S, &S2, &p) == NOTO_E_FAMILY && !p && rel_calls == 2); } }
    { uint8_t kpin2[32]; NotoFontSource A2 = load(LATIN_PATH, 0, lpin), B2 = load(LATIN_PATH, 0, lpin);   /* latin used as KR, valid hash */
      noto_sha256(B2.data, B2.size, kpin2); B2.expected_sha256 = kpin2; rel_calls = 0;
      CHECK(noto_create(&A2, &B2, &p) == NOTO_E_FAMILY && !p && rel_calls == 2); }
    { NotoFontSource A2 = load(KR_PATH, 0, kpin), B2 = load(KR_PATH, 1, kpin); rel_calls = 0;              /* CJK face 0 = "Noto Sans CJK JP" as latin */
      CHECK(noto_create(&A2, &B2, &p) == NOTO_E_FAMILY && !p && rel_calls == 2); }
    /* aliasing: same struct and same pointer: exactly one release */
    L = load(LATIN_PATH, 0, lpin); rel_calls = 0;
    CHECK(noto_create(&L, &L, &p) == NOTO_E_PARAM && !p && rel_calls == 1);
    L = load(LATIN_PATH, 0, lpin); K = L; rel_calls = 0;
    CHECK(noto_create(&L, &K, &p) == NOTO_E_PARAM && !p && rel_calls == 1);
    /* bad bytes: release once each */
    { NotoFontSource x, y; memset(&x, 0, sizeof x); memset(&y, 0, sizeof y);
      x.data = malloc(100); memset((void *)x.data, 7, 100); x.size = 100; x.release = rel; x.expected_sha256 = zpin;
      y.data = malloc(10); y.size = 10; y.release = rel; y.expected_sha256 = zpin; rel_calls = 0;
      CHECK(noto_create(&x, &y, &p) == NOTO_E_HASH && !p && rel_calls == 2); }
    /* NULL provider reports unavailable explicitly */
    CHECK(noto_measure_px(NULL, a, 0, 16, &e1) == NOTO_E_UNAVAILABLE && noto_draw_px(NULL, a, 0, 16, 0, 0, NULL, cb, &im, NULL) == NOTO_E_UNAVAILABLE);
    CHECK(noto_glyph_px(NULL, 'a', 16, &g) == NOTO_E_UNAVAILABLE && noto_metrics_px(NULL, 16, NULL) == NOTO_E_UNAVAILABLE);
    CHECK(noto_destroy(NULL) == NOTO_OK && !noto_has_glyph(NULL, 'a'));

    /* --- good create with counting allocator --- */
    { Acct ac = {0, 0, 0}; NotoConfig cfg; NotoProvider *q = NULL;
      cfg.alloc = a_alloc; cfg.free = a_free; cfg.ctx = &ac; cfg.max_ft_bytes = 0;
      L = load(LATIN_PATH, 0, lpin); K = load(KR_PATH, 1, kpin); rel_calls = 0;
      st = noto_create_ex(&cfg, &L, &K, &q);
      CHECK(st == NOTO_OK && q && ac.allocs > 10);
      if (q) { CHECK(noto_destroy(q) == NOTO_OK); }
      CHECK(ac.allocs == ac.frees && rel_calls == 2);
      printf("custom allocator: allocs=%ld frees=%ld\n", ac.allocs, ac.frees);
      cfg.max_ft_bytes = 4096; ac.allocs = ac.frees = 0; L = load(LATIN_PATH, 0, lpin); K = load(KR_PATH, 1, kpin); rel_calls = 0;
      CHECK(noto_create_ex(&cfg, &L, &K, &q) != NOTO_OK && ac.allocs == ac.frees && rel_calls == 2);   /* tiny budget fails, no leak */
      cfg.max_ft_bytes = NOTO_MAX_FT_BYTES + 1; L = load(LATIN_PATH, 0, lpin); K = load(KR_PATH, 1, kpin); rel_calls = 0;
      CHECK(noto_create_ex(&cfg, &L, &K, &q) == NOTO_E_PARAM && rel_calls == 2); }

    L = load(LATIN_PATH, 0, lpin); K = load(KR_PATH, 1, kpin); rel_calls = 0;
    st = noto_create(&L, &K, &p);
    printf("create=%d latin='%s' kr='%s' ftheap=%zu\n", st, noto_family(p, 0) ? noto_family(p, 0) : "-",
           noto_family(p, 1) ? noto_family(p, 1) : "-", noto_ft_bytes_in_use(p));
    CHECK(st == NOTO_OK && p);
    if (!p) return 1;
    CHECK(!strcmp(noto_family(p, 0), "Noto Sans") && !strcmp(noto_family(p, 1), "Noto Sans CJK KR"));
    w16(a, "iii"); w16(b, "WWW");
    CHECK(noto_measure(p, a, 3, 1, &e1) == NOTO_OK && noto_measure(p, b, 3, 1, &e2) == NOTO_OK);
    printf("iii=%.3f WWW=%.3f\n", e1.width26 / 64.0, e2.width26 / 64.0);
    CHECK(e1.width26 * 2 < e2.width26);
    CHECK((e1.width26 % 64) != 0 || (e2.width26 % 64) != 0);   /* at least one unrounded fractional advance */
    memset(&g, 0xA5, sizeof g);
    CHECK(noto_glyph(p, 'i', 1, &g) == NOTO_OK && g.advance > 0 && g.scalar == 'i' && !g.missing);
    printf("i adv26=%d abc=%d,%d,%d\n", g.advance, g.abc_a, g.abc_b, g.abc_c);
    CHECK(g.advance == g.abc_a + g.abc_b + g.abc_c);
    for (u = 0xAC00; u <= 0xD7A3; ++u) hangul += (unsigned)noto_has_glyph(p, u);
    for (u = 0x1100; u <= 0x11FF; ++u) jamo += (unsigned)noto_has_glyph(p, u);
    printf("hangul=%u/11172 jamo(1100-11FF)=%u/256\n", hangul, jamo);
    CHECK(hangul == 11172);

    /* pixel API equivalence and range */
    { NotoExtent s2, p32; NotoMetrics m1, m2; NotoGlyph g1, g2;
      CHECK(noto_measure(p, a, 3, 2, &s2) == NOTO_OK && noto_measure_px(p, a, 3, 32, &p32) == NOTO_OK && s2.width26 == p32.width26 && s2.cy == p32.cy);
      CHECK(noto_metrics(p, 3, &m1) == NOTO_OK && noto_metrics_px(p, 48, &m2) == NOTO_OK && !memcmp(&m1, &m2, sizeof m1));
      CHECK(noto_glyph(p, 0xD55C, 8, &g1) == NOTO_OK && noto_glyph_px(p, 0xD55C, 128, &g2) == NOTO_OK && !memcmp(&g1, &g2, sizeof g1));
      CHECK(noto_measure_px(p, a, 3, 13, &p32) == NOTO_OK && p32.cx > 0 && p32.cy > 0 && p32.cy < 40);
      CHECK(noto_measure_px(p, a, 3, 1, &p32) == NOTO_OK && noto_measure_px(p, a, 3, 128, &p32) == NOTO_OK);
      CHECK(noto_measure_px(p, a, 3, 0, &p32) == NOTO_E_RANGE && noto_measure_px(p, a, 3, 129, &p32) == NOTO_E_RANGE);
      CHECK(noto_measure(p, a, 3, 0, &p32) == NOTO_E_RANGE && noto_measure(p, a, 3, 9, &p32) == NOTO_E_RANGE); }

    /* Korean AA + measure/draw pair */
    a[0] = 0xAC01; a[1] = 'W'; a[2] = 0xD55C; a[3] = 0;
    CHECK(noto_measure_px(p, a, 3, 16, &e1) == NOTO_OK);
    img_init(&im, 64, 32, NULL);
    CHECK(noto_draw_px(p, a, 3, 16, 1, 1, NULL, cb, &im, NULL) == NOTO_OK && im.clipviol == 0);
    for (i = 0; i < 64u * 32; ++i) if (im.px[i] != 255) { if (im.px[i] == 0) ++full; else ++grey; }
    printf("measure cx=%d cy=%d; ink full=%u grey=%u\n", e1.cx, e1.cy, full, grey);
    CHECK(grey > full / 4 && grey > 20);
    { int maxx = 0, y, x; for (y = 0; y < 32; ++y) for (x = 0; x < 64; ++x) if (im.px[y * 64 + x] != 255 && x > maxx) maxx = x;
      CHECK(maxx <= 1 + e1.cx); }
    free(im.px);

    /* resume exactness: one-shot vs resumed at every span, clipped and unclipped, blending callback */
    { Img one, res; NotoPen pen; int ab, k, spans; unsigned char *ref;
      uint16_t t[8]; w16(t, "Wi\xed\x95"); t[2] = 0xD55C; t[3] = 'g'; t[4] = 0xAC01; t[5] = 0;
      for (k = 0; k < 2; ++k) {
          const NotoRect *cp = k ? &clip : NULL;
          img_init(&one, 80, 32, cp);
          CHECK(noto_draw_px(p, t, 5, 16, 1, 3, cp, cb, &one, NULL) == NOTO_OK);
          spans = one.calls; ref = one.px;
          CHECK(spans > 15 && one.clipviol == 0);
          { int every;
            for (every = 2; every <= spans + 1; every += (every < 12 ? 1 : 7)) {      /* abort every Nth span */
                img_init(&res, 80, 32, cp); res.abort_every = every; memset(&pen, 0, sizeof pen);
                ab = draw_resumed(p, t, 5, 16, 1, 3, cp, &res, &pen);
                CHECK(ab >= 0 && memcmp(res.px, ref, 80 * 32) == 0 && res.clipviol == 0 && pen.cursor == 5 && pen.row == 0);
                if (memcmp(res.px, ref, 80 * 32) != 0) { printf("resume mismatch every=%d clip=%d\n", every, k); free(res.px); break; }
                free(res.px);
            } }
          /* single abort at each span index */
          { int at;
            for (at = 1; at <= spans; ++at) {
                img_init(&res, 80, 32, cp); res.abort_at = at; memset(&pen, 0, sizeof pen);
                ab = draw_resumed(p, t, 5, 16, 1, 3, cp, &res, &pen);
                CHECK(ab == 1 && memcmp(res.px, ref, 80 * 32) == 0);
                free(res.px);
            } }
          /* NEGATIVE CONTROL: a callback that commits and then reports failure double-blends; the comparison must see it */
          img_init(&res, 80, 32, cp); res.abort_at = 3; res.commit_then_fail = 1; memset(&pen, 0, sizeof pen);
          CHECK(draw_resumed(p, t, 5, 16, 1, 3, cp, &res, &pen) == 1);
          CHECK(memcmp(res.px, ref, 80 * 32) != 0);
          free(res.px); free(one.px);
      }
      /* pen validation: size change on resume, bad cursor/row, extreme x26 */
      img_init(&res, 80, 32, NULL); res.abort_at = 2; memset(&pen, 0, sizeof pen);
      CHECK(noto_draw_px(p, t, 5, 16, 1, 3, NULL, cb, &res, &pen) == NOTO_E_ABORT && pen.pixel_size == 16);
      CHECK(noto_draw_px(p, t, 5, 17, 1, 3, NULL, cb, &res, &pen) == NOTO_E_PARAM);
      memset(&pen, 0, sizeof pen); pen.x26 = INT64_MAX; CHECK(noto_draw_px(p, t, 5, 16, 1, 3, NULL, cb, &res, &pen) == NOTO_E_PARAM);
      memset(&pen, 0, sizeof pen); pen.x26 = -1; CHECK(noto_draw_px(p, t, 5, 16, 1, 3, NULL, cb, &res, &pen) == NOTO_E_PARAM);
      memset(&pen, 0, sizeof pen); pen.cursor = 6; CHECK(noto_draw_px(p, t, 5, 16, 1, 3, NULL, cb, &res, &pen) == NOTO_E_PARAM);
      memset(&pen, 0, sizeof pen); pen.row = 100000; CHECK(noto_draw_px(p, t, 5, 16, 1, 3, NULL, cb, &res, &pen) == NOTO_E_PARAM);
      memset(&pen, 0, sizeof pen); pen.row = 4000; CHECK(noto_draw_px(p, t, 5, 16, 1, 3, NULL, cb, &res, &pen) == NOTO_E_PARAM);   /* beyond glyph rows */
      memset(&pen, 0, sizeof pen); pen.x26 = ((int64_t)NOTO_COORD_LIMIT << 6) - 1;
      CHECK(noto_draw_px(p, t, 5, 16, 1, 3, NULL, cb, &res, &pen) == NOTO_E_RANGE);   /* advance would exceed the limit */
      free(res.px); }

    /* clip extremes and coordinate extremes: no UB, no violation, no crash */
    { Img c; NotoRect ex[4]; int k; uint16_t t[3] = {'W', 0xD55C, 0};
      ex[0].left = INT_MIN; ex[0].top = INT_MIN; ex[0].right = INT_MAX; ex[0].bottom = INT_MAX;
      ex[1].left = INT_MAX; ex[1].top = INT_MAX; ex[1].right = INT_MIN; ex[1].bottom = INT_MIN;
      ex[2].left = INT_MIN; ex[2].top = 0; ex[2].right = 5; ex[2].bottom = INT_MAX;
      ex[3].left = 10; ex[3].top = 10; ex[3].right = 5; ex[3].bottom = 5;
      for (k = 0; k < 4; ++k) {
          img_init(&c, 64, 32, NULL); c.clip = ex[0]; c.clip.left = INT_MIN; c.clip.top = INT_MIN; c.clip.right = INT_MAX; c.clip.bottom = INT_MAX;
          CHECK(noto_draw_px(p, t, 2, 16, 1, 1, &ex[k], cb, &c, NULL) == NOTO_OK);
          if (k == 1 || k == 3) CHECK(c.calls == 0);          /* empty/inverted clip draws nothing */
          if (k == 0) CHECK(c.calls > 10);
          free(c.px);
      }
      img_init(&c, 64, 32, NULL);
      CHECK(noto_draw_px(p, t, 2, 16, NOTO_COORD_LIMIT, NOTO_COORD_LIMIT, NULL, cb, &c, NULL) == NOTO_OK);
      CHECK(noto_draw_px(p, t, 2, 16, -NOTO_COORD_LIMIT, -NOTO_COORD_LIMIT, NULL, cb, &c, NULL) == NOTO_OK);
      CHECK(noto_draw_px(p, t, 2, 16, INT_MAX, 0, NULL, cb, &c, NULL) == NOTO_E_RANGE && noto_draw_px(p, t, 2, 16, 0, INT_MIN, NULL, cb, &c, NULL) == NOTO_E_RANGE);
      free(c.px); }

    /* bad input */
    { uint16_t bad[4] = {0xD800, 'a', 0xDC00, 0xD83D}; NotoExtent e; int pres = 0;
      CHECK(noto_measure(p, bad, 4, 1, &e) == NOTO_OK && e.replaced == 3 && e.glyphs == 4);
      CHECK(noto_measure(p, a, 40000, 1, &e) == NOTO_E_PARAM && noto_measure(p, NULL, 1, 1, &e) == NOTO_E_PARAM);
      CHECK(noto_glyph(p, 0xD800, 1, &g) == NOTO_E_PARAM && noto_glyph(p, 0x110000, 1, &g) == NOTO_E_PARAM);
      CHECK(noto_query_glyph(p, 0xD800, &pres) == NOTO_E_PARAM && !noto_has_glyph(p, 0x110000));
      CHECK(noto_query_glyph(p, 'a', &pres) == NOTO_OK && pres == 1); }
    /* missing glyph is reported by the engine (U+0378 is unassigned) */
    { uint16_t t[3] = {'a', 0x0378, 0}; NotoExtent e; NotoPen pen; Img c; memset(&pen, 0, sizeof pen);
      CHECK(noto_measure_px(p, t, 2, 16, &e) == NOTO_OK && e.missing == 1 && e.glyphs == 2);
      img_init(&c, 64, 32, NULL);
      CHECK(noto_draw_px(p, t, 2, 16, 0, 0, NULL, cb, &c, &pen) == NOTO_OK && pen.missing == 1 && pen.replaced == 0);
      free(c.px); }
    for (u = 1; u <= 8; ++u) { NotoGlyph gg; CHECK(noto_glyph(p, 0xD55C, (int)u, &gg) == NOTO_OK && gg.advance > 0); }

    /* busy: every entry point from a callback returns BUSY; destroy from the callback does not free */
    { Img r; uint16_t t[2] = {'W', 0}; img_init(&r, 64, 32, NULL); r.p = p;
      CHECK(noto_draw_px(p, t, 1, 20, 2, 2, NULL, cb_reenter, &r, NULL) == NOTO_OK);
      CHECK(r.busy_ok && r.destroy_busy && r.calls == 0);
      CHECK(noto_measure_px(p, t, 1, 16, &e1) == NOTO_OK);   /* context still alive and usable */
      free(r.px); }
    noto_destroy(p); CHECK(rel_calls == 2);
    printf("%s fails=%d\n", fails ? "FAIL" : "PASS-HOST-CONTROL", fails);
    return fails != 0;
}
