/* Host control: real FreeType (host libfreetype stands in for the COFF archive), real Noto bytes read
 * read-only from the installed fonts through a mock of the Win32 loader boundary. Not a guest test. */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "noto_provider.h"
static int fails, rel_calls;
#define CHECK(c) do { if (!(c)) { printf("FAIL %d: %s\n", __LINE__, #c); ++fails; } } while (0)
static void rel(void *ctx, const void *d) { (void)ctx; ++rel_calls; free((void *)d); }
static NotoFontSource load(const char *path, long idx)
{
    NotoFontSource s = {0}; FILE *f = fopen(path, "rb"); long n;
    s.face_index = idx; s.release = rel;
    if (!f) return s;
    fseek(f, 0, SEEK_END); n = ftell(f); fseek(f, 0, SEEK_SET);
    s.data = malloc((size_t)n); s.size = fread((void *)s.data, 1, (size_t)n, f); fclose(f);
    return s;
}
typedef struct { int w, h; unsigned char *px; int calls, abort_at, clipviol; NotoRect clip; } Img;
static int cb(void *c, int x, int y, const uint8_t *cov, int n)
{
    Img *m = c; int i;
    if (m->abort_at && ++m->calls == m->abort_at) { m->abort_at = 0; return 1; }
    if (x < m->clip.left || y < m->clip.top || x + n > m->clip.right || y >= m->clip.bottom) { ++m->clipviol; printf("viol x=%d y=%d n=%d\n", x, y, n); }
    for (i = 0; i < n; ++i) if (x + i >= 0 && x + i < m->w && y >= 0 && y < m->h) {
        unsigned char *d = &m->px[y * m->w + x + i]; /* composite black text over white background */
        *d = (unsigned char)((*d * (255 - cov[i]) + 127) / 255);
    }
    return 0;
}
static void w16(uint16_t *o, const char *s) { while ((*o++ = (unsigned char)*s++)) { } }
int main(void)
{
    NotoProvider *p = NULL; uint16_t a[64], b[64]; NotoExtent e1, e2; NotoGlyph g; Img im; NotoPen pen = {0, 0};
    NotoStatus st; unsigned u, hangul = 0, jamo = 0, grey = 0, bin = 0, i; NotoRect clip = {2, 2, 30, 20};
    NotoFontSource L = load("/usr/share/fonts/google-noto-vf/NotoSans[wght].ttf", 0);
    NotoFontSource K = load("/usr/share/fonts/google-noto-sans-cjk-vf-fonts/NotoSansCJK-VF.ttc", 1);
    st = noto_create(&L, &K, &p);
    printf("create=%d latin='%s' kr='%s' ftheap=%zu\n", st, noto_family(p, 0) ? noto_family(p, 0) : "-",
           noto_family(p, 1) ? noto_family(p, 1) : "-", noto_ft_bytes_in_use(p));
    CHECK(st == NOTO_OK && p);
    if (!p) return 1;
    w16(a, "iii"); w16(b, "WWW");
    CHECK(noto_measure(p, a, 3, 1, &e1) == NOTO_OK && noto_measure(p, b, 3, 1, &e2) == NOTO_OK);
    printf("iii=%.3f WWW=%.3f\n", e1.width26 / 64.0, e2.width26 / 64.0);
    CHECK(e1.width26 * 2 < e2.width26 && e1.width26 % 64 != 0 + 100000);
    printf("i adv26=%d abc=%d,%d,%d\n", g.advance, g.abc_a, g.abc_b, g.abc_c);
    for (u = 0xAC00; u <= 0xD7A3; ++u) hangul += (unsigned)noto_has_glyph(p, u);
    for (u = 0x1100; u <= 0x11FF; ++u) jamo += (unsigned)noto_has_glyph(p, u);
    printf("hangul=%u/11172 jamo(1100-11FF)=%u/256\n", hangul, jamo);
    CHECK(hangul == 11172);
    /* Korean AA + measure/draw pair */
    a[0] = 0xAC01; a[1] = 'W'; a[2] = 0xD55C; a[3] = 0;
    CHECK(noto_measure(p, a, 3, 1, &e1) == NOTO_OK);
    im.w = 64; im.h = 32; im.px = malloc(64 * 32); memset(im.px, 255, 64 * 32); im.abort_at = 0; im.calls = 0; im.clipviol = 0;
    im.clip.left = 0; im.clip.top = 0; im.clip.right = 64; im.clip.bottom = 32;
    CHECK(noto_draw(p, a, 3, 1, 1, 1, NULL, cb, &im, NULL) == NOTO_OK);
    for (i = 0; i < 64u * 32; ++i) if (im.px[i] != 255) { if (im.px[i] == 0) ++bin; else ++grey; }
    printf("measure cx=%d cy=%d; ink full=%u grey=%u\n", e1.cx, e1.cy, bin, grey);
    CHECK(grey > bin / 4 && grey > 20);
    { int maxx = 0, y, x; for (y = 0; y < 32; ++y) for (x = 0; x < 64; ++x) if (im.px[y * 64 + x] != 255 && x > maxx) maxx = x;
      CHECK(maxx <= 1 + e1.cx); }
    /* clip + retry */
    { Img c1, c2; unsigned char *r1, *r2;
      c1 = c2 = im; c1.px = r1 = malloc(2048); c2.px = r2 = malloc(2048); memset(r1, 255, 2048); memset(r2, 255, 2048);
      c1.clip = c2.clip = clip; c1.abort_at = 0; c2.abort_at = 5; c1.calls = c2.calls = 0;
      CHECK(noto_draw(p, a, 3, 1, 0, 0, &clip, cb, &c1, NULL) == NOTO_OK && c1.clipviol == 0);
      pen.cursor = 0; pen.x26 = 0;
      CHECK(noto_draw(p, a, 3, 1, 0, 0, &clip, cb, &c2, &pen) == NOTO_E_ABORT);
      CHECK(noto_draw(p, a, 3, 1, 0, 0, &clip, cb, &c2, &pen) == NOTO_OK && pen.cursor == 3);
      printf("retry pen.x26=%lld, clip viol=%d\n", (long long)pen.x26, c1.clipviol);
      CHECK(pen.x26 == e1.width26); free(r1); free(r2); }
    /* bad input */
    { uint16_t bad[4] = {0xD800, 'a', 0xDC00, 0xD83D}; NotoExtent e;
      CHECK(noto_measure(p, bad, 4, 1, &e) == NOTO_OK && e.replaced == 3 && e.glyphs == 4);
      CHECK(noto_measure(p, a, 3, 0, &e) == NOTO_E_RANGE && noto_measure(p, a, 3, 9, &e) == NOTO_E_RANGE);
      CHECK(noto_measure(p, a, 40000, 1, &e) == NOTO_E_PARAM && noto_draw(p, a, 3, 1, 1 << 30, 0, NULL, cb, &im, NULL) == NOTO_E_RANGE);
      CHECK(noto_measure(p, NULL, 1, 1, &e) == NOTO_E_PARAM); }
    for (u = 1; u <= 8; ++u) { NotoGlyph gg; CHECK(noto_glyph(p, 0xD55C, (int)u, &gg) == NOTO_OK && gg.advance > 0); }
    noto_glyph(p, 'i', 1, &g); printf("scale8 H adv=%d\n", (noto_glyph(p, 'H', 8, &g), g.advance));
    free(im.px);
    noto_destroy(p); CHECK(rel_calls == 2);
    /* bad font: garbage bytes, release exactly once each */
    { NotoFontSource x = {0}, y = {0}; x.data = malloc(100); memset((void *)x.data, 7, 100); x.size = 100; x.release = rel;
      y.data = malloc(10); y.size = 10; y.release = rel; rel_calls = 0; p = NULL;
      CHECK(noto_create(&x, &y, &p) == NOTO_E_FONT && !p && rel_calls == 2); }
    /* wrong family: swap order (KR/CJK face as latin) */
    { NotoFontSource x = load("/usr/share/fonts/google-noto-vf/NotoSerif[wght].ttf", 0), y = load("/usr/share/fonts/google-noto-vf/NotoSans[wght].ttf", 0);
      rel_calls = 0; p = NULL; CHECK(noto_create(&x, &y, &p) == NOTO_E_FAMILY && rel_calls == 2); }
    printf("%s fails=%d\n", fails ? "FAIL" : "PASS-HOST-CONTROL", fails);
    return fails != 0;
}
