/* SPDX-License-Identifier: GPL-2.0-only
 * Host controls for user32_text_layout.c (the production code that DrawTextW in user32.dll runs). Source-level only: a
 * variable-width fake replaces GetTextExtentPoint32W/GetTextExtentExPointW. This is NOT guest, visual or font acceptance.
 *
 *   cc -std=c11 -Wall -Wextra -Werror -fsanitize=address,undefined -g -I.. ../user32_text_layout.c user32_text_layout_host.c
 *
 * With AddressSanitizer the program also re-executes itself with --baseline-overflow, a verbatim-style reproduction of the
 * baseline DrawTextW allocation ((n+1)*2 WCHARs while one TAB expands to 8 blanks) and requires ASan to report
 * heap-buffer-overflow, then proves the production helper handles the same tab storm without any report. */
#define _POSIX_C_SOURCE 200809L
#include "user32_text_layout.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#if defined(__SANITIZE_ADDRESS__)
#define HAVE_ASAN 1
#elif defined(__has_feature)
#if __has_feature(address_sanitizer)
#define HAVE_ASAN 1
#endif
#endif
#ifndef HAVE_ASAN
#define HAVE_ASAN 0
#endif

static int g_fail, g_checks;
#define CHECK(c, msg) do { ++g_checks; if (!(c)) { ++g_fail; printf("FAIL %s:%d %s\n", __FILE__, __LINE__, msg); } } while (0)

typedef struct {
    int use_fit, calls, fail_at, alloc_calls, alloc_fail_at, live;
} fake_t;

static int cw(uint16_t c)
{
    if (c == 'i' || c == 'l' || c == '.' || c == ',') return 3;
    if (c == ' ') return 4;
    if (c == 'W' || c == 'M' || c == 'm') return 12;
    if (c >= 0xDC00 && c <= 0xDFFF) return 0;
    if (c >= 0xD800 && c <= 0xDBFF) return 16;
    if (shz_tl_is_wide(c)) return 16;
    return 8;
}

static int fk_measure(void *ctx, const uint16_t *s, int n, int *w)
{
    fake_t *f = ctx;
    int i, t = 0;
    if (f->fail_at && ++f->calls >= f->fail_at) return 0;
    for (i = 0; i < n; ++i) t += cw(s[i]);
    *w = t;
    return 1;
}

static int fk_fit(void *ctx, const uint16_t *s, int n, int maxw, int *fit, int *w)
{
    fake_t *f = ctx;
    int i, t = 0;
    if (f->fail_at && ++f->calls >= f->fail_at) return 0;
    for (i = 0; i < n && t + cw(s[i]) <= maxw; ++i) t += cw(s[i]);   /* deliberately not surrogate aware */
    *fit = i; *w = t;
    return 1;
}

static void *fk_alloc(void *ctx, size_t b)
{
    fake_t *f = ctx;
    void *p;
    if (f->alloc_fail_at && ++f->alloc_calls >= f->alloc_fail_at) return NULL;
    p = malloc(b ? b : 1);
    if (p) ++f->live;
    return p;
}

static void fk_free(void *ctx, void *p) { fake_t *f = ctx; if (p) { --f->live; free(p); } }

static shz_tl_params_t params(fake_t *f)
{
    shz_tl_params_t p;
    memset(&p, 0, sizeof p);
    p.measure = fk_measure; p.fit = f->use_fit ? fk_fit : NULL; p.alloc = fk_alloc; p.release = fk_free; p.ctx = f;
    p.line_height = 16; p.external_leading = 3; p.ascent = 12; p.avg_char_width = 8;
    return p;
}

static uint16_t *U(const char *s, int *n)
{
    size_t i, l = strlen(s);
    uint16_t *u = malloc((l ? l : 1) * 2);               /* exact size: reads past it are caught by ASan */
    for (i = 0; i < l; ++i) u[i] = (unsigned char)s[i];
    *n = (int)l;
    return u;
}

static int line_is(const shz_tl_layout_t *L, int line, const char *want)
{
    shz_tl_iter_t it;
    shz_tl_run_t r;
    char got[512];
    size_t o = 0;
    int i;
    shz_tl_iter_begin(L, line, &it);
    while (shz_tl_iter_next(&it, &r) > 0)
        for (i = 0; i < r.n && o < sizeof got - 1; ++i) got[o++] = r.p[i] < 128 ? (char)r.p[i] : '?';
    got[o] = 0;
    if (strcmp(got, want)) printf("   line %d: got \"%s\" want \"%s\"\n", line, got, want);
    return !strcmp(got, want);
}

static int lay(fake_t *f, const char *s, int rw, int rh, uint32_t fmt, shz_tl_layout_t *L)
{
    int n, st;
    uint16_t *u = U(s, &n);
    shz_tl_params_t p = params(f);
    st = shz_tl_layout(&p, u, n, rw, rh, fmt, L);
    free(u);
    return st;
}

static int width_of(const char *s)
{
    int n, i, t = 0;
    uint16_t *u = U(s, &n);
    for (i = 0; i < n; ++i) t += cw(u[i]);
    free(u);
    return t;
}

static void all_modes(void (*fn)(fake_t *)) { fake_t f; int m; for (m = 0; m < 2; ++m) { memset(&f, 0, sizeof f); f.use_fit = m; fn(&f); CHECK(f.live == 0, "no leak"); } }

static void t_width_and_align(fake_t *f)
{
    shz_tl_layout_t L;
    int w = width_of("Wiliiam");
    CHECK(lay(f, "Wiliiam", 200, 40, 0, &L) == SHZ_TL_OK, "ok");
    CHECK(L.lines[0].width == w && w != 7 * 8, "width is the measured sum, not count*avg");
    CHECK(L.lines[0].x == 0 && L.height == 16 && L.max_width == w, "left");
    shz_tl_free(&L);
    lay(f, "Wiliiam", 200, 40, SHZ_TL_DT_CENTER, &L);
    CHECK(L.lines[0].x == (200 - w) / 2, "center");
    shz_tl_free(&L);
    lay(f, "Wiliiam", 200, 40, SHZ_TL_DT_RIGHT, &L);
    CHECK(L.lines[0].x == 200 - w, "right");
    shz_tl_free(&L);
    lay(f, "Wiliiam", 200, 40, SHZ_TL_DT_SINGLELINE | SHZ_TL_DT_VCENTER, &L);
    CHECK(L.lines[0].y == (40 - 16) / 2, "vcenter");
    shz_tl_free(&L);
    lay(f, "Wiliiam", 200, 40, SHZ_TL_DT_SINGLELINE | SHZ_TL_DT_BOTTOM, &L);
    CHECK(L.lines[0].y == 40 - 16, "bottom");
    shz_tl_free(&L);
    lay(f, "Wiliiam", 200, 40, SHZ_TL_DT_VCENTER, &L);
    CHECK(L.lines[0].y == 0, "vcenter ignored without SINGLELINE (documented)");
    shz_tl_free(&L);
    lay(f, "Wiliiam", 200, 40, SHZ_TL_DT_EXTERNALLEADING, &L);
    CHECK(L.line_h == 19 && L.height == 19, "external leading");
    shz_tl_free(&L);
}

static void t_newlines(fake_t *f)
{
    shz_tl_layout_t L;
    lay(f, "a\r\nb\n\rc\n\nd", 500, 100, 0, &L);
    CHECK(L.nlines == 5 && line_is(&L, 0, "a") && line_is(&L, 1, "b") && line_is(&L, 2, "c") && line_is(&L, 3, "") &&
          line_is(&L, 4, "d"), "CRLF, LFCR pairs are one break, LFLF is two");
    shz_tl_free(&L);
    lay(f, "a\r\nb", 500, 100, SHZ_TL_DT_SINGLELINE, &L);
    CHECK(L.nlines == 1 && line_is(&L, 0, "a  b") && L.buf_len == 4, "single line: CRLF are blanks");
    shz_tl_free(&L);
    lay(f, "", 100, 100, 0, &L);
    CHECK(L.nlines == 1 && L.height == 16, "empty text has one empty line");
    shz_tl_free(&L);
}

static void t_wordbreak(fake_t *f)
{
    shz_tl_layout_t L;
    int i;
    lay(f, "aaa bbb ccc", width_of("aaa bbb"), 100, SHZ_TL_DT_WORDBREAK, &L);
    CHECK(L.nlines == 2 && line_is(&L, 0, "aaa bbb") && line_is(&L, 1, "ccc"), "wrap at last blank");
    for (i = 0; i < L.nlines; ++i) CHECK(L.lines[i].width <= width_of("aaa bbb"), "line fits");
    shz_tl_free(&L);
    lay(f, "aaa bbb ccc", 24, 100, SHZ_TL_DT_WORDBREAK, &L);
    CHECK(L.nlines == 3 && line_is(&L, 1, "bbb"), "one word per line");
    shz_tl_free(&L);
    lay(f, "aaa bbb ccc", 24, 100, SHZ_TL_DT_WORDBREAK | SHZ_TL_DT_SINGLELINE, &L);
    CHECK(L.nlines == 1, "SINGLELINE disables wrapping");
    shz_tl_free(&L);
    lay(f, "abcdefghij", 40, 100, SHZ_TL_DT_WORDBREAK, &L);
    CHECK(L.nlines == 2 && line_is(&L, 0, "abcde") && line_is(&L, 1, "fghij"), "long word is broken inside");
    shz_tl_free(&L);
    lay(f, "abcdefghij", 0, 100, SHZ_TL_DT_WORDBREAK, &L);
    CHECK(L.nlines == 10, "zero width still progresses one unit per line");
    shz_tl_free(&L);
    lay(f, "abc    def", 24, 100, SHZ_TL_DT_WORDBREAK, &L);
    CHECK(line_is(&L, 0, "abc"), "trailing blanks at a wrap are dropped");
    shz_tl_free(&L);
    lay(f, "abcdefghij klm", 40, 100, SHZ_TL_DT_WORDBREAK | SHZ_TL_DT_WORD_ELLIPSIS, &L);
    CHECK(L.lines[0].dots == 1 && L.lines[0].width <= 40 && L.nlines == 2 && line_is(&L, 1, "klm"),
          "WORD_ELLIPSIS truncates an over-long word instead of breaking it");
    shz_tl_free(&L);
}

static void t_surrogates(fake_t *f)
{
    shz_tl_layout_t L;
    uint16_t t[8] = { 0xD842, 0xDFB7, 0xD842, 0xDFB7, 0xD842, 0xDFB7, 'a', 0 };   /* three astral chars then 'a' */
    shz_tl_params_t p = params(f);
    int w, i, k, st;
    for (w = 0; w <= 80; ++w) {
        st = shz_tl_layout(&p, t, 7, w, 200, SHZ_TL_DT_WORDBREAK | SHZ_TL_DT_NOFULLWIDTHCHARBREAK, &L);
        CHECK(st == SHZ_TL_OK, "layout ok");
        for (i = 0; i < L.nlines; ++i) {
            const shz_tl_line_t *ln = &L.lines[i];
            if (ln->head_len > 0) {
                CHECK(!(L.buf[ln->start + ln->head_len - 1] >= 0xD800 && L.buf[ln->start + ln->head_len - 1] <= 0xDBFF),
                      "line never ends inside a pair");
                CHECK(!(L.buf[ln->start] >= 0xDC00 && L.buf[ln->start] <= 0xDFFF), "line never starts inside a pair");
            }
        }
        shz_tl_free(&L);
        st = shz_tl_layout(&p, t, 7, w, 200, SHZ_TL_DT_SINGLELINE | SHZ_TL_DT_END_ELLIPSIS, &L);
        CHECK(st == SHZ_TL_OK, "ellipsis ok");
        k = L.lines[0].head_len;
        CHECK(k == 0 || !(L.buf[k - 1] >= 0xD800 && L.buf[k - 1] <= 0xDBFF), "ellipsis cut never splits a pair");
        shz_tl_free(&L);
    }
}

static void t_wide_break(fake_t *f)
{
    shz_tl_layout_t L;
    uint16_t ko[6] = { 0xD55C, 0xAE00, 0xD55C, 0xAE00, 0xD55C, 0xAE00 };   /* Hangul syllables, 16 px each */
    shz_tl_params_t p = params(f);
    CHECK(shz_tl_layout(&p, ko, 6, 40, 100, SHZ_TL_DT_WORDBREAK, &L) == SHZ_TL_OK && L.nlines == 3 && L.lines[0].head_len == 2,
          "wide characters break between characters");
    shz_tl_free(&L);
    CHECK(shz_tl_layout(&p, ko, 6, 40, 100, SHZ_TL_DT_WORDBREAK | SHZ_TL_DT_NOFULLWIDTHCHARBREAK, &L) == SHZ_TL_OK &&
          L.nlines == 3, "NOFULLWIDTHCHARBREAK without blanks falls back to a forced mid-word cut");
    shz_tl_free(&L);
    {
        uint16_t m[7] = { 0xD55C, 0xAE00, ' ', 0xD55C, 0xAE00, 0xD55C, 0xAE00 };
        CHECK(shz_tl_layout(&p, m, 7, 70, 100, SHZ_TL_DT_WORDBREAK | SHZ_TL_DT_NOFULLWIDTHCHARBREAK, &L) == SHZ_TL_OK &&
              L.nlines >= 2 && L.lines[0].head_len == 2, "NOFULLWIDTHCHARBREAK breaks at the blank");
        shz_tl_free(&L);
    }
}

static void t_tabs(fake_t *f)
{
    shz_tl_layout_t L;
    shz_tl_iter_t it;
    shz_tl_run_t r;
    int n;
    uint16_t *u = U("a\tb\tc", &n);
    shz_tl_params_t p = params(f);
    CHECK(shz_tl_layout(&p, u, n, 500, 100, SHZ_TL_DT_EXPANDTABS, &L) == SHZ_TL_OK && L.tab_px == 64, "8 chars * avg 8 = 64 px");
    shz_tl_iter_begin(&L, 0, &it);
    CHECK(shz_tl_iter_next(&it, &r) == 1 && r.x == 0 && r.n == 1, "a at 0");
    CHECK(shz_tl_iter_next(&it, &r) == 1 && r.x == 64, "b at first tab stop");
    CHECK(shz_tl_iter_next(&it, &r) == 1 && r.x == 128, "c at second tab stop");
    CHECK(shz_tl_iter_next(&it, &r) == 0, "end");
    shz_tl_free(&L);
    CHECK(shz_tl_layout(&p, u, n, 500, 100, SHZ_TL_DT_TABSTOP | 0x0300 /* tab length 3 */, &L) == SHZ_TL_OK && L.tab_px == 24,
          "TABSTOP bits 15..8 are the tab length");
    CHECK(L.fmt == SHZ_TL_DT_TABSTOP && !(L.fmt & SHZ_TL_DT_NOCLIP), "those bits are not reinterpreted as DT_NOCLIP/etc");
    shz_tl_free(&L);
    CHECK(shz_tl_layout(&p, u, n, 500, 100, 0, &L) == SHZ_TL_OK && L.tab_px == 0 && L.buf[1] == ' ',
          "without EXPANDTABS a tab is one blank (documented)");
    shz_tl_free(&L);
    free(u);
    u = U("\tx", &n);
    CHECK(shz_tl_layout(&p, u, n, 20, 100, SHZ_TL_DT_EXPANDTABS | SHZ_TL_DT_WORDBREAK, &L) == SHZ_TL_OK && L.nlines >= 1,
          "tab wider than rect still lays out");
    shz_tl_free(&L);
    free(u);
}

static void t_prefix(fake_t *f)
{
    shz_tl_layout_t L;
    int x, w;
    lay(f, "&File", 100, 30, 0, &L);
    CHECK(line_is(&L, 0, "File") && L.ul_index == 0, "&F underlines F");
    CHECK(shz_tl_underline(&L, 0, &x, &w) && x == 0 && w == cw('F'), "underline geometry of first char");
    shz_tl_free(&L);
    lay(f, "Sa&ve", 100, 30, 0, &L);
    CHECK(L.ul_index == 2 && shz_tl_underline(&L, 0, &x, &w) && x == width_of("Sa") && w == cw('v'), "underline in the middle uses measured widths");
    shz_tl_free(&L);
    lay(f, "a&&b&c&", 100, 30, 0, &L);
    CHECK(line_is(&L, 0, "a&bc") && L.ul_index == 3, "&& literal, &c underlined, trailing & dropped");
    shz_tl_free(&L);
    lay(f, "a&&b&c", 100, 30, SHZ_TL_DT_NOPREFIX, &L);
    CHECK(line_is(&L, 0, "a&&b&c") && L.ul_index == -1, "NOPREFIX keeps ampersands");
    shz_tl_free(&L);
    lay(f, "&ab", 100, 30, SHZ_TL_DT_HIDEPREFIX, &L);
    CHECK(line_is(&L, 0, "ab") && L.ul_index == -1, "HIDEPREFIX removes & without underline");
    shz_tl_free(&L);
    lay(f, "&a&b", 100, 30, 0, &L);
    CHECK(L.ul_index == 0, "only the first prefix is underlined (documented)");
    shz_tl_free(&L);
    lay(f, "a&\nb", 100, 30, 0, &L);
    CHECK(L.nlines == 2 && L.ul_index == -1, "& before a line break underlines nothing");
    shz_tl_free(&L);
}

static void t_ellipsis(fake_t *f)
{
    shz_tl_layout_t L;
    uint16_t out[64];
    int d = width_of("..."), n;
    lay(f, "abcdefghijklmnop", 60, 20, SHZ_TL_DT_SINGLELINE | SHZ_TL_DT_END_ELLIPSIS, &L);
    CHECK(L.lines[0].dots && L.lines[0].width <= 60 && L.lines[0].head_len == (60 - d) / 8, "END_ELLIPSIS head");
    CHECK(L.lines[0].width == L.lines[0].head_len * 8 + d, "width = head + dots");
    n = shz_tl_displayed_text(&L, out, 64);
    CHECK(n == L.lines[0].head_len + 3 && out[n - 1] == '.' && out[0] == 'a', "displayed text for MODIFYSTRING");
    shz_tl_free(&L);
    lay(f, "abc", 60, 20, SHZ_TL_DT_SINGLELINE | SHZ_TL_DT_END_ELLIPSIS, &L);
    CHECK(!L.lines[0].dots && !L.modified, "fitting text untouched");
    shz_tl_free(&L);
    lay(f, "abcdefghijklmnop", 60, 20, SHZ_TL_DT_SINGLELINE | SHZ_TL_DT_END_ELLIPSIS | SHZ_TL_DT_CALCRECT, &L);
    CHECK(!L.lines[0].dots && L.max_width == width_of("abcdefghijklmnop"), "CALCRECT ignores ellipsis (documented)");
    shz_tl_free(&L);
    lay(f, "abcdefgh", 10, 20, SHZ_TL_DT_SINGLELINE | SHZ_TL_DT_END_ELLIPSIS, &L);
    CHECK(L.lines[0].dots && L.lines[0].head_len == 0, "narrower than the dots: dots only");
    shz_tl_free(&L);
    lay(f, "C:\\Windows\\System\\Fonts\\verylongname.ttf", 160, 20, SHZ_TL_DT_SINGLELINE | SHZ_TL_DT_PATH_ELLIPSIS, &L);
    CHECK(L.lines[0].dots && L.lines[0].tail_len == (int)strlen("\\verylongname.ttf") && L.lines[0].width <= 160, "PATH keeps the file name");
    n = shz_tl_displayed_text(&L, out, 64);
    CHECK(n > 0 && out[n - 1] == 'f' && out[0] == 'C', "path displayed text");
    shz_tl_free(&L);
    lay(f, "C:\\a\\a_very_very_long_file_name_here.txt", 100, 20, SHZ_TL_DT_SINGLELINE | SHZ_TL_DT_PATH_ELLIPSIS, &L);
    CHECK(L.lines[0].dots && L.lines[0].tail_len == 0 && L.lines[0].width <= 100, "tail too wide: falls back to end ellipsis");
    shz_tl_free(&L);
    lay(f, "no_backslash_in_here_at_all", 80, 20, SHZ_TL_DT_SINGLELINE | SHZ_TL_DT_PATH_ELLIPSIS, &L);
    CHECK(L.lines[0].dots && L.lines[0].tail_len == 0 && L.lines[0].width <= 80, "no backslash: end ellipsis");
    shz_tl_free(&L);
    lay(f, "one two three four five six", 70, 32, SHZ_TL_DT_WORDBREAK | SHZ_TL_DT_END_ELLIPSIS, &L);
    CHECK(L.nlines == 2 && L.lines[1].dots && L.lines[1].width <= 70 && L.lines[0].dots == 0 && L.height == 32,
          "WORDBREAK+END_ELLIPSIS: last visible line carries the ellipsis");
    shz_tl_free(&L);
    lay(f, "one two three four five six", 70, 32, SHZ_TL_DT_WORDBREAK | SHZ_TL_DT_END_ELLIPSIS | SHZ_TL_DT_NOCLIP, &L);
    CHECK(L.nlines > 2 && !L.lines[L.nlines - 1].dots, "NOCLIP: no height truncation");
    shz_tl_free(&L);
}

static void t_visibility(fake_t *f)
{
    shz_tl_layout_t L;
    lay(f, "a\nb\nc\nd", 100, 40, 0, &L);       /* 40px = 2.5 lines */
    CHECK(L.lines[0].visible && L.lines[1].visible && L.lines[2].visible && !L.lines[3].visible, "partial line drawn+clipped, later hidden");
    shz_tl_free(&L);
    lay(f, "a\nb\nc\nd", 100, 40, SHZ_TL_DT_EDITCONTROL, &L);
    CHECK(L.lines[0].visible && L.lines[1].visible && !L.lines[2].visible, "EDITCONTROL hides the partial last line");
    shz_tl_free(&L);
    lay(f, "a\nb\nc\nd", 100, 40, SHZ_TL_DT_NOCLIP, &L);
    CHECK(L.lines[3].visible, "NOCLIP draws all");
    shz_tl_free(&L);
    lay(f, "x\ty", 100, 40, SHZ_TL_DT_EDITCONTROL | SHZ_TL_DT_EXPANDTABS, &L);
    CHECK(L.tab_px == 8 * (((width_of("abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ") / 26) + 1) / 2),
          "EDITCONTROL uses the edit-control average char width");
    shz_tl_free(&L);
}

static void t_params_and_limits(fake_t *f)
{
    shz_tl_layout_t L;
    shz_tl_params_t p = params(f);
    uint16_t c = 'x';
    size_t r;
    CHECK(lay(f, "a", 10, 10, SHZ_TL_DT_RTLREADING, &L) == SHZ_TL_E_UNSUPPORTED, "RTLREADING explicitly unsupported");
    CHECK(lay(f, "a", 10, 10, 0x00400000u, &L) == SHZ_TL_E_UNSUPPORTED, "undefined bit explicitly unsupported");
    CHECK(shz_tl_layout(&p, NULL, 3, 10, 10, 0, &L) == SHZ_TL_E_PARAM, "NULL text with length");
    CHECK(shz_tl_layout(&p, NULL, 0, 10, 10, 0, &L) == SHZ_TL_OK && L.nlines == 1, "NULL text, zero length");
    shz_tl_free(&L);
    CHECK(shz_tl_layout(&p, &c, (int)SHZ_TL_MAX_CHARS + 1, 10, 10, 0, &L) == SHZ_TL_E_TOOBIG, "length cap");
    CHECK(shz_tl_layout(&p, &c, 0x7fffffff, 10, 10, 0, &L) == SHZ_TL_E_TOOBIG, "INT_MAX length refused before any allocation");
    CHECK(f->alloc_calls == 0 && f->live == 0, "no allocation for refused sizes");
    p.line_height = 0;
    CHECK(shz_tl_layout(&p, &c, 1, 10, 10, 0, &L) == SHZ_TL_E_PARAM, "bad line height");
    CHECK(!shz_tl_mul_size((size_t)-1, 2, &r) && shz_tl_mul_size(1 << 20, 2, &r) && r == (1u << 21), "mul overflow detect");
    CHECK(!shz_tl_add_size((size_t)-1, 1, &r) && shz_tl_add_size(5, 6, &r) && r == 11, "add overflow detect");
    CHECK(shz_tl_text_bytes(SHZ_TL_MAX_CHARS, &r) && r == ((size_t)SHZ_TL_MAX_CHARS + 1) * 2 && !shz_tl_text_bytes(-1, &r) &&
          !shz_tl_text_bytes((int)SHZ_TL_MAX_CHARS + 1, &r), "text_bytes");
    CHECK(lay(f, "abc", -5, -5, SHZ_TL_DT_WORDBREAK, &L) == SHZ_TL_OK && L.nlines == 3, "negative rect treated as empty");
    shz_tl_free(&L);
    {                                                      /* NUL terminated (len < 0) */
        uint16_t z[4] = { 'a', 'b', 0, 'c' };
        CHECK(shz_tl_layout(&p, z, -1, 100, 100, 0, &L) == SHZ_TL_E_PARAM, "(line_height still bad here)");
        p.line_height = 16;
        CHECK(shz_tl_layout(&p, z, -1, 100, 100, 0, &L) == SHZ_TL_OK && L.buf_len == 2, "len<0 stops at NUL");
        shz_tl_free(&L);
    }
}

static void t_failure_injection(void)
{
    static const uint32_t modes[] = {
        SHZ_TL_DT_WORDBREAK | SHZ_TL_DT_END_ELLIPSIS, SHZ_TL_DT_PATH_ELLIPSIS | SHZ_TL_DT_SINGLELINE,
        SHZ_TL_DT_WORDBREAK | SHZ_TL_DT_EXPANDTABS | SHZ_TL_DT_EDITCONTROL, SHZ_TL_DT_CENTER | SHZ_TL_DT_WORD_ELLIPSIS |
        SHZ_TL_DT_WORDBREAK };
    size_t m;
    int k, any_fail = 0, any_ok = 0;
    for (m = 0; m < sizeof modes / sizeof modes[0]; ++m) {
        int pass;
        for (pass = 0; pass < 2; ++pass)
            for (k = 1; k < 400; ++k) {
                fake_t f;
                shz_tl_layout_t L;
                int st;
                memset(&f, 0, sizeof f);
                f.use_fit = pass;
                f.fail_at = k;
                st = lay(&f, "C:\\one\\two\\three\tfour &five six seven eight\nnine ten", 90, 48, modes[m], &L);
                if (st == SHZ_TL_OK) { ++any_ok; shz_tl_free(&L); } else { ++any_fail; CHECK(st == SHZ_TL_E_MEASURE, "measure failure propagates as E_MEASURE"); }
                CHECK(f.live == 0, "measure failure leaves nothing allocated");
            }
    }
    CHECK(any_fail > 50 && any_ok > 0, "failure injection reached both outcomes");
    for (k = 1; k < 40; ++k) {
        fake_t f;
        shz_tl_layout_t L;
        int st;
        memset(&f, 0, sizeof f);
        f.alloc_fail_at = k;
        st = lay(&f, "a\nb\nc\nd\ne\nf\ng\nh\ni\nj\nk\nl\nm", 90, 48, 0, &L);
        if (st == SHZ_TL_OK) shz_tl_free(&L); else CHECK(st == SHZ_TL_E_NOMEM, "allocation failure is NOMEM");
        CHECK(f.live == 0, "allocation failure leaves nothing allocated");
    }
}

/* many tabs, tiny widths, every flag mix: the processed text never outgrows n+1 units and nothing reads/writes out of
 * bounds (exact-size heap input, ASan watches) */
static void t_tab_storm(void)
{
    static const int sizes[] = { 1, 2, 3, 7, 8, 9, 64, 1000, 5000 };
    static const uint32_t fm[] = { SHZ_TL_DT_EXPANDTABS, SHZ_TL_DT_TABSTOP | 0x0800, SHZ_TL_DT_EXPANDTABS | SHZ_TL_DT_WORDBREAK,
                                   SHZ_TL_DT_EXPANDTABS | SHZ_TL_DT_END_ELLIPSIS | SHZ_TL_DT_SINGLELINE,
                                   SHZ_TL_DT_EXPANDTABS | SHZ_TL_DT_WORDBREAK | SHZ_TL_DT_END_ELLIPSIS };
    size_t a, b;
    for (a = 0; a < sizeof sizes / sizeof sizes[0]; ++a)
        for (b = 0; b < sizeof fm / sizeof fm[0]; ++b) {
            fake_t f;
            shz_tl_layout_t L;
            shz_tl_params_t p;
            int n = sizes[a], i, st;
            uint16_t *u = malloc((size_t)n * 2);
            for (i = 0; i < n; ++i) u[i] = (i % 5 == 4) ? 'x' : '\t';
            memset(&f, 0, sizeof f);
            f.use_fit = (int)(b & 1);
            p = params(&f);
            st = shz_tl_layout(&p, u, n, 200, 64, fm[b], &L);
            CHECK(st == SHZ_TL_OK, "tab storm layout");
            if (st == SHZ_TL_OK) { CHECK(L.buf_len <= n, "processed text never longer than input"); shz_tl_free(&L); }
            CHECK(f.live == 0, "tab storm no leak");
            free(u);
        }
}

static void t_ellipsis_never_overflow_width(fake_t *f)
{
    int w;
    shz_tl_layout_t L;
    for (w = 0; w < 140; ++w) {
        lay(f, "The quick brown fox jumps", w, 16, SHZ_TL_DT_SINGLELINE | SHZ_TL_DT_END_ELLIPSIS, &L);
        CHECK(L.lines[0].width <= w || L.lines[0].head_len == 0, "ellipsised line fits (or is dots only)");
        shz_tl_free(&L);
    }
}

/* ---- ASan negative control ---- */
static int baseline_overflow(void)
{
    /* Same allocation and expansion as the baseline DrawTextW: (n + 1) * sizeof(WCHAR) * 2 bytes, one TAB -> up to 8 blanks */
    const int n = 4;
    uint16_t *text = malloc((size_t)n * 2), *buf, *o;
    int i;
    for (i = 0; i < n; ++i) text[i] = '\t';
    buf = malloc((size_t)(n + 1) * sizeof(uint16_t) * 2);
    o = buf;
    for (i = 0; i < n; ++i) {
        int col = (int)(o - buf), pad = 8 - (col & 7);
        while (pad--) *o++ = ' ';                          /* writes past the (n+1)*2 units: heap-buffer-overflow */
    }
    printf("baseline wrote %d units into %d\n", (int)(o - buf), (n + 1) * 2);
    free(buf); free(text);
    return 0;
}

static int run_asan_control(const char *self)
{
    char cmd[512], line[512];
    FILE *fp;
    int found = 0, rc;
    if (!HAVE_ASAN) { printf("ASAN CONTROL: not compiled with AddressSanitizer, SKIPPED (not a pass)\n"); return 0; }
    snprintf(cmd, sizeof cmd, "'%s' --baseline-overflow 2>&1", self);
    fp = popen(cmd, "r");
    if (!fp) { printf("FAIL cannot run baseline control\n"); return 1; }
    while (fgets(line, sizeof line, fp)) if (strstr(line, "heap-buffer-overflow")) found = 1;
    rc = pclose(fp);
    printf("ASAN CONTROL: baseline-style allocation exit=%d heap-buffer-overflow-reported=%d\n", rc, found);
    if (!found || rc == 0) { printf("FAIL ASan did not flag the baseline allocation\n"); return 1; }
    return 0;
}

int main(int argc, char **argv)
{
    if (argc > 1 && !strcmp(argv[1], "--baseline-overflow")) return baseline_overflow();
    all_modes(t_width_and_align);
    all_modes(t_newlines);
    all_modes(t_wordbreak);
    all_modes(t_surrogates);
    all_modes(t_wide_break);
    all_modes(t_tabs);
    all_modes(t_prefix);
    all_modes(t_ellipsis);
    all_modes(t_visibility);
    all_modes(t_params_and_limits);
    all_modes(t_ellipsis_never_overflow_width);
    t_failure_injection();
    t_tab_storm();
    printf("checks=%d failures=%d\n", g_checks, g_fail);
    if (!g_fail && run_asan_control(argv[0])) ++g_fail;
    printf(g_fail ? "RESULT: FAIL\n" : "RESULT: PASS (host controls only; asan=%d)\n", HAVE_ASAN);
    return g_fail ? 1 : 0;
}
