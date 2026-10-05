/* SPDX-License-Identifier: GPL-2.0-only
 * Host control for src/theme.c (portable parser/state/capability part only). NOT a guest or Win32 execution test:
 * the native load/persist code (SHZ_THEME_NATIVE) is only compile/link checked by build.py.
 *   gcc -Wall -Wextra -Werror -I src tests/test_theme.c src/theme.c -o test_theme && ./test_theme themes
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "theme.h"

static int g_fail, g_pass;
#define CHECK(c) do { if (c) ++g_pass; else { ++g_fail; printf("FAIL line %d: %s\n", __LINE__, #c); } } while (0)

static char g_ini[3][SHZ_THEME_MAX_BYTES + 1];
static size_t g_len[3];

static size_t rd(const char *dir, const char *name, char *buf)
{
    char p[512]; FILE *f; size_t n;
    snprintf(p, sizeof p, "%s/%s/theme.ini", dir, name);
    f = fopen(p, "rb");
    if (!f) { printf("cannot open %s\n", p); exit(2); }
    n = fread(buf, 1, SHZ_THEME_MAX_BYTES, f);
    fclose(f);
    buf[n] = 0;
    return n;
}

/* returns new length; replaces the first occurrence of `from` with `to` */
static size_t mut(const char *src, size_t n, char *dst, const char *from, const char *to)
{
    const char *p = strstr(src, from); size_t a, fl = strlen(from), tl = strlen(to);
    if (!p) { printf("mut: pattern absent: %s\n", from); exit(2); }
    a = (size_t)(p - src);
    memcpy(dst, src, a); memcpy(dst + a, to, tl); memcpy(dst + a + tl, src + a + fl, n - a - fl);
    dst[n - fl + tl] = 0;
    return n - fl + tl;
}

static int code_of(const char *buf, size_t n, SHZ_THEME_ERR *e)
{
    SHZ_THEME t; return ShzThemeParse(buf, n, &t, e);
}

int main(int argc, char **argv)
{
    const char *dir = argc > 1 ? argv[1] : "themes";
    static char m[SHZ_THEME_MAX_BYTES + 4096], m2[SHZ_THEME_MAX_BYTES + 4096];
    SHZ_THEME_ERR e; SHZ_THEME t; SHZ_THEME_STATE st, snap; size_t n, i;
    char names[256];
    unsigned id;
    static const char *const nm[3] = { "Slade", "Flute", "Jade" };

    for (i = 0; i < 3; ++i) g_len[i] = rd(dir, nm[i], g_ini[i]);

    /* 1. all three external definitions parse, identities exact, bounded size */
    for (id = 0; id < 3; ++id) {
        CHECK(g_len[id] > 1000 && g_len[id] < SHZ_THEME_MAX_BYTES);
        CHECK(ShzThemeParse(g_ini[id], g_len[id], &t, &e) == SHZ_TH_OK);
        CHECK(ShzThemeCheckIdentity(&t, (int)id, &e) == SHZ_TH_OK);
        CHECK(strcmp(t.meta_name, nm[id]) == 0 && t.meta_kind == SHZ_KIND_BUILTIN);
        CHECK(ShzThemeIdFromName(nm[id]) == (int)id && strcmp(ShzThemeIdName((int)id), nm[id]) == 0);
        CHECK(t.buttons_height >= 22 && t.menu_row_height >= 22 && t.files_row_height >= 22 && t.taskbar_height >= t.buttons_height + 4);
    }
    CHECK(ShzThemeIdFromName("slade") == -1 && ShzThemeIdFromName("..") == -1 && ShzThemeIdName(4) == NULL && ShzThemeIdName(-1) == NULL);
    /* the three definitions are genuinely different data (not one palette copied) */
    { SHZ_THEME a, b, c;
      ShzThemeParse(g_ini[0], g_len[0], &a, 0); ShzThemeParse(g_ini[1], g_len[1], &b, 0); ShzThemeParse(g_ini[2], g_len[2], &c, 0);
      CHECK(a.background_desktop_top != b.background_desktop_top && b.background_desktop_top != c.background_desktop_top && a.taskbar_bg_top != c.taskbar_bg_top);
      CHECK(a.background_desktop_top == 0x263B55u);          /* Slade: stored as 0x00RRGGBB */
      CHECK(ShzThemeCR(a.background_desktop_top) == 0x553B26ul);   /* COLORREF 0x00BBGGRR */ }

    /* 2. colour conversion, explicit and tested */
    CHECK(ShzThemeColorRefFromRgb(0x00112233u) == 0x00332211u);
    CHECK(ShzThemeRgbFromColorRef(0x00332211u) == 0x00112233u);
    CHECK(ShzThemeRgbFromColorRef(ShzThemeColorRefFromRgb(0x00ABCDEFu)) == 0x00ABCDEFu);
    CHECK(ShzThemeColorRefFromRgb(0x00FF0000u) == 0x000000FFu);   /* red: RGB 0xFF0000 is COLORREF 0x0000FF */
    { uint32_t v = 0;
      CHECK(ShzThemeParseColor("#112233", &v) && v == 0x112233u);
      CHECK(ShzThemeParseColor("#aBcDeF", &v) && v == 0xABCDEFu);
      CHECK(!ShzThemeParseColor("112233", &v) && !ShzThemeParseColor("#11223", &v) && !ShzThemeParseColor("#1122334", &v) &&
            !ShzThemeParseColor("#11223G", &v) && !ShzThemeParseColor("", &v) && !ShzThemeParseColor(NULL, &v)); }

    /* 3. atomic state: valid, custom valid, invalid custom retains exact state and generation */
    ShzThemeStateInit(&st);
    CHECK(st.generation == 0 && !st.valid && st.id == -1);
    CHECK(ShzThemeStateApply(&st, SHZ_THEME_SLADE, g_ini[0], g_len[0], &e) == SHZ_TH_OK && st.generation == 1 && st.id == SHZ_THEME_SLADE);
    CHECK(ShzThemeStateApply(&st, SHZ_THEME_FLUTE, g_ini[1], g_len[1], &e) == SHZ_TH_OK && st.generation == 2);
    CHECK(ShzThemeStateApply(&st, SHZ_THEME_JADE, g_ini[2], g_len[2], &e) == SHZ_TH_OK && st.generation == 3);
    n = mut(g_ini[0], g_len[0], m, "name=Slade", "name=MyCustom");
    n = mut(m, n, m2, "kind=builtin", "kind=custom");
    CHECK(ShzThemeStateApply(&st, SHZ_THEME_CUSTOM, m2, n, &e) == SHZ_TH_OK && st.generation == 4 && st.id == SHZ_THEME_CUSTOM);
    CHECK(strcmp(st.cur.meta_name, "MyCustom") == 0);
    snap = st;                                           /* byte-exact snapshot of the published configuration */
    {   static char bad[SHZ_THEME_MAX_BYTES + 4096]; size_t bn;
        static const struct { const char *from, *to; int code; const char *label; } bm[] = {
            { "[files]", "[files]\nrow_height=22", SHZ_TH_E_DUP_KEY, "duplicate key" },
            { "row_height=32", "row_height=32\nbogus_key=1", SHZ_TH_E_UNKNOWN_KEY, "unknown key" },
            { "[cursor]", "[nosuch]\nx=1\n[cursor]", SHZ_TH_E_UNKNOWN_SECTION, "unknown section" },
            { "[files]", "[files]\n[files]", SHZ_TH_E_DUP_SECTION, "duplicate section" },
            { "bar_height=44\n", "", SHZ_TH_E_MISSING, "missing key" },
            { "row_height=32", "row_height=19", SHZ_TH_E_RANGE, "file row below 22..40 range" },
            { "bar_height=44", "bar_height=abc", SHZ_TH_E_BAD_VALUE, "non-integer" },
            { "autohide=0", "autohide=2", SHZ_TH_E_BAD_VALUE, "bool" },
            { "position=bottom", "position=center", SHZ_TH_E_BAD_VALUE, "enum" },
            { "desktop_top=#263B55", "desktop_top=263B55", SHZ_TH_E_BAD_VALUE, "colour no hash" },
            { "image=none", "image=../x.png", SHZ_TH_E_BAD_VALUE, "traversal" },
            { "image=none\nstyle=fill", "image=a/../b.png\nstyle=fill", SHZ_TH_E_BAD_VALUE, "dotdot segment" },
            { "image=none\nstyle=fill", "image=/etc/x.png\nstyle=fill", SHZ_TH_E_BAD_VALUE, "absolute" },
            { "image=none\nstyle=fill", "image=a\\b.png\nstyle=fill", SHZ_TH_E_BAD_VALUE, "backslash" },
            { "image=none\nstyle=fill", "image=C:x.png\nstyle=fill", SHZ_TH_E_BAD_VALUE, "drive colon" },
            { "image=none\nstyle=fill", "image=wall.exe\nstyle=fill", SHZ_TH_E_BAD_VALUE, "extension" },
            { "startup=none", "startup=x.mp3", SHZ_TH_E_BAD_VALUE, "sound ext" },
            { "[window]", "[window\nx", SHZ_TH_E_SYNTAX, "bad header" },
            { "[taskbar]\nheight=44", "[taskbar]\nheight 44", SHZ_TH_E_SYNTAX, "missing =" },
            { "[taskbar]\nheight=44", "[taskbar]\nheight=", SHZ_TH_E_BAD_VALUE, "empty value" },
            { "name=MyCustom", "name=My Custom", SHZ_TH_E_BAD_VALUE, "token charset" },
            { "taskbar_alpha=255", "taskbar_alpha=200", SHZ_TH_E_INVARIANT, "alpha without enabled" },
            { "[taskbar]\nheight=44", "[taskbar]\nheight=27", SHZ_TH_E_RANGE, "taskbar below range" },
            { "[icons]\nsize=48", "[icons]\nsize=70", SHZ_TH_E_RANGE, "icon size range" },
            { "text=#FFFFFF\nstatus_text=#FFFFFF", "text=#334C67\nstatus_text=#FFFFFF", SHZ_TH_E_INVARIANT, "contrast" },
            { "mode=gradient", "mode=image", SHZ_TH_E_INVARIANT, "mode=image needs image" },
            { "name=MyCustom", "name=Flute", SHZ_TH_E_IDENTITY, "reserved name (custom slot)" },
            { "kind=custom", "kind=builtin", SHZ_TH_E_IDENTITY, "wrong kind" },
        };
        for (i = 0; i < sizeof bm / sizeof bm[0]; ++i) {
            int rc; bn = mut(m2, n, bad, bm[i].from, bm[i].to);
            rc = ShzThemeStateApply(&st, SHZ_THEME_CUSTOM, bad, bn, &e);
            if (rc != bm[i].code) printf("  case '%s': got %d (%s) expected %d\n", bm[i].label, rc, e.msg, bm[i].code);
            CHECK(rc == bm[i].code);
            CHECK(st.generation == snap.generation && st.id == snap.id && st.valid == snap.valid &&
                  memcmp(&st.cur, &snap.cur, sizeof st.cur) == 0);          /* exact retained config + generation */
        }
        CHECK(st.rejects == sizeof bm / sizeof bm[0]);
        CHECK(st.last_reject.code == SHZ_TH_E_IDENTITY && st.last_reject.msg[0]);
    }
    /* identity: another theme's bytes in the wrong builtin slot are refused atomically */
    CHECK(ShzThemeStateApply(&st, SHZ_THEME_SLADE, g_ini[1], g_len[1], &e) == SHZ_TH_E_IDENTITY && st.generation == 4 && memcmp(&st.cur, &snap.cur, sizeof st.cur) == 0);
    CHECK(ShzThemeStateApply(&st, 9, g_ini[0], g_len[0], &e) == SHZ_TH_E_IDENTITY && st.generation == 4);
    CHECK(ShzThemeStateApply(&st, SHZ_THEME_SLADE, NULL, 10, &e) == SHZ_TH_E_NULL && st.generation == 4);

    /* 4. bounds: size, line length, line count, control/non-ASCII bytes, lone CR, empty */
    CHECK(code_of(g_ini[0], 0, &e) == SHZ_TH_E_EMPTY);
    { static char big[SHZ_THEME_MAX_BYTES + 64]; size_t k;
      memset(big, ' ', sizeof big);
      CHECK(code_of(big, SHZ_THEME_MAX_BYTES + 1, &e) == SHZ_TH_E_TOO_BIG);
      for (k = 0; k < SHZ_THEME_MAX_LINES + 2; ++k) big[k * 2] = '\n', big[k * 2 + 1] = ';';
      CHECK(code_of(big, SHZ_THEME_MAX_LINES * 2 + 8, &e) == SHZ_TH_E_TOO_MANY_LINES);
      memset(big, 'a', 400); big[400] = '\n';
      CHECK(code_of(big, 401, &e) == SHZ_TH_E_LINE_LONG);
      memcpy(big, "; x\x01\n", 5); CHECK(code_of(big, 5, &e) == SHZ_TH_E_BAD_BYTE);
      memcpy(big, "; \xC3\xA9\n", 5); CHECK(code_of(big, 5, &e) == SHZ_TH_E_BAD_BYTE);
      memcpy(big, "; a\rb\n", 6); CHECK(code_of(big, 6, &e) == SHZ_TH_E_BAD_BYTE);
      memcpy(big, "\xEF\xBB\xBF[meta]", 9); CHECK(code_of(big, 9, &e) == SHZ_TH_E_BAD_BYTE);
      memcpy(big, "a=1\n", 4); CHECK(code_of(big, 4, &e) == SHZ_TH_E_SYNTAX);          /* key before any section */
    }
    /* parse failure never writes the output struct */
    { SHZ_THEME sentinel; memset(&sentinel, 0x5A, sizeof sentinel); t = sentinel;
      CHECK(ShzThemeParse("[meta]\nschema=1\n", 16, &t, &e) == SHZ_TH_E_MISSING && memcmp(&t, &sentinel, sizeof t) == 0); }
    /* CRLF line ends are accepted and give identical data */
    { static char crlf[SHZ_THEME_MAX_BYTES + 2048]; size_t o = 0, k; SHZ_THEME a, b;
      for (k = 0; k < g_len[0]; ++k) { if (g_ini[0][k] == '\n') crlf[o++] = '\r'; crlf[o++] = g_ini[0][k]; }
      CHECK(o < SHZ_THEME_MAX_BYTES);
      CHECK(ShzThemeParse(crlf, o, &a, &e) == SHZ_TH_OK && ShzThemeParse(g_ini[0], g_len[0], &b, &e) == SHZ_TH_OK && memcmp(&a, &b, sizeof a) == 0); }

    /* 5. requested vs supported capability semantics (nothing unsupported is reported as applied) */
    { SHZ_THEME s, f, j; uint32_t sup = ShzThemeSupportedMask();
      ShzThemeParse(g_ini[0], g_len[0], &s, 0); ShzThemeParse(g_ini[1], g_len[1], &f, 0); ShzThemeParse(g_ini[2], g_len[2], &j, 0);
      CHECK(ShzThemeUnsupportedMask(&s) == SHZ_CAP_NOTO_RENDER && (ShzThemeEffectiveMask(&s) & (SHZ_CAP_VECTOR_ICONS | SHZ_CAP_PALETTE | SHZ_CAP_METRICS | SHZ_CAP_GRADIENT)) == (SHZ_CAP_VECTOR_ICONS | SHZ_CAP_PALETTE | SHZ_CAP_METRICS | SHZ_CAP_GRADIENT));
      CHECK(!(sup & (SHZ_CAP_BITMAP_FONT | SHZ_CAP_NOTO_RENDER)));
      CHECK((ShzThemeUnsupportedMask(&f) & (SHZ_CAP_TRANSPARENCY | SHZ_CAP_BLUR | SHZ_CAP_ANIMATION)) == (SHZ_CAP_TRANSPARENCY | SHZ_CAP_BLUR | SHZ_CAP_ANIMATION));
      CHECK((ShzThemeUnsupportedMask(&j) & (SHZ_CAP_AUDIO | SHZ_CAP_NC_TITLEBAR)) == (SHZ_CAP_AUDIO | SHZ_CAP_NC_TITLEBAR));
      CHECK((sup & (SHZ_CAP_TRANSPARENCY | SHZ_CAP_BLUR | SHZ_CAP_ANIMATION | SHZ_CAP_WALLPAPER_IMAGE | SHZ_CAP_CUSTOM_FONT | SHZ_CAP_CUSTOM_CURSOR | SHZ_CAP_AUDIO | SHZ_CAP_NC_TITLEBAR | SHZ_CAP_ICON_IMAGES | SHZ_CAP_CORNER_RADIUS | SHZ_CAP_TASKBAR_EDGE | SHZ_CAP_WINDOW_SHADOW | SHZ_CAP_START_USER_PANEL)) == 0);
      CHECK((ShzThemeEffectiveMask(&f) & ShzThemeUnsupportedMask(&f)) == 0 && (ShzThemeRequestedMask(&f) == (ShzThemeEffectiveMask(&f) | ShzThemeUnsupportedMask(&f))));
      ShzThemeMaskNames(ShzThemeUnsupportedMask(&f), names, sizeof names);
      printf("Flute unsupported: %s\n", names);
      CHECK(strstr(names, "alpha") && strstr(names, "blur") && strstr(names, "anim"));
      ShzThemeMaskNames(ShzThemeUnsupportedMask(&j), names, sizeof names);
      printf("Jade unsupported: %s\n", names);
      CHECK(strstr(names, "audio") && strstr(names, "nctitle"));
      /* more requests: image wallpaper, custom font/cursor, corner radius, taskbar edge, icons */
      n = mut(g_ini[0], g_len[0], m, "mode=gradient\nimage=none", "mode=image\nimage=wall/a.png");
      CHECK(code_of(m, n, &e) == SHZ_TH_OK);
      { SHZ_THEME w; ShzThemeParse(m, n, &w, 0); CHECK(ShzThemeUnsupportedMask(&w) & SHZ_CAP_WALLPAPER_IMAGE); CHECK(ShzThemeEffectiveMask(&w) & SHZ_CAP_GRADIENT); }
      /* Metadata readiness is modeled here: this portable test never initialises FreeType or executes Win32.
       * Production publishes ready only after ShzTextFontInit succeeds. No historical bitmap fallback exists. */
      { SHZ_THEME a; int k;
        for (k = 0; k < 3; ++k) {
            ShzThemeParse(g_ini[k], g_len[k], &a, 0);
            CHECK(strcmp(a.typography_face, "Noto Sans KR") == 0 && ShzThemeFontAllowed(ShzThemeRequestedFace(&a)));
            CHECK(ShzThemeRequestedMask(&a) & SHZ_CAP_NOTO_RENDER);              /* requested ... */
            CHECK(ShzThemeUnsupportedMask(&a) & SHZ_CAP_NOTO_RENDER);            /* ... and not available */
            CHECK(!(ShzThemeEffectiveMask(&a) & SHZ_CAP_NOTO_RENDER));
            CHECK(!(ShzThemeEffectiveMask(&a) & SHZ_CAP_BITMAP_FONT));
            ShzThemeMaskNames(ShzThemeUnsupportedMask(&a), names, sizeof names);
            CHECK(strstr(names, "notorender") != NULL);
        }
        CHECK(strcmp(ShzThemeActualRenderer(), "Noto unavailable") == 0);
        CHECK(strstr(ShzThemeFontGaps(), "font-not-ready"));
        ShzThemeSetFontReady(1);                   /* readiness-gate control, not a backend/font proof */
        CHECK(ShzThemeSupportedMask() & SHZ_CAP_NOTO_RENDER);
        CHECK(ShzThemeEffectiveMask(&a) & SHZ_CAP_NOTO_RENDER);
        CHECK(!(ShzThemeUnsupportedMask(&a) & SHZ_CAP_NOTO_RENDER));
        CHECK(strstr(ShzThemeActualRenderer(), "FreeType") && strstr(ShzThemeActualRenderer(), "proportional"));
        CHECK(strstr(ShzThemeFontGaps(), "no-shaping") && !strstr(ShzThemeFontGaps(), "no-antialias"));
        ShzThemeSetFontReady(0);
        CHECK(!(ShzThemeSupportedMask() & SHZ_CAP_NOTO_RENDER) && (ShzThemeUnsupportedMask(&a) & SHZ_CAP_NOTO_RENDER));
        ShzThemeSetFontReady(2);                   /* only exact 1 can publish readiness */
        CHECK(!(ShzThemeSupportedMask() & SHZ_CAP_NOTO_RENDER));
        CHECK(!ShzThemeFontAllowed("noto sans kr") && !ShzThemeFontAllowed("Noto Sans") && !ShzThemeFontAllowed("") && !ShzThemeFontAllowed(NULL) && ShzThemeFontAllowed("Noto Sans KR"));
        CHECK(ShzThemeRequestedFace(NULL) == NULL);
      }
      { static const char *const bad[] = { "face=ShizukuKRBitmap", "face=Segoe UI", "face=noto sans kr", "face=Noto Sans", "face=Noto Sans CJK KR",
                                           "face=Noto Sans KR2", "face=Noto  Sans KR", "face=Noto Sans K", "face=NotoSansKR", "face=Noto Serif KR", "face=Noto Sans KR;x" };
        SHZ_THEME_STATE fs; SHZ_THEME_ERR fe; size_t bi;
        ShzThemeStateInit(&fs);
        CHECK(ShzThemeStateApply(&fs, SHZ_THEME_SLADE, g_ini[0], g_len[0], &fe) == SHZ_TH_OK);
        for (bi = 0; bi < sizeof bad / sizeof bad[0]; ++bi) {
            SHZ_THEME_STATE keep = fs;
            n = mut(g_ini[0], g_len[0], m, "face=Noto Sans KR", bad[bi]);
            CHECK(ShzThemeStateApply(&fs, SHZ_THEME_SLADE, m, n, &fe) == SHZ_TH_E_BAD_VALUE);
            CHECK(strstr(fe.key, "typography.face") != NULL);
            CHECK(fs.generation == keep.generation && memcmp(&fs.cur, &keep.cur, sizeof fs.cur) == 0);   /* atomic */
        }
        /* custom slot is held to the same policy */
        n = mut(g_ini[0], g_len[0], m, "name=Slade", "name=MyCustom"); n = mut(m, n, m2, "kind=builtin", "kind=custom");
        CHECK(code_of(m2, n, &fe) == SHZ_TH_OK);
        n = mut(m2, n, m, "face=Noto Sans KR", "face=Arial");
        CHECK(ShzThemeStateApply(&fs, SHZ_THEME_CUSTOM, m, n, &fe) == SHZ_TH_E_BAD_VALUE && fs.generation == 1);
        /* trailing blanks around the value are trimmed (documented), long face overflows the 32 byte bound */
        n = mut(g_ini[0], g_len[0], m, "face=Noto Sans KR", "face=Noto Sans KR   ");
        CHECK(code_of(m, n, &fe) == SHZ_TH_OK);
        n = mut(g_ini[0], g_len[0], m, "face=Noto Sans KR", "face=Noto Sans KR Noto Sans KR Noto Sans KR");
        CHECK(code_of(m, n, &fe) == SHZ_TH_E_BAD_VALUE);
      }
      /* Actual scalable size is supported; unsupported weight/AA requests remain visible. */
      n = mut(g_ini[0], g_len[0], m, "size=16", "size=20");
      { SHZ_THEME w; CHECK(ShzThemeParse(m, n, &w, 0) == SHZ_TH_OK); CHECK(!(ShzThemeRequestedMask(&w) & SHZ_CAP_CUSTOM_FONT)); CHECK(!(ShzThemeEffectiveMask(&w) & SHZ_CAP_BITMAP_FONT)); }
      n = mut(g_ini[0], g_len[0], m, "weight=normal", "weight=bold");
      { SHZ_THEME w; CHECK(ShzThemeParse(m, n, &w, 0) == SHZ_TH_OK); CHECK(ShzThemeUnsupportedMask(&w) & SHZ_CAP_CUSTOM_FONT); }
      n = mut(g_ini[0], g_len[0], m, "antialias=gray", "antialias=subpixel");
      { SHZ_THEME w; CHECK(ShzThemeParse(m, n, &w, 0) == SHZ_TH_OK); CHECK(ShzThemeUnsupportedMask(&w) & SHZ_CAP_CUSTOM_FONT); }
      n = mut(g_ini[0], g_len[0], m, "scheme=system", "scheme=fancy");
      { SHZ_THEME w; CHECK(ShzThemeParse(m, n, &w, 0) == SHZ_TH_OK); CHECK(ShzThemeUnsupportedMask(&w) & SHZ_CAP_CUSTOM_CURSOR); }
      n = mut(g_ini[0], g_len[0], m, "position=bottom", "position=top");
      { SHZ_THEME w; CHECK(ShzThemeParse(m, n, &w, 0) == SHZ_TH_OK); CHECK(ShzThemeUnsupportedMask(&w) & SHZ_CAP_TASKBAR_EDGE); }
      n = mut(g_ini[0], g_len[0], m, "corner_radius=0", "corner_radius=6");
      { SHZ_THEME w; CHECK(ShzThemeParse(m, n, &w, 0) == SHZ_TH_OK); CHECK(ShzThemeUnsupportedMask(&w) & SHZ_CAP_CORNER_RADIUS); }
      n = mut(g_ini[0], g_len[0], m, "style=flat", "style=glass");
      { SHZ_THEME w; CHECK(ShzThemeParse(m, n, &w, 0) == SHZ_TH_OK); CHECK(ShzThemeUnsupportedMask(&w) & SHZ_CAP_ICON_IMAGES); }
      n = mut(g_ini[0], g_len[0], m, "mode=gradient", "mode=solid");
      { SHZ_THEME w; CHECK(ShzThemeParse(m, n, &w, 0) == SHZ_TH_OK); CHECK(ShzThemeEffectiveMask(&w) & SHZ_CAP_SOLID_WALLPAPER); }
    }
    /* mask-name writer never overflows or cuts a name */
    { char small[8]; size_t w = ShzThemeMaskNames(0xFFFFFFFFu, small, sizeof small);
      CHECK(w < sizeof small && small[w] == 0 && strlen(small) == w);
      CHECK(ShzThemeMaskNames(1, NULL, 0) == 0); CHECK(ShzThemeMaskNames(1, small, 1) == 0 && small[0] == 0); }

    printf("test_theme: %d checks passed, %d failed\n", g_pass, g_fail);
    return g_fail ? 1 : 0;
}
