/* ShizukuOS shell candidate: helpers (locale strings, bounded string ops, gradient, status line).
 * Original ShizukuOS code, LGPL-2.1-or-later. */
#include "shell.h"
#include "search.h"
#include "editor.h"
#include "sound.h"
#include "wallpaper.h"
#include "shz_text_diag.h"
#include "shzcrt.h"       /* printf -> shz_printf (project CRT, serial/debug output) */
#include "layout.h"

SHZ_SHELL g_shell;
const char ShzShellBuildId[] = "ShizukuOS shell";

typedef struct { int id; const WCHAR *text; } STRENT;
static const STRENT g_table[] = {
#define X(n, i, s) { i, s },
    SHZ_STRING_TABLE(X)
#undef X
};
#define STR_MIN 101
#define STR_CAP 160
static WCHAR g_cache[IDS__END - STR_MIN][STR_CAP];
static BOOL  g_cached[IDS__END - STR_MIN];

/* Strings come from the ko-KR STRINGTABLE resource linked into the image (LoadStringW). If the resource is
 * absent the compiled table with identical text is used and counted in g_shell.string_fallbacks (a debug counter; NOT displayed anywhere). */
const WCHAR *ShzStr(int id)
{
    int ix = id - STR_MIN;
    unsigned k;
    if (ix < 0 || ix >= IDS__END - STR_MIN) return L"?";
    if (!g_cached[ix]) {
        if (LoadStringW(g_shell.inst, (UINT)id, g_cache[ix], STR_CAP) == 0) {
            const WCHAR *src = L"?";
            for (k = 0; k < sizeof g_table / sizeof g_table[0]; ++k)
                if (g_table[k].id == id) src = g_table[k].text;
            ShzWcsCopy(g_cache[ix], STR_CAP, src);
            g_shell.string_fallbacks++;
        }
        g_cached[ix] = TRUE;
    }
    return g_cache[ix];
}

SIZE_T ShzWcsLen(const WCHAR *s) { SIZE_T n = 0; while (s[n]) ++n; return n; }

BOOL ShzWcsCopy(WCHAR *dst, SIZE_T cap, const WCHAR *src)
{
    SIZE_T n = ShzWcsLen(src), i;
    if (cap == 0) return FALSE;
    if (n >= cap) { dst[0] = 0; return FALSE; }
    for (i = 0; i <= n; ++i) dst[i] = src[i];
    return TRUE;
}

BOOL ShzWcsCat(WCHAR *dst, SIZE_T cap, const WCHAR *src)
{
    SIZE_T d = ShzWcsLen(dst), n = ShzWcsLen(src), i;
    if (d + n >= cap) return FALSE;
    for (i = 0; i <= n; ++i) dst[d + i] = src[i];
    return TRUE;
}

void ShzFormatU64(unsigned long long v, WCHAR *out, SIZE_T cap)
{
    WCHAR tmp[24]; int n = 0; SIZE_T i;
    do { tmp[n++] = (WCHAR)(L'0' + (int)(v % 10)); v /= 10; } while (v && n < 23);
    for (i = 0; i < (SIZE_T)n && i + 1 < cap; ++i) out[i] = tmp[n - 1 - (int)i];
    out[i < cap ? i : cap - 1] = 0;
}

void ShzSetStatus(int id, DWORD err)
{
    static const WCHAR hex[] = L"0123456789ABCDEF";
    WCHAR s[SHZ_STATUS_CHARS];
    s[0] = 0;
    if (err) {                                      /* error code FIRST so a truncated status box still shows it */
        WCHAR code[16]; int i;
        code[0] = L'0'; code[1] = L'x';
        for (i = 0; i < 8; ++i) code[2 + i] = hex[(err >> (28 - 4 * i)) & 15];
        code[10] = L' '; code[11] = 0;
        ShzWcsCopy(s, SHZ_STATUS_CHARS, code);
    }
    if (!ShzWcsCat(s, SHZ_STATUS_CHARS, ShzStr(id))) ShzWcsCopy(s, SHZ_STATUS_CHARS, ShzStr(id));
    ShzWcsCopy(g_shell.status, SHZ_STATUS_CHARS, s);
    g_shell.status_tick = GetTickCount();
    if (err) ShzSoundEvent(SHZ_SOUND_ERROR);
    else if (id==IDS_LAUNCHED) ShzSoundEvent(SHZ_SOUND_NOTIFICATION);
    if (g_shell.tray) InvalidateRect(g_shell.tray, NULL, FALSE);
}

void ShzFillGradientV(HDC dc, const RECT *rc, COLORREF top, COLORREF bottom)
{
    int h = rc->bottom - rc->top, y;
    if (h <= 0) return;
    if (top == bottom) { ShzFill(dc, rc, top); return; } /* flat external themes: one real GDI fill */
    for (y = 0; y < h; ++y) {
        int r = GetRValue(top) + (GetRValue(bottom) - (int)GetRValue(top)) * y / h;
        int g = GetGValue(top) + (GetGValue(bottom) - (int)GetGValue(top)) * y / h;
        int b = GetBValue(top) + (GetBValue(bottom) - (int)GetBValue(top)) * y / h;
        HBRUSH br = CreateSolidBrush(RGB(r, g, b));
        RECT line;
        line.left = rc->left; line.right = rc->right; line.top = rc->top + y; line.bottom = line.top + 1;
        if (br) { FillRect(dc, &line, br); DeleteObject(br); }
    }
}

/* Font selection is gated on the theme font policy: only a theme whose requested face is exactly Noto Sans KR may select a
 * GDI font (the stock GUI font here, a stand-in: shell text is drawn by the Noto/FreeType provider, not by this HFONT). */
HFONT ShzFont(void)
{
    const SHZ_THEME *t = TH();
    if (!t || !ShzThemeFontAllowed(ShzThemeRequestedFace(t))) return NULL;
    return (HFONT)GetStockObject(DEFAULT_GUI_FONT);
}

/*
 * Own-paint text through the Noto Sans / Noto Sans KR provider (ShzTextMeasureExW/ShzTextDrawW, FreeType, loaded from
 * C:\SHZ\FONTS at run time; see integration/shizuku-font and font23-native/). DrawTextW is NOT used. Layout is proportional: every
 * width, ellipsis, wrap and alignment decision uses the real pixel extent from ShzTextMeasureExW (unhinted advances,
 * identical to what ShzTextDrawW draws; no kerning/shaping/IME). Break points are UTF-16 scalar boundaries (a surrogate
 * pair is never split). Foreground = GetTextColor(dc). Every paint is clipped to *rc with SaveDC/IntersectClipRect/
 * RestoreDC; if clipping cannot be set up, or the font is unavailable, nothing is drawn (no fallback face, no
 * unclipped fallback) and draw_text_failures is incremented. Scalars present in neither face are drawn as that face's
 * .notdef box by the provider and counted in g_shell.font_unsupported (named for history: it now counts missing glyphs).
 */
#define SHZ_BASE_PX 16          /* default before theme publication; builtin themes request 16/20/24 scaled pixels */
#define SHZ_MAXLEN  32767       /* provider text limit */
#define SHZ_COORD_MAX 1000000   /* reject absurd rects: keeps all coordinate arithmetic far from int overflow */

static BOOL IsHi(WCHAR c) { return c >= 0xD800 && c <= 0xDBFF; }
static BOOL IsLo(WCHAR c) { return c >= 0xDC00 && c <= 0xDFFF; }

static int UnitEnd(const WCHAR *s, int n, int i)   /* index after the scalar starting at i */
{
    if (IsHi(s[i]) && i + 1 < n && IsLo(s[i + 1])) return i + 2;
    return i + 1;
}

static int SnapDown(const WCHAR *s, int from, int to, int b)   /* nearest scalar boundary <= b */
{
    if (b > from && b < to && IsHi(s[b - 1]) && IsLo(s[b])) --b;
    return b;
}

/* pixel width of s[from,to); -1 when the font cannot measure (unavailable/busy/invalid) */
static int Width(const WCHAR *s, int from, int to, int px)
{
    SIZE e;
    if (to <= from) return 0;
    if (!ShzTextMeasurePxExW(s + from, to - from, px, &e, NULL, NULL)) return -1;
    return e.cx;
}

static int LineH(int px)         /* real line box of both faces, at this paint's density */
{
    SIZE e;
    const SHZ_THEME *t = TH();
    int minimum = t ? ShzScaleMetric(t->typography_line_height, ShzUiScale()) : 0;
    if (!ShzTextMeasurePxExW(L"Ag\xAC00", 3, px, &e, NULL, NULL) || e.cy <= 0) return 0;
    return e.cy < minimum ? minimum : e.cy;
}

/* largest scalar boundary e in [from,to] with Width(from,e) <= maxw (binary search; invariant lo fits, hi boundary).
 * Returns `from` if not even the first scalar fits; -1 on measure failure. */
static int FitEnd(const WCHAR *s, int from, int to, int maxw, int px)
{
    int lo = from, hi = to;
    if (maxw < 0) return from;
    while (lo < hi) {
        int mid = lo + (hi - lo + 1) / 2, w;
        if (mid < to && mid > from && IsHi(s[mid - 1]) && IsLo(s[mid])) ++mid;     /* snap up to a boundary (<= hi) */
        w = Width(s, from, mid, px);
        if (w < 0) return -1;
        if (w <= maxw) lo = mid; else hi = SnapDown(s, from, to, mid - 1);
    }
    return lo;
}

static BOOL Seg(HDC dc, int x, int y, const WCHAR *s, int from, int to, COLORREF fg, int px)
{
    if (to <= from) return TRUE;
    if (!ShzTextDrawPxW(dc, x, y, s + from, to - from, fg, px)) { g_shell.draw_text_failures++; return FALSE; }
    return TRUE;
}

/* one line s[from,to): alignment + END_ELLIPSIS (only when truncation happens) inside avail pixels */
static BOOL Line(HDC dc, const RECT *rc, int y, const WCHAR *s, int from, int to, int avail, UINT fmt, COLORREF fg, int px)
{
    int w = Width(s, from, to, px), x, end = to, ell = 0, ew = 0, shown;
    if (w < 0) return FALSE;
    shown = w;
    if (w > avail) {
        end = from;
        if (fmt & DT_END_ELLIPSIS) {
            ew = Width(L"...", 0, 3, px);
            if (ew < 0) return FALSE;
            if (ew <= avail) ell = 1;
        }
        end = FitEnd(s, from, to, avail - (ell ? ew : 0), px);
        if (end < 0) return FALSE;
        if (end == from && !ell) end = UnitEnd(s, to, from);       /* a glyph wider than the rect: draw it, clipped */
        shown = Width(s, from, end, px);
        if (shown < 0) return FALSE;
        if (ell) shown += ew;
    }
    if (fmt & DT_RIGHT) x = rc->right - shown;
    else if (fmt & DT_CENTER) x = rc->left + ((rc->right - rc->left) - shown) / 2;
    else x = rc->left;
    if (!Seg(dc, x, y, s, from, end, fg, px)) return FALSE;
    if (ell) {
        int bx = Width(s, from, end, px);
        if (bx < 0) return FALSE;
        return Seg(dc, x + bx, y, L"...", 0, 3, fg, px);
    }
    return TRUE;
}

void ShzDrawText(HDC dc, const WCHAR *s, RECT *rc, UINT fmt)
{
    int n = 0, avail, y, saved, lh, px;
    unsigned missing = 0;
    BOOL ok = TRUE;
    COLORREF fg;
    SIZE all;
    if (!dc || !s || !rc || rc->left < -SHZ_COORD_MAX || rc->top < -SHZ_COORD_MAX ||
        rc->right > SHZ_COORD_MAX || rc->bottom > SHZ_COORD_MAX) { g_shell.draw_text_failures++; return; }
    if (rc->right <= rc->left || rc->bottom <= rc->top) return;          /* empty rect: nothing to draw */
    while (s[n] && n < SHZ_MAXLEN) ++n;
    if (s[n]) g_shell.font_truncated++;                                  /* tail beyond the helper limit is not drawn */
    if (!n) return;
    px = ShzScaleMetric(TH() ? TH()->typography_size : SHZ_BASE_PX, ShzUiScale());
    if (!ShzTextMeasurePxExW(s, n, px, &all, &missing, NULL) || !(lh = LineH(px))) {
        g_shell.draw_text_failures++;                                    /* font unavailable: draw nothing, count it */
        return;
    }
    g_shell.font_unsupported += missing;
    avail = rc->right - rc->left;
    fg = GetTextColor(dc);
    if (fg == CLR_INVALID) { g_shell.draw_text_failures++; return; }
    saved = SaveDC(dc);
    if (!saved) { g_shell.draw_text_failures++; return; }
    if (IntersectClipRect(dc, rc->left, rc->top, rc->right, rc->bottom) == ERROR) {
        g_shell.draw_text_failures++;
        RestoreDC(dc, saved);
        return;
    }
    if ((fmt & DT_WORDBREAK) && !(fmt & DT_SINGLELINE)) {
        int pos = 0;
        y = rc->top;
        while (ok && pos < n && y < rc->bottom) {
            int end = FitEnd(s, pos, n, avail, px), line_end, next, j;
            if (pos && lh > rc->bottom - y) break;                 /* no sliver of a further wrapped line */
            if (end < 0) { ok = FALSE; break; }
            if (end >= n) { line_end = n; next = n; }
            else if (s[end] == L' ') { line_end = end; next = end + 1; }          /* word ends exactly at the edge */
            else {
                for (j = end - 1; j > pos && s[j] != L' '; --j) {}
                if (j > pos) { line_end = j; next = j + 1; }                     /* break at last space that fits */
                else {
                    if (end == pos) end = UnitEnd(s, n, pos);                    /* glyph wider than line: at least one */
                    line_end = end; next = end;                                  /* mid-word */
                }
            }
            if (next <= pos) break;                                              /* cannot advance: stop, never loop */
            ok = Line(dc, rc, y, s, pos, line_end, avail, fmt & ~DT_END_ELLIPSIS, fg, px);
            pos = next; y += lh;
        }
    } else {
        y = rc->top;
        if (fmt & DT_VCENTER) y = rc->top + ((rc->bottom - rc->top) - all.cy) / 2;
        ok = Line(dc, rc, y, s, 0, n, avail, fmt, fg, px);
    }
    if (!ok) g_shell.draw_text_failures++;
    if (!RestoreDC(dc, saved)) g_shell.draw_text_failures++;
}

/* Serial markers (project CRT printf). They state what this process observed about ITSELF only: the Noto/FreeType
 * provider initialised (or why not), SetShellWindow returned TRUE, the first paint calls returned. They are NOT
 * evidence that anything is visible on a guest screen and carry guest=unverified. */
BOOL ShzMarkFontReady(void)
{
    DWORD w32 = 0; int ns = 0;
    if (!ShzTextFontInit(&w32, &ns)) {
        ShzThemeSetFontReady(0);
        g_shell.draw_text_failures++;
        printf("SHZ-SHELL FONT unavailable win32=0x%x noto_status=%d files=C:\\SHZ\\FONTS\\NotoSans.ttf,NotoSansKR.otf guest=unverified\n",
               (unsigned)w32, ns);
        return FALSE;
    }
    ShzThemeSetFontReady(1);
    printf("SHZ-SHELL FONT ready renderer=freetype faces=NotoSans+NotoSansKR init_px=%d theme=not-loaded ime=none guest=unverified\n",
           ShzScaleMetric(SHZ_BASE_PX, ShzUiScale()));
    return TRUE;
}

void ShzMarkRegistered(void)
{
    printf("SHZ-SHELL REGISTERED SetShellWindow=TRUE focus_on_desktop=%d guest=unverified\n", g_shell.focus_on_desktop ? 1 : 0);
}

void ShzMarkPainted(BOOL tray)
{
    if (tray) g_shell.tray_painted = TRUE; else g_shell.desktop_painted = TRUE;
    if (!g_shell.ready_emitted && g_shell.shell_registered && g_shell.timers_ok && g_shell.desktop_painted &&
        g_shell.tray_painted && g_shell.draw_text_failures == 0) {
        g_shell.ready_emitted = TRUE;
        printf("SHZ-SHELL READY registered=1 desktop_painted=1 tray_painted=1 unsupported_scalars=%u guest=unverified\n",
               g_shell.font_unsupported);
    }
}

void ShzFormatTime(const SYSTEMTIME *st, WCHAR out[8])
{
    out[0] = (WCHAR)(L'0' + st->wHour / 10 % 10); out[1] = (WCHAR)(L'0' + st->wHour % 10); out[2] = L':';
    out[3] = (WCHAR)(L'0' + st->wMinute / 10 % 10); out[4] = (WCHAR)(L'0' + st->wMinute % 10); out[5] = 0;
}

BOOL ShzGlobalKey(UINT vk)
{
    if (vk==L'P' && GetKeyState(VK_CONTROL)<0 && GetKeyState(VK_SHIFT)<0) {
        ShzSearchOpen(); return TRUE;
    }
    if (vk == VK_LWIN || vk == VK_RWIN) { ShzStartMenuToggle(); return TRUE; }
    if (vk == VK_ESCAPE && g_shell.start_open) { ShzStartMenuClose(); return TRUE; }
    if (vk == VK_F5) { ShzTasksRefresh(); ShzTaskbarInvalidate(); return FALSE; } /* also let the window refresh itself */
    /* Personalization belongs to Settings. Function keys retain their window's meaning. */
    return FALSE;
}

/* ---------------- theme glue (theme.c holds the data; this propagates it) ---------------- */
void ShzFrame(HDC dc, const RECT *rc, COLORREF c, int width)
{
    HBRUSH b;
    RECT r;
    int i;
    if (width <= 0 || !rc) return;
    if (width > 4) width = 4;
    b = CreateSolidBrush(c);
    if (!b) return;
    r = *rc;
    for (i = 0; i < width && r.right - r.left > 1 && r.bottom - r.top > 1; ++i) {
        FrameRect(dc, &r, b);
        r.left++; r.top++; r.right--; r.bottom--;
    }
    DeleteObject(b);
}

void ShzSetStatusText(int id, const char *ascii)
{
    WCHAR s[SHZ_STATUS_CHARS];
    SIZE_T n;
    ShzWcsCopy(s, SHZ_STATUS_CHARS, ShzStr(id));
    ShzWcsCat(s, SHZ_STATUS_CHARS, L" ");
    n = ShzWcsLen(s);
    while (ascii && *ascii && n + 1 < SHZ_STATUS_CHARS) {            /* ASCII only; longer text is cut, never overflows */
        unsigned char ch = (unsigned char)*ascii++;
        s[n++] = (WCHAR)(ch < 0x20 || ch > 0x7E ? '?' : ch);
    }
    s[n] = 0;
    ShzWcsCopy(g_shell.status, SHZ_STATUS_CHARS, s);
    g_shell.status_tick = GetTickCount();
    if (g_shell.tray) InvalidateRect(g_shell.tray, NULL, FALSE);
}

static void ThemePrepareWallpaper(void)
{
    SHZ_WP_STATUS st;
    int rc = ShzWallpaperPrepare(TH(), ShzThemeCurrentId(), ShzThemeGeneration(), &st);
    if (TH()->wallpaper_mode == SHZ_WP_IMAGE)
        printf("SHZ-SHELL WALLPAPER prepare gen=%u err=%u win32=0x%x ready=%u width=%u height=%u fallback=%s\n",
               (unsigned)ShzThemeGeneration(), (unsigned)rc, (unsigned)st.win32, (unsigned)st.image_ready,
               (unsigned)st.width, (unsigned)st.height, st.image_ready ? "none" : "gradient");
}

static void ThemeAnnounce(const char *what)
{
    const SHZ_THEME *t = TH();
    char names[96];
    unsigned long un = ShzThemeUnsupportedMask(t);
    const char *nm = ShzThemeIdName(ShzThemeCurrentId());
    names[0] = 0;
    ShzThemeMaskNames((uint32_t)un, names, sizeof names);
    /* Settings owns user feedback; capability diagnostics never occupy the taskbar. */
    printf("SHZ-SHELL THEME %s id=%s gen=%u requested=0x%x effective=0x%x unsupported=0x%x [%s] font_requested=\"%s\" font_actual=\"%s\" font_gaps=%s guest=unverified\n", what,
           nm ? nm : "?", (unsigned)ShzThemeGeneration(), (unsigned)ShzThemeRequestedMask(t), (unsigned)ShzThemeEffectiveMask(t),
           (unsigned)un, names, ShzThemeRequestedFace(t), ShzThemeActualRenderer(), ShzThemeFontGaps());
}

static void ThemeRefused(const char *what, int id, const SHZ_THEME_ERR *e)
{
    g_shell.theme_refusals++;
    printf("SHZ-SHELL THEME-REFUSED %s slot=%s code=%d line=%u key=%s win32=0x%x kept_gen=%u msg=%s guest=unverified\n", what,
           ShzThemeIdName(id) ? ShzThemeIdName(id) : "?", e->code, (unsigned)e->line, e->key, (unsigned)e->win32,
           (unsigned)ShzThemeGeneration(), e->msg);
}

BOOL ShzThemeShellStartup(void)
{
    SHZ_THEME_ERR e;
    uint32_t w32 = 0;
    int sel = ShzThemePersistedSelection(&w32), rc;
    if (w32) printf("SHZ-SHELL THEME persisted-selection unreadable win32=0x%x (using Slade)\n", (unsigned)w32);
    rc = ShzThemeLoadSlot(sel, &e);
    if (rc != SHZ_TH_OK && sel != SHZ_THEME_SLADE) {
        SHZ_THEME_ERR first = e;
        ThemeRefused("startup", sel, &first);                   /* e.g. malformed Custom: refused, Slade is loaded instead */
        rc = ShzThemeLoadSlot(SHZ_THEME_SLADE, &e);
        if (rc == SHZ_TH_OK) {
            g_shell.theme_ready = TRUE;
            ThemePrepareWallpaper();
            ThemeAnnounce("startup");
            printf("SHZ-SHELL THEME fallback=Slade gen=%u guest=unverified\n", (unsigned)ShzThemeGeneration());
            ShzSetStatus(IDS_THEME_REFUSED, 0);                      /* keep the refusal visible */
            return TRUE;
        }
    }
    if (rc != SHZ_TH_OK) {
        ThemeRefused("startup", sel, &e);
        ShzSetStatus(IDS_ERR_THEME, 0);
        return FALSE;       /* no external theme file at all: refuse to start (no hardcoded palette exists in code) */
    }
    g_shell.theme_ready = TRUE;
    ThemePrepareWallpaper();
    ThemeAnnounce("startup");
    return TRUE;
}

static void ThemePropagate(void)    /* same shell, same windows: no executable replacement, no new window class */
{
    ShzTaskbarRelayout();
    ShzStartMenuRelayout();
    ShzDesktopRelayout();
    ShzRunDialogRelayout();
    ShzSettingsRelayout();
    ShzFilesRelayoutAll();
    ShzEditorRelayout();
    ShzSearchRelayout();
    g_shell.theme_reloads++;
}

static void ThemeLoad(int id, BOOL persist, const char *what)
{
    SHZ_THEME_ERR e;
    uint32_t w32 = 0;
    if (ShzThemeLoadSlot(id, &e) != SHZ_TH_OK) { ThemeRefused(what, id, &e); return; }   /* atomic: config+generation kept */
    ThemePrepareWallpaper(); /* before invalidation and capability announcement */
    ThemePropagate();
    if (persist && !ShzThemePersistSelection(id, &w32)) {
        g_shell.theme_persist_failures++;
        printf("SHZ-SHELL THEME persist-failed win32=0x%x\n", (unsigned)w32);
        ThemeAnnounce(what);
        return;
    }
    ThemeAnnounce(what);
    ShzSoundEvent(SHZ_SOUND_THEME);
}

void ShzThemeShellSelect(int id) { ThemeLoad(id, TRUE, "select"); }
void ShzThemeShellReload(void)   { int id = ShzThemeCurrentId(); ThemeLoad(id < 0 ? SHZ_THEME_SLADE : id, FALSE, "reload"); }
