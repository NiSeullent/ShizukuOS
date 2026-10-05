/* SPDX-License-Identifier: GPL-2.0-only
 * ShizukuOS native shell theme: strict bounded INI parser, atomic state, capability report, native load/persist.
 * Adaptation provenance: see theme.h (NTTH 0x00RRGGBB convention; shzdesk theme.h exact-reader/atomic-publish idea).
 * Original ShizukuOS code. No allocation is used anywhere (stack/static only), every loop is bounded by the
 * input length, a table size or a documented constant.
 */
#ifdef SHZ_THEME_NATIVE
#include <windows.h>
#endif
#include "theme.h"

/* ---------------- tiny freestanding helpers ---------------- */
static size_t tl(const char *s) { size_t n = 0; while (s[n]) ++n; return n; }
static int teq(const char *a, const char *b) { while (*a && *a == *b) { ++a; ++b; } return *a == *b; }
static void tcpy(char *d, size_t cap, const char *s, size_t n)   /* copies at most cap-1, always terminates */
{
    size_t i;
    if (!cap) return;
    for (i = 0; i < n && i + 1 < cap && s[i]; ++i) d[i] = s[i];
    d[i] = 0;
}
static int tnoc(unsigned char c) { return (c >= 'A' && c <= 'Z') ? c + 32 : c; }

static void set_err(SHZ_THEME_ERR *e, int code, uint32_t line, const char *sec, const char *key, const char *msg)
{
    size_t n;
    if (!e) return;
    e->code = code; e->line = line; e->win32 = 0; e->key[0] = 0; e->msg[0] = 0;
    if (sec) tcpy(e->key, sizeof e->key, sec, tl(sec));
    if (sec && key) { n = tl(e->key); if (n + 2 < sizeof e->key) { e->key[n] = '.'; tcpy(e->key + n + 1, sizeof e->key - n - 1, key, tl(key)); } }
    else if (key) tcpy(e->key, sizeof e->key, key, tl(key));
    tcpy(e->msg, sizeof e->msg, msg, tl(msg));
}

/* ---------------- colour conversion (explicit, both directions) ---------------- */
uint32_t ShzThemeColorRefFromRgb(uint32_t rgb)
{
    return ((rgb & 0xFFu) << 16) | (rgb & 0xFF00u) | ((rgb >> 16) & 0xFFu);
}
uint32_t ShzThemeRgbFromColorRef(uint32_t cr) { return ShzThemeColorRefFromRgb(cr); }   /* the swap is an involution */

int ShzThemeParseColor(const char *s, uint32_t *rgb)
{
    uint32_t v = 0; int i;
    if (!s || !rgb || tl(s) != 7 || s[0] != '#') return 0;
    for (i = 1; i < 7; ++i) {
        char c = s[i]; uint32_t d;
        if (c >= '0' && c <= '9') d = (uint32_t)(c - '0');
        else if (c >= 'a' && c <= 'f') d = (uint32_t)(c - 'a' + 10);
        else if (c >= 'A' && c <= 'F') d = (uint32_t)(c - 'A' + 10);
        else return 0;
        v = (v << 4) | d;
    }
    *rgb = v;
    return 1;
}

/* ---------------- schema table ---------------- */
enum { FT_COLOR, FT_INT, FT_ENUM, FT_BOOL, FT_STR };
typedef struct FIELD { const char *sec, *key; unsigned char type, kind; unsigned short off, cap; int lo, hi; const char *choices; } FIELD;
#define T_C(s,k)          { #s, #k, FT_COLOR, 0, (unsigned short)offsetof(SHZ_THEME, s##_##k), 0, 0, 0, 0 },
#define T_I(s,k,lo,hi)    { #s, #k, FT_INT, 0, (unsigned short)offsetof(SHZ_THEME, s##_##k), 0, (lo), (hi), 0 },
#define T_E(s,k,ch)       { #s, #k, FT_ENUM, 0, (unsigned short)offsetof(SHZ_THEME, s##_##k), 0, 0, 0, ch },
#define T_B(s,k)          { #s, #k, FT_BOOL, 0, (unsigned short)offsetof(SHZ_THEME, s##_##k), 0, 0, 1, 0 },
#define T_S(s,k,cap,kd)   { #s, #k, FT_STR, kd, (unsigned short)offsetof(SHZ_THEME, s##_##k), cap, 0, 0, 0 },
static const FIELD g_fields[] = { SHZ_THEME_FIELDS(T_C, T_I, T_E, T_B, T_S) };
#define NFIELDS (sizeof g_fields / sizeof g_fields[0])


/* ---------------- value parsers ---------------- */
static int val_int(const char *s, int lo, int hi, int32_t *out, int *range)
{
    int neg = 0; size_t i = 0, n = tl(s); long v = 0;
    *range = 0;
    if (n == 0 || n > 6) return 0;
    if (s[0] == '-') { neg = 1; i = 1; if (n == 1) return 0; }
    for (; i < n; ++i) { if (s[i] < '0' || s[i] > '9') return 0; v = v * 10 + (s[i] - '0'); }
    if (neg) v = -v;
    if (v < lo || v > hi) { *range = 1; return 0; }
    *out = (int32_t)v;
    return 1;
}

static int val_enum(const char *s, const char *choices, uint8_t *out)
{
    size_t n = tl(s), i = 0; unsigned idx = 0;
    if (!n) return 0;
    while (choices[i]) {
        size_t j = i;
        while (choices[j] && choices[j] != '|') ++j;
        if (j - i == n) { size_t k; for (k = 0; k < n && choices[i + k] == s[k]; ++k) {} if (k == n) { *out = (uint8_t)idx; return 1; } }
        if (!choices[j]) break;
        i = j + 1; ++idx;
    }
    return 0;
}

static int tok_char(char c) { return (c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z') || (c >= '0' && c <= '9') || c == '_' || c == '-'; }

/* reference: "none" or a relative path of 1..4 segments [A-Za-z0-9_.-]{1,32}; no leading '.', no "..", no
 * separators other than '/', and the last segment must end in one of the allowed extensions. Wallpaper references are
 * resolved only beneath their selected theme root; other reference providers remain unavailable. */
static int val_ref(const char *s, int kind)
{
    static const char *const ex_img[] = { ".bmp", ".png", ".jpg", ".jpeg", 0 };
    static const char *const ex_snd[] = { ".wav", 0 };
    static const char *const ex_cur[] = { ".cur", ".ani", 0 };
    const char *const *ex = kind == 2 ? ex_img : kind == 3 ? ex_snd : ex_cur;
    size_t n = tl(s), i, seg = 0, seglen = 0, lastseg = 0; int e, ok = 0;
    if (!n || n > SHZ_THEME_MAX_REF) return 0;
    if (teq(s, "none")) return 1;
    for (i = 0; i <= n; ++i) {
        char c = s[i];
        if (c == '/' || c == 0) {
            if (seglen == 0 || seglen > 32) return 0;
            if (c == '/') { if (++seg >= 4) return 0; lastseg = i + 1; seglen = 0; }
            continue;
        }
        if (!(tok_char(c) || c == '.')) return 0;
        if (seglen == 0 && c == '.') return 0;
        if (c == '.' && i + 1 < n && s[i + 1] == '.') return 0;
        ++seglen;
    }
    for (e = 0; ex[e]; ++e) {
        size_t el = tl(ex[e]), k;
        if (n - lastseg > el + 0 && n >= el) {
            for (k = 0; k < el && tnoc((unsigned char)s[n - el + k]) == ex[e][k]; ++k) {}
            if (k == el) ok = 1;
        }
    }
    return ok;
}

int ShzThemeValidateSoundRef(const char *reference)
{
    size_t n;
    if (!reference) return 0;
    for (n=0; n<=SHZ_THEME_MAX_REF && reference[n]; ++n) { }
    if (n>SHZ_THEME_MAX_REF) return 0;
    return val_ref(reference,3);  /* exactly the parser's sound policy */
}

static int val_str(const char *s, size_t n, unsigned cap, int kind, char *dst)
{
    size_t i;
    if (!n || n > cap) return 0;
    if (kind == 5) { if (n != tl(SHZ_THEME_FONT_FACE)) return 0; for (i = 0; i < n; ++i) if (s[i] != SHZ_THEME_FONT_FACE[i]) return 0; }
    else if (kind == 0) { for (i = 0; i < n; ++i) if (!tok_char(s[i])) return 0; }
    else if (kind == 1) { for (i = 0; i < n; ++i) if ((unsigned char)s[i] < 0x20 || (unsigned char)s[i] > 0x7E) return 0; }
    else { char tmp[SHZ_THEME_MAX_REF + 1]; tcpy(tmp, sizeof tmp, s, n); if (!val_ref(tmp, kind)) return 0; }
    for (i = 0; i < n; ++i) dst[i] = s[i];
    dst[n] = 0;
    return 1;
}

/* ---------------- cross-field invariants ---------------- */
static int luma(uint32_t c) { return (int)((299u * ((c >> 16) & 255u) + 587u * ((c >> 8) & 255u) + 114u * (c & 255u)) / 1000u); }
static int lavg(uint32_t a, uint32_t b) { return (luma(a) + luma(b)) / 2; }
static int cdiff(int a, int b) { return a > b ? a - b : b - a; }
#define MIN_CONTRAST 96     /* luma difference (0..255) required between text and the surface it is drawn on */

static const char *invariant(const SHZ_THEME *t, const char **key)
{
    *key = 0;
    if (t->taskbar_height < t->buttons_height + 4) { *key = "taskbar.height"; return "taskbar height < button height + 4"; }
    if (t->buttons_start_width + t->taskbar_clock_width + t->taskbar_status_width + t->taskbar_overflow_width + 16 > 760)
        { *key = "taskbar.status_width"; return "taskbar fixed widths exceed 760 px"; }
    if (t->icons_size + 16 > t->icons_cell_w) { *key = "icons.cell_w"; return "icon cell narrower than icon + 16"; }
    if (t->icons_cell_h < t->icons_size + t->icons_label_gap + 22 + 8) { *key = "icons.cell_h"; return "icon cell too short for icon + label (22 px cell)"; }
    if (t->typography_line_height < t->typography_size) { *key = "typography.line_height"; return "line_height < size"; }
    if (t->start_width < 160 + t->menu_indent + 8) { *key = "start.width"; return "start width < 10 cells + indent + 8"; }
    if (2 * t->window_border_width >= t->start_width) { *key = "window.border_width"; return "border wider than menu"; }
    if (!t->transparency_enabled && (t->transparency_taskbar_alpha != 255 || t->transparency_menu_alpha != 255 || t->transparency_window_alpha != 255))
        { *key = "transparency.enabled"; return "alpha < 255 requires enabled=1"; }
    if (t->transparency_enabled && t->transparency_taskbar_alpha == 255 && t->transparency_menu_alpha == 255 && t->transparency_window_alpha == 255)
        { *key = "transparency.enabled"; return "enabled=1 requires some alpha < 255"; }
    if (!t->blur_enabled && (t->blur_radius != 0 || t->blur_target != 0)) { *key = "blur.enabled"; return "blur radius/target require enabled=1"; }
    if (t->blur_enabled && (t->blur_radius < 1 || t->blur_target == 0)) { *key = "blur.enabled"; return "enabled=1 requires radius>=1 and a target"; }
    if (!t->animation_enabled && (t->animation_duration_ms != 0 || t->animation_menu != 0 || t->animation_window != 0))
        { *key = "animation.enabled"; return "animation settings require enabled=1"; }
    if (t->animation_enabled && (t->animation_duration_ms < 1 || (t->animation_menu == 0 && t->animation_window == 0)))
        { *key = "animation.enabled"; return "enabled=1 requires duration>=1 and a menu/window effect"; }
    if ((t->wallpaper_mode == SHZ_WP_IMAGE) != !teq(t->wallpaper_image, "none")) { *key = "wallpaper.image"; return "mode=image iff image != none"; }
    if (t->sound_enabled) {
        if (teq(t->sound_startup, "none") && teq(t->sound_shutdown, "none") && teq(t->sound_login, "none") && teq(t->sound_logout, "none") &&
            teq(t->sound_error, "none") && teq(t->sound_warning, "none") && teq(t->sound_notification, "none") &&
            teq(t->sound_device_connect, "none") && teq(t->sound_device_disconnect, "none") && teq(t->sound_navigation, "none"))
            { *key = "sound.enabled"; return "enabled=1 requires at least one event reference"; }
    }
#define CONTRAST(txt, bg, name) if (cdiff(luma(txt), (bg)) < MIN_CONTRAST) { *key = name; return "text/background contrast below minimum"; }
    CONTRAST(t->background_surface_text, luma(t->background_surface), "background.surface_text")
    CONTRAST(t->background_surface_dim_text, luma(t->background_surface), "background.surface_dim_text")
    CONTRAST(t->background_panel_text, luma(t->background_panel_face), "background.panel_text")
    CONTRAST(t->background_surface_text, luma(t->background_input_bg), "background.input_bg")
    CONTRAST(t->background_desktop_text, lavg(t->background_desktop_top, t->background_desktop_bottom), "background.desktop_text")
    CONTRAST(t->menu_text, lavg(t->start_bg_top, t->start_bg_bottom), "menu.text")
    CONTRAST(t->menu_header_text, lavg(t->start_bg_top, t->start_bg_bottom), "menu.header_text")
    CONTRAST(t->selection_text, lavg(t->selection_top, t->selection_bottom), "selection.text")
    CONTRAST(t->selection_inactive_text, lavg(t->selection_inactive_top, t->selection_inactive_bottom), "selection.inactive_text")
    CONTRAST(t->buttons_text, lavg(t->buttons_normal_top, t->buttons_normal_bottom), "buttons.text")
    CONTRAST(t->buttons_text, lavg(t->buttons_active_top, t->buttons_active_bottom), "buttons.text")
    CONTRAST(t->buttons_text_pressed, lavg(t->buttons_pressed_top, t->buttons_pressed_bottom), "buttons.text_pressed")
    CONTRAST(t->taskbar_text, lavg(t->taskbar_bg_top, t->taskbar_bg_bottom), "taskbar.text")
    CONTRAST(t->taskbar_status_text, lavg(t->taskbar_bg_top, t->taskbar_bg_bottom), "taskbar.status_text")
    CONTRAST(t->taskbar_warn_text, lavg(t->taskbar_bg_top, t->taskbar_bg_bottom), "taskbar.warn_text")
    CONTRAST(t->taskbar_overflow_text, lavg(t->taskbar_bg_top, t->taskbar_bg_bottom), "taskbar.overflow_text")
    CONTRAST(t->files_error_text, lavg(t->files_footer_top, t->files_footer_bottom), "files.error_text")
#undef CONTRAST
    return 0;
}

/* ---------------- parser ---------------- */
static int find_section(const char *name)
{
    size_t i;
    for (i = 0; i < NFIELDS; ++i) if (teq(g_fields[i].sec, name)) return (int)i;
    return -1;
}

int ShzThemeParse(const char *buf, size_t len, SHZ_THEME *out, SHZ_THEME_ERR *err)
{
    SHZ_THEME d;
    uint8_t seen[NFIELDS];
    const char *secs[SHZ_THEME_MAX_SECTIONS];
    unsigned nsec = 0, i;
    const char *cursec = 0;
    size_t pos = 0;
    uint32_t line = 0;
    char *dp = (char *)&d;

    if (!buf || !out) { set_err(err, SHZ_TH_E_NULL, 0, 0, 0, "null argument"); return SHZ_TH_E_NULL; }
    if (len == 0) { set_err(err, SHZ_TH_E_EMPTY, 0, 0, 0, "empty theme"); return SHZ_TH_E_EMPTY; }
    if (len > SHZ_THEME_MAX_BYTES) { set_err(err, SHZ_TH_E_TOO_BIG, 0, 0, 0, "theme larger than 16384 bytes"); return SHZ_TH_E_TOO_BIG; }
    for (i = 0; i < sizeof d; ++i) dp[i] = 0;
    for (i = 0; i < NFIELDS; ++i) seen[i] = 0;

#define FAIL(c, ln, s, k, m) do { set_err(err, (c), (ln), (s), (k), (m)); return (c); } while (0)
    while (pos < len) {
        size_t j = pos, a, b, e;
        char lb[SHZ_THEME_MAX_LINE + 1];
        if (++line > SHZ_THEME_MAX_LINES) FAIL(SHZ_TH_E_TOO_MANY_LINES, line, 0, 0, "more than 512 lines");
        while (j < len && buf[j] != '\n') {
            unsigned char c = (unsigned char)buf[j];
            if (!((c >= 0x20 && c <= 0x7E) || c == '\t' || (c == '\r' && (j + 1 == len || buf[j + 1] == '\n'))))
                FAIL(SHZ_TH_E_BAD_BYTE, line, 0, 0, "control, non-ASCII or lone CR byte");
            ++j;
            if (j - pos > SHZ_THEME_MAX_LINE + 1) FAIL(SHZ_TH_E_LINE_LONG, line, 0, 0, "line longer than 200 bytes");
        }
        a = pos; b = j; pos = j < len ? j + 1 : j;
        if (b > a && buf[b - 1] == '\r') --b;
        if (b - a > SHZ_THEME_MAX_LINE) FAIL(SHZ_TH_E_LINE_LONG, line, 0, 0, "line longer than 200 bytes");
        while (a < b && (buf[a] == ' ' || buf[a] == '\t')) ++a;
        while (b > a && (buf[b - 1] == ' ' || buf[b - 1] == '\t')) --b;
        if (a == b || buf[a] == ';' || buf[a] == '#') continue;
        tcpy(lb, sizeof lb, buf + a, b - a);
        b -= a;
        if (lb[0] == '[') {
            int fi; size_t k;
            if (b < 3 || lb[b - 1] != ']') FAIL(SHZ_TH_E_SYNTAX, line, 0, 0, "malformed section header");
            lb[b - 1] = 0;
            if (b - 2 > 24) FAIL(SHZ_TH_E_UNKNOWN_SECTION, line, 0, 0, "section name too long");
            for (k = 1; lb[k]; ++k) if (!((lb[k] >= 'a' && lb[k] <= 'z') || lb[k] == '_')) FAIL(SHZ_TH_E_SYNTAX, line, 0, 0, "bad section name");
            fi = find_section(lb + 1);
            if (fi < 0) FAIL(SHZ_TH_E_UNKNOWN_SECTION, line, lb + 1, 0, "unknown section");
            for (k = 0; k < nsec; ++k) if (teq(secs[k], g_fields[fi].sec)) FAIL(SHZ_TH_E_DUP_SECTION, line, lb + 1, 0, "duplicate section");
            if (nsec >= SHZ_THEME_MAX_SECTIONS) FAIL(SHZ_TH_E_UNKNOWN_SECTION, line, 0, 0, "too many sections");
            secs[nsec++] = g_fields[fi].sec;
            cursec = g_fields[fi].sec;
        } else {
            size_t eq = 0, ks, ke, vs, ve; char key[SHZ_THEME_MAX_KEYLEN + 1]; const FIELD *f = 0; size_t fx;
            if (!cursec) FAIL(SHZ_TH_E_SYNTAX, line, 0, 0, "key outside any section");
            while (eq < b && lb[eq] != '=') ++eq;
            if (eq == b) FAIL(SHZ_TH_E_SYNTAX, line, 0, 0, "missing '='");
            ks = 0; ke = eq;
            while (ke > ks && (lb[ke - 1] == ' ' || lb[ke - 1] == '\t')) --ke;
            vs = eq + 1; ve = b;
            while (vs < ve && (lb[vs] == ' ' || lb[vs] == '\t')) ++vs;
            if (ke == ks || ke - ks > SHZ_THEME_MAX_KEYLEN) FAIL(SHZ_TH_E_UNKNOWN_KEY, line, cursec, 0, "empty or too long key");
            for (e = ks; e < ke; ++e) if (!((lb[e] >= 'a' && lb[e] <= 'z') || lb[e] == '_')) FAIL(SHZ_TH_E_SYNTAX, line, cursec, 0, "bad key name");
            tcpy(key, sizeof key, lb + ks, ke - ks);
            for (fx = 0; fx < NFIELDS; ++fx) if (teq(g_fields[fx].sec, cursec) && teq(g_fields[fx].key, key)) { f = &g_fields[fx]; break; }
            if (!f) FAIL(SHZ_TH_E_UNKNOWN_KEY, line, cursec, key, "unknown key");
            if (seen[fx]) FAIL(SHZ_TH_E_DUP_KEY, line, cursec, key, "duplicate key");
            if (vs >= ve) FAIL(SHZ_TH_E_BAD_VALUE, line, cursec, key, "empty value");
            lb[ve] = 0;
            {
                const char *v = lb + vs; char *dst = dp + f->off;
                switch (f->type) {
                case FT_COLOR: { uint32_t rgb; if (!ShzThemeParseColor(v, &rgb)) FAIL(SHZ_TH_E_BAD_VALUE, line, cursec, key, "colour must be #RRGGBB");
                                 *(uint32_t *)(void *)dst = rgb; break; }
                case FT_INT:   { int32_t iv = 0; int range;
                                 if (!val_int(v, f->lo, f->hi, &iv, &range)) FAIL(range ? SHZ_TH_E_RANGE : SHZ_TH_E_BAD_VALUE, line, cursec, key, range ? "integer out of range" : "not a decimal integer");
                                 *(int32_t *)(void *)dst = iv; break; }
                case FT_ENUM:  if (!val_enum(v, f->choices, (uint8_t *)dst)) FAIL(SHZ_TH_E_BAD_VALUE, line, cursec, key, "not one of the allowed names"); break;
                case FT_BOOL:  if (!((v[0] == '0' || v[0] == '1') && v[1] == 0)) FAIL(SHZ_TH_E_BAD_VALUE, line, cursec, key, "boolean must be 0 or 1");
                               *(uint8_t *)dst = (uint8_t)(v[0] - '0'); break;
                default:       if (!val_str(v, ve - vs, f->cap, f->kind, dst)) FAIL(SHZ_TH_E_BAD_VALUE, line, cursec, key, f->kind == 5 ? "font face must be exactly Noto Sans KR" : f->kind >= 2 ? "invalid reference (traversal, charset, extension or length)" : "invalid string");
                               break;
                }
            }
            seen[fx] = 1;
        }
    }
    {   /* every section present, every key present exactly once */
        size_t fx;
        for (fx = 0; fx < NFIELDS; ++fx)
            if (!seen[fx]) FAIL(SHZ_TH_E_MISSING, 0, g_fields[fx].sec, g_fields[fx].key, "required key missing");
    }
    {
        const char *key, *m = invariant(&d, &key);
        if (m) FAIL(SHZ_TH_E_INVARIANT, 0, key, 0, m);
    }
#undef FAIL
    {   char *op = (char *)out; for (i = 0; i < sizeof d; ++i) op[i] = dp[i]; }   /* commit only after everything passed */
    if (err) set_err(err, SHZ_TH_OK, 0, 0, 0, "ok");
    return SHZ_TH_OK;
}

int ShzThemeFontAllowed(const char *face) { return face && teq(face, SHZ_THEME_FONT_FACE); }
const char *ShzThemeRequestedFace(const SHZ_THEME *t) { return t ? t->typography_face : 0; }
static int g_font_ready;              /* process-wide metadata, owned by the single shell UI thread */
void ShzThemeSetFontReady(int ready) { g_font_ready = ready == 1; }
const char *ShzThemeActualRenderer(void) { return g_font_ready ? SHZ_THEME_ACTUAL_RENDERER : "Noto unavailable"; }
const char *ShzThemeFontGaps(void) { return g_font_ready ? SHZ_THEME_FONT_GAPS : "font-not-ready," SHZ_THEME_FONT_GAPS; }

/* ---------------- identity ---------------- */
static const char *const g_idnames[SHZ_THEME_COUNT] = { "Slade", "Flute", "Jade", "Custom" };
const char *ShzThemeIdName(int id) { return (id >= 0 && id < SHZ_THEME_COUNT) ? g_idnames[id] : 0; }
int ShzThemeIdFromName(const char *name)
{
    int i;
    if (!name) return -1;
    for (i = 0; i < SHZ_THEME_COUNT; ++i) if (teq(name, g_idnames[i])) return i;
    return -1;
}

int ShzThemeCheckIdentity(const SHZ_THEME *t, int id, SHZ_THEME_ERR *err)
{
    int i;
    if (!t || id < 0 || id >= SHZ_THEME_COUNT) { set_err(err, SHZ_TH_E_IDENTITY, 0, 0, 0, "invalid slot"); return SHZ_TH_E_IDENTITY; }
    if (id != SHZ_THEME_CUSTOM) {
        if (t->meta_kind != SHZ_KIND_BUILTIN || !teq(t->meta_name, g_idnames[id]))
            { set_err(err, SHZ_TH_E_IDENTITY, 0, "meta", "name", "builtin slot needs kind=builtin and its own name"); return SHZ_TH_E_IDENTITY; }
    } else {
        for (i = 0; i < SHZ_THEME_CUSTOM; ++i) {
            const char *a = t->meta_name, *b = g_idnames[i]; int same = 1;
            while (*a || *b) { if (tnoc((unsigned char)*a) != tnoc((unsigned char)*b)) { same = 0; break; } if (*a) ++a; if (*b) ++b; }
            if (same) { set_err(err, SHZ_TH_E_IDENTITY, 0, "meta", "name", "custom theme may not use a reserved name"); return SHZ_TH_E_IDENTITY; }
        }
        if (t->meta_kind != SHZ_KIND_CUSTOM) { set_err(err, SHZ_TH_E_IDENTITY, 0, "meta", "kind", "custom slot needs kind=custom"); return SHZ_TH_E_IDENTITY; }
    }
    return SHZ_TH_OK;
}

/* ---------------- capabilities ---------------- */
static SHZ_THEME_STATE g_state;      /* tentative; defined below */
static uint32_t g_wp_gen;
void ShzThemeSetWallpaperReady(uint32_t generation) { g_wp_gen = generation; }

uint32_t ShzThemeSupportedMask(void)
{
    return (g_wp_gen && g_wp_gen == g_state.generation ? SHZ_CAP_WALLPAPER_IMAGE : 0) | SHZ_CAP_PALETTE | SHZ_CAP_METRICS | SHZ_CAP_GRADIENT | SHZ_CAP_SOLID_WALLPAPER |
           SHZ_CAP_SYSTEM_CURSOR | SHZ_CAP_VECTOR_ICONS | (g_font_ready ? SHZ_CAP_NOTO_RENDER : 0);
}

uint32_t ShzThemeRequestedMask(const SHZ_THEME *t)
{
    uint32_t m = SHZ_CAP_PALETTE | SHZ_CAP_METRICS | SHZ_CAP_GRADIENT;
    if (!t) return 0;
    /* Normal weight/grayscale, pixel size and minimum line spacing are consumed by
     * the real UI provider. Bold, no-AA and subpixel requests remain unapplied. */
    m |= SHZ_CAP_NOTO_RENDER;
    if (!teq(t->typography_face, SHZ_THEME_FONT_FACE) || t->typography_weight != SHZ_WEIGHT_NORMAL ||
        t->typography_antialias != SHZ_AA_GRAY) m |= SHZ_CAP_CUSTOM_FONT;
    if (t->wallpaper_mode == SHZ_WP_SOLID) m |= SHZ_CAP_SOLID_WALLPAPER;
    if (t->wallpaper_mode == SHZ_WP_IMAGE) m |= SHZ_CAP_WALLPAPER_IMAGE;
    if (teq(t->cursor_scheme, "system") && teq(t->cursor_custom, "none") && t->cursor_size == 32 && !t->cursor_shadow) m |= SHZ_CAP_SYSTEM_CURSOR;
    else m |= SHZ_CAP_CUSTOM_CURSOR;
    if (t->transparency_enabled) m |= SHZ_CAP_TRANSPARENCY;
    if (t->blur_enabled) m |= SHZ_CAP_BLUR;
    if (t->animation_enabled) m |= SHZ_CAP_ANIMATION;
    if (t->sound_enabled) m |= SHZ_CAP_AUDIO;
    if (t->titlebar_nonclient) m |= SHZ_CAP_NC_TITLEBAR;
    if (t->icons_style == SHZ_ICON_FLAT) m |= SHZ_CAP_VECTOR_ICONS;
    if (!teq(t->icons_set, "none") || t->icons_style == SHZ_ICON_GLASS) m |= SHZ_CAP_ICON_IMAGES;
    if (t->window_corner_radius > 0) m |= SHZ_CAP_CORNER_RADIUS;
    if (t->taskbar_position != SHZ_TB_BOTTOM || t->taskbar_autohide) m |= SHZ_CAP_TASKBAR_EDGE;
    if (t->window_shadow) m |= SHZ_CAP_WINDOW_SHADOW;
    if (t->start_user_panel) m |= SHZ_CAP_START_USER_PANEL;
    return m;
}
uint32_t ShzThemeEffectiveMask(const SHZ_THEME *t) { return ShzThemeRequestedMask(t) & ShzThemeSupportedMask(); }
uint32_t ShzThemeUnsupportedMask(const SHZ_THEME *t) { return ShzThemeRequestedMask(t) & ~ShzThemeSupportedMask(); }

size_t ShzThemeMaskNames(uint32_t mask, char *out, size_t cap)
{
    static const struct { uint32_t bit; const char *name; } nm[] = {
        { SHZ_CAP_VECTOR_ICONS, "vectoricons" }, { SHZ_CAP_PALETTE, "palette" }, { SHZ_CAP_METRICS, "metrics" }, { SHZ_CAP_GRADIENT, "gradient" },
        { SHZ_CAP_BITMAP_FONT, "bitmapfont" }, { SHZ_CAP_SOLID_WALLPAPER, "solidwall" }, { SHZ_CAP_SYSTEM_CURSOR, "syscursor" },
        { SHZ_CAP_TRANSPARENCY, "alpha" }, { SHZ_CAP_BLUR, "blur" }, { SHZ_CAP_ANIMATION, "anim" },
        { SHZ_CAP_WALLPAPER_IMAGE, "wallimg" }, { SHZ_CAP_CUSTOM_FONT, "font" }, { SHZ_CAP_CUSTOM_CURSOR, "cursor" },
        { SHZ_CAP_AUDIO, "audio" }, { SHZ_CAP_NC_TITLEBAR, "nctitle" }, { SHZ_CAP_ICON_IMAGES, "iconimg" },
        { SHZ_CAP_CORNER_RADIUS, "corner" }, { SHZ_CAP_TASKBAR_EDGE, "tbedge" }, { SHZ_CAP_WINDOW_SHADOW, "shadow" },
        { SHZ_CAP_START_USER_PANEL, "userpanel" }, { SHZ_CAP_NOTO_RENDER, "notorender" } };
    size_t n = 0, i, k;
    if (!out || !cap) return 0;
    out[0] = 0;
    for (i = 0; i < sizeof nm / sizeof nm[0]; ++i) {
        size_t l;
        if (!(mask & nm[i].bit)) continue;
        l = tl(nm[i].name);
        if (n + l + (n ? 1 : 0) + 1 > cap) break;               /* never overflow, never cut a name in half */
        if (n) out[n++] = ',';
        for (k = 0; k < l; ++k) out[n++] = nm[i].name[k];
        out[n] = 0;
    }
    return n;
}

/* ---------------- atomic state ---------------- */
void ShzThemeStateInit(SHZ_THEME_STATE *st)
{
    char *p = (char *)st; size_t i;
    if (!st) return;
    for (i = 0; i < sizeof *st; ++i) p[i] = 0;
    st->id = -1;
}

int ShzThemeStateApply(SHZ_THEME_STATE *st, int id, const char *buf, size_t len, SHZ_THEME_ERR *err)
{
    SHZ_THEME cand; SHZ_THEME_ERR e; int rc;
    if (!st) { set_err(err, SHZ_TH_E_NULL, 0, 0, 0, "null state"); return SHZ_TH_E_NULL; }
    rc = ShzThemeParse(buf, len, &cand, &e);
    if (rc == SHZ_TH_OK) rc = ShzThemeCheckIdentity(&cand, id, &e);
    if (rc != SHZ_TH_OK) {
        st->last_reject = e; st->rejects++;                 /* previous cur/id/generation are untouched */
        if (err) *err = e;
        return rc;
    }
    st->cur = cand; st->id = id; st->valid = 1; st->generation++;
    if (err) *err = e;
    return SHZ_TH_OK;
}

static SHZ_THEME_STATE g_state = { {0}, 0, -1, 0, 0, {0} };
SHZ_THEME_STATE *ShzThemeGlobal(void) { return &g_state; }
const SHZ_THEME *ShzThemeCurrent(void) { return g_state.valid ? &g_state.cur : 0; }
uint32_t ShzThemeGeneration(void) { return g_state.generation; }
int ShzThemeCurrentId(void) { return g_state.id; }

/* ---------------- native Win32 load / persist ---------------- */
#ifdef SHZ_THEME_NATIVE
#define PATHCAP 260
static char g_filebuf[SHZ_THEME_MAX_BYTES + 1];     /* single UI thread; no heap */

static BOOL wcat(WCHAR *d, size_t cap, const WCHAR *s)
{
    size_t n = 0, i = 0;
    while (n < cap && d[n]) ++n;
    if (n >= cap) return FALSE;
    while (s[i]) { if (n + 1 >= cap) { d[0] = 0; return FALSE; } d[n++] = s[i++]; }
    d[n] = 0;
    return TRUE;
}
static BOOL acat(WCHAR *d, size_t cap, const char *s)
{
    size_t n = 0;
    while (n < cap && d[n]) ++n;
    for (; *s; ++s) { if (n + 1 >= cap) { d[0] = 0; return FALSE; } d[n++] = (WCHAR)(unsigned char)*s; }
    d[n] = 0;
    return TRUE;
}

/* exact bounded read; returns 0 ok, else a Win32 error (ERROR_FILE_NOT_FOUND/PATH_NOT_FOUND = absent) */
static DWORD read_bounded(const WCHAR *path, char *buf, DWORD cap, DWORD *outlen)
{
    HANDLE h; LARGE_INTEGER sz; DWORD got = 0, total = 0, fail = 0; unsigned guard = 0;
    *outlen = 0;
    h = CreateFileW(path, GENERIC_READ, FILE_SHARE_READ, 0, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, 0);
    if (h == INVALID_HANDLE_VALUE) { fail = GetLastError(); return fail ? fail : ERROR_READ_FAULT; }
    if (!GetFileSizeEx(h, &sz)) { fail = GetLastError(); if (!fail) fail = ERROR_READ_FAULT; }
    else if (sz.QuadPart <= 0) fail = ERROR_INVALID_DATA;
    else if (sz.QuadPart > (LONGLONG)cap) fail = ERROR_FILE_TOO_LARGE;
    while (!fail && total < (DWORD)sz.QuadPart && guard++ < 64) {
        got = 0;
        if (!ReadFile(h, buf + total, (DWORD)sz.QuadPart - total, &got, 0)) { fail = GetLastError(); if (!fail) fail = ERROR_READ_FAULT; }
        else if (!got || got > (DWORD)sz.QuadPart - total) fail = ERROR_READ_FAULT;
        else total += got;
    }
    if (!fail && total != (DWORD)sz.QuadPart) fail = ERROR_READ_FAULT;
    if (!CloseHandle(h) && !fail) { fail = GetLastError(); if (!fail) fail = ERROR_READ_FAULT; }   /* cleanup failures count */
    if (!fail) *outlen = total;
    return fail;
}

static BOOL absent(DWORD e) { return e == ERROR_FILE_NOT_FOUND || e == ERROR_PATH_NOT_FOUND; }

static BOOL exe_theme_path(int id, WCHAR *p, size_t cap)
{
    WCHAR m[PATHCAP]; DWORD n = GetModuleFileNameW(NULL, m, PATHCAP), i;
    if (n == 0 || n >= PATHCAP) return FALSE;
    for (i = n; i > 0 && m[i - 1] != L'\\'; --i) {}
    if (i == 0) return FALSE;
    m[i] = 0;
    p[0] = 0;
    return wcat(p, cap, m) && wcat(p, cap, L"THEMES\\") && acat(p, cap, ShzThemeIdName(id)) && wcat(p, cap, L"\\theme.ini");
}

int ShzThemeLoadSlot(int id, SHZ_THEME_ERR *err)
{
    WCHAR p[PATHCAP]; DWORD len = 0, e;
    if (id < 0 || id >= SHZ_THEME_COUNT) { set_err(err, SHZ_TH_E_IDENTITY, 0, 0, 0, "invalid slot"); return SHZ_TH_E_IDENTITY; }
    p[0] = 0;
    if (id == SHZ_THEME_CUSTOM) { wcat(p, PATHCAP, L"E:\\SHZ\\THEME\\CUSTOM.INI"); e = read_bounded(p, g_filebuf, SHZ_THEME_MAX_BYTES, &len); }
    else {
        if (!wcat(p, PATHCAP, L"C:\\SHZ\\SYSTEM\\THEMES\\") || !acat(p, PATHCAP, ShzThemeIdName(id)) || !wcat(p, PATHCAP, L"\\theme.ini"))
            { set_err(err, SHZ_TH_E_IO, 0, 0, 0, "path too long"); return SHZ_TH_E_IO; }
        e = read_bounded(p, g_filebuf, SHZ_THEME_MAX_BYTES, &len);
        if (absent(e) && exe_theme_path(id, p, PATHCAP)) e = read_bounded(p, g_filebuf, SHZ_THEME_MAX_BYTES, &len);
    }
    if (e) {
        set_err(err, SHZ_TH_E_IO, 0, ShzThemeIdName(id), 0, absent(e) ? "theme file not found" : "theme file unreadable or too large");
        if (err) err->win32 = e;
        g_state.rejects++; if (err) g_state.last_reject = *err;     /* state/generation themselves untouched */
        return SHZ_TH_E_IO;
    }
    return ShzThemeStateApply(&g_state, id, g_filebuf, len, err);
}

/* The parser admits 1..4 safe relative segments; resolve that exact contract beneath the selected theme root. */
static int wallpaper_refcat(WCHAR *p, unsigned cap, const char *ref)
{
    size_t n = 0;
    while (p[n]) ++n;
    while (*ref) {
        if (n + 1 >= cap) return 0;
        p[n++] = *ref == '/' ? L'\\' : (WCHAR)(unsigned char)*ref;
        ++ref;
    }
    p[n] = 0;
    return 1;
}

uint32_t ShzThemeWallpaperOpen(int id, const char *ref, uint32_t cap, void **ph, uint64_t *psize)
{
    WCHAR p[PATHCAP]; HANDLE h = INVALID_HANDLE_VALUE; LARGE_INTEGER sz; DWORD e = 0; int pass;
    if (!ph || !psize || id < 0 || id >= SHZ_THEME_COUNT || !ref || !ref[0]) return ERROR_INVALID_PARAMETER;
    *ph = 0; *psize = 0;
    if (!val_ref(ref, 2) || teq(ref, "none")) return ERROR_INVALID_NAME;
    for (pass = 0; pass < 2; ++pass) {
        p[0] = 0;
        if (id == SHZ_THEME_CUSTOM) { if (pass) return e; if (!wcat(p, PATHCAP, L"E:\\SHZ\\THEME\\") || !wallpaper_refcat(p, PATHCAP, ref)) return ERROR_BUFFER_OVERFLOW; }
        else if (pass == 0) { if (!wcat(p, PATHCAP, L"C:\\SHZ\\SYSTEM\\THEMES\\") || !acat(p, PATHCAP, ShzThemeIdName(id)) || !wcat(p, PATHCAP, L"\\") || !wallpaper_refcat(p, PATHCAP, ref)) return ERROR_BUFFER_OVERFLOW; }
        else { WCHAR m[PATHCAP]; DWORD n = GetModuleFileNameW(NULL, m, PATHCAP), i;
               if (n == 0 || n >= PATHCAP) return e;
               for (i = n; i > 0 && m[i - 1] != L'\\'; --i) {} if (!i) return e; m[i] = 0;
               if (!wcat(p, PATHCAP, m) || !wcat(p, PATHCAP, L"THEMES\\") || !acat(p, PATHCAP, ShzThemeIdName(id)) || !wcat(p, PATHCAP, L"\\") || !wallpaper_refcat(p, PATHCAP, ref)) return ERROR_BUFFER_OVERFLOW; }
        h = CreateFileW(p, GENERIC_READ, FILE_SHARE_READ, 0, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, 0);
        if (h != INVALID_HANDLE_VALUE) break;
        e = GetLastError(); if (!e) e = ERROR_READ_FAULT;
        if (!absent(e)) return e;                       /* only absence falls through to the exe-dir copy */
    }
    if (h == INVALID_HANDLE_VALUE) return e;
    if (!GetFileSizeEx(h, &sz)) e = GetLastError() ? GetLastError() : ERROR_READ_FAULT;
    else if (sz.QuadPart <= 0) e = ERROR_INVALID_DATA;
    else if (sz.QuadPart > (LONGLONG)cap) e = ERROR_FILE_TOO_LARGE;
    else e = 0;
    if (e) { CloseHandle(h); return e; }
    *ph = h; *psize = (uint64_t)sz.QuadPart;
    return 0;
}

static const WCHAR kDir1[] = L"E:\\SHZ", kDir2[] = L"E:\\SHZ\\THEME", kSel[] = L"E:\\SHZ\\THEME\\SELECT.CFG", kTmp[] = L"E:\\SHZ\\THEME\\SELNEW.TMP";
#define SEL_MAGIC "SHZTHSEL1\n"
#define SEL_MAXLEN 24                                     /* magic(10) + name(<=6) + '\n' */

int ShzThemePersistedSelection(uint32_t *win32err)
{
    char b[SEL_MAXLEN + 1]; DWORD len = 0, e; int i; size_t magic = tl(SEL_MAGIC), n;
    char name[8];
    if (win32err) *win32err = 0;
    e = read_bounded(kSel, b, SEL_MAXLEN, &len);
    if (e) { if (win32err && !absent(e)) *win32err = e; return SHZ_THEME_SLADE; }
    if (len <= magic + 1 || b[len - 1] != '\n') { if (win32err) *win32err = ERROR_INVALID_DATA; return SHZ_THEME_SLADE; }
    for (i = 0; (size_t)i < magic; ++i) if (b[i] != SEL_MAGIC[i]) { if (win32err) *win32err = ERROR_INVALID_DATA; return SHZ_THEME_SLADE; }
    n = len - 1 - magic;
    if (n >= sizeof name) { if (win32err) *win32err = ERROR_INVALID_DATA; return SHZ_THEME_SLADE; }
    tcpy(name, sizeof name, b + magic, n);
    i = ShzThemeIdFromName(name);
    if (i < 0) { if (win32err) *win32err = ERROR_INVALID_DATA; return SHZ_THEME_SLADE; }
    return i;
}

static DWORD mkdir_ok(const WCHAR *d)
{
    if (CreateDirectoryW(d, 0)) return 0;
    { DWORD e = GetLastError(); if (e == ERROR_ALREADY_EXISTS) return 0; return e ? e : ERROR_WRITE_FAULT; }
}

int ShzThemePersistSelection(int id, uint32_t *win32err)
{
    char rec[SEL_MAXLEN + 1], rb[SEL_MAXLEN + 1]; DWORD n = 0, w, fail = 0, rl = 0, i; HANDLE h; const char *nm = ShzThemeIdName(id);
    size_t k = 0, m;
    if (win32err) *win32err = 0;
    if (!nm) { if (win32err) *win32err = ERROR_INVALID_PARAMETER; return 0; }
    for (m = 0; SEL_MAGIC[m]; ++m) rec[k++] = SEL_MAGIC[m];
    for (m = 0; nm[m]; ++m) rec[k++] = nm[m];
    rec[k++] = '\n'; rec[k] = 0;
    fail = mkdir_ok(kDir1); if (!fail) fail = mkdir_ok(kDir2);
    if (fail) { if (win32err) *win32err = fail; return 0; }
    h = CreateFileW(kTmp, GENERIC_WRITE, 0, 0, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, 0);
    if (h == INVALID_HANDLE_VALUE) { if (win32err) *win32err = GetLastError() ? GetLastError() : ERROR_WRITE_FAULT; return 0; }
    for (i = 0; !fail && n < (DWORD)k && i < 64; ++i) {
        w = 0;
        if (!WriteFile(h, rec + n, (DWORD)k - n, &w, 0)) { fail = GetLastError(); if (!fail) fail = ERROR_WRITE_FAULT; }
        else if (!w || w > (DWORD)k - n) fail = ERROR_WRITE_FAULT;
        else n += w;
    }
    if (!fail && n != (DWORD)k) fail = ERROR_WRITE_FAULT;
    if (!fail && !FlushFileBuffers(h)) { fail = GetLastError(); if (!fail) fail = ERROR_WRITE_FAULT; }
    if (!CloseHandle(h) && !fail) { fail = GetLastError(); if (!fail) fail = ERROR_WRITE_FAULT; }
    if (!fail) {                                           /* read-back verify before publishing */
        DWORD e = read_bounded(kTmp, rb, SEL_MAXLEN, &rl);
        if (e) fail = e;
        else if (rl != (DWORD)k) fail = ERROR_INVALID_DATA;
        else for (i = 0; i < rl; ++i) if (rb[i] != rec[i]) { fail = ERROR_INVALID_DATA; break; }
    }
    if (!fail && !MoveFileExW(kTmp, kSel, MOVEFILE_REPLACE_EXISTING)) { fail = GetLastError(); if (!fail) fail = ERROR_WRITE_FAULT; }
    if (fail) {
        if (!DeleteFileW(kTmp)) { DWORD e = GetLastError(); if (e != ERROR_FILE_NOT_FOUND && win32err) { *win32err = fail; return 0; } }
        if (win32err) *win32err = fail;
        return 0;
    }
    return 1;
}
#endif /* SHZ_THEME_NATIVE */
