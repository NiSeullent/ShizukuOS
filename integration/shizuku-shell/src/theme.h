/* SPDX-License-Identifier: GPL-2.0-only
 * ShizukuOS native shell theme schema, bounded parser, state and capability report.
 *
 * Adaptation provenance (ideas only, nothing copied wholesale, no provider replaced):
 *   - ntwddm/include/nttheme.h (GPL-2.0-only, "NTTH"): colour convention 0x00RRGGBB for parsed theme data and the
 *     bounded/strict-declared-parts philosophy. The Win32 COLORREF (0x00BBGGRR) conversion is explicit here:
 *     ShzThemeColorRefFromRgb / ShzThemeRgbFromColorRef. NTTH's painter is NOT used by the shell (the shell keeps
 *     its own GDI gradient paint and the shared genuine Noto/FreeType text provider).
 *   - shizukudos/win64/apps/shzdesk/theme.h (GPL-2.0-only): exact bounded reader and atomic
 *     temp-write / flush / read-back verify / MoveFileExW publish idea for the persisted selection record.
 * Original ShizukuOS code. Status: source/native-import proof only; no guest execution evidence.
 *
 * Portable part (no OS headers) is host-testable; the native Win32 I/O part needs SHZ_THEME_NATIVE.
 */
#ifndef SHZ_THEME_H
#define SHZ_THEME_H

#include <stddef.h>
#include <stdint.h>

/* ---- documented bounds (all enforced; see THEME-INTEGRATION.md) ---- */
#define SHZ_THEME_MAX_BYTES   16384u   /* file/buffer total */
#define SHZ_THEME_MAX_LINES   512u     /* physical lines incl. blank/comment */
#define SHZ_THEME_MAX_LINE    200u     /* bytes per line without the line break */
#define SHZ_THEME_MAX_KEYLEN  32u      /* key name */
#define SHZ_THEME_MAX_SECTIONS 32u
#define SHZ_THEME_MAX_REF     64u      /* wallpaper/icon/sound/cursor reference text */
#define SHZ_THEME_SCHEMA      1

/* Identities. The Custom slot is the writable external file on the data volume. */
enum { SHZ_THEME_SLADE = 0, SHZ_THEME_FLUTE = 1, SHZ_THEME_JADE = 2, SHZ_THEME_CUSTOM = 3, SHZ_THEME_COUNT = 4 };

/* Enum value indices (position in the key's choice list, see the field list below). */
enum { SHZ_KIND_BUILTIN = 0, SHZ_KIND_CUSTOM = 1 };
enum { SHZ_WP_NONE = 0, SHZ_WP_SOLID = 1, SHZ_WP_GRADIENT = 2, SHZ_WP_IMAGE = 3 };
enum { SHZ_TB_BOTTOM = 0, SHZ_TB_TOP = 1, SHZ_TB_LEFT = 2, SHZ_TB_RIGHT = 3 };
enum { SHZ_WEIGHT_NORMAL = 0, SHZ_WEIGHT_BOLD = 1 };
enum { SHZ_AA_NONE = 0, SHZ_AA_GRAY = 1, SHZ_AA_SUBPIXEL = 2 };
enum { SHZ_ICON_PLACEHOLDER = 0, SHZ_ICON_FLAT = 1, SHZ_ICON_GLASS = 2 };
enum { SHZ_ANIM_NONE = 0 };

/* Field kinds for string keys: 0 token [A-Za-z0-9_-], 1 printable text, 2 image ref, 3 sound ref, 4 cursor ref,
 * 5 font face: exactly SHZ_THEME_FONT_FACE (case-exact ASCII; any other family is rejected). */
#define SHZ_THEME_FONT_FACE "Noto Sans KR"      /* user requirement: Noto Sans family, Noto Sans KR for Hangul */
/*   C(sec,key)                colour "#RRGGBB" (stored 0x00RRGGBB, NTTH order)
 *   I(sec,key,lo,hi)          decimal integer in [lo,hi]
 *   E(sec,key,"a|b|c")        enum, stored as index
 *   B(sec,key)                0 or 1
 *   S(sec,key,cap,kind)       string up to cap characters
 * Every key is REQUIRED exactly once. Order inside the file is free. */
#define SHZ_THEME_FIELDS(C,I,E,B,S) \
 I(meta,schema,1,1) S(meta,name,24,0) S(meta,description,64,1) E(meta,kind,"builtin|custom") \
 I(window,border_width,0,4) I(window,padding,0,16) I(window,corner_radius,0,16) B(window,shadow) \
 B(titlebar,nonclient) I(titlebar,height,22,48) E(titlebar,align,"left|center") \
 C(titlebar,active_top) C(titlebar,active_bottom) C(titlebar,inactive_top) C(titlebar,inactive_bottom) \
 C(titlebar,text_active) C(titlebar,text_inactive) E(titlebar,buttons,"flat|beveled|glass") \
 C(border,active) C(border,inactive) C(border,light) C(border,dark) C(border,focus) \
 C(background,desktop_top) C(background,desktop_bottom) C(background,desktop_text) C(background,panel_face) \
 C(background,panel_text) C(background,surface) C(background,surface_text) C(background,surface_dim_text) \
 C(background,input_bg) C(background,input_border) \
 B(transparency,enabled) I(transparency,taskbar_alpha,0,255) I(transparency,menu_alpha,0,255) I(transparency,window_alpha,0,255) \
 B(blur,enabled) I(blur,radius,0,32) E(blur,target,"none|taskbar|menu|window|all") \
 S(typography,face,32,5) I(typography,size,12,32) E(typography,weight,"normal|bold") \
 E(typography,antialias,"none|gray|subpixel") I(typography,line_height,16,48) \
 I(icons,size,16,64) I(icons,cell_w,64,128) I(icons,cell_h,64,128) I(icons,label_gap,0,16) S(icons,set,64,2) \
 E(icons,style,"placeholder|flat|glass") C(icons,glyph_computer) C(icons,glyph_files) C(icons,glyph_run) \
 I(buttons,height,22,40) I(buttons,gap,0,8) I(buttons,start_width,48,160) I(buttons,min_width,48,120) \
 C(buttons,normal_top) C(buttons,normal_bottom) C(buttons,active_top) C(buttons,active_bottom) \
 C(buttons,pressed_top) C(buttons,pressed_bottom) C(buttons,edge) C(buttons,text) C(buttons,text_pressed) \
 I(taskbar,height,28,64) E(taskbar,position,"bottom|top|left|right") B(taskbar,autohide) \
 C(taskbar,bg_top) C(taskbar,bg_bottom) C(taskbar,gloss_top) C(taskbar,gloss_bottom) C(taskbar,text) \
 C(taskbar,status_text) C(taskbar,warn_text) C(taskbar,overflow_text) \
 I(taskbar,clock_width,72,160) I(taskbar,status_width,192,512) I(taskbar,overflow_width,40,96) \
 I(start,width,200,480) I(start,max_task_rows,1,8) C(start,bg_top) C(start,bg_bottom) C(start,frame) B(start,user_panel) \
 I(menu,row_height,22,48) I(menu,sep_height,4,16) I(menu,indent,0,32) \
 C(menu,text) C(menu,header_text) C(menu,disabled_text) C(menu,separator) \
 C(selection,top) C(selection,bottom) C(selection,text) C(selection,border) \
 C(selection,inactive_top) C(selection,inactive_bottom) C(selection,inactive_text) \
 I(files,row_height,22,40) I(files,bar_height,28,48) I(files,footer_height,22,40) \
 C(files,bar_top) C(files,bar_bottom) C(files,footer_top) C(files,footer_bottom) C(files,error_text) \
 B(animation,enabled) I(animation,duration_ms,0,2000) E(animation,easing,"linear|ease_in|ease_out|ease_in_out") \
 E(animation,menu,"none|fade|slide") E(animation,window,"none|fade|zoom") \
 B(sound,enabled) I(sound,volume,0,100) S(sound,scheme,24,0) \
 S(sound,startup,64,3) S(sound,shutdown,64,3) S(sound,login,64,3) S(sound,logout,64,3) S(sound,error,64,3) \
 S(sound,warning,64,3) S(sound,notification,64,3) S(sound,device_connect,64,3) S(sound,device_disconnect,64,3) \
 S(sound,navigation,64,3) \
 E(wallpaper,mode,"none|solid|gradient|image") S(wallpaper,image,64,2) \
 E(wallpaper,style,"fill|fit|stretch|tile|center") C(wallpaper,color) \
 S(cursor,scheme,24,0) I(cursor,size,16,64) S(cursor,custom,64,4) B(cursor,shadow)

#define SHZ_D_C(s,k) uint32_t s##_##k;
#define SHZ_D_I(s,k,lo,hi) int32_t s##_##k;
#define SHZ_D_E(s,k,ch) uint8_t s##_##k;
#define SHZ_D_B(s,k) uint8_t s##_##k;
#define SHZ_D_S(s,k,cap,kind) char s##_##k[(cap) + 1];

/* Parsed definition (colours are 0x00RRGGBB; use ShzThemeColorRefFromRgb before passing to GDI). */
typedef struct SHZ_THEME {
    SHZ_THEME_FIELDS(SHZ_D_C, SHZ_D_I, SHZ_D_E, SHZ_D_B, SHZ_D_S)
} SHZ_THEME;

/* Result/error codes of the parser. */
enum {
    SHZ_TH_OK = 0, SHZ_TH_E_NULL, SHZ_TH_E_EMPTY, SHZ_TH_E_TOO_BIG, SHZ_TH_E_BAD_BYTE, SHZ_TH_E_LINE_LONG,
    SHZ_TH_E_TOO_MANY_LINES, SHZ_TH_E_SYNTAX, SHZ_TH_E_UNKNOWN_SECTION, SHZ_TH_E_DUP_SECTION,
    SHZ_TH_E_UNKNOWN_KEY, SHZ_TH_E_DUP_KEY, SHZ_TH_E_BAD_VALUE, SHZ_TH_E_RANGE, SHZ_TH_E_MISSING,
    SHZ_TH_E_INVARIANT, SHZ_TH_E_IDENTITY, SHZ_TH_E_IO, SHZ_TH_E_PERSIST, SHZ_TH_E_NO_THEME
};

typedef struct SHZ_THEME_ERR {
    int      code;            /* SHZ_TH_* */
    uint32_t line;            /* 1-based, 0 = not line specific */
    uint32_t win32;           /* Win32 error for IO/persist codes, else 0 */
    char     key[48];         /* section.key or section, truncated */
    char     msg[80];
} SHZ_THEME_ERR;

/* Capability / request bits (one namespace for "requested", "supported", "effective", "unsupported"). */
#define SHZ_CAP_PALETTE          (1u << 0)   /* colours */
#define SHZ_CAP_METRICS          (1u << 1)   /* sizes used by own layout/hit-testing */
#define SHZ_CAP_GRADIENT         (1u << 2)   /* opaque vertical GDI gradients (ShzFillGradientV) */
#define SHZ_CAP_BITMAP_FONT      (1u << 3)   /* historical bit; the Noto successor never advertises it */
#define SHZ_CAP_SOLID_WALLPAPER  (1u << 4)
#define SHZ_CAP_SYSTEM_CURSOR    (1u << 5)
#define SHZ_CAP_TRANSPARENCY     (1u << 8)
#define SHZ_CAP_BLUR             (1u << 9)
#define SHZ_CAP_ANIMATION        (1u << 10)
#define SHZ_CAP_WALLPAPER_IMAGE  (1u << 11)
#define SHZ_CAP_CUSTOM_FONT      (1u << 12)
#define SHZ_CAP_CUSTOM_CURSOR    (1u << 13)
#define SHZ_CAP_AUDIO            (1u << 14)  /* sound scheme refs; no audio output exists */
#define SHZ_CAP_NC_TITLEBAR      (1u << 15)  /* shell windows use the system non-client caption */
#define SHZ_CAP_ICON_IMAGES      (1u << 16)
#define SHZ_CAP_VECTOR_ICONS     (1u << 22)  /* native GDI pictograms; no external image loading */
#define SHZ_CAP_CORNER_RADIUS    (1u << 17)
#define SHZ_CAP_TASKBAR_EDGE     (1u << 18)  /* non-bottom position or auto-hide */
#define SHZ_CAP_WINDOW_SHADOW    (1u << 19)
#define SHZ_CAP_START_USER_PANEL (1u << 20)
#define SHZ_CAP_NOTO_RENDER      (1u << 21)  /* real proportional/grayscale Noto; supported only after actual font init */

/* The requested family is parser-enforced. Runtime metadata stays unavailable until
 * ShzTextFontInit succeeds; portable parser tests can model this state but prove no font execution. */
#define SHZ_THEME_ACTUAL_RENDERER "FreeType Noto Sans/KR (grayscale, proportional)"
#define SHZ_THEME_FONT_GAPS "no-shaping,no-vertical-text,nonclient-external"
void ShzThemeSetFontReady(int ready);               /* single UI owner: publish 1 only after real init; clear on teardown/failure */
int  ShzThemeFontAllowed(const char *face);          /* 1 only for exactly "Noto Sans KR" (gates every font selection) */
const char *ShzThemeRequestedFace(const SHZ_THEME *t);   /* requested face (NULL if t NULL) */
const char *ShzThemeActualRenderer(void);
const char *ShzThemeFontGaps(void);

/* ---- portable API ---- */
uint32_t ShzThemeColorRefFromRgb(uint32_t rgb);      /* 0x00RRGGBB -> COLORREF 0x00BBGGRR */
uint32_t ShzThemeRgbFromColorRef(uint32_t colorref); /* COLORREF 0x00BBGGRR -> 0x00RRGGBB */
int  ShzThemeParseColor(const char *s, uint32_t *rgb);   /* "#RRGGBB" only; 1 ok, 0 reject */
/* Strict parse into *out. On any error *out is NOT touched. Returns SHZ_TH_OK or SHZ_TH_E_*; err may be NULL. */
int  ShzThemeParse(const char *buf, size_t len, SHZ_THEME *out, SHZ_THEME_ERR *err);
const char *ShzThemeIdName(int id);                  /* "Slade","Flute","Jade","Custom", NULL if invalid */
int  ShzThemeIdFromName(const char *name);           /* exact match, -1 otherwise */
/* identity rule: builtin slots need kind=builtin and name==slot name; Custom needs kind=custom and a non-reserved name */
int  ShzThemeCheckIdentity(const SHZ_THEME *t, int id, SHZ_THEME_ERR *err);

uint32_t ShzThemeRequestedMask(const SHZ_THEME *t);  /* what the definition asks for */
uint32_t ShzThemeSupportedMask(void);                /* what THIS shell build implements */
uint32_t ShzThemeEffectiveMask(const SHZ_THEME *t);  /* requested & supported */
uint32_t ShzThemeUnsupportedMask(const SHZ_THEME *t);/* requested & ~supported: never silently applied */
size_t   ShzThemeMaskNames(uint32_t mask, char *out, size_t cap);  /* "blur,anim,..." NUL-terminated, never overflows */

/* Atomic state: a candidate that fails any check leaves cur/id/generation untouched (reject_* record the refusal). */
typedef struct SHZ_THEME_STATE {
    SHZ_THEME cur;
    uint32_t  generation;      /* 0 = nothing published; +1 per successful publish */
    int       id;              /* SHZ_THEME_* of cur, -1 if none */
    int       valid;
    uint32_t  rejects;         /* refused candidates since init */
    SHZ_THEME_ERR last_reject;
} SHZ_THEME_STATE;
void ShzThemeStateInit(SHZ_THEME_STATE *st);
int  ShzThemeStateApply(SHZ_THEME_STATE *st, int id, const char *buf, size_t len, SHZ_THEME_ERR *err);

/* process-wide state used by the shell (single UI thread) */
SHZ_THEME_STATE *ShzThemeGlobal(void);
const SHZ_THEME *ShzThemeCurrent(void);              /* NULL until a theme has been published */
uint32_t ShzThemeGeneration(void);
int      ShzThemeCurrentId(void);

#define ShzThemeCR(rgb) ((unsigned long)ShzThemeColorRefFromRgb(rgb))   /* COLORREF for GDI */

/* Wallpaper provider publication (single UI owner = wallpaper.c). Image capability is supported only while the
 * published generation equals the generation whose pixels were really decoded; 0 clears. */
void ShzThemeSetWallpaperReady(uint32_t generation);

/* Reuses the existing bounded .wav reference grammar; no filesystem authority claim. */
int ShzThemeValidateSoundRef(const char *reference);

#ifdef SHZ_THEME_NATIVE
/* ---- native Win32 part (exported kernel32 file calls only) ---- */
/* Load theme slot `id` from its external file(s): C:\SHZ\SYSTEM\THEMES\<Name>\theme.ini, then
 * <exe dir>\THEMES\<Name>\theme.ini (only when the C: file is absent); Custom: E:\SHZ\THEME\CUSTOM.INI.
 * A failure (missing/IO/malformed) leaves the published theme and generation unchanged. */
int ShzThemeLoadSlot(int id, SHZ_THEME_ERR *err);
/* Open the theme's wallpaper image read-only: C:\SHZ\SYSTEM\THEMES\<Name>\<ref>, then <exe dir>\THEMES\<Name>\<ref>
 * (only when the C: file is absent; Custom: E:\SHZ\THEME\<ref>). ref is a parser-validated safe relative path (1..4 segments, no dots-escape,
 * checked again here). Size is checked against cap (0 < size <= cap). Returns 0 or a Win32 error; caller CloseHandle()s *h. */
uint32_t ShzThemeWallpaperOpen(int id, const char *ref, uint32_t cap, void **h, uint64_t *size);
/* Read persisted selection E:\SHZ\THEME\SELECT.CFG; absent -> Slade. Returns the slot id to try, never fails. */
int ShzThemePersistedSelection(uint32_t *win32err);
/* Atomically publish the selection record (temp, flush, read-back verify, MoveFileExW). 1 ok, 0 fail (err set). */
int ShzThemePersistSelection(int id, uint32_t *win32err);
#endif

#endif
