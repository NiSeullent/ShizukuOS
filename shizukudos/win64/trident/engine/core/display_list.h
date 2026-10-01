/* SPDX-License-Identifier: GPL-2.0-only
 *
 * ShizukuTrident Lite - the display list: what layout (portable, L1) hands to a painter (win/paint_gdi.c, L1).
 * Owner: L1 (display_list.c implements the helpers). Format fixed by DESIGN.md section 6.
 *
 * Items are in painting order (CSS 2.1 Appendix E, simplified: for each stacking context the backgrounds and borders
 * of blocks, floats, inline content, then positioned descendants by z-index). All coordinates are integer CSS px in
 * DOCUMENT space (origin = the initial containing block's top-left); the painter subtracts the scroll offset.
 * Colors are 0xAARRGGBB with straight (not premultiplied) alpha; A = 0 items are not emitted.
 */
#ifndef SHZ_DISPLAY_LIST_H
#define SHZ_DISPLAY_LIST_H

#include "dom.h"
#include "font.h"
#include "image.h"

typedef enum {
    SHZ_DL_FILL = 1,        /* solid rectangle r in color */
    SHZ_DL_BORDER,          /* border of the border box r: u.border per side (top, right, bottom, left) */
    SHZ_DL_TEXT,            /* text run starting at (u.text.x, u.text.baseline) in color with u.text.font */
    SHZ_DL_IMAGE,           /* u.image.image scaled into r */
    SHZ_DL_CONTROL,         /* form control drawn by the engine in its border box r (extra = SHZ_CTL_*) */
    SHZ_DL_MARKER,          /* list marker glyph (extra = SHZ_LIST_*) filling r in color */
    SHZ_DL_CLIP_PUSH,       /* intersect the clip with r (overflow: hidden / scroll) until the matching POP */
    SHZ_DL_CLIP_POP,
    SHZ_DL_FOCUS_RING,      /* dotted focus rectangle around r */
    SHZ_DL_CARET            /* caret bar r (a focused text control) */
} shz_dl_kind;

/* border styles */
enum { SHZ_BS_NONE = 0, SHZ_BS_HIDDEN, SHZ_BS_SOLID, SHZ_BS_DASHED, SHZ_BS_DOTTED, SHZ_BS_DOUBLE, SHZ_BS_GROOVE,
       SHZ_BS_RIDGE, SHZ_BS_INSET, SHZ_BS_OUTSET };
/* list-style-type */
enum { SHZ_LIST_NONE = 0, SHZ_LIST_DISC, SHZ_LIST_CIRCLE, SHZ_LIST_SQUARE, SHZ_LIST_DECIMAL };
/* text decoration flags (item.flags for SHZ_DL_TEXT) */
#define SHZ_DL_UNDERLINE    0x01
#define SHZ_DL_OVERLINE     0x02
#define SHZ_DL_LINE_THROUGH 0x04
/* control state flags (item.flags for SHZ_DL_CONTROL) */
#define SHZ_DL_CHECKED      0x01
#define SHZ_DL_DISABLED     0x02
#define SHZ_DL_FOCUSED      0x04
#define SHZ_DL_PRESSED      0x08

typedef struct shz_dl_item {
    uint8_t kind;                       /* shz_dl_kind */
    uint8_t flags;
    uint16_t extra;
    shz_irect r;
    uint32_t color;
    shz_node *node;                     /* generating node (no reference; valid while the list is) */
    union {
        struct {
            uint8_t style[4];           /* SHZ_BS_*: top, right, bottom, left */
            uint16_t width[4];
            uint32_t color[4];
        } border;
        struct {
            uint32_t text_off, text_len;    /* into the list's text arena (shz_dl_text) */
            shz_font *font;
            int32_t x, baseline;
        } text;
        struct {
            shz_image *image;           /* reference held by the list */
        } image;
        struct {
            uint32_t text_off, text_len;    /* label / value shown in the control */
            shz_font *font;
            uint32_t text_color;
        } control;
    } u;
} shz_dl_item;

typedef struct shz_display_list {
    shz_dl_item *items;
    size_t count, cap;
    shz_buf text;                       /* text arena */
    uint32_t canvas_color;              /* background of the canvas (root/body background propagation) */
    int32_t width, height;              /* document size the list covers */
} shz_display_list;

void         shz_dl_init(shz_display_list *dl);
void         shz_dl_free(shz_display_list *dl);          /* releases image references */
shz_dl_item *shz_dl_push(shz_display_list *dl, int kind);   /* zeroed item, NULL on OOM */
uint32_t     shz_dl_add_text(shz_display_list *dl, const shz_char *s, size_t n);   /* returns the arena offset */
static inline const shz_char *shz_dl_text(const shz_display_list *dl, uint32_t off) { return dl->text.s + off; }

#endif /* SHZ_DISPLAY_LIST_H */
