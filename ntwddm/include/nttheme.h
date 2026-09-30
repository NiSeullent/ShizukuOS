/* SPDX-License-Identifier: GPL-2.0-only
 * In-process visual-style painter for the NTWDDM software framebuffer.
 * Behavior is adapted from the LGPL-2.1-or-later border-fill path in
 * Wine/ReactOS/One-Core uxtheme draw.c. Those sources were not copied.
 * See ../PROVENANCE.md.
 */
#ifndef NTTHEME_H
#define NTTHEME_H

#include "ntwddm.h"

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

/* Public theme-part values used by the bundled styles. They match the
 * Windows BUTTON/WINDOW part and state enumerations for the parts we draw. */
#define NTTH_BP_PUSHBUTTON 1
#define NTTH_PBS_NORMAL 1
#define NTTH_PBS_HOT 2
#define NTTH_PBS_PRESSED 3
#define NTTH_PBS_DISABLED 4
#define NTTH_WP_CAPTION 1
#define NTTH_WP_FRAMELEFT 7
#define NTTH_WP_FRAMERIGHT 8
#define NTTH_WP_FRAMEBOTTOM 9
#define NTTH_CS_ACTIVE 1
#define NTTH_CS_INACTIVE 2
#define NTTH_FS_ACTIVE 1

#define NTTH_BG_IMAGEFILE 0u
#define NTTH_BG_BORDERFILL 1u
#define NTTH_BG_NONE 2u
#define NTTH_FT_SOLID 0u
#define NTTH_FT_VERTGRADIENT 1u
#define NTTH_FT_HORZGRADIENT 2u
#define NTTH_FT_RADIALGRADIENT 3u
#define NTTH_FT_TILEIMAGE 4u

#define NTTH_DRAW_OMIT_BORDER 1u
#define NTTH_DRAW_OMIT_CONTENT 2u
#define NTTH_DRAW_CLIP 4u
#define NTTH_TEXT_GRAYED 8u

typedef enum ntth_status {
    NTTH_OK = 0,
    NTTH_E_INVALID = -1,
    NTTH_E_PARSE = -2,
    NTTH_E_NOMEM = -3,
    NTTH_E_BOUNDS = -4,
    NTTH_E_HANDLE = -5,
    NTTH_E_NO_THEME = -6,
    NTTH_E_UNSUPPORTED = -7,
    NTTH_E_BUSY = -8,
    NTTH_E_EXHAUSTED = -9
} ntth_status;

typedef struct ntth_session ntth_session;
typedef uint64_t ntth_theme;

typedef struct ntth_create_desc {
    uint32_t struct_size;
    ntwg_allocate_fn allocate;
    ntwg_deallocate_fn deallocate;
    void *allocator_user;
} ntth_create_desc;

typedef struct ntth_draw_opts {
    uint32_t struct_size;
    uint32_t flags;
    ntwg_rect clip;
} ntth_draw_opts;

/* An exact declared part/state, with colors in 0x00RRGGBB. Queries do not
 * invent properties for undefined parts and leave output untouched on error. */
typedef struct ntth_part_properties {
    uint32_t bgtype, bordersize, bordercolor, filltype, fillcolor;
    uint32_t gradient1, gradient2, textcolor;
} ntth_part_properties;

ntth_status ntth_query_part(ntth_session *session, ntth_theme theme,
                            int32_t part, int32_t state,
                            ntth_part_properties *out);

/* Built-in style texts. They are parsed; they are not pre-rendered pixels. */
extern const char ntth_builtin_classic_text[];
extern const char ntth_builtin_modern_text[];
extern const size_t ntth_builtin_classic_length;
extern const size_t ntth_builtin_modern_length;

ntth_status ntth_session_open(const ntth_create_desc *desc, ntth_session **out);
ntth_status ntth_session_load(ntth_session *session, const char *text, size_t length);
int ntth_theme_active(const ntth_session *session);
ntth_status ntth_open_data(ntth_session *session, const char *class_name,
                           ntth_theme *out);
ntth_status ntth_close_data(ntth_session *session, ntth_theme theme);
ntth_status ntth_session_close(ntth_session *session);

/* pixels is NTWG_PIXEL_XRGB8888 (B, G, R, X). A missing part still paints the
 * border-fill defaults. Image, radial, and tiled backgrounds fail and write
 * nothing. opts may be NULL. */
ntth_status ntth_draw_background(ntth_session *session, ntth_theme theme,
                                 int32_t part, int32_t state,
                                 uint8_t *pixels, uint32_t width, uint32_t height,
                                 uint32_t pitch, const ntwg_rect *rect,
                                 const ntth_draw_opts *opts);
ntth_status ntth_draw_text(ntth_session *session, ntth_theme theme,
                           int32_t part, int32_t state,
                           const char *text, size_t text_bytes,
                           uint8_t *pixels, uint32_t width, uint32_t height,
                           uint32_t pitch, const ntwg_rect *rect,
                           const ntth_draw_opts *opts);

#ifdef __cplusplus
}
#endif
#endif
