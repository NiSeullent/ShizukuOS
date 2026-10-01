/* SPDX-License-Identifier: GPL-2.0-only */
#ifndef M98_UXTHEME_ENGINE_CORE_H
#define M98_UXTHEME_ENGINE_CORE_H
#include "nttheme.h"

#define M98_THEME_OFF 0u
#define M98_THEME_CLASSIC 1u
#define M98_THEME_MODERN 2u
#define M98_THEME_ALLOW_NONCLIENT 1u
#define M98_THEME_ALLOW_CONTROLS 2u
#define M98_THEME_ALLOW_WEBCONTENT 4u
#define M98_THEME_CAPACITY 128u

typedef uint32_t m98_theme_handle;
typedef struct m98_theme_engine m98_theme_engine;
ntth_status m98_theme_engine_create(const ntth_create_desc *, m98_theme_engine **);
ntth_status m98_theme_engine_destroy(m98_theme_engine *);
void m98_theme_engine_dispose(m98_theme_engine *);
ntth_status m98_theme_engine_style(m98_theme_engine *, uint32_t);
uint32_t m98_theme_engine_get_style(const m98_theme_engine *);
uint32_t m98_theme_engine_get_flags(const m98_theme_engine *);
void m98_theme_engine_set_flags(m98_theme_engine *, uint32_t);
int m98_theme_engine_active(const m98_theme_engine *);
int m98_theme_engine_app_themed(const m98_theme_engine *);
ntth_status m98_theme_engine_open(m98_theme_engine *, const char *, m98_theme_handle *);
ntth_status m98_theme_engine_close(m98_theme_engine *, m98_theme_handle);
ntth_status m98_theme_engine_query(m98_theme_engine *, m98_theme_handle,
                                  int32_t, int32_t, ntth_part_properties *);
ntth_status m98_theme_engine_draw(m98_theme_engine *, m98_theme_handle,
                                 int32_t, int32_t, uint8_t *, uint32_t,
                                 uint32_t, uint32_t, const ntwg_rect *,
                                 const ntth_draw_opts *);
#endif
