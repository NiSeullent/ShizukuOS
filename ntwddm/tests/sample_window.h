/* SPDX-License-Identifier: GPL-2.0-only */
#ifndef NTWDM_SAMPLE_WINDOW_H
#define NTWDM_SAMPLE_WINDOW_H
#include "evidence.h"
#include "nttheme.h"
#define SAMPLE_WINDOW_W 180u
#define SAMPLE_WINDOW_H 120u
/* with_text 0 keeps the parts filled and the glyphs unpainted. */
ntth_status sample_window_paint(ntth_session *session, uint8_t *pixels,
                               uint32_t pitch, const char *caption,
                               uint32_t client, int with_text);
#endif
