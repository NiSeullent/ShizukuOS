/* SPDX-License-Identifier: GPL-2.0-only */
#ifndef SHZ_SETUP_INTERACTIVE_UI_H
#define SHZ_SETUP_INTERACTIVE_UI_H
#include "plat.h"
#include "native_gui.h"
/* 0 approved, 1 cancelled, -1 display/runtime failure. */
int setup_ui_choose(const plat_t *p, char *answer, size_t capacity);
int setup_ui_choose_native(const plat_t *,shz_native_gui *);
void setup_ui_progress(const char *text);
void setup_ui_finish(setup_result_t *result);
#endif
