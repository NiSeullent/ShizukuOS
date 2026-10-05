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
/* Public installer authority. review returns real current device facts and a
 * reason for an excluded disk. claim/check/release are process-owned kernel
 * authority operations, not UI authorization. No ordinal fallback exists. */
typedef struct setup_ui_backend {
    void *ctx;
    int (*prepare)(void *, const char *payload);
    int (*finish)(void *);
    int (*review)(void *, unsigned index, setup_target_t *, char *reason, size_t capacity);
    int (*claim)(void *, const setup_plan_t *);
    int (*check)(void *, const setup_plan_t *);
    int (*release)(void *);
} setup_ui_backend_t;
int setup_ui_run(const plat_t *, const setup_ui_backend_t *, char *answer, size_t capacity,
                 const char *answer_path, const char *payload, setup_result_t *);
#endif
