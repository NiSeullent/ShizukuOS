/* SPDX-License-Identifier: GPL-2.0-only
 * Modern-retro shell profile = ShizukuOS system colours (SetSysColors, owned by
 * ../theme_selector) + modern window metrics (chrome_native). This pure module is
 * the two-step transaction with verified rollback; it performs no OS call itself.
 * Win32 adapters are in native.c. Reports only what actually happened.
 */
#ifndef SZR_RETRO_CORE_H
#define SZR_RETRO_CORE_H
#include <stdint.h>
enum { SZR_STYLE_CLASSIC = 0, SZR_STYLE_SHIZUKUOS = 1, SZR_STYLE_CUSTOM = 2 };
typedef struct szr_ops {
    void *ctx;
    int (*get_style)(void *, uint32_t *style);    /* current colours; 1 ok */
    int (*set_style)(void *, uint32_t style);     /* SZR_STYLE_CLASSIC/SHIZUKUOS, verified by backend */
    int (*metrics_applied)(void *);               /* 1 when modern metrics recorded applied */
    int (*apply_metrics)(void *);                 /* 1 ok (verified by backend) */
    int (*restore_metrics)(void *);               /* 1 ok */
} szr_ops;
enum szr_status {
    SZR_OK,
    SZR_REFUSED,                 /* nothing touched: bad args, unreadable state or custom colours (no exact rollback) */
    SZR_FAILED_ROLLED_BACK,      /* a step failed, earlier step undone and verified */
    SZR_FAILED_ROLLBACK_FAILED   /* a step failed and the undo could not be verified */
};
typedef struct szr_result {
    enum szr_status status;
    int failed_step;   /* 1 colours, 2 metrics, 0 none */
    int undone;        /* rollback attempted */
} szr_result;
/* modern=1: colours ShizukuOS then metrics modern. modern=0: metrics classic then colours Classic.
 * Idempotent: steps already in the target state are skipped. */
int szr_apply(const szr_ops *, int modern, szr_result *);
#endif
