/* SPDX-License-Identifier: GPL-2.0-only */
#ifndef SHZ_THEME_NATIVE_BACKEND_H
#define SHZ_THEME_NATIVE_BACKEND_H
#include <windows.h>
#include "selector_core.h"

typedef struct shz_theme_native {
    HANDLE mutex;
    shz_theme_value startup;
    uint32_t baseline[SHZ_THEME_COLORS];
    unsigned baseline_captured, poisoned;
} shz_theme_native;

enum shz_theme_current {
    SHZ_THEME_CURRENT_CLASSIC, SHZ_THEME_CURRENT_SHIZUKUOS,
    SHZ_THEME_CURRENT_CUSTOM
};
typedef struct shz_theme_snapshot {
    unsigned saved;
    uint32_t saved_style;
    enum shz_theme_current current;
} shz_theme_snapshot;

/* Open a zero/unopened context. No registry, palette, wallpaper or UI writes.
 * Actual Win98, a bounded executable path and the shared mutex are required. */
int shz_theme_native_open(shz_theme_native *, uint32_t *);
int shz_theme_native_close(shz_theme_native *);
/* UI calls acquire the mutex without waiting, preventing a synchronous native
 * color broadcast from waiting on a window thread that is blocked on its sender. */
int shz_theme_native_snapshot(shz_theme_native *, shz_theme_snapshot *, shz_theme_result *);
/* Apply requires a successful snapshot to capture/validate the Classic baseline.
 * Windowless restore waits at most five seconds, has no snapshot requirement
 * and never writes a profile or Run value. Never call it from a window thread. */
int shz_theme_native_apply(shz_theme_native *, uint32_t, shz_theme_result *);
int shz_theme_native_restore(shz_theme_native *, shz_theme_result *);
#endif
