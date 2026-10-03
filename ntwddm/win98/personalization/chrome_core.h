/* SPDX-License-Identifier: GPL-2.0-only
 * Modern-retro window chrome metrics (caption/menu/scroll/border sizes).
 * Pure policy and record validation; the Win32 application is chrome_native.c.
 * Colours are owned by ../theme_selector; fonts and the taskbar are untouched.
 */
#ifndef SZC_CHROME_CORE_H
#define SZC_CHROME_CORE_H
#include <stdint.h>
#define SZC_KEY "Software\\ShizukuOS\\Personalization\\ChromeMetrics"
#define SZC_COUNT 9u
enum { SZC_BORDER, SZC_CAPTION_W, SZC_CAPTION_H, SZC_SMCAPTION_W, SZC_SMCAPTION_H,
       SZC_MENU_W, SZC_MENU_H, SZC_SCROLL_W, SZC_SCROLL_H };
extern const char *const szc_names[SZC_COUNT];
typedef struct szc_metrics { int32_t v[SZC_COUNT]; } szc_metrics;
/* Every field 1..64 and caption/menu/scroll >= 8 (Win98 refuses smaller). */
int szc_valid(const szc_metrics *);
/* Modern profile derived from the user's current classic metrics: raises the
 * title/menu/scroll targets but never shrinks a larger user setting. 0 on invalid input. */
int szc_modern(const szc_metrics *current, szc_metrics *out);
int szc_equal(const szc_metrics *, const szc_metrics *);
#endif
