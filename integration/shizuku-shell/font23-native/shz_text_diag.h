/* SPDX-License-Identifier: GPL-2.0-only
 * Diagnostic/init companions of shz_text.h for the Noto-backed wrapper (font23-native/shz_text_noto.c).
 * Consumed by the shell (ui.c). Kept in a separate header so the shared shz_text.h (owned elsewhere) is not edited. */
#ifndef SHZ_TEXT_DIAG_H
#define SHZ_TEXT_DIAG_H
#include "shz_text.h"

/* Real font initialisation (loads pinned C:\SHZ\FONTS files, FT_New_Library, faces). Idempotent, thread-safe once-init;
 * a failure is REMEMBERED (returns the same failure and the same *win32 / *noto_status every call). A caller racing an
 * in-flight init waits (bounded ~5 s); if that wait expires it gets FALSE with ERROR_BUSY and nothing is remembered.
 * Returns TRUE only when both faces are open; after shutdown it returns ERROR_INVALID_STATE. */
BOOL ShzTextFontInit(DWORD *win32, int *noto_status);

/* Like ShzTextMeasureW, additionally reports the number of scalars present in neither face (that face's .notdef box
 * is what ShzTextDrawW draws for them), the font ascent and the glyph count. Any out pointer may be NULL. */
BOOL ShzTextMeasureExW(LPCWSTR text, int length, int scale, SIZE *extent, unsigned *missing, int *ascent);

/* Pixel-size adapters (px 1..128); the scale API above is px = 16*scale. All calls are serialized by a wrapper lock. */
BOOL ShzTextMeasurePxExW(LPCWSTR text, int length, int px, SIZE *extent, unsigned *missing, int *ascent);
BOOL ShzTextDrawPxW(HDC dc, int x, int y, LPCWSTR text, int length, COLORREF foreground, int px);
/* Destroy the owned provider at shell exit (not from DllMain). Subsequent calls fail with ERROR_INVALID_STATE. */
BOOL ShzTextFontShutdown(void);
#endif
