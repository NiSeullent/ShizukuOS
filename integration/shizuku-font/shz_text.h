/* SPDX-License-Identifier: GPL-2.0-only */
#ifndef SHZ_TEXT_H
#define SHZ_TEXT_H
#include <windows.h>
/* UTF-16 text for the shell, antialiased and proportional: rendered through the Noto Sans / Noto Sans KR provider
 * (FreeType, unhinted 26.6 advances) over a transparent background. `scale` 1..8 means 16*scale pixels. This helper
 * does not replace DrawTextW, shaping, vertical layout or an IME. */
BOOL ShzTextMeasureW(LPCWSTR text, int length, int scale, SIZE *extent);
BOOL ShzTextDrawW(HDC dc, int x, int y, LPCWSTR text, int length,
                 COLORREF foreground, int scale);
#endif
