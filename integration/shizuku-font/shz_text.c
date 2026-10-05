/* SPDX-License-Identifier: GPL-2.0-only
 * Bitmap data is separately licensed OFL-1.1; distribute its OFL.txt. */
#include <limits.h>
#include "shz_text.h"
#include "generated/glyphs.h"

static int glyph_index(unsigned cp)
{
    if (cp >= 0x20 && cp <= 0x7e) return (int)(cp - 0x20);
    if (cp >= 0x1100 && cp <= 0x11ff) return 95 + (int)(cp - 0x1100);
    if (cp >= 0x3131 && cp <= 0x318e) return 351 + (int)(cp - 0x3131);
    if (cp >= 0xac00 && cp <= 0xd7a3) return 445 + (int)(cp - 0xac00);
    return '?' - 0x20;
}

static BOOL parameters(LPCWSTR text, int *length, int scale)
{
    if (!text || *length < -1 || scale < 1 || scale > 8) return FALSE;
    if (*length == -1) {
        int count = 0;
        while (text[count]) {
            if (count == 32767) return FALSE;
            ++count;
        }
        *length = count;
    }
    return *length <= 32767;
}

/* A UTF-16 surrogate pair represents one unsupported scalar, hence one
 * replacement cell. Isolated surrogates also get one replacement cell. */
static unsigned scalar(LPCWSTR text, int length, int *cursor)
{
    unsigned cp = text[(*cursor)++];
    if (cp >= 0xd800 && cp <= 0xdbff && *cursor < length &&
        text[*cursor] >= 0xdc00 && text[*cursor] <= 0xdfff) {
        ++*cursor;
        return 0xfffd;
    }
    return cp;
}

BOOL ShzTextMeasureW(LPCWSTR text, int length, int scale, SIZE *extent)
{
    int cursor = 0, count = 0;
    if (!extent || !parameters(text, &length, scale)) {
        SetLastError(ERROR_INVALID_PARAMETER);
        return FALSE;
    }
    while (cursor < length) { (void)scalar(text, length, &cursor); ++count; }
    extent->cx = count * 16 * scale;
    extent->cy = SHZ_KR_GLYPH_HEIGHT * scale;
    return TRUE;
}

BOOL ShzTextDrawW(HDC dc, int x, int y, LPCWSTR text, int length,
                 COLORREF foreground, int scale)
{
    HBRUSH brush;
    SIZE extent;
    int cursor = 0, cell = 0;
    BOOL ok = TRUE;
    if (!dc || !parameters(text, &length, scale) ||
        !ShzTextMeasureW(text, length, scale, &extent) ||
        x > INT_MAX - extent.cx || y > INT_MAX - extent.cy) {
        SetLastError(ERROR_INVALID_PARAMETER);
        return FALSE;
    }
    if (!length) return TRUE;
    brush = CreateSolidBrush(foreground);
    if (!brush) return FALSE;
    while (cursor < length && ok) {
        int row, index = glyph_index(scalar(text, length, &cursor));
        for (row = 0; row < SHZ_KR_GLYPH_HEIGHT && ok; ++row) {
            unsigned bits = shz_kr_rows[index][row];
            int column = 0;
            while (column < 16) {
                int start;
                RECT rect;
                if (!(bits & (0x8000u >> column))) { ++column; continue; }
                start = column++;
                while (column < 16 && (bits & (0x8000u >> column))) ++column;
                rect.left = x + cell * 16 * scale + start * scale;
                rect.right = x + cell * 16 * scale + column * scale;
                rect.top = y + row * scale;
                rect.bottom = rect.top + scale;
                if (!FillRect(dc, &rect, brush)) { ok = FALSE; break; }
            }
        }
        ++cell;
    }
    if (!DeleteObject(brush)) ok = FALSE;
    return ok;
}
