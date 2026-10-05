/* SPDX-License-Identifier: LGPL-2.1-or-later
 * Shared bounded shell geometry. Screen density is a conservative fallback,
 * not an invented monitor DPI. Painting and hit tests use the same rectangles. */
#ifndef SHZ_SHELL_LAYOUT_H
#define SHZ_SHELL_LAYOUT_H

typedef struct SHZ_BOX { int left, top, right, bottom; } SHZ_BOX;
typedef struct SHZ_FILES_LAYOUT { int sidebar, toolbar, address, header, row, footer, list_top, list_bottom; } SHZ_FILES_LAYOUT;
typedef struct SHZ_TASK_ROW { int width, shown, hidden; } SHZ_TASK_ROW;

static int ShzClamp(int v, int lo, int hi) { return v < lo ? lo : v > hi ? hi : v; }
static int ShzScreenScale(int width, int height)
{
    if (width >= 3200 && height >= 1800) return 150;
    if (width >= 1920 && height >= 1200) return 125;
    return 100;
}
static int ShzScaleMetric(int value, int scale)
{
    /* Theme integers are validated before publication; keep this boundary
     * independently bounded for tiny windows and future callers. */
    return (ShzClamp(value, 0, 4096) * ShzClamp(scale, 100, 150) + 50) / 100;
}
static SHZ_FILES_LAYOUT ShzFilesLayout(int width, int height, int scale, int toolbar_height, int row_height, int footer_height)
{
    SHZ_FILES_LAYOUT g;
    width = ShzClamp(width, 0, 32768); height = ShzClamp(height, 0, 32768);
    g.toolbar = ShzScaleMetric(toolbar_height, scale); g.address = ShzScaleMetric(38, scale);
    g.header = ShzScaleMetric(30, scale); g.row = ShzScaleMetric(row_height, scale);
    if (g.row < 1) g.row = 1;
    g.footer = ShzScaleMetric(footer_height, scale);
    if (g.footer > height) g.footer = height;
    g.sidebar = width >= ShzScaleMetric(680, scale) ? ShzScaleMetric(176, scale) : 0;
    g.list_bottom = height - g.footer;
    g.list_top = g.toolbar + g.address + g.header;
    if (g.list_top > g.list_bottom) g.list_top = g.list_bottom;
    return g;
}
static int ShzVisibleRows(const SHZ_FILES_LAYOUT *g) { return (g->list_bottom - g->list_top) / g->row; }
static int ShzListHit(const SHZ_FILES_LAYOUT *g, int width, int x, int y, int top, int count)
{
    int row;
    if (x < g->sidebar || x >= width || y < g->list_top || y >= g->list_bottom) return -1;
    row = (y - g->list_top) / g->row;
    if (row >= ShzVisibleRows(g) || top < 0 || top >= count || row >= count - top) return -1;
    return top + row;
}
/* ReactOS CTaskSwitchWnd::UpdateButtonsSize: derive how many equal-width
 * buttons fit, then cap their width. This shell reserves one actual tray row. */
static SHZ_TASK_ROW ShzTaskRow(int width, int count, int scale, int gap)
{
    SHZ_TASK_ROW r = { 0, 0, 0 }; int capacity;
    width = ShzClamp(width, 0, 32768); count = ShzClamp(count, 0, 64);
    gap = ShzClamp(gap, 0, 32); r.hidden = count;
    if (!width || !count) return r;
    capacity = (width + gap) / (ShzScaleMetric(108, scale) + gap);
    if (capacity < 1) capacity = 1;
    r.shown = count < capacity ? count : capacity;
    r.width = (width - (r.shown - 1) * gap) / r.shown;
    if (r.width > ShzScaleMetric(232, scale)) r.width = ShzScaleMetric(232, scale);
    r.hidden = count - r.shown;
    return r;
}
static int ShzMenuRowHeight(int screen_height, int scale, int tray_height, int requested, int sep)
{
    int available = ShzClamp(screen_height, 0, 32768) - ShzScaleMetric(tray_height, scale)
        - ShzScaleMetric(142, scale) - 2 * ShzScaleMetric(sep, scale);
    int row = ShzScaleMetric(requested, scale);
    /* Seven fixed actions stay reachable on a small display; header and
     * separators never become selectable. Larger screens retain theme sizing. */
    if (available > 0 && row > available / 7) row = available / 7;
    if (row < 1) row = 1;
    return row;
}
static int ShzMenuTaskLimit(int screen_height, int scale, int tray_height, int row, int sep, int limit)
{
    int available = ShzClamp(screen_height, 0, 32768) - ShzScaleMetric(tray_height, scale)
        - ShzScaleMetric(142, scale) - 7 * ShzClamp(row, 1, 4096) - 2 * ShzScaleMetric(sep, scale);
    return available <= 0 ? 0 : ShzClamp(available / ShzClamp(row, 1, 4096), 0, ShzClamp(limit, 0, 8));
}

#ifndef SHZ_LAYOUT_PORTABLE
static int ShzUiScale(void) { return ShzScreenScale(GetSystemMetrics(SM_CXSCREEN), GetSystemMetrics(SM_CYSCREEN)); }
static int ShzPx(int value) { return ShzScaleMetric(value, ShzUiScale()); }
static void ShzFill(HDC dc, const RECT *r, COLORREF color)
{
    HBRUSH b;
    if (r->right <= r->left || r->bottom <= r->top) return;
    b = CreateSolidBrush(color);
    if (b) { FillRect(dc, r, b); DeleteObject(b); }
}
static void ShzHeading(HDC dc, const WCHAR *text, const RECT *r, COLORREF color)
{
    SIZE size; int scale = 2, saved;
    if (r->right <= r->left || r->bottom <= r->top) return;
    if (!ShzTextMeasureW(text, -1, scale, &size)) { g_shell.draw_text_failures++; return; }
    if (size.cx > r->right - r->left || size.cy > r->bottom - r->top) {
        scale = 1;
        if (!ShzTextMeasureW(text, -1, scale, &size)) { g_shell.draw_text_failures++; return; }
    }
    saved = SaveDC(dc);
    if (!saved) { g_shell.draw_text_failures++; return; }
    if (IntersectClipRect(dc, r->left, r->top, r->right, r->bottom) == ERROR ||
        !ShzTextDrawW(dc, r->left, r->top + (r->bottom - r->top - size.cy) / 2, text, -1, color, scale)) g_shell.draw_text_failures++;
    if (!RestoreDC(dc, saved)) g_shell.draw_text_failures++;
}
#endif
#endif
