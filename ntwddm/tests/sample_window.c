/* SPDX-License-Identifier: GPL-2.0-only
 * Paints one caption, frame, and two buttons into an XRGB buffer.
 * The gray or light client wash is the test fixture, not a theme part.
 */
#include "sample_window.h"

static ntth_status paint_part(ntth_session *session, ntth_theme theme,
                              int32_t part, int32_t state, uint8_t *pixels,
                              uint32_t pitch, uint32_t x, uint32_t y,
                              uint32_t width, uint32_t height)
{
    ntwg_rect rect;
    rect.x = x;
    rect.y = y;
    rect.width = width;
    rect.height = height;
    return ntth_draw_background(session, theme, part, state, pixels,
                                SAMPLE_WINDOW_W, SAMPLE_WINDOW_H, pitch,
                                &rect, NULL);
}

static ntth_status paint_label(ntth_session *session, ntth_theme theme,
                               int32_t part, int32_t state, const char *text,
                               uint8_t *pixels, uint32_t pitch,
                               uint32_t x, uint32_t y)
{
    ntwg_rect rect;
    size_t n = 0;
    rect.x = x;
    rect.y = y;
    while (text[n] != 0) ++n;
    rect.width = (uint32_t)n * 6u;
    rect.height = 7;
    return ntth_draw_text(session, theme, part, state, text, n, pixels,
                          SAMPLE_WINDOW_W, SAMPLE_WINDOW_H, pitch, &rect, NULL);
}

ntth_status sample_window_paint(ntth_session *session, uint8_t *pixels,
                               uint32_t pitch, const char *caption,
                               uint32_t client, int with_text)
{
    ntth_theme window = 0;
    ntth_theme button = 0;
    ntth_status status;
    evidence_fill_xrgb(pixels, SAMPLE_WINDOW_W, SAMPLE_WINDOW_H, pitch, client);
    status = ntth_open_data(session, "WINDOW", &window);
    if (status != NTTH_OK) return status;
    status = ntth_open_data(session, "BUTTON", &button);
    if (status != NTTH_OK) goto close_window;
    status = paint_part(session, window, NTTH_WP_CAPTION, NTTH_CS_ACTIVE,
                        pixels, pitch, 0, 0, SAMPLE_WINDOW_W, 22);
    if (status != NTTH_OK) goto close_all;
    status = paint_part(session, window, NTTH_WP_FRAMELEFT, NTTH_FS_ACTIVE,
                        pixels, pitch, 0, 22, 4, 94);
    if (status != NTTH_OK) goto close_all;
    status = paint_part(session, window, NTTH_WP_FRAMERIGHT, NTTH_FS_ACTIVE,
                        pixels, pitch, SAMPLE_WINDOW_W - 4u, 22, 4, 94);
    if (status != NTTH_OK) goto close_all;
    status = paint_part(session, window, NTTH_WP_FRAMEBOTTOM, NTTH_FS_ACTIVE,
                        pixels, pitch, 0, SAMPLE_WINDOW_H - 4u, SAMPLE_WINDOW_W, 4);
    if (status != NTTH_OK) goto close_all;
    status = paint_part(session, button, NTTH_BP_PUSHBUTTON, NTTH_PBS_NORMAL,
                        pixels, pitch, 16, 48, 72, 26);
    if (status != NTTH_OK) goto close_all;
    status = paint_part(session, button, NTTH_BP_PUSHBUTTON, NTTH_PBS_PRESSED,
                        pixels, pitch, 100, 48, 64, 26);
    if (status != NTTH_OK) goto close_all;
    if (with_text) {
        status = paint_label(session, window, NTTH_WP_CAPTION, NTTH_CS_ACTIVE,
                             caption, pixels, pitch, 8, 7);
        if (status != NTTH_OK) goto close_all;
        status = paint_label(session, button, NTTH_BP_PUSHBUTTON, NTTH_PBS_NORMAL,
                             "OK", pixels, pitch, 46, 57);
        if (status != NTTH_OK) goto close_all;
        status = paint_label(session, button, NTTH_BP_PUSHBUTTON, NTTH_PBS_PRESSED,
                             "OK", pixels, pitch, 126, 57);
    }
close_all:
    if (ntth_close_data(session, button) != NTTH_OK && status == NTTH_OK)
        status = NTTH_E_HANDLE;
close_window:
    if (ntth_close_data(session, window) != NTTH_OK && status == NTTH_OK)
        status = NTTH_E_HANDLE;
    return status;
}
