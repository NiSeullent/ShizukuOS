/* SPDX-License-Identifier: GPL-2.0-only
 *
 * ShizukuTrident Lite - the fixed 8x16 font model (see font.h): the metrics of Shizuku gdi32's built-in font, so host
 * tests compute the same layout as the DLL does on Shizuku.
 */
#include "font.h"

struct shz_font {
    int scale;
};

static struct shz_font fixed_fonts[4] = { {1}, {2}, {3}, {4} };

int shz_font_fixed_scale(float size_px)
{
    long hgt = (long)(size_px + 0.5f);
    int scale;
    if (hgt < 0) hgt = -hgt;
    scale = hgt == 0 ? 1 : (int)((hgt + 8) / 16);
    if (scale < 1) scale = 1;
    if (scale > 4) scale = 4;
    return scale;
}

static shz_font *fixed_get_font(shz_font_backend *self, const shz_font_desc *desc)
{
    SHZ_UNUSED(self);
    return &fixed_fonts[shz_font_fixed_scale(desc->size) - 1];
}

static void fixed_metrics(shz_font_backend *self, shz_font *font, shz_font_metrics *out)
{
    SHZ_UNUSED(self);
    out->ascent = 13.0f * font->scale;
    out->descent = 3.0f * font->scale;
    out->line_height = 16.0f * font->scale;
    out->x_height = 8.0f * font->scale;
    out->avg_width = 8.0f * font->scale;
}

static float fixed_text_width(shz_font_backend *self, shz_font *font, const shz_char *text, size_t n)
{
    SHZ_UNUSED(self);
    SHZ_UNUSED(text);
    return (float)(8 * font->scale) * (float)n;
}

static void fixed_advances(shz_font_backend *self, shz_font *font, const shz_char *text, size_t n, float *pos)
{
    size_t i;
    SHZ_UNUSED(self);
    SHZ_UNUSED(text);
    for (i = 0; i < n; ++i) pos[i] = (float)(8 * font->scale) * (float)(i + 1);
}

static shz_font_backend fixed_backend = {
    "fixed", fixed_get_font, fixed_metrics, fixed_text_width, fixed_advances
};

static shz_font_backend *current_backend;

shz_font_backend *shz_font_fixed_backend(void)
{
    return &fixed_backend;
}

void shz_font_set_backend(shz_font_backend *backend)
{
    current_backend = backend;
}

shz_font_backend *shz_font_get_backend(void)
{
    return current_backend ? current_backend : &fixed_backend;
}
