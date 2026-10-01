/* SPDX-License-Identifier: GPL-2.0-only
 * Guest check of HarfBuzz (libharfbuzz-0.dll, libharfbuzz-icu-0.dll): shape Latin text with Noto Sans (the "ffi"
 * ligature and kerning come from the font's GSUB/GPOS), and use ICU's Unicode functions for a script run. */
#include <string.h>
#include <hb.h>
#include <hb-icu.h>
#include "deptest.h"

int main(void)
{
    printf("HarfBuzz %s\n", hb_version_string());
    hb_blob_t *blob = hb_blob_create_from_file_or_fail(dt_font_path("NotoSans.ttf"));
    CHECK(blob != NULL);
    if (!blob) return DONE("t_dep_harfbuzz");
    hb_face_t *face = hb_face_create(blob, 0);
    hb_font_t *font = hb_font_create(face);
    CHECK(hb_face_get_glyph_count(face) > 1000);
    hb_buffer_t *buf = hb_buffer_create();
    hb_buffer_add_utf8(buf, "office AV", -1, 0, -1);
    hb_buffer_guess_segment_properties(buf);
    hb_shape(font, buf, NULL, 0);
    unsigned n = hb_buffer_get_length(buf);
    hb_glyph_position_t *pos = hb_buffer_get_glyph_positions(buf, NULL);
    printf("\"office AV\": %u glyphs for 9 characters\n", n);
    CHECK(n < 9);                                               /* ffi (or fi) ligature */
    hb_buffer_t *av = hb_buffer_create(), *aa = hb_buffer_create();
    hb_buffer_add_utf8(av, "AV", -1, 0, -1); hb_buffer_guess_segment_properties(av); hb_shape(font, av, NULL, 0);
    hb_buffer_add_utf8(aa, "AA", -1, 0, -1); hb_buffer_guess_segment_properties(aa); hb_shape(font, aa, NULL, 0);
    hb_position_t w_av = hb_buffer_get_glyph_positions(av, NULL)[0].x_advance;
    hb_position_t w_aa = hb_buffer_get_glyph_positions(aa, NULL)[0].x_advance;
    printf("advance of A before V %d, before A %d\n", w_av, w_aa);
    CHECK(w_av < w_aa);                                         /* GPOS kerning */
    (void)pos;
    hb_unicode_funcs_t *icu = hb_icu_get_unicode_funcs();
    CHECK(icu != NULL && hb_unicode_script(icu, 0x3042) == HB_SCRIPT_HIRAGANA && hb_unicode_script(icu, 0x0627) == HB_SCRIPT_ARABIC);
    hb_buffer_t *ar = hb_buffer_create();
    hb_buffer_set_unicode_funcs(ar, icu);
    hb_buffer_add_utf8(ar, "\xd8\xb3\xd9\x84\xd8\xa7\xd9\x85", -1, 0, -1);      /* سلام */
    hb_buffer_guess_segment_properties(ar);
    CHECK(hb_buffer_get_direction(ar) == HB_DIRECTION_RTL && hb_buffer_get_script(ar) == HB_SCRIPT_ARABIC);
    hb_buffer_destroy(ar); hb_buffer_destroy(av); hb_buffer_destroy(aa); hb_buffer_destroy(buf);
    hb_font_destroy(font); hb_face_destroy(face); hb_blob_destroy(blob);
    return DONE("t_dep_harfbuzz");
}
