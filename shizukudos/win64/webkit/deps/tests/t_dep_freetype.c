/* SPDX-License-Identifier: GPL-2.0-only
 * Guest check of FreeType (libfreetype-6.dll): open the shipped Noto Sans variable font, select a weight through the
 * MM interface, render 'A' anti-aliased at 32 px and check the bitmap is plausible. */
#include <ft2build.h>
#include FT_FREETYPE_H
#include FT_MULTIPLE_MASTERS_H
#include "deptest.h"

int main(void)
{
    FT_Library lib;
    FT_Face face;
    FT_Int maj, min, pat;
    CHECK(FT_Init_FreeType(&lib) == 0);
    FT_Library_Version(lib, &maj, &min, &pat);
    printf("FreeType %d.%d.%d, font %s\n", maj, min, pat, dt_font_path("NotoSans.ttf"));
    CHECK(FT_New_Face(lib, dt_font_path("NotoSans.ttf"), 0, &face) == 0);
    if (dt_failures) return DONE("t_dep_freetype");
    printf("family \"%s\" style \"%s\", %ld glyphs\n", face->family_name, face->style_name, face->num_glyphs);
    CHECK(face->num_glyphs > 1000 && (face->face_flags & FT_FACE_FLAG_MULTIPLE_MASTERS));
    FT_MM_Var *mm = NULL;
    CHECK(FT_Get_MM_Var(face, &mm) == 0 && mm->num_axis >= 1);
    if (mm) {
        FT_Fixed coords[4] = {0};
        for (FT_UInt i = 0; i < mm->num_axis && i < 4; ++i)
            coords[i] = (mm->axis[i].tag == FT_MAKE_TAG('w', 'g', 'h', 't')) ? 700 << 16 : mm->axis[i].def;
        CHECK(FT_Set_Var_Design_Coordinates(face, mm->num_axis < 4 ? mm->num_axis : 4, coords) == 0);
        FT_Done_MM_Var(lib, mm);
    }
    CHECK(FT_Set_Pixel_Sizes(face, 0, 32) == 0);
    FT_UInt gi = FT_Get_Char_Index(face, 'A');
    CHECK(gi != 0 && FT_Load_Glyph(face, gi, FT_LOAD_DEFAULT) == 0 && FT_Render_Glyph(face->glyph, FT_RENDER_MODE_NORMAL) == 0);
    FT_Bitmap *bm = &face->glyph->bitmap;
    int ink = 0, grey = 0;
    for (unsigned y = 0; y < bm->rows; ++y)
        for (unsigned x = 0; x < bm->width; ++x) {
            unsigned char c = bm->buffer[y * bm->pitch + x];
            if (c) ++ink;
            if (c > 0 && c < 255) ++grey;
        }
    printf("'A' bitmap %ux%u, %d inked pixels (%d anti-aliased)\n", bm->width, bm->rows, ink, grey);
    CHECK(bm->rows >= 20 && bm->rows <= 26 && bm->width >= 16 && ink > 100 && grey > 20);
    FT_Done_Face(face);
    FT_Done_FreeType(lib);
    return DONE("t_dep_freetype");
}
