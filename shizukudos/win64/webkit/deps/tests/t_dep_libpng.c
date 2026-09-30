/* SPDX-License-Identifier: GPL-2.0-only
 * Guest check of libpng (libpng16.dll over libzlib1.dll): write an RGBA image to a file with the simplified API,
 * read it back as RGBA and as RGB, compare every pixel. */
#include <stdlib.h>
#include <string.h>
#include <png.h>
#include "deptest.h"

int main(void)
{
    enum { W = 61, H = 37 };
    static unsigned char img[W * H * 4], back[W * H * 4], rgb[W * H * 3];
    for (int y = 0; y < H; ++y)
        for (int x = 0; x < W; ++x) {
            unsigned char *p = img + (y * W + x) * 4;
            p[0] = (unsigned char)(x * 4); p[1] = (unsigned char)(y * 6); p[2] = (unsigned char)(x ^ y); p[3] = (unsigned char)(255 - x);
        }
    png_image w;
    memset(&w, 0, sizeof w);
    w.version = PNG_IMAGE_VERSION; w.width = W; w.height = H; w.format = PNG_FORMAT_RGBA;
    CHECK(png_image_write_to_file(&w, "t_png.png", 0, img, 0, NULL) && !w.warning_or_error);
    png_image r;
    memset(&r, 0, sizeof r);
    r.version = PNG_IMAGE_VERSION;
    CHECK(png_image_begin_read_from_file(&r, "t_png.png") && r.width == W && r.height == H);
    r.format = PNG_FORMAT_RGBA;
    CHECK(png_image_finish_read(&r, NULL, back, 0, NULL) && !memcmp(img, back, sizeof img));
    memset(&r, 0, sizeof r);
    r.version = PNG_IMAGE_VERSION;
    png_color bg = {0, 0, 0};
    CHECK(png_image_begin_read_from_file(&r, "t_png.png"));
    r.format = PNG_FORMAT_RGB;
    CHECK(png_image_finish_read(&r, &bg, rgb, 0, NULL));
    int maxdiff = 0;                                        /* composited on black: c * a / 255 (sRGB, libpng rounding) */
    for (int i = 0; i < W * H; ++i)
        for (int c = 0; c < 3; ++c) {
            int want = img[i * 4 + c] * img[i * 4 + 3] / 255, d = abs(want - rgb[i * 3 + c]);
            if (d > maxdiff) maxdiff = d;
        }
    printf("libpng %s, RGB-on-black max difference %d\n", png_get_libpng_ver(NULL), maxdiff);
    CHECK(maxdiff <= 40);
    /* error path: a truncated file makes libpng longjmp out of its reader (vcruntime140 longjmp) */
    FILE *f = fopen("t_png.png", "rb"), *g = fopen("t_png_cut.png", "wb");
    unsigned char chunk[W * H * 4];
    size_t got = f ? fread(chunk, 1, sizeof chunk, f) : 0;
    printf("PNG file %zu bytes, keeping the first %zu\n", got, got / 2);
    got /= 2;                                               /* signature, IHDR and part of the image data */
    if (g) { fwrite(chunk, 1, got, g); fclose(g); }
    if (f) fclose(f);
    memset(&r, 0, sizeof r);
    r.version = PNG_IMAGE_VERSION;
    int began = png_image_begin_read_from_file(&r, "t_png_cut.png");
    r.format = PNG_FORMAT_RGBA;
    int finished = began && png_image_finish_read(&r, NULL, back, 0, NULL);
    printf("truncated file: begin=%d finish=%d message=\"%s\"\n", began, finished, r.message);
    CHECK(began && !finished && (r.warning_or_error & PNG_IMAGE_ERROR) && r.message[0]);
    png_image_free(&r);
    remove("t_png_cut.png");
    remove("t_png.png");
    return DONE("t_dep_libpng");
}
