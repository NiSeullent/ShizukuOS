/* SPDX-License-Identifier: GPL-2.0-only
 * Guest check of libjpeg-turbo (libturbojpeg.dll, libjpeg-62.dll; NASM SIMD paths): compress a gradient at quality 95,
 * decompress it, check the size and the PSNR, and read the header through the libjpeg API. */
#include <math.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <turbojpeg.h>
#include <jpeglib.h>
#include "deptest.h"

int main(void)
{
    enum { W = 160, H = 96 };
    static unsigned char img[W * H * 3], back[W * H * 3];
    for (int y = 0; y < H; ++y)
        for (int x = 0; x < W; ++x) {
            unsigned char *p = img + (y * W + x) * 3;
            p[0] = (unsigned char)(x * 255 / W); p[1] = (unsigned char)(y * 255 / H); p[2] = (unsigned char)((x + y) & 255);
        }
    tjhandle c = tjInitCompress();
    unsigned char *jpg = NULL;
    unsigned long jsize = 0;
    CHECK(c && tjCompress2(c, img, W, 0, H, TJPF_RGB, &jpg, &jsize, TJSAMP_444, 95, 0) == 0 && jsize > 500);
    tjhandle d = tjInitDecompress();
    int w = 0, h = 0, ss = 0, cs = 0;
    CHECK(d && tjDecompressHeader3(d, jpg, jsize, &w, &h, &ss, &cs) == 0 && w == W && h == H && ss == TJSAMP_444);
    CHECK(tjDecompress2(d, jpg, jsize, back, W, 0, H, TJPF_RGB, 0) == 0);
    double se = 0;
    for (int i = 0; i < W * H * 3; ++i) se += (double)(img[i] - back[i]) * (img[i] - back[i]);
    double psnr = 10 * log10(255.0 * 255.0 / (se / (W * H * 3) + 1e-9));
    printf("JPEG %lu bytes, PSNR %.2f dB\n", jsize, psnr);
    CHECK(psnr > 35.0);
    struct jpeg_decompress_struct ci;
    struct jpeg_error_mgr err;
    ci.err = jpeg_std_error(&err);
    jpeg_create_decompress(&ci);
    jpeg_mem_src(&ci, jpg, jsize);
    CHECK(jpeg_read_header(&ci, TRUE) == JPEG_HEADER_OK && ci.image_width == W && ci.num_components == 3);
    jpeg_destroy_decompress(&ci);
    /* error path: a truncated stream (libjpeg-turbo's error manager longjmps inside the DLL) */
    int rc = tjDecompress2(d, jpg, 200, back, W, 0, H, TJPF_RGB, 0);
    printf("truncated stream: rc=%d \"%s\"\n", rc, tjGetErrorStr2(d));
    CHECK(rc != 0 || tjGetErrorCode(d) == TJERR_WARNING);
    CHECK(tjDecompress2(d, jpg, jsize, back, W, 0, H, TJPF_RGB, 0) == 0);                /* still usable */
    tjFree(jpg);
    tjDestroy(c);
    tjDestroy(d);
    return DONE("t_dep_jpeg");
}
