/* SPDX-License-Identifier: GPL-2.0-only
 * Guest check of libwebp (libwebp.dll, libwebpdemux.dll, libwebpmux.dll, libsharpyuv.dll): lossless round trip must be
 * exact, lossy must stay close, and the demuxer must see one frame of the right size. */
#include <stdlib.h>
#include <string.h>
#include <webp/decode.h>
#include <webp/demux.h>
#include <webp/encode.h>
#include "deptest.h"

int main(void)
{
    enum { W = 50, H = 40 };
    static unsigned char img[W * H * 4];
    for (int i = 0; i < W * H; ++i) {
        img[i * 4] = (unsigned char)(i * 7); img[i * 4 + 1] = (unsigned char)(i / 3); img[i * 4 + 2] = (unsigned char)(255 - i);
        img[i * 4 + 3] = (unsigned char)(10 + (i % W) * 5);   /* never 0: lossless keeps RGB under alpha > 0 */
    }
    uint8_t *out = NULL;
    size_t n = WebPEncodeLosslessRGBA(img, W, H, W * 4, &out);
    CHECK(n > 0);
    int w = 0, h = 0;
    uint8_t *dec = WebPDecodeRGBA(out, n, &w, &h);
    CHECK(dec && w == W && h == H && !memcmp(dec, img, sizeof img));
    WebPFree(dec);
    WebPData data = {out, n};
    WebPDemuxer *dmx = WebPDemux(&data);
    CHECK(dmx && WebPDemuxGetI(dmx, WEBP_FF_CANVAS_WIDTH) == W && WebPDemuxGetI(dmx, WEBP_FF_FRAME_COUNT) == 1);
    WebPDemuxDelete(dmx);
    WebPFree(out);
    out = NULL;
    static unsigned char smooth[W * H * 4];                 /* lossy: a smooth opaque gradient */
    for (int y = 0; y < H; ++y)
        for (int x = 0; x < W; ++x) {
            unsigned char *p = smooth + (y * W + x) * 4;
            p[0] = (unsigned char)(x * 5); p[1] = (unsigned char)(y * 6); p[2] = (unsigned char)(128 + x - y); p[3] = 255;
        }
    n = WebPEncodeRGBA(smooth, W, H, W * 4, 90.0f, &out);
    CHECK(n > 0);
    dec = WebPDecodeRGBA(out, n, &w, &h);
    long sum = 0;
    for (int i = 0; dec && i < W * H * 4; ++i) sum += abs(dec[i] - smooth[i]);
    printf("lossy mean abs error %.2f, encoder 0x%06x\n", dec ? (double)sum / (W * H * 4) : -1.0, WebPGetEncoderVersion());
    CHECK(dec && (double)sum / (W * H * 4) < 4.0);
    WebPFree(dec);
    WebPFree(out);
    return DONE("t_dep_webp");
}
