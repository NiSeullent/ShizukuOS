/* SPDX-License-Identifier: GPL-2.0-only
 * Guest check of brotli (libbrotlienc.dll, libbrotlidec.dll, libbrotlicommon.dll): round trip at quality 5 and 11. */
#include <string.h>
#include <brotli/decode.h>
#include <brotli/encode.h>
#include "deptest.h"

int main(void)
{
    static uint8_t src[100000], packed[110000], back[100000];
    for (size_t i = 0; i < sizeof src; ++i) src[i] = (uint8_t)("<div class=\"item\">text</div>\n"[i % 30] + (i / 4096));
    for (int q = 5; q <= 11; q += 6) {
        size_t plen = sizeof packed, blen = sizeof back;
        CHECK(BrotliEncoderCompress(q, BROTLI_DEFAULT_WINDOW, BROTLI_MODE_TEXT, sizeof src, src, &plen, packed));
        CHECK(BrotliDecoderDecompress(plen, packed, &blen, back) == BROTLI_DECODER_RESULT_SUCCESS &&
              blen == sizeof src && !memcmp(src, back, sizeof src));
        printf("quality %d: %zu -> %zu bytes\n", q, sizeof src, plen);
    }
    printf("brotli decoder %08x encoder %08x\n", BrotliDecoderVersion(), BrotliEncoderVersion());
    CHECK(BrotliDecoderVersion() == BrotliEncoderVersion());
    return DONE("t_dep_brotli");
}
