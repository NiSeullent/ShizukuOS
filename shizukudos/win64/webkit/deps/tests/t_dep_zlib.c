/* SPDX-License-Identifier: GPL-2.0-only
 * Guest check of zlib (libzlib1.dll): CRC-32 and Adler-32 check values, deflate/inflate round trip, gzip framing. */
#include <string.h>
#include <zlib.h>
#include "deptest.h"

int main(void)
{
    static unsigned char src[200000], packed[220000], back[200000];
    for (size_t i = 0; i < sizeof src; ++i) src[i] = (unsigned char)("the quick brown fox "[i % 20] ^ (i / 997));
    CHECK(crc32(0, (const Bytef *)"123456789", 9) == 0xcbf43926UL);
    CHECK(adler32(1, (const Bytef *)"Wikipedia", 9) == 0x11e60398UL);
    uLongf plen = sizeof packed, blen = sizeof back;
    CHECK(compress2(packed, &plen, src, sizeof src, 9) == Z_OK && plen < sizeof src / 4);
    CHECK(uncompress(back, &blen, packed, plen) == Z_OK && blen == sizeof src && !memcmp(src, back, sizeof src));
    z_stream s;
    memset(&s, 0, sizeof s);
    CHECK(deflateInit2(&s, 6, Z_DEFLATED, 31, 8, Z_DEFAULT_STRATEGY) == Z_OK);   /* gzip wrapper */
    s.next_in = src; s.avail_in = sizeof src; s.next_out = packed; s.avail_out = sizeof packed;
    CHECK(deflate(&s, Z_FINISH) == Z_STREAM_END && packed[0] == 0x1f && packed[1] == 0x8b);
    plen = s.total_out;
    deflateEnd(&s);
    memset(&s, 0, sizeof s);
    CHECK(inflateInit2(&s, 47) == Z_OK);
    s.next_in = packed; s.avail_in = (uInt)plen; s.next_out = back; s.avail_out = sizeof back;
    CHECK(inflate(&s, Z_FINISH) == Z_STREAM_END && s.total_out == sizeof src && !memcmp(src, back, sizeof src));
    inflateEnd(&s);
    printf("zlib %s\n", zlibVersion());
    CHECK(!strcmp(zlibVersion(), ZLIB_VERSION));
    return DONE("t_dep_zlib");
}
