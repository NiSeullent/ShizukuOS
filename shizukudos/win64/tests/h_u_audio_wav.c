/* SPDX-License-Identifier: GPL-2.0-only
 * Host control for the production WAV parser (dlls/winmm/wavefile.c). Not a guest test and not audio proof. */
#include <stdio.h>
#include <string.h>
#include "../dlls/winmm/wavefile.h"
static int fails;
#define CK(n, c) do { if (c) printf("PASS: %s\n", n); else { ++fails; printf("FAIL: %s\n", n); } } while (0)
static void p32(uint8_t *p, uint32_t v) { p[0]=v; p[1]=v>>8; p[2]=v>>16; p[3]=v>>24; }
static uint32_t mk(uint8_t *b, uint32_t dlen, int junk)
{
    uint32_t o = 12;
    memcpy(b, "RIFF", 4); memcpy(b + 8, "WAVE", 4);
    if (junk) { memcpy(b + o, "LIST", 4); p32(b + o + 4, 3); memcpy(b + o + 8, "abc\0", 4); o += 12; }  /* odd + pad */
    memcpy(b + o, "fmt ", 4); p32(b + o + 4, 16);
    b[o+8]=1; b[o+9]=0; b[o+10]=2; b[o+11]=0; p32(b+o+12, 44100); p32(b+o+16, 176400); b[o+20]=4; b[o+21]=0; b[o+22]=16; b[o+23]=0;
    o += 24;
    memcpy(b + o, "data", 4); p32(b + o + 4, dlen); memset(b + o + 8, 0x11, dlen);
    o += 8 + dlen;
    p32(b + 4, o - 8);
    return o;
}
int main(void)
{
    static uint8_t b[4096];
    shz_wav_info w;
    uint32_t n = mk(b, 400, 0);
    CK("good 16-bit stereo 44100", shz_wav_parse(b, n, &w) == 0 && w.channels == 2 && w.bits == 16 && w.rate == 44100 && w.data_len == 400 && w.data_off == 44);
    n = mk(b, 402, 1);
    CK("odd LIST pad skipped, partial frame trimmed", shz_wav_parse(b, n, &w) == 0 && w.data_len == 400 && w.data_off == 56);
    n = mk(b, 400, 0); b[12 + 16 + 8 + 4] = 0;   /* sanity: unchanged parse still ok after harmless edit? */
    n = mk(b, 400, 0);
    CK("truncated data chunk rejected", shz_wav_parse(b, n - 1, &w) == SHZ_WAV_E_CHUNK);
    n = mk(b, 400, 0); p32(b + 40, 0xfffffff0u);
    CK("data size overflow rejected", shz_wav_parse(b, n, &w) == SHZ_WAV_E_CHUNK);
    n = mk(b, 400, 0); b[22] = 6;
    CK("6 channels rejected", shz_wav_parse(b, n, &w) == SHZ_WAV_E_FORMAT);
    n = mk(b, 400, 0); b[34] = 24;
    CK("24 bit rejected", shz_wav_parse(b, n, &w) == SHZ_WAV_E_FORMAT);
    n = mk(b, 400, 0); b[32] = 3;
    CK("bad block align rejected", shz_wav_parse(b, n, &w) == SHZ_WAV_E_FORMAT);
    n = mk(b, 400, 0); memcpy(b + 36, "junk", 4);
    CK("no data chunk -> NODATA", shz_wav_parse(b, n, &w) == SHZ_WAV_E_NODATA);
    CK("bad magic", (b[0] = 'X', shz_wav_parse(b, n, &w) == SHZ_WAV_E_RIFF));
    CK("too big", shz_wav_parse(b, SHZ_WAV_MAX + 1, &w) == SHZ_WAV_E_TOOBIG);
    CK("short", shz_wav_parse(b, 11, &w) == SHZ_WAV_E_RIFF);
    return fails;
}
