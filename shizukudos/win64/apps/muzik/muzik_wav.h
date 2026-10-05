/* SPDX-License-Identifier: GPL-2.0-only
 * Muzik private bounded RIFF/WAVE PCM header reader. Pure: no allocation, no OS calls, never reads outside [b,b+n).
 * Mirrors the accepted-format set of winmm waveOutOpen (PCM 8/16 bit, 1/2 ch, 11025..48000 Hz) so that anything it
 * accepts is a format the exported waveOut path can actually open; the real authority stays waveOutOpen's result.
 * Exists only because winmm's shz_wav_parse is not exported; replace by that export if winmm ever publishes it. */
#ifndef MUZIK_WAV_H
#define MUZIK_WAV_H
#include <stdint.h>
#define MZ_WAV_MAX (8u * 1024u * 1024u)
typedef struct { uint16_t ch, bits; uint32_t rate, off, len; } mz_wav;
enum { MZ_OK = 0, MZ_E_RIFF, MZ_E_CHUNK, MZ_E_NOFMT, MZ_E_FORMAT, MZ_E_NODATA };
static uint32_t mz_u32(const uint8_t *p) { return p[0] | (uint32_t)p[1] << 8 | (uint32_t)p[2] << 16 | (uint32_t)p[3] << 24; }
static uint16_t mz_u16(const uint8_t *p) { return (uint16_t)(p[0] | p[1] << 8); }
static int mz_wav_parse(const uint8_t *b, uint32_t n, mz_wav *o)
{
    uint32_t pos = 12; int fmt = 0;
    if (n < 12 || n > MZ_WAV_MAX || memcmp(b, "RIFF", 4) || memcmp(b + 8, "WAVE", 4)) return MZ_E_RIFF;
    o->len = 0;
    while (n - pos >= 8) {
        uint32_t sz = mz_u32(b + pos + 4), body = pos + 8;
        if (sz > n - body) { if (memcmp(b + pos, "data", 4) || !fmt) return MZ_E_CHUNK; sz = n - body; }  /* truncated data: play what exists */
        if (!memcmp(b + pos, "fmt ", 4)) {
            uint16_t tag, blk; uint32_t avg;
            if (sz < 16) return MZ_E_FORMAT;
            tag = mz_u16(b + body); o->ch = mz_u16(b + body + 2); o->rate = mz_u32(b + body + 4);
            avg = mz_u32(b + body + 8); blk = mz_u16(b + body + 12); o->bits = mz_u16(b + body + 14);
            if (tag != 1) return MZ_E_FORMAT;                        /* plain PCM only; EXTENSIBLE intentionally not offered here */
            if (o->ch < 1 || o->ch > 2 || (o->bits != 8 && o->bits != 16)) return MZ_E_FORMAT;
            if (o->rate != 11025 && o->rate != 22050 && o->rate != 44100 && o->rate != 48000) return MZ_E_FORMAT;
            if (blk != o->ch * (o->bits / 8) || avg != o->rate * blk) return MZ_E_FORMAT;
            fmt = 1;
        } else if (!memcmp(b + pos, "data", 4)) {
            if (!fmt) return MZ_E_NOFMT;
            o->off = body; o->len = sz - sz % (o->ch * (o->bits / 8));
            return o->len ? MZ_OK : MZ_E_NODATA;
        }
        if (sz + (sz & 1) > n - body) break;
        pos = body + sz + (sz & 1);
    }
    return fmt ? MZ_E_NODATA : MZ_E_NOFMT;
}
#endif
