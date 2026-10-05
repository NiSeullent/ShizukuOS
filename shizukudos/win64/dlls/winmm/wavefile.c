/* SPDX-License-Identifier: GPL-2.0-only
 * Bounded RIFF/WAVE parser; see wavefile.h. */
#include "wavefile.h"

static uint32_t rd32(const uint8_t *p) { return p[0] | (uint32_t)p[1] << 8 | (uint32_t)p[2] << 16 | (uint32_t)p[3] << 24; }
static uint16_t rd16(const uint8_t *p) { return (uint16_t)(p[0] | p[1] << 8); }

static const uint8_t pcm_guid[16] = { 1, 0, 0, 0, 0, 0, 0x10, 0, 0x80, 0, 0, 0xaa, 0, 0x38, 0x9b, 0x71 };

int shz_wav_parse(const uint8_t *buf, uint32_t len, shz_wav_info *out)
{
    uint32_t pos, end;
    int have_fmt = 0, i;
    shz_wav_info w = {0, 0, 0, 0, 0};
    if (!buf || !out) return SHZ_WAV_E_PARAM;
    if (len > SHZ_WAV_MAX) return SHZ_WAV_E_TOOBIG;
    if (len < 12 || rd32(buf) != 0x46464952u /* RIFF */ || rd32(buf + 8) != 0x45564157u /* WAVE */) return SHZ_WAV_E_RIFF;
    end = rd32(buf + 4);
    if (end < 4) return SHZ_WAV_E_RIFF;
    end = end > len - 8 ? len : end + 8;                 /* a RIFF size past the buffer is clamped to what exists */
    pos = 12;
    while (end - pos >= 8) {                              /* pos <= end always holds */
        uint32_t id = rd32(buf + pos), sz = rd32(buf + pos + 4), body = pos + 8;
        if (sz > end - body) return SHZ_WAV_E_CHUNK;      /* chunk overruns the RIFF: reject, never clamp */
        if (id == 0x20746d66u /* "fmt " */) {
            const uint8_t *f = buf + body;
            uint16_t tag;
            if (have_fmt) return SHZ_WAV_E_FORMAT;
            if (sz < 16) return SHZ_WAV_E_FORMAT;
            tag = rd16(f);
            w.channels = rd16(f + 2); w.rate = rd32(f + 4); w.bits = rd16(f + 14);
            if (tag == 0xfffeu) {
                if (sz < 40 || rd16(f + 16) < 22) return SHZ_WAV_E_FORMAT;
                for (i = 0; i < 16; ++i) if (f[24 + i] != pcm_guid[i]) return SHZ_WAV_E_FORMAT;   /* subformat must be PCM */
                if (rd16(f + 18) != w.bits) return SHZ_WAV_E_FORMAT;                  /* valid bits must equal container */
            } else if (tag != 1) return SHZ_WAV_E_FORMAT;
            if ((w.channels != 1 && w.channels != 2) || (w.bits != 8 && w.bits != 16)) return SHZ_WAV_E_FORMAT;
            if (w.rate != 11025 && w.rate != 22050 && w.rate != 44100 && w.rate != 48000) return SHZ_WAV_E_FORMAT;
            if (rd16(f + 12) != w.channels * (w.bits / 8)) return SHZ_WAV_E_FORMAT;   /* nBlockAlign */
            if (rd32(f + 8) != w.rate * rd16(f + 12)) return SHZ_WAV_E_FORMAT;        /* nAvgBytesPerSec */
            have_fmt = 1;
        } else if (id == 0x61746164u /* "data" */) {
            uint32_t frame;
            if (!have_fmt) return SHZ_WAV_E_NOFMT;        /* data before fmt cannot be interpreted */
            frame = w.channels * (w.bits / 8u);
            sz -= sz % frame;
            if (!sz) return SHZ_WAV_E_NODATA;
            w.data_off = body; w.data_len = sz;
            *out = w;
            return SHZ_WAV_OK;
        }
        if (sz & 1) { if (end - body - sz < 1) return SHZ_WAV_E_CHUNK; ++sz; }       /* odd chunks are padded */
        pos = body + sz;
    }
    return have_fmt ? SHZ_WAV_E_NODATA : SHZ_WAV_E_NOFMT;
}
