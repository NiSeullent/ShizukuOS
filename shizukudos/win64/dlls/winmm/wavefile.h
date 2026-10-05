/* SPDX-License-Identifier: GPL-2.0-only
 * Bounded RIFF/WAVE PCM parser used by winmm PlaySound. Pure function: no allocation, no OS calls, never reads outside
 * [buf, buf+len). Accepts WAVE_FORMAT_PCM and WAVE_FORMAT_EXTENSIBLE(PCM subformat), 8/16 bit, 1/2 channels,
 * 11025/22050/44100/48000 Hz. Input and data are capped at SHZ_WAV_MAX bytes. */
#ifndef SHZ_WAVEFILE_H
#define SHZ_WAVEFILE_H
#include <stdint.h>
#define SHZ_WAV_MAX (8u * 1024u * 1024u)
enum { SHZ_WAV_OK = 0, SHZ_WAV_E_PARAM, SHZ_WAV_E_TOOBIG, SHZ_WAV_E_RIFF, SHZ_WAV_E_CHUNK, SHZ_WAV_E_NOFMT, SHZ_WAV_E_FORMAT,
       SHZ_WAV_E_NODATA };
typedef struct {
    uint16_t channels, bits;
    uint32_t rate;
    uint32_t data_off, data_len;     /* data_len is a whole number of frames, > 0 */
} shz_wav_info;
int shz_wav_parse(const uint8_t *buf, uint32_t len, shz_wav_info *out);
#endif
