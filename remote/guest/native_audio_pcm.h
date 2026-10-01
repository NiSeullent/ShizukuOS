/* SPDX-License-Identifier: GPL-2.0-only */
#ifndef M98_NATIVE_AUDIO_PCM_H
#define M98_NATIVE_AUDIO_PCM_H
#include <stdint.h>
#define AUDIO_RATE 22050u
#define AUDIO_SECONDS 5u
#define AUDIO_FRAMES (AUDIO_RATE * AUDIO_SECONDS)
#define AUDIO_HZ 440u
static void audio_pcm_fill(int16_t *samples, unsigned frames) {
    static const int16_t sine[64] = {0,980,1951,2903,3827,4714,5556,6344,7071,7730,8315,8819,9239,9569,9808,9952,10000,9952,9808,9569,9239,8819,8315,7730,7071,6344,5556,4714,3827,2903,1951,980,0,-980,-1951,-2903,-3827,-4714,-5556,-6344,-7071,-7730,-8315,-8819,-9239,-9569,-9808,-9952,-10000,-9952,-9808,-9569,-9239,-8819,-8315,-7730,-7071,-6344,-5556,-4714,-3827,-2903,-1951,-980};
    unsigned i, phase = 0;
    for (i = 0; i < frames; ++i) {
        int value = sine[(phase * 64u) / AUDIO_RATE];
        /* Ten millisecond envelope prevents unrelated click transients. */
        if (i < 220u) value = value * (int)i / 220;
        else if (frames - i <= 220u) value = value * (int)(frames - i - 1u) / 220;
        samples[i] = (int16_t)value;
        phase += AUDIO_HZ;
        if (phase >= AUDIO_RATE) phase -= AUDIO_RATE;
    }
}
#endif

