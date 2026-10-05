/* SPDX-License-Identifier: GPL-2.0-only
 * Kernel64 audio: backend contract between the PCM/stream service (audio.c) and a hardware driver (audio_ac97.c).
 * ABI toward user mode: ../abi/shz_audio.h. A backend owns the DMA engine and all bus-addressable memory; audio.c never
 * sees a physical address and user mode never supplies one.
 */
#ifndef K64_AUDIO_H
#define K64_AUDIO_H
#include <stdint.h>

#define AUDIO_RING_SLOTS 32u                    /* descriptors in the ring (AC97 BDL has 32 entries) */
#define AUDIO_MAX_INFLIGHT 31u                  /* one slot is never queued: LVI/CIV stay unambiguous */
#define AUDIO_SLOT_BYTES 4096u                  /* one page of 48 kHz stereo 16-bit per descriptor */
#define AUDIO_SLOT_FRAMES (AUDIO_SLOT_BYTES / 4u)

typedef struct {
    uint32_t sr, civ, picb;                     /* status (AC97 SR bits), current index, samples left in current buffer */
} audio_hw_pos;

typedef struct {
    uint32_t vendor, device, irq_line;          /* irq_line 0xffffffff: no completion interrupt attached */
} audio_hw_info;

#define AUDIO_SR_DCH 0x01u                      /* DMA halted */
#define AUDIO_SR_CELV 0x02u

typedef struct audio_backend {
    int (*probe)(audio_hw_info *info);          /* lazy; 0 only when initialised and the codec is ready */
    uint8_t *(*slot_cpu)(unsigned slot);        /* kernel-owned, page aligned buffer of AUDIO_SLOT_BYTES */
    void (*slot_program)(unsigned slot, uint32_t samples16);  /* descriptor = buffer + sample count, IOC set */
    int (*irq_attach)(void);                    /* shared INTx when safe; 0 attached, -1 polled */
    void (*irq_detach)(void);
    int (*start)(unsigned lvi);                 /* from reset state: BDBAR, LVI, RUN; 0 once DMA is confirmed running */
    int (*extend)(unsigned lvi);                /* publish a new LVI, resume a halted engine; 0 once confirmed */
    void (*position)(audio_hw_pos *p);          /* SR first, then CIV, then PICB */
    int (*pause)(int pause);                    /* RUN clear/set; pause=1 returns 0 only once DMA reads halted */
    int (*stop)(void);                          /* halt + register reset; 0 only when inactive is proven */
    uint32_t (*irq_count)(void);
} audio_backend;

/* Provided by audio_ac97.c (NULL: no backend compiled for this profile). Host tests supply a modelled device instead. */
const audio_backend *audio_backend_get(void);
#endif
