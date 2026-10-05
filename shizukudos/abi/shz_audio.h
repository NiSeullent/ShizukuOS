/* SPDX-License-Identifier: GPL-2.0-only
 * ShizukuOS Core audio service ABI v1 (kernel owner: kernel64/audio*.c; user consumer: WinMM).
 *
 *   NTSTATUS NtShzSound(ULONG op, PVOID in, ULONG in_len, PVOID out, ULONG out_len, PULONG ret_len);
 *   syscall 0xda (SYS_NtShzSound). Arguments 5 and 6 are on the user stack (Windows x64 convention), the generated
 *   ntdll stub also exports ZwShzSound. 0xdb-0xdf stay reserved for audio.
 *
 * Every in/out structure starts with `uint32_t size` = sizeof(struct); the kernel rejects other sizes.
 * Output of a successful call is returned only if out_len >= sizeof(out struct); *ret_len gets the bytes written.
 * The kernel never returns pointers. Hardware: Intel AC97 (PCI 8086:2415), playback only, fixed 48 kHz stereo signed
 * 16-bit. Source PCM (8/16-bit, mono/stereo, 11025/22050/44100/48000 Hz) is converted by the kernel. One exclusive
 * stream at a time. No capture, no MIDI. With no initialised hardware: QUERY reports present=0 and returns
 * STATUS_DEVICE_NOT_READY; every other op returns STATUS_DEVICE_NOT_READY / STATUS_INVALID_HANDLE.
 * Completion semantics: a write cookie is reported only after the hardware consumed (DMA-played) the descriptors that
 * carry its last byte, or as ABORTED after RESET/CLOSE.
 */
#ifndef SHZ_AUDIO_H
#define SHZ_AUDIO_H
#include <stdint.h>

#define SHZ_SND_ABI_VERSION 1u

enum {
    SHZ_SND_OP_QUERY = 0,   /* in: none (in_len 0) -> out shz_snd_caps */
    SHZ_SND_OP_OPEN = 1,    /* in shz_snd_open_in -> out shz_snd_open_out */
    SHZ_SND_OP_WRITE = 2,   /* in shz_snd_write_in -> out shz_snd_write_out */
    SHZ_SND_OP_STATUS = 3,  /* in shz_snd_handle_in -> out shz_snd_status (drains completed cookies) */
    SHZ_SND_OP_PAUSE = 4,   /* in shz_snd_pause_in */
    SHZ_SND_OP_RESET = 5,   /* in shz_snd_handle_in: stop, discard unplayed data, cookies complete as ABORTED */
    SHZ_SND_OP_CLOSE = 6,   /* in shz_snd_handle_in */
    SHZ_SND_OP_VOLUME = 7,  /* in shz_snd_volume_in (applies to data written afterwards) */
    SHZ_SND_OP_OUTPUT_GET = 8, /* none -> shz_snd_output; actual software gain */
    SHZ_SND_OP_OUTPUT_SET = 9  /* shz_snd_output -> identical confirmed reply */
};

/* Output gain affects PCM committed after this update, including subsequent
 * streams. Already published DMA buffers retain their prior samples. This is
 * software output attenuation, not capture gain or an invented hardware mixer.
 * SET is accepted only for a real normal account, elevated administrator, or
 * explicit anonymous development context; sandbox and logon helpers refuse.
 * No device/faulted backend refuses. Default unity is per boot; the owning
 * shell may load its user's durable preference and request this same service. */
typedef struct shz_snd_output {
    uint32_t size,volume_left,volume_right,muted;
} shz_snd_output;
_Static_assert(sizeof(shz_snd_output)==16,"output gain wire layout");
#define SHZ_SND_BACKEND_NONE 0u
#define SHZ_SND_BACKEND_AC97 1u

#define SHZ_SND_FMT_8BIT  0x01u        /* caps.bits_mask */
#define SHZ_SND_FMT_16BIT 0x02u
#define SHZ_SND_RATE_11025 0x01u       /* caps.rate_mask */
#define SHZ_SND_RATE_22050 0x02u
#define SHZ_SND_RATE_44100 0x04u
#define SHZ_SND_RATE_48000 0x08u

#define SHZ_SND_CAPF_STREAM_OPEN 0x01u /* a stream is currently open (exclusive) */
#define SHZ_SND_CAPF_IRQ         0x02u /* completion interrupt attached (otherwise state is polled) */
#define SHZ_SND_CAPF_FAULTED     0x04u /* device quarantined after a failed stop proof; no further streams */

#define SHZ_SND_MAX_COOKIES 16u
#define SHZ_SND_MAX_WRITE_BYTES 65536u /* upper bound for one WRITE request */

typedef struct shz_snd_caps {
    uint32_t size, abi_version;
    uint32_t present;                  /* 1 only when an AC97 function was initialised and codec ready */
    uint32_t backend;                  /* SHZ_SND_BACKEND_* */
    uint32_t flags;                    /* SHZ_SND_CAPF_* */
    uint32_t bits_mask, rate_mask;     /* source formats accepted */
    uint32_t max_channels;             /* 2 */
    uint32_t hw_rate;                  /* 48000 */
    uint32_t ring_slots;               /* descriptors, 32 */
    uint32_t queue_bytes;              /* playback capacity in hardware bytes (48 kHz stereo 16-bit) */
    uint32_t pci_vendor, pci_device;
    uint32_t irq_line;                 /* 0xffffffff when polled */
} shz_snd_caps;

typedef struct shz_snd_open_in {
    uint32_t size;
    uint32_t channels;                 /* 1 or 2 */
    uint32_t bits;                     /* 8 (unsigned) or 16 (signed little endian) */
    uint32_t rate;                     /* 11025, 22050, 44100, 48000 */
    uint32_t volume_left, volume_right;/* 0..0xffff, 0xffff = unity */
    uint32_t reserved;                 /* must be 0 */
} shz_snd_open_in;

typedef struct shz_snd_open_out {
    uint32_t size, reserved;
    uint64_t handle;                   /* opaque, generational, owned by the calling process */
    uint32_t hw_rate, queue_bytes;
} shz_snd_open_out;

typedef struct shz_snd_write_in {
    uint32_t size, reserved;
    uint64_t handle;
    uint64_t data;                     /* user pointer, read once and copied by the kernel */
    uint32_t length;                   /* source bytes, whole source frames, <= SHZ_SND_MAX_WRITE_BYTES */
    uint32_t reserved2;
    uint64_t cookie;                   /* caller token returned on completion; 0 = none */
} shz_snd_write_in;

#define SHZ_SND_WRITEF_QUEUE_FULL 0x01u /* accepted < length because the ring is full */

typedef struct shz_snd_write_out {
    uint32_t size;
    uint32_t accepted_bytes;           /* source bytes taken (whole frames); the cookie covers exactly these */
    uint32_t flags;                    /* SHZ_SND_WRITEF_* */
    uint32_t free_slots;
} shz_snd_write_out;

typedef struct shz_snd_handle_in {
    uint32_t size, reserved;
    uint64_t handle;
} shz_snd_handle_in;

typedef struct shz_snd_pause_in {
    uint32_t size, pause;              /* 1 = pause, 0 = restart */
    uint64_t handle;
} shz_snd_pause_in;

typedef struct shz_snd_volume_in {
    uint32_t size, volume_left;
    uint64_t handle;
    uint32_t volume_right, reserved;
} shz_snd_volume_in;

#define SHZ_SND_COOKIEF_ABORTED 0x01u  /* discarded by RESET/CLOSE, not played */

typedef struct shz_snd_cookie {
    uint64_t cookie;
    uint32_t flags, reserved;
} shz_snd_cookie;

#define SHZ_SND_STF_RUNNING 0x01u      /* DMA engine running */
#define SHZ_SND_STF_PAUSED  0x02u
#define SHZ_SND_STF_FAULT   0x04u      /* engine failed to start/stop; stream unusable, close it */
#define SHZ_SND_STF_UNDERRUN 0x08u     /* engine halted with the ring drained since the last STATUS */
#define SHZ_SND_STF_MORE_COOKIES 0x10u /* more completed cookies are waiting; call STATUS again */

typedef struct shz_snd_status {
    uint32_t size, flags;
    uint64_t played_bytes;             /* hardware (48 kHz stereo 16-bit) bytes actually consumed by DMA */
    uint64_t submitted_bytes;          /* hardware bytes queued in total */
    uint32_t queued_slots, free_slots;
    uint32_t underruns, irq_count;
    uint32_t cookie_count;             /* valid entries in cookies[] */
    uint32_t reserved;
    shz_snd_cookie cookies[SHZ_SND_MAX_COOKIES];
} shz_snd_status;

#ifndef STATUS_DEVICE_NOT_READY
#define STATUS_DEVICE_NOT_READY ((int32_t)0xC00000A3)
#endif
#ifndef STATUS_DEVICE_BUSY
#define STATUS_DEVICE_BUSY ((int32_t)0x80000011)
#endif
#endif
