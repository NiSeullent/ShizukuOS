/* SPDX-License-Identifier: GPL-2.0-only
 * ShizukuDOS 10.0 inter-kernel ABI, version 1.1.
 *
 * 1.1 adds, both backward compatible with 1.0 (same major, same header):
 *  - the WIN64 subsystem message family (shz_ipc.h, opcodes 0x200..0x2ff): a 32-bit Windows 98 program
 *    starts, feeds and observes a Win64 process running in the Kernel64 domain; 1.0 receivers still
 *    accept every 1.1 frame;
 *  - the boot info tail (framebuffer, cmdline): a 1.0 reader only reads the 1.0 prefix, and `size`
 *    tells a 1.1 reader whether the writer provided the tail.
 *
 * Everything on the wire is fixed-width, little-endian and naturally aligned so the
 * same header compiles identically for 16-bit-real-mode assemblers (as offsets), for
 * 32-bit Kernel32 and for 64-bit Kernel64 / Supervisor. Pointers never cross a
 * domain boundary: shared buffers are named by (region offset, length), never by
 * address, and 64-bit offsets prevent truncation above 4 GiB.
 *
 * Three layers are defined here:
 *   1. Hypercalls: guest kernel -> Supervisor (VMCALL).
 *   2. Boot information: Supervisor -> guest kernel at entry.
 *   3. IPC channel: guest <-> guest through shared memory rings + doorbells.
 */
#ifndef SHZ_ABI_H
#define SHZ_ABI_H
#include <stdint.h>
#include "../boot_profile/storage/provenance.h"

#define SHZ_ABI_MAJOR 1
#define SHZ_ABI_MINOR 1                 /* 1.1: WIN64 subsystem messages; boot info framebuffer + cmdline tail */

/* ---------------------------------------------------------------- domains */
enum shz_domain_id {
    SHZ_DOM_NONE = 0,
    SHZ_DOM_SUPERVISOR = 1,
    SHZ_DOM_DOS16 = 2,
    SHZ_DOM_KERNEL32 = 3,
    SHZ_DOM_KERNEL64 = 4,
    SHZ_DOM_WIN98 = 5,
    SHZ_DOM_MAX = 8
};

/* ---------------------------------------------------------------- hypercalls
 * VMCALL from guest CPL0. RAX = opcode, RBX/RCX/RDX/RSI/RDI = arguments.
 * On return RAX = status (0 = ok, otherwise negative shz_status), RBX = result. */
enum shz_hcall {
    SHZ_HC_CONSOLE_WRITE = 1,   /* rbx = guest-physical address, rcx = length (<= 512) */
    SHZ_HC_EXIT = 2,            /* rbx = exit code; the calling domain terminates */
    SHZ_HC_TIMER_SET = 3,       /* rbx = vector, rcx = period in microseconds (0 = stop) */
    SHZ_HC_NOTIFY = 4,          /* rbx = target domain, rcx = doorbell bit mask */
    SHZ_HC_WAIT = 5,            /* idle until an interrupt or doorbell is pending */
    SHZ_HC_TIME = 6,            /* rbx <- monotonic nanoseconds since Supervisor start */
    SHZ_HC_SET_DOORBELL_VECTOR = 7, /* rbx = interrupt vector used for doorbell delivery */
    SHZ_HC_DOORBELL_ACK = 8,    /* rbx <- pending doorbell mask, atomically cleared */
    SHZ_HC_EVIDENCE = 9,        /* rbx = slot (0..31), rcx = value: harness-visible, guest-generated */
    SHZ_HC_DOMAIN_STATE = 10,   /* rbx = domain id; rbx <- state, rcx <- generation */
    SHZ_HC_ABI_VERSION = 11,    /* rbx <- (major << 16) | minor */
    SHZ_HC_WALLTIME = 12,       /* rbx <- seconds since 1970-01-01 UTC from the platform RTC */
    SHZ_HC_CHANNEL_INFO = 13,   /* ABI 1.1: rbx = channel index; rbx <- guest-physical base, rcx <- peer domain, or E_NOENT.
                                 * For domains that receive no bootinfo (the Win98 domain's VxD). */
    SHZ_HC_NATIVE_GOP_EPOCH = 14 /* readonly: rbx=word index, rcx=contract version1;
                                  rbx<-word, rcx<-40. Actual guardian/domain only. */
};

enum shz_status {
    SHZ_OK = 0,
    SHZ_E_INVALID = -1,
    SHZ_E_RANGE = -2,
    SHZ_E_NOENT = -3,
    SHZ_E_BUSY = -4,
    SHZ_E_QUEUE_FULL = -5,
    SHZ_E_STALE = -6,
    SHZ_E_TIMEOUT = -7,
    SHZ_E_CANCELLED = -8,
    SHZ_E_PROTO = -9,
    SHZ_E_NOMEM = -10,
    SHZ_E_UNSUPPORTED = -11,
    SHZ_E_DENIED = -12
};

enum shz_domain_state {
    SHZ_DS_UNUSED = 0, SHZ_DS_RUNNABLE = 1, SHZ_DS_WAITING = 2, SHZ_DS_EXITED = 3, SHZ_DS_FAILED = 4
};

/* ---------------------------------------------------------------- boot info
 * Placed by the Supervisor at guest-physical SHZ_BOOTINFO_GPA before the first
 * guest instruction. Fixed width, no pointers. */
#define SHZ_BOOTINFO_MAGIC 0x544f4f42u          /* "BOOT" */
#define SHZ_BOOTINFO_GPA 0x7000u
#define SHZ_IPC_GPA_BASE 0xe0000000u            /* channel c at base + c * SHZ_IPC_REGION_SIZE */
#define SHZ_IPC_REGION_SIZE 0x100000u
#define SHZ_MAX_CHANNELS 4

/* shz_bootinfo_t.flags */
#define SHZ_BIF_UEFI_DIRECT 0x1u        /* started by the UEFI boot manager as the only OS (no Supervisor) */

/* shz_bootinfo_t.fb_format: byte order of one 32-bit pixel in memory */
enum shz_fb_format {
    SHZ_FB_NONE = 0,
    SHZ_FB_RGBX8888 = 1,            /* R,G,B,X  (GOP PixelRedGreenBlueReserved8BitPerColor) */
    SHZ_FB_BGRX8888 = 2             /* B,G,R,X  (GOP PixelBlueGreenRedReserved8BitPerColor) */
};

#define SHZ_CMDLINE_MAX 256

typedef struct {
    uint32_t magic;
    uint16_t abi_major, abi_minor;
    uint32_t size;                  /* sizeof(shz_bootinfo_t) of the WRITER: fields past it are absent */
    uint32_t domain_id;
    uint32_t generation;
    uint32_t flags;                 /* SHZ_BIF_* */
    uint64_t ram_size;              /* guest RAM is [0, ram_size) */
    uint64_t kernel_gpa, kernel_size;
    uint64_t initrd_gpa, initrd_size;
    uint64_t tsc_hz;
    uint32_t channel_count;
    uint32_t reserved0;
    struct {
        uint64_t gpa, size;
        uint32_t peer_domain, channel_id;
    } channel[SHZ_MAX_CHANNELS];
    /* ---- ABI 1.1 tail (offset 176). A reader must test SHZ_BOOTINFO_HAS() first: a 1.0
     * writer's `size` (176) ends before it.
     * Framebuffer: written only by the UEFI boot manager's direct Kernel64 boot
     * (shizukudos/supervisor/loader, BOOT.INI mode = kernel64) from the firmware's GOP
     * mode at ExitBootServices; the Supervisor and the Multiboot stubs write zeros.
     * HOOK for the window manager's GOP backend (kernel64/gfx_fb.c, owned by the gfx
     * work): Kernel64 exposes these fields through k64_boot_framebuffer() (kernel64/main.c).
     * The range is NOT in the kernel's direct map (it lies outside [0, ram_size)), so a
     * backend must map [fb_base, fb_base + fb_size) uncached/write-combining first.
     * Command line: the UEFI boot manager copies \SHZDOS\KERNEL64.INI `cmdline`; the
     * Multiboot stubs copy the Multiboot command line; the Supervisor writes an empty one. */
    uint64_t fb_base, fb_size;      /* physical linear framebuffer; 0 = none */
    uint32_t fb_width, fb_height;   /* visible pixels */
    uint32_t fb_pitch;              /* bytes per scan line */
    uint32_t fb_format;             /* enum shz_fb_format */
    uint32_t fb_bpp;                /* bits per pixel (32 for both formats above; 0 = none) */
    uint32_t cmdline_size;          /* bytes before the NUL, < SHZ_CMDLINE_MAX */
    char cmdline[SHZ_CMDLINE_MAX];  /* NUL-terminated printable ASCII */
    /* Independently versioned additive loader-only tail. Old 472-byte writers
     * leave provenance absent; IPC version remains unchanged. */
    shz_storage_provenance_t storage;
} shz_bootinfo_t;

/* True when the writer's boot info is long enough to contain `field`. */
#define SHZ_BOOTINFO_HAS(bi, field) \
    ((bi)->size >= __builtin_offsetof(shz_bootinfo_t, field) + sizeof((bi)->field))

/* ---------------------------------------------------------------- IPC wire format */
#define SHZ_MSG_MAGIC 0x43505a53u               /* "SZPC" */
#define SHZ_MSG_SLOT_SIZE 256u
#define SHZ_MSG_MAX_INLINE (SHZ_MSG_SLOT_SIZE - 64u)

typedef struct {
    uint32_t magic;             /* 0x00 SHZ_MSG_MAGIC */
    uint16_t abi_major;         /* 0x04 must match the receiver's major */
    uint16_t abi_minor;         /* 0x06 */
    uint16_t header_size;       /* 0x08 sizeof(shz_msg_hdr_t) = 64 */
    uint16_t flags;             /* 0x0a SHZ_MSGF_* */
    uint32_t message_size;      /* 0x0c header + inline payload, bytes (<= SHZ_MSG_SLOT_SIZE) */
    uint32_t opcode;            /* 0x10 */
    uint16_t src_domain;        /* 0x14 */
    uint16_t dst_domain;        /* 0x16 */
    uint64_t request_id;        /* 0x18 chosen by the requester, echoed in the reply */
    uint32_t generation;        /* 0x20 sender's view of the peer generation; stale = reject */
    int32_t status;             /* 0x24 replies: shz_status or protocol-specific */
    uint16_t payload_offset;    /* 0x28 inline payload offset from message start (>= header_size) */
    uint16_t payload_length;    /* 0x2a inline bytes */
    uint32_t buffer_length;     /* 0x2c shared-buffer reference length, 0 when unused ... */
    uint64_t buffer_offset;     /* 0x30 ... and its byte offset into the channel pool */
    uint32_t capability_id;     /* 0x38 handle broker id (never a raw handle or pointer) */
    uint32_t checksum;          /* 0x3c CRC-32 over header+inline payload, this field zero */
} shz_msg_hdr_t;

enum shz_msg_flags {
    SHZ_MSGF_REPLY = 1, SHZ_MSGF_ONEWAY = 2, SHZ_MSGF_CANCEL = 4, SHZ_MSGF_BUFFER = 8
};

/* Single-producer / single-consumer ring. The producer owns `head`, the consumer
 * owns `tail`; each lives on its own cache line. Slots are SHZ_MSG_SLOT_SIZE bytes. */
#define SHZ_RING_MAGIC 0x474e4952u              /* "RING" */
typedef struct {
    uint32_t magic;
    uint32_t slot_count;            /* power of two */
    uint32_t slot_size;
    uint32_t reserved;
    uint8_t pad0[48];
    volatile uint32_t head;         /* next slot to write (producer) */
    uint8_t pad1[60];
    volatile uint32_t tail;         /* next slot to read (consumer) */
    uint8_t pad2[60];
} shz_ring_hdr_t;

/* Channel = header + two rings (a->b, b->a) + shared buffer pool. */
#define SHZ_CHANNEL_MAGIC 0x4c4e4843u           /* "CHNL" */
typedef struct {
    uint32_t magic;
    uint16_t abi_major, abi_minor;
    uint32_t channel_id;
    uint32_t generation;            /* bumped by the Supervisor whenever either peer restarts */
    uint32_t domain_a, domain_b;
    uint64_t ring_ab_offset, ring_ba_offset;
    uint64_t pool_offset, pool_size;
    uint32_t slot_count;
    uint32_t reserved;
    uint8_t pad[64];
} shz_channel_hdr_t;

_Static_assert(sizeof(shz_msg_hdr_t) == 64, "message header layout");
_Static_assert(__builtin_offsetof(shz_msg_hdr_t, request_id) == 0x18, "request_id offset");
_Static_assert(__builtin_offsetof(shz_msg_hdr_t, buffer_offset) == 0x30, "buffer_offset offset");
_Static_assert(sizeof(shz_ring_hdr_t) == 192, "ring header layout");
_Static_assert(sizeof(shz_channel_hdr_t) == 128, "channel header layout");
_Static_assert(__builtin_offsetof(shz_bootinfo_t, fb_base) == 176, "ABI 1.0 boot info prefix is 176 bytes");
_Static_assert(__builtin_offsetof(shz_bootinfo_t, cmdline) == 216, "boot info 1.1 tail layout");
_Static_assert(__builtin_offsetof(shz_bootinfo_t, storage) == 472, "old boot info prefix unchanged");
_Static_assert(sizeof(shz_bootinfo_t) == 616, "boot info layout");
_Static_assert(SHZ_MSG_MAX_INLINE == 192, "inline capacity");
#endif
