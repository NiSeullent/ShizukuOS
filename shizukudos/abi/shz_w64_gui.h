/* SPDX-License-Identifier: GPL-2.0-only
 * WIN64 subsystem native GUI frame-pull protocol, version 1 (DRAFT ABI, clone-local claim).
 * Source: PROPOSAL-1A36-ROOT-1A40-74B0-NATIVE-GUI-WIRE-20261003. Opcodes 0x240..0x245 and QUERY capability bit
 * 0x20 are claimed here only for this isolated clone; root/1a40/74b0 must ACK before canonical assignment.
 *
 * Pointer-free little-endian inline packets on the existing W64 channel (shz_msg_hdr_t, SHZ_MSGF_REPLY replies,
 * buffer_length/offset 0). Every request and reply has an exact fixed size, version 1 and zero reserved fields.
 * The pid is a slot SELECTOR only; authority comes from the server's own slot/process/channel binding.
 *
 *   QUERY_VIEW    req 24  -> reply 64 view info
 *   FRAME_ACQUIRE req 64  -> reply 80 snapshot
 *   FRAME_READ    req 64  -> reply 192 (prefix + offset/length + data[128])
 *   FRAME_RELEASE req 48  -> reply 48
 *   INPUT         req 80  -> reply 48 (sequence confirmed)
 *   CLOSE_VIEW    req 48  -> reply 48
 * Pixels: top-down tightly packed B,G,R,X (dword 0x00RRGGBB), stride = width*4, CRC-32 (IEEE) over all bytes. */
#ifndef SHZ_W64_GUI_H
#define SHZ_W64_GUI_H
#include <stdint.h>

#define SHZ_OP_W64_GUI_QUERY_VIEW    0x240u
#define SHZ_OP_W64_GUI_FRAME_ACQUIRE 0x241u
#define SHZ_OP_W64_GUI_FRAME_READ    0x242u
#define SHZ_OP_W64_GUI_FRAME_RELEASE 0x243u
#define SHZ_OP_W64_GUI_INPUT         0x244u
#define SHZ_OP_W64_GUI_CLOSE_VIEW    0x245u
#define SHZ_OP_W64_GUI_FIRST SHZ_OP_W64_GUI_QUERY_VIEW
#define SHZ_OP_W64_GUI_LAST  SHZ_OP_W64_GUI_CLOSE_VIEW

#define SHZ_W64_CAP_GUI 0x20u                       /* distinct from the five existing W64 capability bits */
#define SHZ_W64_GUI_VERSION 1u
#define SHZ_W64_GUI_MAX_WIDTH 1024u
#define SHZ_W64_GUI_MAX_HEIGHT 768u
#define SHZ_W64_GUI_MAX_FRAME_BYTES (SHZ_W64_GUI_MAX_WIDTH * SHZ_W64_GUI_MAX_HEIGHT * 4u)
#define SHZ_W64_GUI_CHUNK 128u
#define SHZ_W64_GUI_LEASE_MS 10000u
#define SHZ_W64_GUI_FMT_BGRX32 1u
#define SHZ_W64_GUI_ACQ_CLIENT_ONLY 1u

/* shz_w64_gui_view_t.display_backend: a view exists only over a real K64 display. Neither value claims GOP
 * ownership or acceleration; HOSTED_PRIVATE is the w64-hosted software back buffer with no scanout. */
#define SHZ_W64_GUI_DISPLAY_SCANOUT 1u              /* gfx_fb backend driving a real framebuffer (virtio/BGA/GOP) */
#define SHZ_W64_GUI_DISPLAY_HOSTED_PRIVATE 2u       /* private back buffer, frame pull only, no scanout */

/* Derived owner identity. With NTWV_W64_DERIVED_OWNER the NTWRAP9X VxD overwrites capability_id of EVERY W64 SEND
 * with DERIVED|token, token issued per (VWIN32 DIOC tagProcess, system VM, channel generation) and never reused;
 * trusted in-VxD endpoint sends have the DERIVED bit cleared. The application value is never forwarded. */
#define SHZ_W64_OWNER_CAP_DERIVED 0x80000000u
#define SHZ_W64_OWNER_CAP_TOKEN 0x7fffffffu

enum shz_w64_gui_input_kind {
    SHZ_W64_GUI_IN_MOVE = 1, SHZ_W64_GUI_IN_LDOWN = 2, SHZ_W64_GUI_IN_LUP = 3, SHZ_W64_GUI_IN_RDOWN = 4,
    SHZ_W64_GUI_IN_RUP = 5, SHZ_W64_GUI_IN_KEYDOWN = 6, SHZ_W64_GUI_IN_KEYUP = 7, SHZ_W64_GUI_IN_CLOSE = 8
};
#define SHZ_W64_GUI_INF_SHIFT 1u
#define SHZ_W64_GUI_INF_CTRL 2u
#define SHZ_W64_GUI_INF_ALT 4u
#define SHZ_W64_GUI_INF_KNOWN 7u

typedef struct { uint32_t size, version, pid, expected_channel_generation, reserved[2]; } shz_w64_gui_query_t;
typedef struct {
    uint32_t size, version, pid, process_generation;
    uint64_t view_id;
    uint32_t channel_generation, capabilities, max_width, max_height, max_frame_bytes, max_chunk_bytes,
             snapshot_lease_ms, display_backend;   /* SHZ_W64_GUI_DISPLAY_* (never 0 in a reply) */
    uint64_t default_window_id;                     /* 0: the process has no visible owned top-level window yet */
} shz_w64_gui_view_t;
typedef struct {
    uint32_t size, version, pid, process_generation;
    uint64_t window_id, view_id, snapshot_id;
    uint32_t expected_channel_generation, sequence;
} shz_w64_gui_prefix_t;
typedef struct { shz_w64_gui_prefix_t p; uint64_t previous_snapshot_id; uint32_t flags, reserved; } shz_w64_gui_acquire_t;
typedef struct {
    shz_w64_gui_prefix_t p;
    uint32_t width, height, stride, byte_length, pixel_format, pixels_crc32, lease_ms, flags;
} shz_w64_gui_snapshot_t;
typedef struct { shz_w64_gui_prefix_t p; uint32_t offset, length, reserved[2]; } shz_w64_gui_read_t;
typedef struct { shz_w64_gui_read_t r; uint8_t data[SHZ_W64_GUI_CHUNK]; } shz_w64_gui_chunk_t;
typedef struct {
    shz_w64_gui_prefix_t p;
    uint32_t kind, flags;
    int32_t x, y;
    uint32_t key, scancode, clock_ms, reserved;
} shz_w64_gui_input_t;

_Static_assert(sizeof(shz_w64_gui_query_t) == 24, "gui query");
_Static_assert(sizeof(shz_w64_gui_view_t) == 64, "gui view");
_Static_assert(sizeof(shz_w64_gui_prefix_t) == 48, "gui prefix");
_Static_assert(sizeof(shz_w64_gui_acquire_t) == 64, "gui acquire");
_Static_assert(sizeof(shz_w64_gui_snapshot_t) == 80, "gui snapshot");
_Static_assert(sizeof(shz_w64_gui_read_t) == 64, "gui read");
_Static_assert(sizeof(shz_w64_gui_chunk_t) == 192, "gui chunk = SHZ_MSG_MAX_INLINE");
_Static_assert(sizeof(shz_w64_gui_input_t) == 80, "gui input");

static inline void shz_w64_gui_copy(void *dst, const void *src, uint32_t n)
{
    uint8_t *d = (uint8_t *)dst;
    const uint8_t *s = (const uint8_t *)src;
    while (n--) *d++ = *s++;
}

static inline void shz_w64_gui_zero(void *dst, uint32_t n)
{
    uint8_t *d = (uint8_t *)dst;
    while (n--) *d++ = 0;
}

/* Request size the receiver must see for `opcode`, 0 for a non-GUI opcode. */
static inline uint32_t shz_w64_gui_request_size(uint32_t opcode)
{
    switch (opcode) {
    case SHZ_OP_W64_GUI_QUERY_VIEW: return sizeof(shz_w64_gui_query_t);
    case SHZ_OP_W64_GUI_FRAME_ACQUIRE: return sizeof(shz_w64_gui_acquire_t);
    case SHZ_OP_W64_GUI_FRAME_READ: return sizeof(shz_w64_gui_read_t);
    case SHZ_OP_W64_GUI_FRAME_RELEASE: case SHZ_OP_W64_GUI_CLOSE_VIEW: return sizeof(shz_w64_gui_prefix_t);
    case SHZ_OP_W64_GUI_INPUT: return sizeof(shz_w64_gui_input_t);
    default: return 0;
    }
}

static inline uint32_t shz_w64_gui_reply_size(uint32_t opcode)
{
    switch (opcode) {
    case SHZ_OP_W64_GUI_QUERY_VIEW: return sizeof(shz_w64_gui_view_t);
    case SHZ_OP_W64_GUI_FRAME_ACQUIRE: return sizeof(shz_w64_gui_snapshot_t);
    case SHZ_OP_W64_GUI_FRAME_READ: return sizeof(shz_w64_gui_chunk_t);
    case SHZ_OP_W64_GUI_FRAME_RELEASE: case SHZ_OP_W64_GUI_CLOSE_VIEW: case SHZ_OP_W64_GUI_INPUT:
        return sizeof(shz_w64_gui_prefix_t);
    default: return 0;
    }
}

/* Selector pid of any well-sized GUI request (offset 8 in every request), 0 if the payload is short. */
static inline uint32_t shz_w64_gui_selector_pid(const void *payload, uint32_t length)
{
    uint32_t pid = 0;
    if (payload && length >= 12u) shz_w64_gui_copy(&pid, (const uint8_t *)payload + 8, 4);
    return pid;
}

/* FRAME_READ bounds: 1..128 bytes, 4-aligned offset and length, inside the image. 0 = valid. */
static inline int shz_w64_gui_read_bounds(uint32_t byte_length, uint32_t offset, uint32_t length)
{
    if (!length || length > SHZ_W64_GUI_CHUNK || (offset & 3u) || (length & 3u) || (byte_length & 3u)) return -1;
    if (offset > byte_length || length > byte_length - offset) return -1;
    return 0;
}

/* Checked stride*height for a snapshot; 0 when the geometry is invalid or over the advertised limits. */
static inline uint32_t shz_w64_gui_frame_bytes(uint32_t width, uint32_t height)
{
    if (!width || !height || width > SHZ_W64_GUI_MAX_WIDTH || height > SHZ_W64_GUI_MAX_HEIGHT) return 0;
    return width * 4u * height;                     /* <= 3145728: no overflow */
}

/* IEEE 802.3 CRC-32 (reflected 0xEDB88320), table-free so it compiles in every profile. Start with crc = 0. */
static inline uint32_t shz_w64_gui_crc32(uint32_t crc, const void *data, uint32_t n)
{
    const uint8_t *p = (const uint8_t *)data;
    crc = ~crc;
    while (n--) {
        unsigned k;
        crc ^= *p++;
        for (k = 0; k < 8; ++k) crc = (crc >> 1) ^ (0xEDB88320u & (0u - (crc & 1u)));
    }
    return ~crc;
}
static inline int shz_w64_owner_cap_derived(uint32_t cap)
{
    return (cap & SHZ_W64_OWNER_CAP_DERIVED) != 0 && (cap & SHZ_W64_OWNER_CAP_TOKEN) != 0;
}
/* The one authority predicate for every GUI op: the request's endpoint identity must equal the identity that
 * created the slot (the pid in the payload only SELECTS the slot). When derived_required, both identities must be
 * VxD-derived; an application cannot forge a different Win98 process's derived token through the VxD. */
static inline int shz_w64_gui_subject_authorized(uint32_t owner_cap, uint32_t request_cap, int derived_required)
{
    if (owner_cap != request_cap) return 0;
    return !derived_required || shz_w64_owner_cap_derived(request_cap);
}
/* wire b5 s2: on an attested channel a DERIVED (VxD-stamped user) sender acts only on the slot it created; a
 * non-DERIVED capability there is the VxD's own in-ring-0 endpoint. Unattested channel: legacy (no isolation). */
static inline int shz_w64_console_owner_ok(int attested, uint32_t owner_cap, uint32_t request_cap)
{
    if (!attested || !shz_w64_owner_cap_derived(request_cap)) return 1;
    return owner_cap == request_cap;
}
/* Per-authorization console rule over shz_chan_auth_state(): revoked (attester gone after a positive attestation)
 * refuses every sender, including the former in-VxD endpoint; legacy rules apply only to a never-attested channel. */
static inline int shz_w64_console_owner_auth(int attested, int revoked, uint32_t owner_cap, uint32_t request_cap)
{
    if (revoked) return 0;
    return shz_w64_console_owner_ok(attested, owner_cap, request_cap);
}
/* Supervised GUI rule: derived creator identity AND the VxD stamping attested by the Supervisor for this generation. */
static inline int shz_w64_gui_subject_ok(uint32_t owner_cap, uint32_t request_cap, int derived_required, int attested)
{
    return shz_w64_gui_subject_authorized(owner_cap, request_cap, derived_required) && (!derived_required || attested);
}
static inline int shz_w64_gui_display_valid(uint32_t display_backend)
{
    return display_backend == SHZ_W64_GUI_DISPLAY_SCANOUT || display_backend == SHZ_W64_GUI_DISPLAY_HOSTED_PRIVATE;
}
#endif
