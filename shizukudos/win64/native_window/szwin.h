/* SPDX-License-Identifier: GPL-2.0-only
 * ShizukuOS native Win64 GUI frontend core (szwin): original, freestanding, no libc, no allocator.
 *
 * This leaf module owns only frontend-side state for presenting an actual W64 process's window scene:
 *   - a fixed window object table with generation-bound opaque handles (a destroyed or retired handle never
 *     resolves again; generations retire instead of wrapping),
 *   - a linear framebuffer descriptor (B,G,R,X 32-bit, top-down, explicit pitch) that can describe a Win98
 *     CreateDIBSection body, the Kernel64 gfx_fb back buffer (0x00RRGGBB dwords) or a mapped GOP mode,
 *   - immutable-frame assembly (bounded chunks, CRC32 over the whole image) into a private staging buffer; only a
 *     complete, CRC-verified frame is committed to the presented buffer, so a partial frame is never visible,
 *   - clipped blits/presents of a window's committed buffer into a framebuffer,
 *   - a bounded per-window input queue (pointer moves coalesced; key/button overflow is an observable error),
 *   - close-request / process-exit / destroy lifecycle.
 *
 * It assigns no opcode and defines no shared wire ABI: the transport is a caller-supplied vtable
 * (szwin_transport) so the draft NATIVE-GUI-WIRE proposal can be bound once its owner publishes the ABI.
 * Callers serialize all calls on one table; nothing here sleeps or blocks. */
#ifndef SZWIN_H
#define SZWIN_H
#include <stddef.h>
#include <stdint.h>

#define SZWIN_OK            0
#define SZWIN_E_INVALID   (-1)   /* malformed argument */
#define SZWIN_E_HANDLE    (-2)   /* unknown, stale or retired handle */
#define SZWIN_E_EXHAUSTED (-3)   /* no free slot / sequence or generation space exhausted */
#define SZWIN_E_BOUNDS    (-4)   /* size/offset/length outside the advertised limits */
#define SZWIN_E_FULL      (-5)   /* input queue full (event NOT queued) */
#define SZWIN_E_STATE     (-6)   /* operation not valid in the current lifecycle state */
#define SZWIN_E_CRC       (-7)   /* assembled frame failed its CRC; frame discarded, prior frame kept */
#define SZWIN_E_UNSUPPORTED (-8) /* transport/backend does not provide the capability */
#define SZWIN_E_TRANSPORT (-9)   /* transport failure; frontend state retained for retry/cleanup */
#define SZWIN_E_EMPTY     (-10)  /* nothing queued */

#define SZWIN_FMT_BGRX32 1u      /* bytes B,G,R,X; as little-endian dword 0x00RRGGBB; X ignored on read */

#define SZWIN_MAX_WINDOWS 8u
#define SZWIN_QUEUE_CAP   32u
#define SZWIN_CHUNK_MAX   128u   /* proposal FRAME_READ data[128] */
#define SZWIN_MAX_WIDTH   1024u
#define SZWIN_MAX_HEIGHT  768u
#define SZWIN_MAX_FRAME_BYTES (SZWIN_MAX_WIDTH * SZWIN_MAX_HEIGHT * 4u)

typedef uint64_t szwin_handle;   /* opaque; 0 is never valid */

typedef struct szwin_fb {
    uint8_t *base;
    size_t bytes;                /* mapped bytes; pitch*height <= bytes */
    uint32_t width, height, pitch, format;
} szwin_fb;

typedef struct szwin_rect { int32_t x, y, w, h; } szwin_rect;

enum szwin_event_kind {
    SZWIN_EV_MOVE = 1, SZWIN_EV_LDOWN, SZWIN_EV_LUP, SZWIN_EV_RDOWN, SZWIN_EV_RUP,
    SZWIN_EV_KEYDOWN, SZWIN_EV_KEYUP, SZWIN_EV_CLOSE
};
#define SZWIN_EVF_SHIFT 1u
#define SZWIN_EVF_CTRL  2u
#define SZWIN_EVF_ALT   4u
#define SZWIN_EVF_KNOWN (SZWIN_EVF_SHIFT | SZWIN_EVF_CTRL | SZWIN_EVF_ALT)

typedef struct szwin_event {
    uint32_t kind, flags;
    int32_t x, y;                /* client coordinates */
    uint32_t key, scancode, clock_ms;
    uint32_t sequence;           /* assigned on enqueue, monotonic per window, never 0 */
} szwin_event;

enum szwin_state { SZWIN_FREE = 0, SZWIN_OPEN, SZWIN_CLOSING, SZWIN_EXITED, SZWIN_RETIRED };

typedef struct szwin_window {
    uint32_t generation, state;
    int32_t x, y;                /* placement in the target framebuffer */
    uint32_t width, height;      /* client size == committed frame size */
    uint32_t *front;             /* committed, presentable pixels (caller storage, width*height dwords) */
    uint32_t *staging;           /* in-progress frame (caller storage, same size) */
    int has_frame, dirty;
    /* frame assembly */
    int assembling;
    uint64_t snapshot_id, last_committed_id;
    uint32_t frame_bytes, frame_received, frame_crc;
    /* input */
    szwin_event queue[SZWIN_QUEUE_CAP];
    uint32_t q_head, q_count, next_sequence;
    uint32_t exit_code;
} szwin_window;

typedef struct szwin_table {
    szwin_window slots[SZWIN_MAX_WINDOWS];
} szwin_table;

typedef struct szwin_frame_info {
    uint64_t snapshot_id;        /* nonzero, unique per acquire */
    uint32_t width, height, stride, byte_length, pixel_format, pixels_crc32;
} szwin_frame_info;

/* ---- framebuffer descriptor ---- */
/* Binds an existing linear mapping. Fails unless format is BGRX32, pitch >= width*4, pitch 4-aligned and
 * pitch*height (checked) fits in `bytes`. Works for a DIB body, gfx_fb.back (pitch=width*4) or a GOP mode. */
int szwin_fb_bind(szwin_fb *fb, void *base, size_t bytes, uint32_t width, uint32_t height, uint32_t pitch,
                  uint32_t format);
/* Copy a (sw x sh) source of `src_pitch` bytes to (dx,dy) in fb, clipped to fb bounds and to `clip` (fb
 * coordinates, NULL = whole fb). Returns number of pixels written (0 when fully clipped) or a negative error. */
int32_t szwin_blit(szwin_fb *fb, int32_t dx, int32_t dy, const uint32_t *src, uint32_t src_pitch, uint32_t sw,
                   uint32_t sh, const szwin_rect *clip);
uint32_t szwin_crc32(uint32_t crc, const void *data, size_t n);  /* IEEE 802.3, start with 0 */

/* ---- window table ---- */
void szwin_table_init(szwin_table *t);
/* front/staging each hold width*height dwords and stay owned by the caller until destroy succeeds. */
int szwin_create(szwin_table *t, uint32_t width, uint32_t height, int32_t x, int32_t y, uint32_t *front,
                 uint32_t *staging, size_t each_bytes, szwin_handle *out);
szwin_window *szwin_lookup(szwin_table *t, szwin_handle h);  /* NULL for stale/unknown/retired */
int szwin_destroy(szwin_table *t, szwin_handle h);           /* requires szwin_note_exit first (E_STATE otherwise) */
int szwin_move(szwin_table *t, szwin_handle h, int32_t x, int32_t y);

/* ---- frame assembly ---- */
int szwin_frame_begin(szwin_table *t, szwin_handle h, const szwin_frame_info *info);
int szwin_frame_chunk(szwin_table *t, szwin_handle h, uint64_t snapshot_id, uint32_t offset, const void *data,
                      uint32_t length);
int szwin_frame_commit(szwin_table *t, szwin_handle h, uint64_t snapshot_id);
void szwin_frame_abort(szwin_table *t, szwin_handle h);
/* Clipped present of the committed frame. Returns pixels written or negative error; no frame -> E_STATE. */
int32_t szwin_present(szwin_table *t, szwin_handle h, szwin_fb *fb, const szwin_rect *clip);

/* ---- input ---- */
/* Copies *ev, assigns the sequence. A MOVE directly following a queued, unsent MOVE replaces it. */
int szwin_input_push(szwin_table *t, szwin_handle h, const szwin_event *ev, uint32_t *sequence);
int szwin_input_peek(szwin_table *t, szwin_handle h, szwin_event *out);
int szwin_input_pop(szwin_table *t, szwin_handle h, uint32_t sequence);  /* only after the transport confirmed */

/* ---- lifecycle ---- */
int szwin_close_request(szwin_table *t, szwin_handle h);    /* queues CLOSE; window -> CLOSING; idempotent */
int szwin_note_exit(szwin_table *t, szwin_handle h, uint32_t exit_code);  /* drops queued input/frame */

/* ---- transport-driven session (szwin_session.c) ---- */
typedef struct szwin_transport {
    /* All return SZWIN_OK or a negative SZWIN_E_*; an unimplemented backend returns SZWIN_E_UNSUPPORTED. */
    int (*acquire)(void *ctx, szwin_frame_info *out);
    int (*read)(void *ctx, uint64_t snapshot_id, uint32_t offset, uint32_t length, uint8_t *out);
    int (*release)(void *ctx, uint64_t snapshot_id);
    int (*input)(void *ctx, const szwin_event *ev);
    /* 1 = exited (*code set), 0 = still running */
    int (*poll_exit)(void *ctx, uint32_t *code);
} szwin_transport;

/* One serialized step: forward at most `max_inputs` queued events (each popped only after the transport accepts),
 * check for exit, then acquire + fully read + CRC-verify + commit + release one frame. A failed or partial frame is
 * discarded and the previously committed frame stays presentable. *changed set when a new frame was committed. */
int szwin_session_step(szwin_table *t, szwin_handle h, const szwin_transport *tp, void *ctx, uint32_t max_inputs,
                       int *changed);
#endif
