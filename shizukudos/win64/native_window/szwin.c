/* SPDX-License-Identifier: GPL-2.0-only
 * ShizukuOS native Win64 GUI frontend core: window table, framebuffer blits, frame assembly, input, lifecycle.
 * Original code. Freestanding: no libc calls, no allocation, no struct copies that could emit memcpy. */
#include "szwin.h"

#define HANDLE_TAG 0x5Au

static szwin_handle make_handle(uint32_t index, uint32_t generation)
{
    return ((uint64_t)generation << 32) | ((uint64_t)HANDLE_TAG << 8) | (uint64_t)(index + 1u);
}

uint32_t szwin_crc32(uint32_t crc, const void *data, size_t n)
{
    const uint8_t *p = (const uint8_t *)data;
    crc = ~crc;
    while (n--) {
        uint32_t k;
        crc ^= *p++;
        for (k = 0; k < 8; ++k) crc = (crc >> 1) ^ (0xEDB88320u & (0u - (crc & 1u)));
    }
    return ~crc;
}

int szwin_fb_bind(szwin_fb *fb, void *base, size_t bytes, uint32_t width, uint32_t height, uint32_t pitch,
                  uint32_t format)
{
    uint64_t need;
    if (!fb) return SZWIN_E_INVALID;
    fb->base = 0; fb->bytes = 0; fb->width = fb->height = fb->pitch = fb->format = 0;
    if (!base || format != SZWIN_FMT_BGRX32 || !width || !height || (pitch & 3u)) return SZWIN_E_INVALID;
    if ((uint64_t)pitch < (uint64_t)width * 4u) return SZWIN_E_BOUNDS;
    need = (uint64_t)pitch * height;
    if (need > (uint64_t)bytes || need > (uint64_t)(size_t)-1) return SZWIN_E_BOUNDS;
    if (((uintptr_t)base & 3u) != 0) return SZWIN_E_INVALID;
    fb->base = (uint8_t *)base; fb->bytes = bytes;
    fb->width = width; fb->height = height; fb->pitch = pitch; fb->format = format;
    return SZWIN_OK;
}

static int64_t min64(int64_t a, int64_t b) { return a < b ? a : b; }
static int64_t max64(int64_t a, int64_t b) { return a > b ? a : b; }

int32_t szwin_blit(szwin_fb *fb, int32_t dx, int32_t dy, const uint32_t *src, uint32_t src_pitch, uint32_t sw,
                   uint32_t sh, const szwin_rect *clip)
{
    int64_t x0, y0, x1, y1, row, col;
    int64_t written;
    if (!fb || !fb->base || fb->format != SZWIN_FMT_BGRX32 || !src) return SZWIN_E_INVALID;
    if ((src_pitch & 3u) || (uint64_t)src_pitch < (uint64_t)sw * 4u) return SZWIN_E_INVALID;
    if (!sw || !sh) return 0;
    /* destination rectangle intersected with the framebuffer */
    x0 = max64(dx, 0); y0 = max64(dy, 0);
    x1 = min64((int64_t)dx + sw, fb->width); y1 = min64((int64_t)dy + sh, fb->height);
    if (clip) {
        if (clip->w < 0 || clip->h < 0) return SZWIN_E_INVALID;
        x0 = max64(x0, clip->x); y0 = max64(y0, clip->y);
        x1 = min64(x1, (int64_t)clip->x + clip->w); y1 = min64(y1, (int64_t)clip->y + clip->h);
    }
    if (x0 >= x1 || y0 >= y1) return 0;
    written = (x1 - x0) * (y1 - y0);
    if (written > 0x7fffffff) return SZWIN_E_BOUNDS;
    for (row = y0; row < y1; ++row) {
        uint32_t *d = (uint32_t *)(fb->base + (size_t)row * fb->pitch) + x0;
        const uint32_t *s = (const uint32_t *)((const uint8_t *)src + (size_t)(row - dy) * src_pitch) + (x0 - dx);
        for (col = 0; col < x1 - x0; ++col) d[col] = s[col] & 0x00FFFFFFu;
    }
    return (int32_t)written;
}

void szwin_table_init(szwin_table *t)
{
    uint8_t *p = (uint8_t *)t;
    size_t i;
    if (!t) return;
    for (i = 0; i < sizeof *t; ++i) p[i] = 0;
}

szwin_window *szwin_lookup(szwin_table *t, szwin_handle h)
{
    uint32_t index, generation;
    szwin_window *w;
    if (!t || !h || ((h >> 8) & 0xFFu) != HANDLE_TAG || ((h >> 16) & 0xFFFFu) != 0) return 0;
    index = (uint32_t)(h & 0xFFu);
    generation = (uint32_t)(h >> 32);
    if (!index || index > SZWIN_MAX_WINDOWS || !generation) return 0;
    w = &t->slots[index - 1u];
    if (w->generation != generation) return 0;
    if (w->state == SZWIN_FREE || w->state == SZWIN_RETIRED) return 0;
    return w;
}

static void reset_window_body(szwin_window *w)
{
    uint8_t *p = (uint8_t *)w;
    uint32_t generation = w->generation, state = w->state;
    size_t i;
    for (i = 0; i < sizeof *w; ++i) p[i] = 0;
    w->generation = generation; w->state = state;
}

int szwin_create(szwin_table *t, uint32_t width, uint32_t height, int32_t x, int32_t y, uint32_t *front,
                 uint32_t *staging, size_t each_bytes, szwin_handle *out)
{
    uint32_t i;
    uint64_t need;
    if (out) *out = 0;
    if (!t || !out || !front || !staging || front == staging) return SZWIN_E_INVALID;
    if (!width || !height || width > SZWIN_MAX_WIDTH || height > SZWIN_MAX_HEIGHT) return SZWIN_E_BOUNDS;
    need = (uint64_t)width * height * 4u;
    if (need > each_bytes) return SZWIN_E_BOUNDS;
    if (((uintptr_t)front & 3u) || ((uintptr_t)staging & 3u)) return SZWIN_E_INVALID;
    /* the two buffers must not overlap */
    if ((uintptr_t)front < (uintptr_t)staging + need && (uintptr_t)staging < (uintptr_t)front + need)
        return SZWIN_E_INVALID;
    for (i = 0; i < SZWIN_MAX_WINDOWS; ++i) {
        szwin_window *w = &t->slots[i];
        if (w->state != SZWIN_FREE) continue;
        if (w->generation == 0xFFFFFFFFu) { w->state = SZWIN_RETIRED; continue; }
        w->generation += 1u;
        w->state = SZWIN_OPEN;
        reset_window_body(w);
        w->x = x; w->y = y; w->width = width; w->height = height;
        w->front = front; w->staging = staging;
        w->next_sequence = 1u;
        *out = make_handle(i, w->generation);
        return SZWIN_OK;
    }
    return SZWIN_E_EXHAUSTED;
}

int szwin_destroy(szwin_table *t, szwin_handle h)
{
    szwin_window *w = szwin_lookup(t, h);
    if (!w) return SZWIN_E_HANDLE;
    if (w->state != SZWIN_EXITED) return SZWIN_E_STATE;
    reset_window_body(w);
    /* generation stays; the next create bumps it, and an exhausted generation retires the slot */
    w->state = w->generation == 0xFFFFFFFFu ? SZWIN_RETIRED : SZWIN_FREE;
    return SZWIN_OK;
}

int szwin_move(szwin_table *t, szwin_handle h, int32_t x, int32_t y)
{
    szwin_window *w = szwin_lookup(t, h);
    if (!w) return SZWIN_E_HANDLE;
    w->x = x; w->y = y; w->dirty = w->has_frame;
    return SZWIN_OK;
}

/* ---- frame assembly ---- */
void szwin_frame_abort(szwin_table *t, szwin_handle h)
{
    szwin_window *w = szwin_lookup(t, h);
    if (!w) return;
    w->assembling = 0; w->snapshot_id = 0; w->frame_bytes = w->frame_received = w->frame_crc = 0;
}

int szwin_frame_begin(szwin_table *t, szwin_handle h, const szwin_frame_info *info)
{
    szwin_window *w = szwin_lookup(t, h);
    uint64_t stride, total;
    if (!w) return SZWIN_E_HANDLE;
    if (w->state != SZWIN_OPEN && w->state != SZWIN_CLOSING) return SZWIN_E_STATE;
    if (!info || !info->snapshot_id || info->pixel_format != SZWIN_FMT_BGRX32) return SZWIN_E_INVALID;
    if (info->snapshot_id == w->last_committed_id) return SZWIN_E_INVALID;  /* ids are unique per capture */
    stride = (uint64_t)info->width * 4u;
    total = stride * info->height;
    if (info->stride != stride || info->byte_length != total || !total) return SZWIN_E_INVALID;
    /* the client area is fixed at create; a resized scene needs a new window record */
    if (info->width != w->width || info->height != w->height) return SZWIN_E_BOUNDS;
    if (total > SZWIN_MAX_FRAME_BYTES) return SZWIN_E_BOUNDS;
    w->assembling = 1;
    w->snapshot_id = info->snapshot_id;
    w->frame_bytes = (uint32_t)total;
    w->frame_received = 0;
    w->frame_crc = info->pixels_crc32;
    return SZWIN_OK;
}

int szwin_frame_chunk(szwin_table *t, szwin_handle h, uint64_t snapshot_id, uint32_t offset, const void *data,
                      uint32_t length)
{
    szwin_window *w = szwin_lookup(t, h);
    const uint8_t *s = (const uint8_t *)data;
    uint8_t *d;
    uint32_t i;
    if (!w) return SZWIN_E_HANDLE;
    if (!w->assembling || snapshot_id != w->snapshot_id) return SZWIN_E_STATE;
    if (!data || !length || length > SZWIN_CHUNK_MAX || (offset & 3u) || (length & 3u)) return SZWIN_E_INVALID;
    if (offset > w->frame_bytes || length > w->frame_bytes - offset) return SZWIN_E_BOUNDS;
    /* strictly sequential; gaps or reordering abort nothing but are refused */
    if (offset != w->frame_received) return SZWIN_E_BOUNDS;
    d = (uint8_t *)w->staging + offset;
    for (i = 0; i < length; ++i) d[i] = s[i];
    w->frame_received += length;
    return SZWIN_OK;
}

int szwin_frame_commit(szwin_table *t, szwin_handle h, uint64_t snapshot_id)
{
    szwin_window *w = szwin_lookup(t, h);
    uint32_t i, n;
    if (!w) return SZWIN_E_HANDLE;
    if (!w->assembling || snapshot_id != w->snapshot_id) return SZWIN_E_STATE;
    if (w->frame_received != w->frame_bytes) { szwin_frame_abort(t, h); return SZWIN_E_BOUNDS; }
    if (szwin_crc32(0, w->staging, w->frame_bytes) != w->frame_crc) { szwin_frame_abort(t, h); return SZWIN_E_CRC; }
    n = w->frame_bytes / 4u;
    for (i = 0; i < n; ++i) w->front[i] = w->staging[i];
    w->last_committed_id = snapshot_id;
    w->has_frame = 1; w->dirty = 1;
    szwin_frame_abort(t, h);
    return SZWIN_OK;
}

int32_t szwin_present(szwin_table *t, szwin_handle h, szwin_fb *fb, const szwin_rect *clip)
{
    szwin_window *w = szwin_lookup(t, h);
    int32_t r;
    if (!w) return SZWIN_E_HANDLE;
    if (!w->has_frame) return SZWIN_E_STATE;
    r = szwin_blit(fb, w->x, w->y, w->front, w->width * 4u, w->width, w->height, clip);
    if (r >= 0) w->dirty = 0;
    return r;
}

/* ---- input ---- */
int szwin_input_push(szwin_table *t, szwin_handle h, const szwin_event *ev, uint32_t *sequence)
{
    szwin_window *w = szwin_lookup(t, h);
    szwin_event *slot;
    if (sequence) *sequence = 0;
    if (!w) return SZWIN_E_HANDLE;
    if (!ev || ev->kind < SZWIN_EV_MOVE || ev->kind > SZWIN_EV_CLOSE || (ev->flags & ~SZWIN_EVF_KNOWN))
        return SZWIN_E_INVALID;
    if ((ev->kind == SZWIN_EV_KEYDOWN || ev->kind == SZWIN_EV_KEYUP) ? (!ev->key || ev->key > 0xFFu || ev->scancode > 0x1FFu)
                                                                     : (ev->key || ev->scancode))
        return SZWIN_E_INVALID;
    if (w->state == SZWIN_EXITED) return SZWIN_E_STATE;
    if (w->state == SZWIN_CLOSING && ev->kind != SZWIN_EV_CLOSE) return SZWIN_E_STATE;
    if (ev->kind == SZWIN_EV_MOVE && w->q_count > 1u) {
        /* coalesce with the newest queued move; the head may be in flight so it is never rewritten */
        szwin_event *last = &w->queue[(w->q_head + w->q_count - 1u) % SZWIN_QUEUE_CAP];
        if (last->kind == SZWIN_EV_MOVE) {
            last->x = ev->x; last->y = ev->y; last->flags = ev->flags; last->clock_ms = ev->clock_ms;
            if (sequence) *sequence = last->sequence;
            return SZWIN_OK;
        }
    }
    if (w->q_count >= SZWIN_QUEUE_CAP) return SZWIN_E_FULL;
    if (w->next_sequence == 0) return SZWIN_E_EXHAUSTED;
    slot = &w->queue[(w->q_head + w->q_count) % SZWIN_QUEUE_CAP];
    slot->kind = ev->kind; slot->flags = ev->flags; slot->x = ev->x; slot->y = ev->y;
    slot->key = ev->key; slot->scancode = ev->scancode; slot->clock_ms = ev->clock_ms;
    slot->sequence = w->next_sequence;
    w->next_sequence = w->next_sequence == 0xFFFFFFFFu ? 0u : w->next_sequence + 1u;
    w->q_count += 1u;
    if (sequence) *sequence = slot->sequence;
    return SZWIN_OK;
}

int szwin_input_peek(szwin_table *t, szwin_handle h, szwin_event *out)
{
    szwin_window *w = szwin_lookup(t, h);
    const szwin_event *s;
    if (!w) return SZWIN_E_HANDLE;
    if (!out) return SZWIN_E_INVALID;
    if (!w->q_count) return SZWIN_E_EMPTY;
    s = &w->queue[w->q_head];
    out->kind = s->kind; out->flags = s->flags; out->x = s->x; out->y = s->y;
    out->key = s->key; out->scancode = s->scancode; out->clock_ms = s->clock_ms; out->sequence = s->sequence;
    return SZWIN_OK;
}

int szwin_input_pop(szwin_table *t, szwin_handle h, uint32_t sequence)
{
    szwin_window *w = szwin_lookup(t, h);
    if (!w) return SZWIN_E_HANDLE;
    if (!w->q_count) return SZWIN_E_EMPTY;
    if (w->queue[w->q_head].sequence != sequence) return SZWIN_E_STATE;
    w->q_head = (w->q_head + 1u) % SZWIN_QUEUE_CAP;
    w->q_count -= 1u;
    return SZWIN_OK;
}

/* ---- lifecycle ---- */
int szwin_close_request(szwin_table *t, szwin_handle h)
{
    szwin_window *w = szwin_lookup(t, h);
    szwin_event ev;
    uint32_t i;
    int r;
    if (!w) return SZWIN_E_HANDLE;
    if (w->state == SZWIN_EXITED) return SZWIN_E_STATE;
    for (i = 0; i < w->q_count; ++i)
        if (w->queue[(w->q_head + i) % SZWIN_QUEUE_CAP].kind == SZWIN_EV_CLOSE) return SZWIN_OK;
    ev.kind = SZWIN_EV_CLOSE; ev.flags = 0; ev.x = ev.y = 0; ev.key = ev.scancode = ev.clock_ms = 0; ev.sequence = 0;
    r = szwin_input_push(t, h, &ev, 0);
    if (r == SZWIN_OK) w->state = SZWIN_CLOSING;
    return r;
}

int szwin_note_exit(szwin_table *t, szwin_handle h, uint32_t exit_code)
{
    szwin_window *w = szwin_lookup(t, h);
    if (!w) return SZWIN_E_HANDLE;
    w->state = SZWIN_EXITED;
    w->exit_code = exit_code;
    w->q_head = w->q_count = 0;
    w->assembling = 0; w->snapshot_id = 0;
    return SZWIN_OK;
}
