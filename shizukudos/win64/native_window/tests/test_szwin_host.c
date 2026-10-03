/* SPDX-License-Identifier: GPL-2.0-only
 * Host unit test for szwin (handle lifetime, blit clipping, pixel output, frame assembly, input, session step).
 * HOST-ONLY evidence: the transport below is a test model of a frame server, not the ShizukuCore GUI service. */
#include <stdio.h>
#include <string.h>
#include "../szwin.h"

static int failures, checks;
#define CHECK(c) do { ++checks; if (!(c)) { ++failures; printf("FAIL %s:%d %s\n", __FILE__, __LINE__, #c); } } while (0)

static uint32_t fa[64 * 32], fb_[64 * 32], fc[64 * 32], fd[64 * 32];

static void test_handles(void)
{
    szwin_table t;
    szwin_handle h, h2, hs[SZWIN_MAX_WINDOWS], extra;
    static uint32_t bufs[SZWIN_MAX_WINDOWS][2][4];
    uint32_t i;
    szwin_table_init(&t);
    CHECK(szwin_create(&t, 4, 4, 0, 0, fa, fa, sizeof fa, &h) == SZWIN_E_INVALID);       /* aliasing */
    CHECK(szwin_create(&t, 4, 4, 0, 0, fa, fa + 8, sizeof fa, &h) == SZWIN_E_INVALID);   /* overlap */
    CHECK(szwin_create(&t, 2000, 4, 0, 0, fa, fb_, sizeof fa, &h) == SZWIN_E_BOUNDS);
    CHECK(szwin_create(&t, 64, 32, 0, 0, fa, fb_, 64, &h) == SZWIN_E_BOUNDS);            /* too small */
    CHECK(szwin_create(&t, 4, 4, 0, 0, fa, fb_, sizeof fa, &h) == SZWIN_OK && h);
    CHECK(szwin_lookup(&t, h) != NULL);
    CHECK(szwin_lookup(&t, h ^ (1ull << 32)) == NULL);                                  /* wrong generation */
    CHECK(szwin_lookup(&t, (h & ~0xFFull) | 9u) == NULL);                               /* bad index */
    CHECK(szwin_lookup(&t, h | (1ull << 20)) == NULL);                                  /* reserved bits */
    CHECK(szwin_lookup(&t, 0) == NULL);
    CHECK(szwin_destroy(&t, h) == SZWIN_E_STATE);                                       /* still open */
    CHECK(szwin_note_exit(&t, h, 7) == SZWIN_OK);
    CHECK(szwin_destroy(&t, h) == SZWIN_OK);
    CHECK(szwin_lookup(&t, h) == NULL);                                                 /* stale after destroy */
    CHECK(szwin_destroy(&t, h) == SZWIN_E_HANDLE);
    CHECK(szwin_create(&t, 4, 4, 0, 0, fa, fb_, sizeof fa, &h2) == SZWIN_OK);
    CHECK(h2 != h && (h2 & 0xFF) == (h & 0xFF));                                        /* same slot, new gen */
    CHECK(szwin_lookup(&t, h) == NULL && szwin_lookup(&t, h2) != NULL);
    szwin_note_exit(&t, h2, 0); szwin_destroy(&t, h2);
    for (i = 0; i < SZWIN_MAX_WINDOWS; ++i)
        CHECK(szwin_create(&t, 2, 2, 0, 0, bufs[i][0], bufs[i][1], 16, &hs[i]) == SZWIN_OK);
    CHECK(szwin_create(&t, 2, 2, 0, 0, fc, fd, sizeof fc, &extra) == SZWIN_E_EXHAUSTED && extra == 0);
    /* generation exhaustion retires the slot instead of wrapping */
    t.slots[0].generation = 0xFFFFFFFFu;
    CHECK(szwin_lookup(&t, hs[0]) == NULL);
    hs[0] = ((uint64_t)0xFFFFFFFFu << 32) | (0x5Au << 8) | 1u;
    CHECK(szwin_lookup(&t, hs[0]) != NULL);
    szwin_note_exit(&t, hs[0], 0);
    CHECK(szwin_destroy(&t, hs[0]) == SZWIN_OK);
    CHECK(t.slots[0].state == SZWIN_RETIRED && szwin_lookup(&t, hs[0]) == NULL);
    CHECK(szwin_create(&t, 2, 2, 0, 0, fc, fd, sizeof fc, &extra) == SZWIN_E_EXHAUSTED);
}

static void test_blit(void)
{
    static uint8_t mem[8 * 80 + 16];
    szwin_fb fb;
    uint32_t src[6 * 4];
    szwin_rect clip = { 1, 1, 2, 1 };
    int x, y, i;
    memset(mem, 0xEE, sizeof mem);
    CHECK(szwin_fb_bind(&fb, mem, sizeof mem, 16, 8, 60, SZWIN_FMT_BGRX32) == SZWIN_E_BOUNDS);  /* pitch < w*4 */
    CHECK(szwin_fb_bind(&fb, mem, 8 * 80 - 1, 16, 8, 80, SZWIN_FMT_BGRX32) == SZWIN_E_BOUNDS);
    CHECK(szwin_fb_bind(&fb, mem, sizeof mem, 16, 8, 80, 2) == SZWIN_E_INVALID);
    CHECK(szwin_fb_bind(&fb, mem, sizeof mem, 16, 8, 80, SZWIN_FMT_BGRX32) == SZWIN_OK);
    for (i = 0; i < 24; ++i) src[i] = 0xAA000000u | (uint32_t)(i + 1);
    /* partly off the top-left corner: visible 4 x 3 */
    CHECK(szwin_blit(&fb, -2, -1, src, 24, 6, 4, NULL) == 12);
    for (y = 0; y < 8; ++y)
        for (x = 0; x < 20; ++x) {
            uint32_t v; memcpy(&v, mem + y * 80 + x * 4, 4);
            if (x < 4 && y < 3) CHECK(v == (uint32_t)((y + 1) * 6 + (x + 2) + 1));  /* X byte cleared */
            else CHECK(v == 0xEEEEEEEEu);                                            /* incl. pitch padding */
        }
    /* bottom-right corner clipping */
    CHECK(szwin_blit(&fb, 14, 6, src, 24, 6, 4, NULL) == 4);
    { uint32_t v; memcpy(&v, mem + 7 * 80 + 15 * 4, 4); CHECK(v == (uint32_t)(1 * 6 + 1 + 1)); }
    { uint32_t v; memcpy(&v, mem + 7 * 80 + 16 * 4, 4); CHECK(v == 0xEEEEEEEEu); }  /* padding untouched */
    /* explicit clip rectangle */
    CHECK(szwin_blit(&fb, 0, 0, src, 24, 6, 4, &clip) == 2);
    CHECK(szwin_blit(&fb, 100, 0, src, 24, 6, 4, NULL) == 0);
    CHECK(szwin_blit(&fb, -0x7fffffff, -0x7fffffff, src, 24, 6, 4, NULL) == 0);
    CHECK(szwin_blit(&fb, 0, 0, src, 20, 6, 4, NULL) == SZWIN_E_INVALID);          /* src pitch too small */
}

/* ---- test frame server model ---- */
typedef struct server {
    uint32_t scene[8 * 8];
    uint64_t next_id, held;
    int fail_read_at, corrupt, exited, released, inputs;
    uint32_t exit_code, last_kinds[16];
} server;

static int s_acquire(void *c, szwin_frame_info *o)
{
    server *s = c;
    if (s->held) return SZWIN_E_STATE;
    o->snapshot_id = s->held = ++s->next_id;
    o->width = 8; o->height = 8; o->stride = 32; o->byte_length = 8 * 8 * 4;
    o->pixel_format = SZWIN_FMT_BGRX32;
    o->pixels_crc32 = szwin_crc32(0, s->scene, sizeof s->scene);
    return SZWIN_OK;
}
static int s_read(void *c, uint64_t id, uint32_t off, uint32_t len, uint8_t *out)
{
    server *s = c;
    if (id != s->held || off + len > sizeof s->scene) return SZWIN_E_STATE;
    if (s->fail_read_at && off >= (uint32_t)s->fail_read_at) return SZWIN_E_TRANSPORT;
    memcpy(out, (uint8_t *)s->scene + off, len);
    if (s->corrupt) out[0] ^= 1;
    return SZWIN_OK;
}
static int s_release(void *c, uint64_t id) { server *s = c; if (id != s->held) return SZWIN_E_STATE; s->held = 0; ++s->released; return SZWIN_OK; }
static int s_input(void *c, const szwin_event *e) { server *s = c; if (s->inputs < 16) s->last_kinds[s->inputs] = e->kind; ++s->inputs; return SZWIN_OK; }
static int s_poll(void *c, uint32_t *code) { server *s = c; if (s->exited) { *code = s->exit_code; return 1; } return 0; }
static const szwin_transport tp = { s_acquire, s_read, s_release, s_input, s_poll };

static void test_session(void)
{
    szwin_table t;
    szwin_handle h;
    server s;
    szwin_fb fb;
    static uint32_t screen[16 * 8];
    static uint32_t front[64], staging[64];
    szwin_event ev;
    uint32_t seq, i;
    int changed;
    memset(&s, 0, sizeof s);
    memset(screen, 0, sizeof screen);
    for (i = 0; i < 64; ++i) s.scene[i] = 0x00102030u + i;
    szwin_table_init(&t);
    CHECK(szwin_create(&t, 8, 8, 3, 2, front, staging, sizeof front, &h) == SZWIN_OK);
    CHECK(szwin_fb_bind(&fb, screen, sizeof screen, 16, 8, 64, SZWIN_FMT_BGRX32) == SZWIN_OK);
    CHECK(szwin_present(&t, h, &fb, NULL) == SZWIN_E_STATE);                         /* nothing committed yet */
    CHECK(szwin_session_step(&t, h, &tp, &s, 8, &changed) == SZWIN_OK && changed && s.released == 1);
    CHECK(szwin_present(&t, h, &fb, NULL) == 48);                                  /* 8x6 visible */
    CHECK(screen[2 * 16 + 3] == 0x00102030u && screen[5 * 16 + 10] == 0x00102030u + 31 && screen[0] == 0);
    /* corrupted transfer: CRC failure, snapshot released, prior frame kept */
    s.scene[0] = 0x00FFFFFFu; s.corrupt = 1;
    CHECK(szwin_session_step(&t, h, &tp, &s, 8, &changed) == SZWIN_E_CRC && !changed && s.released == 2);
    CHECK(szwin_present(&t, h, &fb, NULL) == 48 && screen[2 * 16 + 3] == 0x00102030u);
    /* transport failure mid-frame: partial frame never committed */
    s.corrupt = 0; s.fail_read_at = 128;                                            /* second chunk */
    CHECK(szwin_session_step(&t, h, &tp, &s, 8, &changed) == SZWIN_E_TRANSPORT && !changed && s.released == 3);
    CHECK(front[0] == 0x00102030u);
    s.fail_read_at = 0;
    CHECK(szwin_session_step(&t, h, &tp, &s, 8, &changed) == SZWIN_OK && changed && front[0] == 0x00FFFFFFu);
    /* frame protocol violations */
    {
        szwin_frame_info bad = { 99, 8, 8, 31, 256, SZWIN_FMT_BGRX32, 0 };
        uint8_t chunk[8] = { 0 };
        CHECK(szwin_frame_begin(&t, h, &bad) == SZWIN_E_INVALID);                   /* stride */
        bad.stride = 32; bad.width = 9; bad.byte_length = 9 * 8 * 4; bad.stride = 36;
        CHECK(szwin_frame_begin(&t, h, &bad) == SZWIN_E_BOUNDS);                    /* size change */
        bad.width = 8; bad.stride = 32; bad.byte_length = 256;
        CHECK(szwin_frame_begin(&t, h, &bad) == SZWIN_OK);
        CHECK(szwin_frame_chunk(&t, h, 98, 0, chunk, 8) == SZWIN_E_STATE);          /* wrong snapshot */
        CHECK(szwin_frame_chunk(&t, h, 99, 8, chunk, 8) == SZWIN_E_BOUNDS);         /* gap */
        CHECK(szwin_frame_chunk(&t, h, 99, 0, chunk, 6) == SZWIN_E_INVALID);        /* not pixel aligned */
        CHECK(szwin_frame_chunk(&t, h, 99, 0, chunk, 8) == SZWIN_OK);
        CHECK(szwin_frame_commit(&t, h, 99) == SZWIN_E_BOUNDS);                     /* incomplete */
        CHECK(szwin_frame_chunk(&t, h, 99, 8, chunk, 8) == SZWIN_E_STATE);          /* aborted */
    }
    /* input: coalescing, ordering, overflow, close lifecycle */
    memset(&ev, 0, sizeof ev);
    ev.kind = SZWIN_EV_LDOWN;
    CHECK(szwin_input_push(&t, h, &ev, &seq) == SZWIN_OK && seq == 1);
    ev.kind = SZWIN_EV_MOVE; ev.x = 1;
    CHECK(szwin_input_push(&t, h, &ev, &seq) == SZWIN_OK && seq == 2);
    ev.x = 5;
    CHECK(szwin_input_push(&t, h, &ev, &seq) == SZWIN_OK && seq == 2);              /* coalesced */
    ev.kind = SZWIN_EV_KEYDOWN; ev.x = 0;
    CHECK(szwin_input_push(&t, h, &ev, &seq) == SZWIN_E_INVALID);                   /* key 0 */
    ev.key = 0x41; ev.scancode = 0x1E;
    CHECK(szwin_input_push(&t, h, &ev, &seq) == SZWIN_OK && seq == 3);
    ev.flags = 0x80;
    CHECK(szwin_input_push(&t, h, &ev, &seq) == SZWIN_E_INVALID);                   /* unknown flag */
    CHECK(szwin_input_peek(&t, h, &ev) == SZWIN_OK && ev.sequence == 1);
    CHECK(szwin_input_pop(&t, h, 2) == SZWIN_E_STATE);                              /* not head */
    CHECK(szwin_session_step(&t, h, &tp, &s, 8, &changed) == SZWIN_OK);
    CHECK(s.inputs == 3 && s.last_kinds[0] == SZWIN_EV_LDOWN && s.last_kinds[1] == SZWIN_EV_MOVE &&
          s.last_kinds[2] == SZWIN_EV_KEYDOWN);
    memset(&ev, 0, sizeof ev); ev.kind = SZWIN_EV_LDOWN;
    for (i = 0; i < SZWIN_QUEUE_CAP; ++i) CHECK(szwin_input_push(&t, h, &ev, &seq) == SZWIN_OK);
    CHECK(szwin_input_push(&t, h, &ev, &seq) == SZWIN_E_FULL);                      /* observable overflow */
    CHECK(szwin_close_request(&t, h) == SZWIN_E_FULL);                              /* close not lost silently */
    while (szwin_input_peek(&t, h, &ev) == SZWIN_OK) szwin_input_pop(&t, h, ev.sequence);
    CHECK(szwin_close_request(&t, h) == SZWIN_OK && t.slots[h & 0xFF ? (h & 0xFF) - 1 : 0].state == SZWIN_CLOSING);
    CHECK(szwin_close_request(&t, h) == SZWIN_OK);                                  /* idempotent */
    ev.kind = SZWIN_EV_LDOWN;
    CHECK(szwin_input_push(&t, h, &ev, &seq) == SZWIN_E_STATE);
    s.inputs = 0;
    CHECK(szwin_session_step(&t, h, &tp, &s, 8, &changed) == SZWIN_OK && s.inputs == 1 &&
          s.last_kinds[0] == SZWIN_EV_CLOSE);
    s.exited = 1; s.exit_code = 7;
    CHECK(szwin_session_step(&t, h, &tp, &s, 8, &changed) == SZWIN_OK);
    CHECK(szwin_lookup(&t, h)->state == SZWIN_EXITED && szwin_lookup(&t, h)->exit_code == 7);
    CHECK(szwin_session_step(&t, h, &tp, &s, 8, &changed) == SZWIN_E_STATE);
    CHECK(szwin_destroy(&t, h) == SZWIN_OK && szwin_lookup(&t, h) == NULL);
    CHECK(szwin_present(&t, h, &fb, NULL) == SZWIN_E_HANDLE);
    CHECK(szwin_crc32(0, "123456789", 9) == 0xCBF43926u);
}

int main(void)
{
    test_handles();
    test_blit();
    test_session();
    printf("szwin host: %d checks, %d failures\n", checks, failures);
    return failures ? 1 : 0;
}
