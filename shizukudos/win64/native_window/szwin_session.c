/* SPDX-License-Identifier: GPL-2.0-only
 * ShizukuOS native Win64 GUI frontend: one serialized transport step (input forward, exit poll, frame pull).
 * Original code. The transport is supplied by the caller; this file assigns no opcode and owns no wire ABI. */
#include "szwin.h"

static int pull_frame(szwin_table *t, szwin_handle h, const szwin_transport *tp, void *ctx, int *changed)
{
    szwin_frame_info info;
    uint8_t chunk[SZWIN_CHUNK_MAX];
    uint32_t offset;
    int r, rr;
    r = tp->acquire(ctx, &info);
    if (r != SZWIN_OK) return r;
    r = szwin_frame_begin(t, h, &info);
    if (r == SZWIN_OK) {
        for (offset = 0; offset < info.byte_length; offset += SZWIN_CHUNK_MAX) {
            uint32_t length = info.byte_length - offset;
            if (length > SZWIN_CHUNK_MAX) length = SZWIN_CHUNK_MAX;
            r = tp->read(ctx, info.snapshot_id, offset, length, chunk);
            if (r != SZWIN_OK) break;
            r = szwin_frame_chunk(t, h, info.snapshot_id, offset, chunk, length);
            if (r != SZWIN_OK) break;
        }
        if (r == SZWIN_OK) r = szwin_frame_commit(t, h, info.snapshot_id);
        else szwin_frame_abort(t, h);
        if (r == SZWIN_OK && changed) *changed = 1;
    }
    /* the snapshot is released whether or not it was committed; a release failure is reported, never hidden */
    rr = tp->release(ctx, info.snapshot_id);
    return r != SZWIN_OK ? r : rr;
}

int szwin_session_step(szwin_table *t, szwin_handle h, const szwin_transport *tp, void *ctx, uint32_t max_inputs,
                       int *changed)
{
    szwin_window *w = szwin_lookup(t, h);
    szwin_event ev;
    uint32_t code = 0, sent = 0;
    int r;
    if (changed) *changed = 0;
    if (!w) return SZWIN_E_HANDLE;
    if (!tp || !tp->acquire || !tp->read || !tp->release || !tp->input || !tp->poll_exit) return SZWIN_E_INVALID;
    if (w->state == SZWIN_EXITED) return SZWIN_E_STATE;
    while (sent < max_inputs && szwin_input_peek(t, h, &ev) == SZWIN_OK) {
        r = tp->input(ctx, &ev);
        if (r != SZWIN_OK) return r;              /* event stays queued for a bounded retry by the caller */
        r = szwin_input_pop(t, h, ev.sequence);
        if (r != SZWIN_OK) return r;
        ++sent;
    }
    r = tp->poll_exit(ctx, &code);
    if (r < 0) return r;
    if (r == 1) return szwin_note_exit(t, h, code);
    return pull_frame(t, h, tp, ctx, changed);
}
