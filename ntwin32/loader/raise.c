/* SPDX-License-Identifier: GPL-2.0-only */
#include "raise.h"
#define NTW_ERR_INVALID 87u
#define NTW_ERR_INVALID_HANDLE 6u
static struct { ntw_veh_routine routine; uint32_t live; } veh_slots[NTW_VEH_LIMIT];
static uint32_t veh_order[NTW_VEH_LIMIT];
static uint32_t veh_count;
void ntw_veh_reset(void) {
    uint32_t i;
    for (i = 0; i < NTW_VEH_LIMIT; ++i) { veh_slots[i].routine = 0; veh_slots[i].live = 0; veh_order[i] = 0; }
    veh_count = 0;
}
int ntw_veh_add(uint32_t first, ntw_veh_routine routine, uint32_t *handle, uint32_t *error) {
    uint32_t i, slot;
    if (!routine || !handle) { if (error) *error = NTW_ERR_INVALID; return 0; }
    slot = NTW_VEH_LIMIT;
    for (i = 0; i < NTW_VEH_LIMIT; ++i) if (!veh_slots[i].live) { slot = i; break; }
    if (slot == NTW_VEH_LIMIT) { if (error) *error = 8; return 0; }
    veh_slots[slot].routine = routine;
    veh_slots[slot].live = 1;
    if (first) {
        for (i = veh_count; i > 0; --i) veh_order[i] = veh_order[i - 1];
        veh_order[0] = slot;
    } else veh_order[veh_count] = slot;
    veh_count++;
    *handle = slot + 1u;
    if (error) *error = 0;
    return 1;
}
int ntw_veh_remove(uint32_t handle, uint32_t *error) {
    uint32_t slot, i, found = 0;
    if (!handle || handle > NTW_VEH_LIMIT || !veh_slots[handle - 1].live) {
        if (error) *error = NTW_ERR_INVALID_HANDLE;
        return 0;
    }
    slot = handle - 1u;
    veh_slots[slot].live = 0;
    veh_slots[slot].routine = 0;
    for (i = 0; i < veh_count; ++i) if (veh_order[i] == slot) { found = i; break; }
    for (i = found; i + 1 < veh_count; ++i) veh_order[i] = veh_order[i + 1];
    if (veh_count) veh_count--;
    if (error) *error = 0;
    return 1;
}
static uint32_t read32(uint32_t address) {
    return *(uint32_t *)(uintptr_t)address;
}
static int resume_ok(ntw_ex_record *record, uint32_t *final_code) {
    if (record->flags & NTW_EX_NONCONTINUABLE) {
        record->code = NTW_STATUS_NONCONTINUABLE;
        record->flags = NTW_EX_NONCONTINUABLE;
        record->count = 0;
        if (final_code) *final_code = NTW_STATUS_NONCONTINUABLE;
        return NTW_RAISE_TERMINATE;
    }
    return NTW_RAISE_RESUME;
}
int ntw_raise_software(ntw_ex_record *record, ntw_context *context, uint32_t seh_head,
                       ntw_frame_ok frame_ok, void *frame_user, ntw_unhandled_routine unhandled,
                       void *unhandled_user, uint32_t *final_code) {
    ntw_ex_pointers pointers;
    uint32_t i, frame;
    if (!record || !context || record->count > NTW_EX_MAXIMUM_PARAMETERS) return NTW_RAISE_TERMINATE;
    pointers.record = record;
    pointers.context = context;
    if (final_code) *final_code = record->code;
    for (i = 0; i < veh_count; ++i) {
        ntw_veh_routine routine = veh_slots[veh_order[i]].routine;
        int32_t disposition;
        if (!veh_slots[veh_order[i]].live || !routine) continue;
        disposition = routine(&pointers);
        if (disposition == NTW_EX_CONTINUE_EXECUTION) return resume_ok(record, final_code);
    }
    frame = seh_head;
    while (frame != NTW_EX_CHAIN_END && frame != 0) {
        uint32_t next, handler;
        int32_t disposition;
        if ((frame & 3u) || (frame_ok && !frame_ok(frame, frame_user))) {
            record->flags |= NTW_EX_STACK_INVALID;
            break;
        }
        next = read32(frame);
        handler = read32(frame + 4u);
        if (!handler) break;
        disposition = ((ntw_seh_routine)(uintptr_t)handler)(record, (void *)(uintptr_t)frame, context, 0);
        if (disposition == NTW_DISP_CONTINUE) return resume_ok(record, final_code);
        if (disposition != NTW_DISP_SEARCH) break;
        if (next != NTW_EX_CHAIN_END && next != 0 && next < frame + 8u) {
            record->flags |= NTW_EX_STACK_INVALID;
            break;
        }
        frame = next;
    }
    if (unhandled) {
        int32_t disposition = unhandled(&pointers, unhandled_user);
        if (disposition == NTW_EX_CONTINUE_EXECUTION) return resume_ok(record, final_code);
    }
    if (final_code) *final_code = record->code;
    return NTW_RAISE_TERMINATE;
}
int ntw_unwind_chain(uint32_t *seh_head, uint32_t target_frame, ntw_ex_record *record,
                     ntw_context *context, ntw_frame_ok frame_ok, void *frame_user, uint32_t *error) {
    ntw_ex_record local;
    uint32_t frame;
    if (!seh_head || !context) { if (error) *error = NTW_ERR_INVALID; return 0; }
    if (!record) {
        local.code = NTW_STATUS_NONCONTINUABLE;
        local.flags = 0;
        local.next = 0;
        local.address = context->Eip;
        local.count = 0;
        record = &local;
    }
    record->flags |= NTW_EX_UNWINDING;
    if (!target_frame) record->flags |= NTW_EX_EXIT_UNWIND;
    frame = *seh_head;
    while (frame != NTW_EX_CHAIN_END && frame != 0 && frame != target_frame) {
        uint32_t next, handler;
        if ((frame & 3u) || (frame_ok && !frame_ok(frame, frame_user))) {
            if (error) *error = NTW_ERR_INVALID;
            return 0;
        }
        next = read32(frame);
        handler = read32(frame + 4u);
        if (handler) (void)((ntw_seh_routine)(uintptr_t)handler)(record, (void *)(uintptr_t)frame, context, 0);
        if (next != NTW_EX_CHAIN_END && next != 0 && next < frame + 8u) {
            if (error) *error = NTW_ERR_INVALID;
            return 0;
        }
        frame = next;
    }
    *seh_head = target_frame ? target_frame : NTW_EX_CHAIN_END;
    if (error) *error = 0;
    return 1;
}
