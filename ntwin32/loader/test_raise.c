/* SPDX-License-Identifier: GPL-2.0-only */
#include "raise.h"
#include <stddef.h>
#include "raise.h"
#include <stdio.h>
#include <string.h>
static int failures;
static int frame_ok(uint32_t frame, void *user) {
    (void)user;
    return frame != 0;
}
typedef struct { uint32_t next, handler; } seh_frame;
static int32_t search_handler(ntw_ex_record *record, void *frame, ntw_context *context, void *dispatch) {
    (void)record; (void)frame; (void)context; (void)dispatch;
    return NTW_DISP_SEARCH;
}
static int32_t continue_handler(ntw_ex_record *record, void *frame, ntw_context *context, void *dispatch) {
    (void)record; (void)frame; (void)context; (void)dispatch;
    return NTW_DISP_CONTINUE;
}
static uint32_t unwind_hits;
static int32_t unwind_handler(ntw_ex_record *record, void *frame, ntw_context *context, void *dispatch) {
    (void)frame; (void)context; (void)dispatch;
    if (record->flags & NTW_EX_UNWINDING) unwind_hits++;
    return NTW_DISP_SEARCH;
}
static int32_t veh_stop(ntw_ex_pointers *pointers) {
    (void)pointers;
    return NTW_EX_CONTINUE_EXECUTION;
}
static int32_t veh_search(ntw_ex_pointers *pointers) {
    (void)pointers;
    return NTW_EX_CONTINUE_SEARCH;
}
static int check(int cond, const char *name) {
    if (!cond) { fprintf(stderr, "fail %s\n", name); failures++; return 0; }
    return 1;
}
int main(void) {
    ntw_ex_record record;
    ntw_context context;
    seh_frame frames[2];
    uint32_t handle = 0, error = 0, final_code = 0;
    int result;
    _Static_assert(offsetof(ntw_context, Eip) == 0xB8, "CONTEXT.Eip");
    memset(&record, 0, sizeof record);
    memset(&context, 0, sizeof context);
    record.code = 0xC0000005u;
    record.address = 0x1000;
    context.Eip = 0x2000;
    frames[0].next = (uint32_t)(uintptr_t)&frames[1];
    frames[0].handler = (uint32_t)(uintptr_t)search_handler;
    frames[1].next = NTW_EX_CHAIN_END;
    frames[1].handler = (uint32_t)(uintptr_t)continue_handler;
    ntw_veh_reset();
    if (sizeof(void *) == 4) {
        result = ntw_raise_software(&record, &context, (uint32_t)(uintptr_t)&frames[0], frame_ok, 0, 0, 0, &final_code);
        check(result == NTW_RAISE_RESUME && final_code == 0xC0000005u, "seh continue");
        frames[1].handler = (uint32_t)(uintptr_t)search_handler;
        result = ntw_raise_software(&record, &context, (uint32_t)(uintptr_t)&frames[0], frame_ok, 0, 0, 0, &final_code);
        check(result == NTW_RAISE_TERMINATE, "unhandled");
        record.flags = NTW_EX_NONCONTINUABLE;
        frames[1].handler = (uint32_t)(uintptr_t)continue_handler;
        result = ntw_raise_software(&record, &context, (uint32_t)(uintptr_t)&frames[0], frame_ok, 0, 0, 0, &final_code);
        check(result == NTW_RAISE_TERMINATE && final_code == NTW_STATUS_NONCONTINUABLE, "noncontinuable");
        record.flags = 0;
    } else {
        record.flags = NTW_EX_NONCONTINUABLE;
        check(ntw_veh_add(1, veh_stop, &handle, &error), "veh noncontinuable add");
        result = ntw_raise_software(&record, &context, NTW_EX_CHAIN_END, frame_ok, 0, 0, 0, &final_code);
        check(result == NTW_RAISE_TERMINATE && final_code == NTW_STATUS_NONCONTINUABLE, "noncontinuable");
        ntw_veh_reset();
        record.flags = 0;
        handle = 0;
    }
    final_code = 0;
    check(ntw_veh_add(1, veh_stop, &handle, &error) && handle, "veh add");
    result = ntw_raise_software(&record, &context, (uint32_t)(uintptr_t)&frames[0], frame_ok, 0, 0, 0, &final_code);
    check(result == NTW_RAISE_RESUME, "veh before seh");
    check(ntw_veh_remove(handle, &error), "veh remove");
    check(!ntw_veh_add(0, 0, &handle, &error) && error == 87, "null veh");
    check(ntw_veh_add(0, veh_search, &handle, &error), "veh search add");
    if (sizeof(void *) == 4) {
        frames[0].handler = (uint32_t)(uintptr_t)continue_handler;
        result = ntw_raise_software(&record, &context, (uint32_t)(uintptr_t)&frames[0], frame_ok, 0, 0, 0, &final_code);
        check(result == NTW_RAISE_RESUME, "veh search then seh");
        ntw_veh_reset();
        unwind_hits = 0;
        frames[0].handler = (uint32_t)(uintptr_t)unwind_handler;
        frames[1].handler = (uint32_t)(uintptr_t)unwind_handler;
        {
            uint32_t head = (uint32_t)(uintptr_t)&frames[0];
            record.flags = 0;
            check(ntw_unwind_chain(&head, (uint32_t)(uintptr_t)&frames[1], &record, &context, frame_ok, 0, &error), "unwind");
            check(head == (uint32_t)(uintptr_t)&frames[1] && unwind_hits == 1, "unwind one");
            check(record.flags & NTW_EX_UNWINDING, "unwind flag");
        }
    } else {
        result = ntw_raise_software(&record, &context, NTW_EX_CHAIN_END, frame_ok, 0, 0, 0, &final_code);
        check(result == NTW_RAISE_TERMINATE, "veh search does not resume");
    }
    if (failures) return 1;
    printf("{\"passed\":true,\"raise\":true}\n");
    return 0;
}
