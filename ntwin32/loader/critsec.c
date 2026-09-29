/* SPDX-License-Identifier: GPL-2.0-only
 * Flag checks follow ReactOS sdk/lib/rtl/critical.c RtlInitializeCriticalSectionEx
 * at 9dc3ca87209fd8ebabd96c8ea95d439c13e7fdf8, including the Win7+ flag bits,
 * and the project's src/m98wrap.c validation. The lock words are a new
 * uniprocessor state machine: spin count is stored as zero, and a missing
 * owner does not unlock. No ReactOS function body is copied.
 */
#include "critsec.h"
#define NTW_CS_DEBUG_POOL 2048u
typedef struct ntw_cs_debug {
    uint16_t type;
    uint16_t creator_back_trace_index;
    uint32_t critical_section;
    uint32_t process_locks_list[2];
    uint32_t entry_count;
    uint32_t contention_count;
    uint32_t flags;
    uint16_t creator_back_trace_index_high;
    uint16_t spare;
} ntw_cs_debug;
static ntw_cs_debug debug_pool[NTW_CS_DEBUG_POOL];
static uint8_t debug_used[NTW_CS_DEBUG_POOL];
static uint32_t cs_error;
uint32_t ntw_cs_last_error(void) { return cs_error; }
static void fail(uint32_t error) { cs_error = error; }
static int32_t cas_lock(int32_t *lock, int32_t expect, int32_t next) {
    return __sync_bool_compare_and_swap(lock, expect, next);
}
int ntw_cs_initialize(ntw_critical_section *section, uint32_t spin_count, uint32_t flags) {
    uint32_t n, masked;
    ntw_cs_debug *debug = 0;
    if (!section) { fail(NTW_CS_INVALID); return 0; }
    masked = flags & NTW_CS_FLAG_BITS;
    if ((flags & ~NTW_CS_FLAG_BITS) || (masked & ~NTW_CS_ALLOWED) || (spin_count & NTW_CS_FLAG_BITS)) {
        fail(NTW_CS_INVALID);
        return 0;
    }
    section->lock_count = -1;
    section->recursion_count = 0;
    section->owning_thread = 0;
    section->lock_semaphore = 0;
    section->spin_count = 0;
    if ((masked & NTW_CS_NO_DEBUG_INFO) && !(masked & NTW_CS_FORCE_DEBUG_INFO)) {
        section->debug_info = 0xffffffffu;
        cs_error = NTW_CS_OK;
        return 1;
    }
    for (n = 0; n < NTW_CS_DEBUG_POOL; ++n) {
        if (!debug_used[n]) { debug_used[n] = 1; debug = &debug_pool[n]; break; }
    }
    if (!debug) {
        section->debug_info = 0xffffffffu;
        cs_error = NTW_CS_OK;
        return 1;
    }
    debug->type = 0;
    debug->creator_back_trace_index = 0;
    debug->critical_section = (uint32_t)(uintptr_t)section;
    debug->process_locks_list[0] = debug->process_locks_list[1] = 0;
    debug->entry_count = 0;
    debug->contention_count = 0;
    debug->flags = masked;
    debug->creator_back_trace_index_high = 0;
    debug->spare = 0;
    section->debug_info = (uint32_t)(uintptr_t)debug;
    cs_error = NTW_CS_OK;
    return 1;
}
void ntw_cs_enter(ntw_critical_section *section) {
    uint32_t self;
    if (!section) return;
    self = ntw_cs_thread_id();
    if (section->owning_thread == self && section->recursion_count > 0) {
        section->recursion_count++;
        section->lock_count++;
        return;
    }
    for (;;) {
        if (cas_lock(&section->lock_count, -1, 0)) {
            section->owning_thread = self;
            section->recursion_count = 1;
            return;
        }
        ntw_cs_yield();
    }
}
int ntw_cs_try_enter(ntw_critical_section *section) {
    uint32_t self;
    if (!section) { fail(NTW_CS_INVALID); return 0; }
    self = ntw_cs_thread_id();
    if (section->owning_thread == self && section->recursion_count > 0) {
        section->recursion_count++;
        section->lock_count++;
        return 1;
    }
    if (!cas_lock(&section->lock_count, -1, 0)) return 0;
    section->owning_thread = self;
    section->recursion_count = 1;
    return 1;
}
void ntw_cs_leave(ntw_critical_section *section) {
    if (!section) return;
    if (section->owning_thread != ntw_cs_thread_id() || section->recursion_count <= 0) {
        fail(NTW_CS_NOT_OWNER);
        return;
    }
    section->lock_count--;
    if (--section->recursion_count == 0) {
        section->owning_thread = 0;
        section->lock_count = -1;
        __sync_synchronize();
    }
}
void ntw_cs_delete(ntw_critical_section *section) {
    uint32_t n;
    if (!section) return;
    if (section->recursion_count != 0) { fail(NTW_CS_INVALID); return; }
    if (section->debug_info && section->debug_info != 0xffffffffu) {
        for (n = 0; n < NTW_CS_DEBUG_POOL; ++n) {
            if ((uint32_t)(uintptr_t)&debug_pool[n] == section->debug_info) debug_used[n] = 0;
        }
    }
    section->debug_info = 0;
    section->lock_count = -1;
    section->owning_thread = 0;
    section->lock_semaphore = 0;
    section->spin_count = 0;
}
