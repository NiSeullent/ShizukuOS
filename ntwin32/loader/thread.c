/* SPDX-License-Identifier: GPL-2.0-only */
#include "thread.h"
#define NTW_THREAD_SLOTS 16u
#define NTW_THREAD_BASE 0x4500u
#define NTW_STILL_ACTIVE 259u
static struct ntw_worker {
    int live;
    volatile int release;
    volatile int done;
    uint32_t exit_code;
    volatile uint32_t tid;
    ntw_thread_start start;
    void *param;
} workers[NTW_THREAD_SLOTS];
static ntw_thread_spawn spawn_fn;
static ntw_thread_enter enter_fn;
static ntw_thread_leave leave_fn;
static ntw_thread_pause pause_fn;
static ntw_thread_tid tid_fn;
static void *spawn_user;
static uint32_t self_handle;
int ntw_thread_flags_ok(uint32_t flags) {
    /* CREATE_SUSPENDED and STACK_SIZE_PARAM_IS_A_RESERVATION. Other bits are 87. */
    return (flags & ~0x10004u) == 0;
}
void ntw_thread_set_spawn(ntw_thread_spawn spawn, ntw_thread_enter enter, ntw_thread_leave leave,
                          ntw_thread_pause pause, ntw_thread_tid tid, void *user) {
    spawn_fn = spawn;
    enter_fn = enter;
    leave_fn = leave;
    pause_fn = pause;
    tid_fn = tid;
    spawn_user = user;
}
static void run_worker(void *slot) {
    struct ntw_worker *worker = slot;
    uint32_t code, index = (uint32_t)(worker - workers);
    if (tid_fn) worker->tid = tid_fn();
    self_handle = NTW_THREAD_BASE + index;
    if (enter_fn) enter_fn(index, self_handle);
    while (!worker->release) {
        if (pause_fn) pause_fn();
    }
    code = worker->start(worker->param);
    worker->exit_code = code;
    worker->done = 1;
    if (leave_fn) leave_fn(code);
}
int ntw_thread_create(ntw_thread_start start, void *param, int suspended, uint32_t *handle, uint32_t *tid, uint32_t *error) {
    uint32_t slot;
    int rc;
    if (!error || !handle) return 0;
    *handle = 0;
    if (tid) *tid = 0;
    if (!start || !spawn_fn) { *error = 87; return 0; }
    for (slot = 0; slot < NTW_THREAD_SLOTS; ++slot) if (!workers[slot].live) break;
    if (slot == NTW_THREAD_SLOTS) { *error = 8; return 0; }
    workers[slot].live = 1;
    workers[slot].release = suspended ? 0 : 1;
    workers[slot].done = 0;
    workers[slot].exit_code = NTW_STILL_ACTIVE;
    workers[slot].tid = 0;
    workers[slot].start = start;
    workers[slot].param = param;
    rc = spawn_fn(spawn_user, run_worker, &workers[slot]);
    if (rc < 0) {
        workers[slot].live = 0;
        *error = rc == -12 ? 8u : 87u;
        return 0;
    }
    *handle = NTW_THREAD_BASE + slot;
    if (tid) *tid = workers[slot].tid ? workers[slot].tid : (slot + 1u);
    *error = 0;
    return 1;
}
int ntw_thread_resume(uint32_t handle, uint32_t *previous, uint32_t *error) {
    uint32_t slot = handle - NTW_THREAD_BASE;
    if (!error || handle < NTW_THREAD_BASE || slot >= NTW_THREAD_SLOTS || !workers[slot].live) {
        if (error) *error = 6;
        return 0;
    }
    if (previous) *previous = workers[slot].release ? 0u : 1u;
    workers[slot].release = 1;
    *error = 0;
    return 1;
}
int ntw_thread_owns(uint32_t handle) {
    uint32_t slot = handle - NTW_THREAD_BASE;
    return handle >= NTW_THREAD_BASE && slot < NTW_THREAD_SLOTS && workers[slot].live;
}
int ntw_thread_exit_code(uint32_t handle, uint32_t *code, uint32_t *error) {
    uint32_t slot = handle - NTW_THREAD_BASE;
    if (!error || !code || !ntw_thread_owns(handle)) { if (error) *error = handle ? 6u : 87u; return 0; }
    *code = workers[slot].done ? workers[slot].exit_code : NTW_STILL_ACTIVE;
    *error = 0;
    return 1;
}
int ntw_thread_wait(uint32_t handle, int block, uint32_t *result, uint32_t *error) {
    uint32_t slot = handle - NTW_THREAD_BASE;
    uint32_t spins = 0;
    if (!error || !result || !ntw_thread_owns(handle)) { if (error) *error = 6; return 0; }
    while (!workers[slot].done) {
        if (!block) { *result = 258; *error = 0; return 1; }
        if (pause_fn) pause_fn();
        else if (++spins > 1000000u) { *result = 258; *error = 0; return 1; }
    }
    *result = 0;
    *error = 0;
    return 1;
}
int ntw_thread_close(uint32_t handle, uint32_t *error) {
    uint32_t slot = handle - NTW_THREAD_BASE;
    if (!error || !ntw_thread_owns(handle)) { if (error) *error = 6; return 0; }
    if (!workers[slot].done && workers[slot].start) { *error = 5; return 0; }
    workers[slot].live = 0;
    *error = 0;
    return 1;
}
uint32_t ntw_thread_self(void) { return self_handle; }
int ntw_thread_duplicate(uint32_t source, uint32_t *out, uint32_t *error) {
    uint32_t slot, tid = 1;
    if (!out || !error) return 0;
    *out = 0;
    if (source != 0xfffffffeu && !ntw_thread_owns(source)) { *error = 6; return 0; }
    for (slot = 0; slot < NTW_THREAD_SLOTS; ++slot) if (!workers[slot].live) break;
    if (slot == NTW_THREAD_SLOTS) { *error = 8; return 0; }
    if (source == 0xfffffffeu) {
        if (tid_fn) tid = tid_fn();
    } else tid = workers[source - NTW_THREAD_BASE].tid;
    workers[slot].live = 1;
    workers[slot].release = 1;
    workers[slot].done = 0;
    workers[slot].exit_code = NTW_STILL_ACTIVE;
    workers[slot].tid = tid;
    workers[slot].start = 0;
    workers[slot].param = 0;
    *out = NTW_THREAD_BASE + slot;
    *error = 0;
    return 1;
}
void ntw_thread_complete(uint32_t handle, uint32_t code) {
    uint32_t slot = handle - NTW_THREAD_BASE;
    if (!ntw_thread_owns(handle)) return;
    workers[slot].exit_code = code;
    workers[slot].done = 1;
}
