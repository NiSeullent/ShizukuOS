/* SPDX-License-Identifier: GPL-2.0-only */
#define _POSIX_C_SOURCE 200809L
#include "thread.h"
#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <time.h>
static int failures;
static pthread_t main_thread;
static pthread_t worker_thread;
static int started;
static void expect(int cond, const char *text, int line) {
    if (!cond) { fprintf(stderr, "line %d: %s\n", line, text); ++failures; }
}
#define C(x) expect((x), #x, __LINE__)
static uint32_t worker_start(void *param) {
    worker_thread = pthread_self();
    started = 1;
    return param ? *(uint32_t *)param : 0;
}
static void *host_go(void *raw) {
    struct { ntw_thread_body body; void *slot; } *box = raw;
    box->body(box->slot);
    return 0;
}
static int host_spawn(void *user, ntw_thread_body body, void *slot) {
    struct box { ntw_thread_body body; void *slot; } *box;
    pthread_t thread;
    (void)user;
    box = malloc(sizeof *box);
    if (!box) return -12;
    box->body = body;
    box->slot = slot;
    if (pthread_create(&thread, 0, host_go, box) != 0) return -11;
    pthread_detach(thread);
    return 0;
}
static void host_pause(void) {
    struct timespec step;
    step.tv_sec = 0;
    step.tv_nsec = 1000000;
    nanosleep(&step, 0);
}
int main(void) {
    uint32_t handle = 0, tid = 0, error = 0, code = 0, wait_result = 9, value = 21, previous = 9;
    ntw_thread_set_spawn(host_spawn, 0, 0, host_pause, 0, 0);
    main_thread = pthread_self();
    C(ntw_thread_create(0, 0, 0, &handle, &tid, &error) == 0 && error == 87 && handle == 0 && started == 0);
    C(ntw_thread_create(worker_start, &value, 1, &handle, &tid, &error) == 1);
    nanosleep(&(struct timespec){0, 20000000}, 0);
    C(started == 0);
    C(ntw_thread_exit_code(handle, &code, &error) == 1 && code == 259);
    C(ntw_thread_resume(handle, &previous, &error) == 1 && previous == 1);
    C(ntw_thread_wait(handle, 1, &wait_result, &error) == 1 && wait_result == 0);
    C(started == 1 && !pthread_equal(worker_thread, main_thread));
    C(ntw_thread_exit_code(handle, &code, &error) == 1 && code == 21);
    C(ntw_thread_close(handle, &error) == 1);
    C(ntw_thread_exit_code(handle, &code, &error) == 0 && error == 6);
    C(ntw_thread_duplicate(0xfffffffeu, &handle, &error) == 1 && handle != 0);
    C(ntw_thread_owns(handle) == 1);
    C(ntw_thread_close(handle, &error) == 1);
    C(ntw_thread_duplicate(1, &handle, &error) == 0 && error == 6);
    C(ntw_thread_flags_ok(0) && ntw_thread_flags_ok(4) && ntw_thread_flags_ok(0x10000u) && ntw_thread_flags_ok(0x10004u));
    C(!ntw_thread_flags_ok(1) && !ntw_thread_flags_ok(8));
    if (failures) { fprintf(stderr, "failures %d\n", failures); return 1; }
    printf("{\"passed\":true,\"thread\":true}\n");
    return 0;
}
