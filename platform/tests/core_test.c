/* SPDX-License-Identifier: GPL-2.0-only */
#include "../../ntwrapper/include/ntwrapper.h"
#include "../../ntwin32/sync.h"
#include <assert.h>
#include <pthread.h>
#include <sched.h>
#include <stdio.h>
static pthread_mutex_t mutex = PTHREAD_MUTEX_INITIALIZER;
static uintptr_t enter(void *p) { assert(!pthread_mutex_lock(p)); return 42; }
static void leave(void *p, uintptr_t saved) { assert(saved == 42); assert(!pthread_mutex_unlock(p)); }
static struct ntw_context context;
static ntw_handle shared_event;
static unsigned winners;
static ntw_srw rw;
static unsigned counter;
static void yield_cpu(void) { sched_yield(); }
static void *waiter(void *arg) {
    unsigned i;
    (void)arg;
    if (ntw_event_try_wait(&context, shared_event) == NTW_OK)
        __atomic_fetch_add(&winners, 1, __ATOMIC_RELAXED);
    for (i = 0; i < 20000; ++i) {
        ntw_srw_acquire_exclusive(&rw, yield_cpu);
        ++counter;
        ntw_srw_release_exclusive(&rw);
        ntw_srw_acquire_shared(&rw, yield_cpu);
        assert(counter >= i + 1);
        ntw_srw_release_shared(&rw);
    }
    return NULL;
}
int main(void) {
    struct ntw_lock_ops lock = { enter, leave, &mutex };
    struct ntw_lease lease = {0};
    struct ntw_tick_clock clock = {0};
    ntw_handle h, replacement, handles[NTW_MAX_OBJECTS];
    pthread_t threads[4];
    unsigned i;
    int previous = -1;
    assert(ntw_initialize(&context, NULL) == NTW_INVALID);
    assert(ntw_initialize(&context, &lock) == NTW_OK);
    assert(ntw_event_create(&context, 1, 0, NTW_EVENT_ALL, &h) == NTW_OK);
    assert(ntw_event_try_wait(&context, h) == NTW_PENDING);
    assert(ntw_event_set(&context, h, &previous) == NTW_OK && previous == 0);
    assert(ntw_event_try_wait(&context, h) == NTW_OK);
    assert(ntw_event_try_wait(&context, h) == NTW_OK);
    assert(ntw_event_reset(&context, h, &previous) == NTW_OK && previous == 1);
    assert(ntw_reference(&context, h, NTW_EVENT_WAIT, &lease) == NTW_OK);
    assert(ntw_shutdown(&context) == NTW_BUSY);
    assert(ntw_close(&context, h) == NTW_OK);
    assert(ntw_close(&context, h) == NTW_BAD_HANDLE);
    assert(ntw_event_set(&context, h, NULL) == NTW_BAD_HANDLE);
    assert(ntw_event_create(&context, 0, 0, NTW_EVENT_QUERY, &replacement) == NTW_OK);
    assert((h & 0xffffu) != (replacement & 0xffffu));
    assert(ntw_event_set(&context, replacement, NULL) == NTW_ACCESS_DENIED);
    assert(ntw_dereference(&lease) == NTW_OK);
    assert(ntw_dereference(&lease) == NTW_INVALID);
    assert(ntw_close(&context, replacement) == NTW_OK);
    assert(ntw_event_create(&context, 0, 1, NTW_EVENT_ALL, &shared_event) == NTW_OK);
    assert(shared_event != h);
    ntw_srw_init(&rw);
    assert(ntw_srw_try_shared(&rw));
    assert(ntw_srw_try_shared(&rw));
    assert(!ntw_srw_try_exclusive(&rw));
    ntw_srw_release_shared(&rw); ntw_srw_release_shared(&rw);
    assert(ntw_srw_try_exclusive(&rw));
    assert(!ntw_srw_try_shared(&rw));
    assert(!ntw_srw_try_exclusive(&rw));
    ntw_srw_release_exclusive(&rw);
    for (i = 0; i < 4; ++i) assert(!pthread_create(&threads[i], NULL, waiter, NULL));
    for (i = 0; i < 4; ++i) assert(!pthread_join(threads[i], NULL));
    assert(counter == 80000 && winners == 1);
    assert(ntw_close(&context, shared_event) == NTW_OK);
    for (i = 0; i < NTW_MAX_OBJECTS; ++i)
        assert(ntw_event_create(&context, 0, 0, NTW_EVENT_ALL, &handles[i]) == NTW_OK);
    assert(ntw_event_create(&context, 0, 0, NTW_EVENT_ALL, &h) == NTW_NO_MEMORY && h == 0);
    for (i = 0; i < NTW_MAX_OBJECTS; ++i) assert(ntw_close(&context, handles[i]) == NTW_OK);
    /* Exhaust a generation slot and prove stale handles never reappear. */
    context.objects[0].generation = 0xffffu;
    assert(ntw_event_create(&context, 0, 0, NTW_EVENT_ALL, &h) == NTW_OK);
    assert((h & 0xffffu) != 1);
    assert(ntw_close(&context, h) == NTW_OK);
    assert(ntw_event_query(&context, 0, &previous) == NTW_BAD_HANDLE);
    assert(ntw_shutdown(&context) == NTW_OK);
    assert(ntw_event_create(&context, 0, 0, 0, &h) == NTW_INVALID);
    assert(ntw_tick_sample(&clock, 0xfffffff0u) == 0xfffffff0ull);
    assert(ntw_tick_sample(&clock, 5) == 0x100000005ull);
    assert(ntw_tick_sample(&clock, 6) == 0x100000006ull);
    puts("PASS: NTWrapper9x lifetime/events + NTWin32Wrapper9x SRW concurrency/tick wrap");
    return 0;
}
