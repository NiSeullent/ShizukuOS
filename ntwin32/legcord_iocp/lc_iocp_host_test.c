/* Host regression for the completion port core with real POSIX threads.
 * SPDX-License-Identifier: GPL-2.0-only
 * This exercises core logic only; it is not Win98 guest evidence.
 */
#define _POSIX_C_SOURCE 200809L
#include "lc_iocp.h"
#include <errno.h>
#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <time.h>

#define CHECK(x) do { if (!(x)) { fprintf(stderr, "FAIL %s:%d %s\n", __FILE__, __LINE__, #x); exit(1); } } while (0)

typedef struct host_sem {
    pthread_mutex_t m;
    pthread_cond_t cv;
    uint32_t count, maximum;
} host_sem;
static pthread_mutex_t big = PTHREAD_MUTEX_INITIALIZER;
static int fail_next_create, live_sems;
static uint32_t last_error;

static void h_enter(void *o) { (void)o; pthread_mutex_lock(&big); }
static void h_leave(void *o) { (void)o; pthread_mutex_unlock(&big); }
static uintptr_t h_create(void *o, uint32_t maximum)
{
    host_sem *s;
    (void)o;
    if (fail_next_create) { fail_next_create = 0; last_error = 8; return 0; }
    s = calloc(1, sizeof(*s));
    if (!s) return 0;
    pthread_mutex_init(&s->m, NULL);
    pthread_cond_init(&s->cv, NULL);
    s->maximum = maximum;
    __atomic_add_fetch(&live_sems, 1, __ATOMIC_SEQ_CST);
    return (uintptr_t)s;
}
static int h_release(void *o, uintptr_t h, uint32_t n)
{
    host_sem *s = (host_sem *)h;
    (void)o;
    pthread_mutex_lock(&s->m);
    if (s->maximum - s->count < n) { pthread_mutex_unlock(&s->m); last_error = 298; return 0; }
    s->count += n;
    pthread_cond_broadcast(&s->cv);
    pthread_mutex_unlock(&s->m);
    return 1;
}
static uint32_t h_wait(void *o, uintptr_t h, uint32_t ms)
{
    host_sem *s = (host_sem *)h;
    struct timespec t;
    (void)o;
    clock_gettime(CLOCK_REALTIME, &t);
    t.tv_sec += ms / 1000;
    t.tv_nsec += (long)(ms % 1000) * 1000000L;
    if (t.tv_nsec >= 1000000000L) { t.tv_sec++; t.tv_nsec -= 1000000000L; }
    pthread_mutex_lock(&s->m);
    while (!s->count) {
        int r;
        if (!ms) { pthread_mutex_unlock(&s->m); return LC_WAIT_TIMEOUT; }
        r = ms == LC_INFINITE ? pthread_cond_wait(&s->cv, &s->m) : pthread_cond_timedwait(&s->cv, &s->m, &t);
        if (r == ETIMEDOUT && !s->count) { pthread_mutex_unlock(&s->m); return LC_WAIT_TIMEOUT; }
    }
    s->count--;
    pthread_mutex_unlock(&s->m);
    return 0;
}
static int h_close(void *o, uintptr_t h)
{
    host_sem *s = (host_sem *)h;
    (void)o;
    pthread_mutex_destroy(&s->m);
    pthread_cond_destroy(&s->cv);
    free(s);
    __atomic_sub_fetch(&live_sems, 1, __ATOMIC_SEQ_CST);
    return 1;
}
static uint32_t h_error(void *o) { (void)o; return last_error; }

static lc_iocp_context ctx;
static uint32_t port;
enum { PRODUCERS = 4, PER_PRODUCER = 5000, CONSUMERS = 3 };
static unsigned char seen[PRODUCERS * PER_PRODUCER];
static unsigned long consumed;

static void *producer(void *arg)
{
    uintptr_t base = (uintptr_t)arg * PER_PRODUCER;
    unsigned i;
    for (i = 0; i < PER_PRODUCER; i++) {
        uint32_t e;
        while (!lc_iocp_post(&ctx, port, 7, base + i + 1, (void *)(base + i + 1), &e)) {
            if (e != LC_NO_SYSTEM_RESOURCES) { fprintf(stderr, "post %u\n", e); exit(1); }
            sched_yield();
        }
    }
    return NULL;
}
static void *consumer(void *arg)
{
    lc_entry entries[8];
    (void)arg;
    for (;;) {
        uint32_t n, e, i;
        if (!lc_iocp_get(&ctx, port, entries, 8, &n, LC_INFINITE, &e)) {
            if (e == LC_ABANDONED_WAIT_0) return NULL;
            fprintf(stderr, "get %u\n", e); exit(1);
        }
        unsigned stops = 0;
        for (i = 0; i < n; i++) {
            uintptr_t k = entries[i].key;
            if (!k) { stops++; continue; } /* shutdown packet */
            CHECK(k <= PRODUCERS * PER_PRODUCER && entries[i].bytes == 7 && entries[i].internal == 0);
            CHECK(__atomic_add_fetch(&seen[k - 1], 1, __ATOMIC_SEQ_CST) == 1);
            __atomic_add_fetch(&consumed, 1, __ATOMIC_SEQ_CST);
        }
        if (stops) { /* hand surplus shutdown packets back to other consumers */
            while (--stops) CHECK(lc_iocp_post(&ctx, port, 0, 0, NULL, &e));
            return NULL;
        }
    }
}
static void *abandoned_waiter(void *arg)
{
    lc_entry entry;
    uint32_t n, e = 0;
    int ok = lc_iocp_get(&ctx, (uint32_t)(uintptr_t)arg, &entry, 1, &n, LC_INFINITE, &e);
    return (void *)(uintptr_t)(!ok && e == LC_ABANDONED_WAIT_0);
}

int main(void)
{
    lc_iocp_ops ops = { NULL, h_enter, h_leave, h_create, h_release, h_wait, h_close, h_error };
    lc_entry entries[4];
    uint32_t e, n, a, b, stale;
    pthread_t threads[PRODUCERS + CONSUMERS], w[2];
    unsigned i;
    void *r;

    CHECK(!lc_iocp_init(&ctx, NULL));
    CHECK(lc_iocp_init(&ctx, &ops));
    /* FIFO, multi-dequeue, timeout and parameter checks. */
    CHECK(lc_iocp_create(&ctx, 0, &a, &e) && a);
    CHECK(!lc_iocp_get(&ctx, a, entries, 4, &n, 0, &e) && e == LC_WAIT_TIMEOUT && n == 0);
    CHECK(!lc_iocp_get(&ctx, a, entries, 4, &n, 30, &e) && e == LC_WAIT_TIMEOUT);
    CHECK(!lc_iocp_get(&ctx, a, entries, 0, &n, 0, &e) && e == LC_INVALID_PARAMETER);
    for (i = 1; i <= 3; i++) CHECK(lc_iocp_post(&ctx, a, i * 10, i, (void *)(uintptr_t)(i * 100), &e));
    CHECK(lc_iocp_get(&ctx, a, entries, 2, &n, 0, &e) && n == 2);
    CHECK(entries[0].key == 1 && entries[0].bytes == 10 && entries[1].key == 2 &&
          entries[1].overlapped == (void *)(uintptr_t)200);
    CHECK(lc_iocp_get(&ctx, a, entries, 4, &n, LC_INFINITE, &e) && n == 1 && entries[0].key == 3);
    /* Association is a truthful unsupported gap, not success. */
    CHECK(!lc_iocp_associate(&ctx, a, 0x44, 1, &e) && e == LC_NOT_SUPPORTED);
    CHECK(!lc_iocp_associate(&ctx, a + 1, 0x44, 1, &e) && e == LC_INVALID_HANDLE);
    /* Generation-bound handles: stale handle rejected after slot reuse. */
    stale = a;
    CHECK(lc_iocp_post(&ctx, a, 1, 1, NULL, &e));
    CHECK(lc_iocp_close(&ctx, a, &e));
    CHECK(lc_iocp_create(&ctx, 0, &b, &e) && b != stale && (b & 0xff) == (stale & 0xff));
    CHECK(!lc_iocp_post(&ctx, stale, 1, 1, NULL, &e) && e == LC_INVALID_HANDLE);
    CHECK(!lc_iocp_close(&ctx, stale, &e) && e == LC_INVALID_HANDLE);
    CHECK(!lc_iocp_get(&ctx, b, entries, 1, &n, 0, &e) && e == LC_WAIT_TIMEOUT); /* old packet discarded */
    /* Packet capacity is bounded with a truthful error, and slots recycle. */
    for (i = 0; i < LC_PACKET_CAPACITY; i++) CHECK(lc_iocp_post(&ctx, b, 0, i + 1, NULL, &e));
    CHECK(!lc_iocp_post(&ctx, b, 0, 9, NULL, &e) && e == LC_NO_SYSTEM_RESOURCES);
    CHECK(lc_iocp_close(&ctx, b, &e));
    CHECK(lc_iocp_create(&ctx, 0, &b, &e));
    CHECK(lc_iocp_post(&ctx, b, 0, 9, NULL, &e));
    CHECK(lc_iocp_close(&ctx, b, &e));
    /* Backend creation failure propagates its error. */
    fail_next_create = 1;
    CHECK(!lc_iocp_create(&ctx, 0, &b, &e) && e == 8 && b == 0);
    /* Close while two threads block: both observe abandonment, semaphore freed. */
    CHECK(lc_iocp_create(&ctx, 0, &a, &e));
    for (i = 0; i < 2; i++) CHECK(!pthread_create(&w[i], NULL, abandoned_waiter, (void *)(uintptr_t)a));
    for (;;) { /* wait until both are inside the core wait */
        unsigned waiting;
        h_enter(NULL); waiting = ctx.ports[(a & 0xff) - 1].waiters; h_leave(NULL);
        if (waiting == 2) break;
        sched_yield();
    }
    CHECK(lc_iocp_close(&ctx, a, &e));
    for (i = 0; i < 2; i++) { CHECK(!pthread_join(w[i], &r)); CHECK(r == (void *)1); }
    CHECK(live_sems == 0 && lc_iocp_open_ports(&ctx) == 0 && ctx.retained == 0);
    /* Concurrent producers/consumers: every packet delivered exactly once. */
    CHECK(lc_iocp_create(&ctx, 0, &port, &e));
    for (i = 0; i < CONSUMERS; i++) CHECK(!pthread_create(&threads[PRODUCERS + i], NULL, consumer, NULL));
    for (i = 0; i < PRODUCERS; i++) CHECK(!pthread_create(&threads[i], NULL, producer, (void *)(uintptr_t)i));
    for (i = 0; i < PRODUCERS; i++) CHECK(!pthread_join(threads[i], NULL));
    while (__atomic_load_n(&consumed, __ATOMIC_SEQ_CST) < PRODUCERS * PER_PRODUCER) sched_yield();
    for (i = 0; i < CONSUMERS; i++) CHECK(lc_iocp_post(&ctx, port, 0, 0, NULL, &e));
    for (i = 0; i < CONSUMERS; i++) CHECK(!pthread_join(threads[PRODUCERS + i], NULL));
    for (i = 0; i < PRODUCERS * PER_PRODUCER; i++) CHECK(seen[i] == 1);
    CHECK(lc_iocp_close(&ctx, port, &e) && live_sems == 0);
    puts("lc_iocp host core: PASS (host-only, not guest evidence)");
    return 0;
}
