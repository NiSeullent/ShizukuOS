/* Shutdown-contract regression for the completion port core (host, real threads).
 * SPDX-License-Identifier: GPL-2.0-only
 *
 * Blocked INFINITE getters are woken by lc_iocp_close. The test then destroys
 * the backend lock and frees the whole context IMMEDIATELY after close returns
 * and only then joins the getters. If close returned before a getter had left
 * the port state/lock (the earlier defect: open_ports fell at close start and
 * the DLL deleted the lock), ASan reports a use-after-free and TSan a data
 * race on the destroyed mutex. Built under both sanitizers by check.py.
 * Not Win98 guest evidence.
 */
#define _POSIX_C_SOURCE 200809L
#include "lc_iocp.h"
#include <errno.h>
#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#define CHECK(x) do { if (!(x)) { fprintf(stderr, "FAIL %s:%d %s\n", __FILE__, __LINE__, #x); exit(1); } } while (0)

typedef struct sem { pthread_mutex_t m; pthread_cond_t cv; uint32_t count, maximum; } sem;
typedef struct env { pthread_mutex_t lock; int live_sems; } env;

static void e_enter(void *o) { pthread_mutex_lock(&((env *)o)->lock); }
static void e_leave(void *o) { pthread_mutex_unlock(&((env *)o)->lock); }
static uintptr_t e_create(void *o, uint32_t max)
{
    sem *s = calloc(1, sizeof(*s));
    if (!s) return 0;
    pthread_mutex_init(&s->m, NULL);
    pthread_cond_init(&s->cv, NULL);
    s->maximum = max;
    ((env *)o)->live_sems++; /* always under the core lock */
    return (uintptr_t)s;
}
static int e_release(void *o, uintptr_t h, uint32_t n)
{
    sem *s = (sem *)h;
    (void)o;
    pthread_mutex_lock(&s->m);
    if (s->maximum - s->count < n) { pthread_mutex_unlock(&s->m); return 0; }
    s->count += n;
    pthread_cond_broadcast(&s->cv);
    pthread_mutex_unlock(&s->m);
    return 1;
}
static uint32_t e_wait(void *o, uintptr_t h, uint32_t ms)
{
    sem *s = (sem *)h;
    struct timespec t;
    (void)o;
    clock_gettime(CLOCK_REALTIME, &t);
    t.tv_sec += ms / 1000;
    t.tv_nsec += (long)(ms % 1000) * 1000000L;
    if (t.tv_nsec >= 1000000000L) { t.tv_sec++; t.tv_nsec -= 1000000000L; }
    pthread_mutex_lock(&s->m);
    while (!s->count) {
        int r = ms == LC_INFINITE ? pthread_cond_wait(&s->cv, &s->m) : pthread_cond_timedwait(&s->cv, &s->m, &t);
        if (r == ETIMEDOUT && !s->count) { pthread_mutex_unlock(&s->m); return LC_WAIT_TIMEOUT; }
    }
    s->count--;
    pthread_mutex_unlock(&s->m);
    return 0;
}
static int e_close(void *o, uintptr_t h)
{
    sem *s = (sem *)h;
    pthread_mutex_destroy(&s->m);
    pthread_cond_destroy(&s->cv);
    free(s);
    ((env *)o)->live_sems--;
    return 1;
}
static uint32_t e_error(void *o) { (void)o; return 0; }

typedef struct getter { lc_iocp_context *ctx; uint32_t port, error; int ok; pthread_t th; } getter;

static void *get_thread(void *arg)
{
    getter *g = arg;
    lc_entry e;
    uint32_t n = 0;
    g->ok = lc_iocp_get(g->ctx, g->port, &e, 1, &n, LC_INFINITE, &g->error);
    return NULL;
}

static void round_trip(unsigned getters, int pre_post)
{
    env *en = calloc(1, sizeof(*en));
    lc_iocp_context *ctx = calloc(1, sizeof(*ctx));
    lc_iocp_ops ops = { en, e_enter, e_leave, e_create, e_release, e_wait, e_close, e_error };
    getter g[8];
    uint32_t port = 0, err = 0;
    unsigned i, spins;
    CHECK(en && ctx);
    pthread_mutex_init(&en->lock, NULL);
    CHECK(lc_iocp_init(ctx, &ops));
    CHECK(lc_iocp_create(ctx, 0, &port, &err));
    if (pre_post) CHECK(lc_iocp_post(ctx, port, 1, 2, (void *)3, &err)); /* discarded by close */
    for (i = 0; i < getters; i++) {
        g[i].ctx = ctx; g[i].port = port; g[i].error = 0; g[i].ok = -1;
        /* with a pre-posted packet one getter legitimately consumes it first */
        if (pre_post && i == 0) { lc_entry e; uint32_t n = 0; CHECK(lc_iocp_get(ctx, port, &e, 1, &n, 0, &err) && n == 1); }
        CHECK(pthread_create(&g[i].th, NULL, get_thread, &g[i]) == 0);
    }
    /* wait until every getter is registered inside the port */
    for (spins = 0;; spins++) {
        unsigned w;
        pthread_mutex_lock(&en->lock);
        w = ctx->ports[(port & 0xff) - 1].waiters;
        pthread_mutex_unlock(&en->lock);
        if (w == getters) break;
        CHECK(spins < 20000);
        { struct timespec t = { 0, 500000 }; nanosleep(&t, NULL); }
    }
    CHECK(lc_iocp_close(ctx, port, &err));
    /* Quiescence: nothing is blocked in, closing, or registered with the port. */
    CHECK(lc_iocp_busy(ctx) == 0);
    CHECK(lc_iocp_open_ports(ctx) == 0);
    CHECK(en->live_sems == 0 && ctx->retained == 0);
    /* The DLL would now delete its lock. Do the equivalent, free everything,
     * and only then join the getters (they must not touch freed state). */
    pthread_mutex_destroy(&en->lock);
    memset(ctx, 0xdd, sizeof(*ctx));
    free(ctx);
    free(en);
    for (i = 0; i < getters; i++) {
        CHECK(pthread_join(g[i].th, NULL) == 0);
        CHECK(g[i].ok == 0 && g[i].error == LC_ABANDONED_WAIT_0);
    }
}

int main(void)
{
    unsigned r;
    for (r = 0; r < 150; r++) round_trip(1 + r % 6, r & 1);
    /* second close of a dead handle and close without getters */
    {
        env *en = calloc(1, sizeof(*en));
        lc_iocp_context *ctx = calloc(1, sizeof(*ctx));
        lc_iocp_ops ops = { en, e_enter, e_leave, e_create, e_release, e_wait, e_close, e_error };
        uint32_t port = 0, err = 0;
        pthread_mutex_init(&en->lock, NULL);
        CHECK(lc_iocp_init(ctx, &ops) && lc_iocp_create(ctx, 0, &port, &err));
        CHECK(lc_iocp_close(ctx, port, &err));
        CHECK(!lc_iocp_close(ctx, port, &err) && err == LC_INVALID_HANDLE);
        CHECK(lc_iocp_busy(ctx) == 0 && en->live_sems == 0);
        pthread_mutex_destroy(&en->lock);
        free(ctx);
        free(en);
    }
    puts("lc_iocp quiescence: PASS (host-only, not guest evidence)");
    return 0;
}
