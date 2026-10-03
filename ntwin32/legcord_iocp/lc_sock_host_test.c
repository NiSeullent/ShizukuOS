/* Host regression: socket completion bridge -> real lc_iocp core, real threads.
 * SPDX-License-Identifier: GPL-2.0-only
 * Events/sockets are host test doubles; the bridge, worker and port are the
 * production cores. Not Win98 guest evidence. */
#include "lc_iocp.h"
#include "lc_sock.h"
#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define CHECK(x) do { if (!(x)) { fprintf(stderr, "FAIL %s:%d %s\n", __FILE__, __LINE__, #x); exit(1); } } while (0)

static pthread_mutex_t big = PTHREAD_MUTEX_INITIALIZER, em = PTHREAD_MUTEX_INITIALIZER;
static pthread_cond_t ec = PTHREAD_COND_INITIALIZER;
struct ev { int used, manual, set; };
static struct ev evs[256];
static pthread_t threads[16];
static int nthreads, fail_thread;
static uint32_t connect_err[64];
static lc_iocp_context port_ctx;
static lc_sock_context sk;

struct tov { uint32_t result_bytes, result_err; uint32_t status, bytes; uintptr_t event_out; int finished; };

static void h_enter(void *o) { (void)o; pthread_mutex_lock(&big); }
static void h_leave(void *o) { (void)o; pthread_mutex_unlock(&big); }
/* Counting semaphore for the port core. */
struct sem { int used, count; };
static struct sem sems[8];
static uintptr_t p_create(void *o, uint32_t m) { (void)o; (void)m; pthread_mutex_lock(&em);
    for (int i = 0; i < 8; i++) if (!sems[i].used) { sems[i].used = 1; sems[i].count = 0; pthread_mutex_unlock(&em); return (uintptr_t)i + 1; }
    pthread_mutex_unlock(&em); return 0; }
static int p_release(void *o, uintptr_t s, uint32_t n) { (void)o; pthread_mutex_lock(&em); sems[s - 1].count += (int)n;
    pthread_cond_broadcast(&ec); pthread_mutex_unlock(&em); return 1; }
static uint32_t p_wait(void *o, uintptr_t s, uint32_t t) { (void)o; (void)t; pthread_mutex_lock(&em);
    while (!sems[s - 1].count) pthread_cond_wait(&ec, &em); sems[s - 1].count--; pthread_mutex_unlock(&em); return 0; }
static int p_close(void *o, uintptr_t s) { (void)o; pthread_mutex_lock(&em); sems[s - 1].used = 0; pthread_mutex_unlock(&em); return 1; }
static uint32_t p_error(void *o) { (void)o; return 31; }

static uintptr_t e_create(void *o, int manual) { (void)o; pthread_mutex_lock(&em);
    for (int i = 0; i < 256; i++) if (!evs[i].used) { evs[i].used = 1; evs[i].manual = manual; evs[i].set = 0;
        pthread_mutex_unlock(&em); return (uintptr_t)i + 1; }
    pthread_mutex_unlock(&em); return 0; }
static void e_reset(void *o, uintptr_t e) { (void)o; pthread_mutex_lock(&em); evs[e - 1].set = 0; pthread_mutex_unlock(&em); }
static void e_set(void *o, uintptr_t e) { (void)o; pthread_mutex_lock(&em); evs[e - 1].set = 1; pthread_cond_broadcast(&ec); pthread_mutex_unlock(&em); }
static void e_close(void *o, uintptr_t e) { (void)o; pthread_mutex_lock(&em); evs[e - 1].used = 0; pthread_mutex_unlock(&em); }
static uint32_t e_wait(void *o, const uintptr_t *e, uint32_t n) { (void)o; pthread_mutex_lock(&em);
    for (;;) { for (uint32_t i = 0; i < n; i++) if (evs[e[i] - 1].set) { if (!evs[e[i] - 1].manual) evs[e[i] - 1].set = 0;
            pthread_mutex_unlock(&em); return i; }
        pthread_cond_wait(&ec, &em); } }
struct start { void (*fn)(void *); void *arg; };
static void *t_main(void *p) { struct start s = *(struct start *)p; free(p); s.fn(s.arg); return NULL; }
static int t_start(void *o, void (*fn)(void *), void *arg) { (void)o;
    if (fail_thread || nthreads == 16) return 0;
    struct start *s = malloc(sizeof *s); s->fn = fn; s->arg = arg;
    return pthread_create(&threads[nthreads++], NULL, t_main, s) == 0; }
static void t_exit(void *o) { (void)o; }
static void io_result(void *o, uintptr_t sock, void *ov, uint32_t *bytes, uint32_t *err) { (void)o; (void)sock;
    struct tov *t = ov; *bytes = t->result_bytes; *err = t->result_err; }
static void conn_result(void *o, uintptr_t sock, uintptr_t ev, uint32_t *err) { (void)o; (void)ev; *err = connect_err[sock]; }
static void finish(void *o, void *ov, uint32_t status, uint32_t bytes, uintptr_t caller) { (void)o;
    struct tov *t = ov; pthread_mutex_lock(&em); t->status = status; t->bytes = bytes; t->event_out = caller; t->finished = 1; pthread_mutex_unlock(&em); }
static int finished(struct tov *t) { pthread_mutex_lock(&em); int f = t->finished; pthread_mutex_unlock(&em); return f; }
static int post(void *o, uint32_t port, uint32_t bytes, uintptr_t key, void *ov, uint32_t *error) { (void)o;
    return lc_iocp_post(&port_ctx, port, bytes, key, ov, error); }

static void signal_op(uintptr_t event) { e_set(NULL, event); }
static void get1(uint32_t port, lc_entry *e) {
    uint32_t n = 0, err = 0; CHECK(lc_iocp_get(&port_ctx, port, e, 1, &n, LC_INFINITE, &err) && n == 1); }
static void wait_idle(void) { while (lc_sock_worker_running(&sk)) { struct timespec ts = {0, 1000000}; nanosleep(&ts, NULL); } }

int main(void)
{
    static const lc_iocp_ops pops = { NULL, h_enter, h_leave, p_create, p_release, p_wait, p_close, p_error };
    static const lc_sock_ops sops = { NULL, h_enter, h_leave, e_create, e_reset, e_set, e_close, e_wait,
                                      t_start, t_exit, io_result, conn_result, finish, post };
    uint32_t port = 0, port2 = 0, err = 0, tok[LC_SOCK_OP_CAPACITY + 1], ctok = 0;
    uintptr_t ev[LC_SOCK_OP_CAPACITY + 1];
    struct tov ov[LC_SOCK_OP_CAPACITY + 1];
    lc_entry e;
    memset(ov, 0, sizeof ov);
    CHECK(lc_iocp_init(&port_ctx, &pops) && lc_sock_init(&sk, &sops));
    CHECK(lc_iocp_create(&port_ctx, 1, &port, &err) && lc_iocp_create(&port_ctx, 1, &port2, &err));

    /* Unassociated socket passes through; worker start failure is truthful. */
    CHECK(lc_sock_begin(&sk, 7, &ov[0], 0, LC_SOCK_IO, &tok[0], &ev[0], &err) == LC_SOCK_PASSTHROUGH);
    fail_thread = 1;
    CHECK(!lc_sock_associate(&sk, port, 7, 0x77, &err) && err == LC_NO_SYSTEM_RESOURCES && !lc_sock_active(&sk));
    fail_thread = 0;
    CHECK(lc_sock_associate(&sk, port, 7, 0x77, &err));
    CHECK(!lc_sock_associate(&sk, port2, 7, 0x78, &err) && err == LC_INVALID_PARAMETER);

    /* Success + failure completions reach the port with key, bytes and NTSTATUS. */
    ov[0].result_bytes = 512;
    ov[1].result_err = 10054; /* WSAECONNRESET */
    for (int i = 0; i < 2; i++) {
        CHECK(lc_sock_begin(&sk, 7, &ov[i], i ? 0x99 : 0, LC_SOCK_IO, &tok[i], &ev[i], &err) == LC_SOCK_ARMED);
        lc_sock_commit(&sk, tok[i], 0);
    }
    signal_op(ev[1]);
    get1(port, &e);
    CHECK(e.overlapped == &ov[1] && e.key == 0x77 && ov[1].status == 0xC0072746u && ov[1].event_out == 0x99);
    signal_op(ev[0]);
    get1(port, &e);
    CHECK(e.overlapped == &ov[0] && e.bytes == 512 && ov[0].status == 0 && ov[0].bytes == 512);

    /* Synchronous submit failure: abort leaves no completion and frees the slot. */
    CHECK(lc_sock_begin(&sk, 7, &ov[2], 0, LC_SOCK_IO, &tok[2], &ev[2], &err) == LC_SOCK_ARMED);
    lc_sock_abort(&sk, tok[2]);
    lc_sock_commit(&sk, tok[2], 0); /* stale token: ignored */

    /* Capacity: 63 armed, the 64th is refused with a resource error. */
    for (int i = 0; i < LC_SOCK_OP_CAPACITY; i++)
        CHECK(lc_sock_begin(&sk, 7, &ov[i], 0, LC_SOCK_IO, &tok[i], &ev[i], &err) == LC_SOCK_ARMED);
    CHECK(lc_sock_begin(&sk, 7, &ov[63], 0, LC_SOCK_IO, &tok[63], &ev[63], &err) == LC_SOCK_FAILED &&
          err == LC_NO_SYSTEM_RESOURCES);
    for (int i = 0; i < LC_SOCK_OP_CAPACITY; i++) lc_sock_abort(&sk, tok[i]);

    /* Emulated ConnectEx: immediate success and asynchronous refusal. */
    CHECK(lc_sock_associate(&sk, port2, 9, 0x90, &err));
    connect_err[9] = 10061; /* WSAECONNREFUSED */
    memset(&ov[3], 0, sizeof ov[3]);
    CHECK(lc_sock_begin(&sk, 9, &ov[3], 0, LC_SOCK_CONNECT, &ctok, &ev[3], &err) == LC_SOCK_ARMED);
    lc_sock_commit(&sk, ctok, 0);
    signal_op(ev[3]);
    get1(port2, &e);
    CHECK(e.overlapped == &ov[3] && e.key == 0x90 && ov[3].status == 0xC007274Du);
    CHECK(lc_sock_begin(&sk, 9, &ov[4], 0, LC_SOCK_CONNECT, &ctok, &ev[4], &err) == LC_SOCK_ARMED);
    lc_sock_commit(&sk, ctok, 1);
    get1(port2, &e);
    CHECK(e.overlapped == &ov[4] && ov[4].status == 0);

    /* closesocket with a pending op: failed close restores, real close drains
     * the aborted completion (stale socket mapped to aborted) and frees. */
    memset(&ov[5], 0, sizeof ov[5]);
    ov[5].result_err = 10038; /* WSAENOTSOCK after close */
    CHECK(lc_sock_begin(&sk, 7, &ov[5], 0, LC_SOCK_IO, &tok[5], &ev[5], &err) == LC_SOCK_ARMED);
    lc_sock_commit(&sk, tok[5], 0);
    CHECK(lc_sock_close_begin(&sk, 7, &ctok));
    lc_sock_close_end(&sk, ctok, 0);
    CHECK(lc_sock_close_begin(&sk, 7, &ctok));
    CHECK(lc_sock_begin(&sk, 7, &ov[6], 0, LC_SOCK_IO, &tok[6], &ev[6], &err) == LC_SOCK_PASSTHROUGH);
    lc_sock_close_end(&sk, ctok, 1);
    CHECK(lc_sock_active(&sk) == 2); /* still draining */
    signal_op(ev[5]);
    get1(port, &e);
    CHECK(e.overlapped == &ov[5] && ov[5].status == (0xC0070000u | LC_WSA_OPERATION_ABORTED));
    while (lc_sock_active(&sk) != 1) { struct timespec ts = {0, 1000000}; nanosleep(&ts, NULL); }
    CHECK(lc_sock_associate(&sk, port, 7, 0x70, &err)); /* socket value reuse */

    /* Port closed before completion: dropped, op slot still released. */
    CHECK(lc_sock_begin(&sk, 7, &ov[7], 0, LC_SOCK_IO, &tok[7], &ev[7], &err) == LC_SOCK_ARMED);
    lc_sock_commit(&sk, tok[7], 0);
    CHECK(lc_iocp_close(&port_ctx, port, &err));
    signal_op(ev[7]);
    while (!finished(&ov[7])) { struct timespec ts = {0, 1000000}; nanosleep(&ts, NULL); }

    /* Release refused while associated; worker idles out after last close. */
    CHECK(!lc_sock_release(&sk));
    CHECK(lc_sock_close_begin(&sk, 7, &ctok)); lc_sock_close_end(&sk, ctok, 1);
    CHECK(lc_sock_close_begin(&sk, 9, &ctok)); lc_sock_close_end(&sk, ctok, 1);
    wait_idle();
    CHECK(!lc_sock_active(&sk) && lc_sock_release(&sk));
    for (int i = 0; i < nthreads; i++) pthread_join(threads[i], NULL);
    CHECK(sk.dropped == 1 && nthreads == 1);
    CHECK(lc_iocp_close(&port_ctx, port2, &err));
    puts("lc_sock host regression PASS");
    return 0;
}
