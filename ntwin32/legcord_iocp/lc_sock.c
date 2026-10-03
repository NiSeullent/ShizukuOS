/* Winsock overlapped-completion -> completion port bridge core.
 * SPDX-License-Identifier: GPL-2.0-only
 * See lc_sock.h. Lock order: this context's lock is never held while calling
 * a Winsock result function, finish() or post().
 */
#include "lc_sock.h"
#include "lc_iocp.h" /* LC_* Win32 error numbers */
#include <stddef.h>

#define LC_SOCK_MAGIC 0x4c43534bu /* LCSK */
#define GEN_MASK 0x00ffffffu
#define WSAENOTSOCK_ 10038u

static int fail(uint32_t *error, uint32_t code)
{
    if (error) *error = code;
    return LC_SOCK_FAILED;
}

static uint32_t token_of(uint32_t index, uint32_t generation) { return index | (generation & GEN_MASK) << 8; }

static void lock(lc_sock_context *c) { c->ops.enter(c->ops.opaque); }
static void unlock(lc_sock_context *c) { c->ops.leave(c->ops.opaque); }

int lc_sock_init(lc_sock_context *c, const lc_sock_ops *ops)
{
    if (!c || !ops || !ops->enter || !ops->leave || !ops->event_create || !ops->event_reset ||
        !ops->event_set || !ops->event_close || !ops->wait_any || !ops->thread_start ||
        !ops->thread_exit || !ops->io_result || !ops->connect_result || !ops->finish || !ops->post)
        return 0;
    for (size_t i = 0; i < sizeof(*c); i++) ((unsigned char *)c)[i] = 0; /* -nostdlib PE32 */
    c->ops = *ops;
    for (unsigned i = 0; i < LC_SOCK_ASSOC_CAPACITY; i++) c->assoc[i].generation = 1;
    for (unsigned i = 0; i < LC_SOCK_OP_CAPACITY; i++) c->op[i].generation = 1;
    c->magic = LC_SOCK_MAGIC;
    return 1;
}

static void assoc_free(lc_sock_context *c, lc_sock_assoc *a)
{
    a->state = 0;
    a->sock = 0;
    a->generation = (a->generation + 1) & GEN_MASK;
    if (!a->generation) a->generation = 1;
    c->active--;
    c->ops.event_set(c->ops.opaque, c->control); /* worker re-evaluates idle exit */
}

/* Drops one pending reference from the op's association. Lock held. */
static void op_free(lc_sock_context *c, lc_sock_op *o)
{
    lc_sock_assoc *a = &c->assoc[o->assoc];
    if (a->generation == o->assoc_generation && a->state && a->pending) {
        a->pending--;
        if (a->state == 2 && !a->pending) assoc_free(c, a);
    }
    o->state = 0;
    o->ov = NULL;
    o->caller_event = 0;
    o->immediate = 0;
    o->generation = (o->generation + 1) & GEN_MASK;
    if (!o->generation) o->generation = 1;
}

static lc_sock_op *op_lookup(lc_sock_context *c, uint32_t token, unsigned state)
{
    uint32_t index = token & 0xffu;
    if (!c || c->magic != LC_SOCK_MAGIC || index >= LC_SOCK_OP_CAPACITY) return NULL;
    lc_sock_op *o = &c->op[index];
    return o->state == state && o->generation == (token >> 8) ? o : NULL;
}

static void worker(void *arg)
{
    lc_sock_context *c = arg;
    uintptr_t events[LC_SOCK_OP_CAPACITY + 1];
    uint32_t slot[LC_SOCK_OP_CAPACITY + 1], generation[LC_SOCK_OP_CAPACITY + 1];
    for (;;) {
        uint32_t n = 0, r, bytes = 0, wsaerr = 0, port = 0, post_error = 0;
        uintptr_t sock, event, caller_event, key = 0;
        void *ov;
        unsigned kind, immediate, closing = 0, matched = 0;
        lock(c);
        if (!c->active) { /* no association can still produce a completion */
            c->running = 0;
            unlock(c);
            break;
        }
        events[n++] = c->control;
        unsigned start = c->rotate++ % LC_SOCK_OP_CAPACITY; /* fairness among signaled ops */
        for (unsigned k = 0; k < LC_SOCK_OP_CAPACITY; k++) {
            unsigned j = (start + k) % LC_SOCK_OP_CAPACITY;
            if (c->op[j].state != 2) continue;
            events[n] = c->op[j].event;
            slot[n] = j;
            generation[n] = c->op[j].generation;
            n++;
        }
        unlock(c);
        r = c->ops.wait_any(c->ops.opaque, events, n);
        if (r == LC_SOCK_WAIT_FAILED) {
            /* Backend wait failure: stop truthfully; the next association restarts. */
            lock(c);
            c->running = 0;
            unlock(c);
            break;
        }
        if (r == 0 || r >= n) continue;
        lock(c);
        lc_sock_op *o = &c->op[slot[r]];
        if (o->state != 2 || o->generation != generation[r]) {
            unlock(c);
            continue;
        }
        sock = o->sock; ov = o->ov; event = o->event; caller_event = o->caller_event;
        kind = o->kind; immediate = o->immediate;
        unlock(c);

        if (kind == LC_SOCK_CONNECT) {
            if (!immediate) c->ops.connect_result(c->ops.opaque, sock, event, &wsaerr);
        } else {
            c->ops.io_result(c->ops.opaque, sock, ov, &bytes, &wsaerr);
        }

        lock(c);
        lc_sock_assoc *a = &c->assoc[o->assoc];
        if (a->generation == o->assoc_generation && a->state) {
            matched = 1;
            closing = a->state == 2;
            port = a->port;
            key = a->key;
        }
        unlock(c);
        /* closesocket aborts pending operations; Win98 may then report the
         * stale socket instead of the abort. */
        if (closing && wsaerr == WSAENOTSOCK_) wsaerr = LC_WSA_OPERATION_ABORTED;
        c->ops.finish(c->ops.opaque, ov, LC_SOCK_STATUS(wsaerr), bytes, caller_event);
        int posted = matched && c->ops.post(c->ops.opaque, port, bytes, key, ov, &post_error);
        lock(c);
        if (!posted) c->dropped++; /* port closed first: NT also loses these */
        op_free(c, o);
        unlock(c);
    }
    c->ops.thread_exit(c->ops.opaque);
}

int lc_sock_associate(lc_sock_context *c, uint32_t port, uintptr_t sock, uintptr_t key, uint32_t *error)
{
    lc_sock_assoc *slot = NULL;
    if (error) *error = 0;
    if (!c || c->magic != LC_SOCK_MAGIC || !port) return fail(error, LC_INVALID_PARAMETER);
    lock(c);
    for (unsigned i = 0; i < LC_SOCK_ASSOC_CAPACITY; i++) {
        lc_sock_assoc *a = &c->assoc[i];
        if (a->state == 1 && a->sock == sock) {
            unlock(c);
            return fail(error, LC_INVALID_PARAMETER); /* NT: already associated */
        }
        if (!a->state && !slot) slot = a;
    }
    if (!slot) goto resources;
    if (!c->control && !(c->control = c->ops.event_create(c->ops.opaque, 0))) goto resources;
    if (!c->running) {
        if (!c->ops.thread_start(c->ops.opaque, worker, c)) goto resources;
        c->running = 1;
    }
    slot->sock = sock;
    slot->port = port;
    slot->key = key;
    slot->pending = 0;
    slot->state = 1;
    c->active++;
    unlock(c);
    return 1;
resources:
    unlock(c);
    return fail(error, LC_NO_SYSTEM_RESOURCES);
}

int lc_sock_begin(lc_sock_context *c, uintptr_t sock, void *ov, uintptr_t caller_event, unsigned kind,
                  uint32_t *token, uintptr_t *event, uint32_t *error)
{
    lc_sock_assoc *a = NULL;
    lc_sock_op *o = NULL;
    unsigned ai = 0, oi = 0;
    if (error) *error = 0;
    if (!c || c->magic != LC_SOCK_MAGIC || !token || !event || !ov ||
        (kind != LC_SOCK_IO && kind != LC_SOCK_CONNECT))
        return fail(error, LC_INVALID_PARAMETER);
    lock(c);
    for (ai = 0; ai < LC_SOCK_ASSOC_CAPACITY; ai++)
        if (c->assoc[ai].state == 1 && c->assoc[ai].sock == sock) { a = &c->assoc[ai]; break; }
    if (!a) {
        unlock(c);
        return LC_SOCK_PASSTHROUGH;
    }
    for (oi = 0; oi < LC_SOCK_OP_CAPACITY; oi++)
        if (!c->op[oi].state) { o = &c->op[oi]; break; }
    if (!o || (!o->event && !(o->event = c->ops.event_create(c->ops.opaque, 1)))) {
        unlock(c);
        return fail(error, LC_NO_SYSTEM_RESOURCES);
    }
    c->ops.event_reset(c->ops.opaque, o->event);
    o->sock = sock;
    o->ov = ov;
    o->caller_event = caller_event;
    o->kind = kind;
    o->immediate = 0;
    o->assoc = ai;
    o->assoc_generation = a->generation;
    o->state = 1;
    a->pending++;
    *token = token_of(oi, o->generation);
    *event = o->event;
    unlock(c);
    return LC_SOCK_ARMED;
}

void lc_sock_commit(lc_sock_context *c, uint32_t token, int immediate)
{
    lc_sock_op *o;
    if (!c) return;
    lock(c);
    if ((o = op_lookup(c, token, 1))) {
        o->state = 2;
        if (immediate) {
            o->immediate = 1;
            c->ops.event_set(c->ops.opaque, o->event);
        }
        c->ops.event_set(c->ops.opaque, c->control);
    }
    unlock(c);
}

void lc_sock_abort(lc_sock_context *c, uint32_t token)
{
    lc_sock_op *o;
    if (!c) return;
    lock(c);
    if ((o = op_lookup(c, token, 1))) op_free(c, o);
    unlock(c);
}

int lc_sock_close_begin(lc_sock_context *c, uintptr_t sock, uint32_t *token)
{
    if (!c || c->magic != LC_SOCK_MAGIC || !token) return 0;
    lock(c);
    for (uint32_t i = 0; i < LC_SOCK_ASSOC_CAPACITY; i++) {
        lc_sock_assoc *a = &c->assoc[i];
        if (a->state == 1 && a->sock == sock) {
            a->state = 2;
            *token = token_of(i, a->generation);
            unlock(c);
            return 1;
        }
    }
    unlock(c);
    return 0;
}

void lc_sock_close_end(lc_sock_context *c, uint32_t token, int ok)
{
    uint32_t i = token & 0xffu;
    if (!c || c->magic != LC_SOCK_MAGIC) return;
    lock(c);
    lc_sock_assoc *a = &c->assoc[i];
    if (a->state == 2 && a->generation == token >> 8) {
        if (!ok) a->state = 1;           /* socket is still open */
        else if (!a->pending) assoc_free(c, a);
        /* else: the worker frees it after the aborted completions drain */
    }
    unlock(c);
}

unsigned lc_sock_active(lc_sock_context *c)
{
    unsigned n;
    lock(c);
    n = c->active;
    unlock(c);
    return n;
}

unsigned lc_sock_worker_running(lc_sock_context *c)
{
    unsigned n;
    lock(c);
    n = c->running;
    unlock(c);
    return n;
}

int lc_sock_release(lc_sock_context *c)
{
    if (!c || c->magic != LC_SOCK_MAGIC) return 0;
    lock(c);
    if (c->active || c->running) {
        unlock(c);
        return 0;
    }
    for (unsigned i = 0; i < LC_SOCK_OP_CAPACITY; i++)
        if (c->op[i].event) {
            c->ops.event_close(c->ops.opaque, c->op[i].event);
            c->op[i].event = 0;
        }
    if (c->control) c->ops.event_close(c->ops.opaque, c->control);
    c->control = 0;
    unlock(c);
    return 1;
}
