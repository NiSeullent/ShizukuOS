/* Process-local I/O completion port core (posted-packet subset).
 * SPDX-License-Identifier: GPL-2.0-only
 *
 * Invariant while a port is open: semaphore count + tokens held by woken
 * waiters that have not yet re-entered the lock == queued packets. Every
 * removed packet consumes exactly one token, so a woken waiter always finds
 * a packet and no packet is ever delivered twice or lost.
 */
#include "lc_iocp.h"

#define LC_MAGIC 0x4c43494fu /* "LCIO" */
#define LC_GEN_MASK 0x00ffffffu
enum { PORT_FREE = 0, PORT_OPEN = 1, PORT_CLOSING = 2, PORT_RETAINED = 3 };

static int fail(uint32_t *error, uint32_t value)
{
    if (error) *error = value;
    return 0;
}

static uint32_t backend_error(lc_iocp_context *c)
{
    uint32_t e = c->ops.error(c->ops.opaque);
    return e ? e : LC_BAD_BACKEND;
}

int lc_iocp_init(lc_iocp_context *c, const lc_iocp_ops *ops)
{
    size_t i;
    lc_iocp_ops saved;
    if (!c || !ops || !ops->enter || !ops->leave || !ops->sem_create || !ops->sem_release ||
        !ops->sem_wait || !ops->sem_close || !ops->error)
        return 0;
    saved = *ops;
    for (i = 0; i < sizeof(*c); i++) ((unsigned char *)c)[i] = 0;
    c->ops = saved;
    for (i = 0; i < LC_PORT_CAPACITY; i++) {
        c->ports[i].generation = 1;
        c->ports[i].head = c->ports[i].tail = -1;
    }
    for (i = 0; i < LC_PACKET_CAPACITY; i++)
        c->packets[i].next = i + 1 < LC_PACKET_CAPACITY ? (int)(i + 1) : -1;
    c->free_packet = 0;
    c->magic = LC_MAGIC;
    return 1;
}

/* Caller holds the lock. Returns the open port or NULL. */
static lc_port *lookup(lc_iocp_context *c, uint32_t handle)
{
    uint32_t index = (handle & 0xffu);
    lc_port *port;
    if (!index || index > LC_PORT_CAPACITY) return 0;
    port = &c->ports[index - 1];
    if (port->state != PORT_OPEN || port->generation != (handle >> 8)) return 0;
    return port;
}

static void discard_packets(lc_iocp_context *c, lc_port *port)
{
    while (port->head >= 0) {
        int index = port->head;
        port->head = c->packets[index].next;
        c->packets[index].overlapped = 0;
        c->packets[index].next = c->free_packet;
        c->free_packet = index;
    }
    port->tail = -1;
    port->queued = 0;
}

/* Caller holds the lock; port is closing, has no waiters and the caller is the
 * closer (it owns the drain semaphore). A failed semaphore close retains the
 * slot forever (never reused). */
static uint32_t finalize(lc_iocp_context *c, lc_port *port)
{
    uint32_t e = 0;
    if (port->drain && !c->ops.sem_close(c->ops.opaque, port->drain)) e = backend_error(c);
    port->drain = 0;
    if (!c->ops.sem_close(c->ops.opaque, port->semaphore) && !e) e = backend_error(c);
    if (e) {
        port->state = PORT_RETAINED;
        c->retained++;
        return e;
    }
    port->semaphore = 0;
    port->generation = (port->generation + 1) & LC_GEN_MASK;
    if (!port->generation) port->generation = 1;
    port->state = PORT_FREE;
    return 0;
}

int lc_iocp_create(lc_iocp_context *c, uint32_t concurrency, uint32_t *handle, uint32_t *error)
{
    unsigned i;
    lc_port *port;
    (void)concurrency; /* scheduling hint only; documented as not throttled */
    if (error) *error = 0;
    if (!c || c->magic != LC_MAGIC || !handle) return fail(error, LC_INVALID_PARAMETER);
    *handle = 0;
    c->ops.enter(c->ops.opaque);
    for (i = 0; i < LC_PORT_CAPACITY; i++)
        if (c->ports[i].state == PORT_FREE) break;
    if (i == LC_PORT_CAPACITY) {
        c->ops.leave(c->ops.opaque);
        return fail(error, LC_NO_SYSTEM_RESOURCES);
    }
    port = &c->ports[i];
    port->semaphore = c->ops.sem_create(c->ops.opaque, 0x7fffffffu);
    if (!port->semaphore) {
        uint32_t e = backend_error(c);
        c->ops.leave(c->ops.opaque);
        return fail(error, e);
    }
    port->drain = c->ops.sem_create(c->ops.opaque, 1);
    if (!port->drain) {
        uint32_t e = backend_error(c);
        c->ops.sem_close(c->ops.opaque, port->semaphore);
        port->semaphore = 0;
        c->ops.leave(c->ops.opaque);
        return fail(error, e);
    }
    port->state = PORT_OPEN;
    port->waiters = port->queued = 0;
    port->head = port->tail = -1;
    c->open_ports++;
    *handle = (port->generation << 8) | (i + 1);
    c->ops.leave(c->ops.opaque);
    return 1;
}

int lc_iocp_associate(lc_iocp_context *c, uint32_t handle, uintptr_t file, uintptr_t key, uint32_t *error)
{
    int valid;
    (void)key;
    if (error) *error = 0;
    if (!c || c->magic != LC_MAGIC) return fail(error, LC_INVALID_PARAMETER);
    c->ops.enter(c->ops.opaque);
    valid = lookup(c, handle) != 0;
    c->ops.leave(c->ops.opaque);
    if (!valid || !file) return fail(error, LC_INVALID_HANDLE);
    /* Win98 has no overlapped disk I/O completion source to bind; sockets need
     * a separate Winsock2 event bridge. Report the real gap. */
    return fail(error, LC_NOT_SUPPORTED);
}

int lc_iocp_validate(lc_iocp_context *c, uint32_t handle, uint32_t *error)
{
    int valid;
    if (error) *error = 0;
    if (!c || c->magic != LC_MAGIC) return fail(error, LC_INVALID_PARAMETER);
    c->ops.enter(c->ops.opaque);
    valid = lookup(c, handle) != 0;
    c->ops.leave(c->ops.opaque);
    return valid ? 1 : fail(error, LC_INVALID_HANDLE);
}

int lc_iocp_post(lc_iocp_context *c, uint32_t handle, uint32_t bytes, uintptr_t key, void *overlapped, uint32_t *error)
{
    lc_port *port;
    int index;
    if (error) *error = 0;
    if (!c || c->magic != LC_MAGIC) return fail(error, LC_INVALID_PARAMETER);
    c->ops.enter(c->ops.opaque);
    port = lookup(c, handle);
    if (!port) {
        c->ops.leave(c->ops.opaque);
        return fail(error, LC_INVALID_HANDLE);
    }
    index = c->free_packet;
    if (index < 0) {
        c->ops.leave(c->ops.opaque);
        return fail(error, LC_NO_SYSTEM_RESOURCES);
    }
    c->free_packet = c->packets[index].next;
    c->packets[index].key = key;
    c->packets[index].overlapped = overlapped;
    c->packets[index].bytes = bytes;
    c->packets[index].next = -1;
    if (!c->ops.sem_release(c->ops.opaque, port->semaphore, 1)) {
        uint32_t e = backend_error(c);
        c->packets[index].overlapped = 0;
        c->packets[index].next = c->free_packet;
        c->free_packet = index;
        c->ops.leave(c->ops.opaque);
        return fail(error, e);
    }
    if (port->tail < 0) port->head = index;
    else c->packets[port->tail].next = index;
    port->tail = index;
    port->queued++;
    c->ops.leave(c->ops.opaque);
    return 1;
}

static void take(lc_iocp_context *c, lc_port *port, lc_entry *out)
{
    int index = port->head;
    lc_packet *packet = &c->packets[index];
    port->head = packet->next;
    if (port->head < 0) port->tail = -1;
    port->queued--;
    out->key = packet->key;
    out->overlapped = packet->overlapped;
    out->internal = 0; /* STATUS_SUCCESS for posted packets */
    out->bytes = packet->bytes;
    packet->overlapped = 0;
    packet->next = c->free_packet;
    c->free_packet = index;
}

int lc_iocp_get(lc_iocp_context *c, uint32_t handle, lc_entry *entries, uint32_t count,
                uint32_t *removed, uint32_t timeout_ms, uint32_t *error)
{
    lc_port *port;
    uintptr_t semaphore;
    uint32_t result, outcome = 0, n = 0;
    if (error) *error = 0;
    if (removed) *removed = 0;
    if (!c || c->magic != LC_MAGIC || !entries || !removed || !count)
        return fail(error, LC_INVALID_PARAMETER);
    c->ops.enter(c->ops.opaque);
    port = lookup(c, handle);
    if (!port) {
        c->ops.leave(c->ops.opaque);
        return fail(error, LC_INVALID_HANDLE);
    }
    port->waiters++; /* pins the slot and semaphore across the unlocked wait */
    semaphore = port->semaphore;
    c->ops.leave(c->ops.opaque);

    result = c->ops.sem_wait(c->ops.opaque, semaphore, timeout_ms);

    c->ops.enter(c->ops.opaque);
    port->waiters--;
    if (result == LC_WAIT_FAILED) outcome = backend_error(c);
    else if (result != 0 && result != LC_WAIT_TIMEOUT) outcome = LC_BAD_BACKEND;
    if (port->state != PORT_OPEN) {
        /* Closing (or retained after a refused wake): the closer owns slot
         * finalization. The last waiter out signals it while still holding the
         * lock, so the closer's re-entry orders after this leave(). */
        if (port->state == PORT_CLOSING && !port->waiters)
            (void)c->ops.sem_release(c->ops.opaque, port->drain, 1);
        c->ops.leave(c->ops.opaque);
        return fail(error, LC_ABANDONED_WAIT_0);
    }
    if (outcome || result == LC_WAIT_TIMEOUT) {
        c->ops.leave(c->ops.opaque);
        return fail(error, outcome ? outcome : LC_WAIT_TIMEOUT);
    }
    /* One token held: at least one packet is queued. */
    take(c, port, &entries[n++]);
    while (n < count && port->queued) {
        /* Extra packets need their own tokens; a token already owned by an
         * in-flight waiter is never taken here. */
        if (c->ops.sem_wait(c->ops.opaque, semaphore, 0) != 0) break;
        take(c, port, &entries[n++]);
    }
    c->ops.leave(c->ops.opaque);
    *removed = n;
    return 1;
}

int lc_iocp_close(lc_iocp_context *c, uint32_t handle, uint32_t *error)
{
    lc_port *port;
    uint32_t e = 0;
    if (error) *error = 0;
    if (!c || c->magic != LC_MAGIC) return fail(error, LC_INVALID_PARAMETER);
    c->ops.enter(c->ops.opaque);
    port = lookup(c, handle);
    if (!port) {
        c->ops.leave(c->ops.opaque);
        return fail(error, LC_INVALID_HANDLE);
    }
    port->state = PORT_CLOSING; /* handle is dead from here on; no new getter can join */
    c->open_ports--;
    discard_packets(c, port);
    if (port->waiters) {
        /* Waking failed waiters is required for liveness. If the backend
         * refuses, nobody can be waited for: retain the slot, never reuse it. */
        if (!c->ops.sem_release(c->ops.opaque, port->semaphore, port->waiters)) {
            e = backend_error(c);
            port->state = PORT_RETAINED;
            c->retained++;
            c->ops.leave(c->ops.opaque);
            return fail(error, e);
        }
        /* Quiescence: wait until the last getter has left. The timeout only
         * bounds one sleep; the loop re-checks the authoritative counter. */
        while (port->waiters) {
            uint32_t r;
            c->ops.leave(c->ops.opaque);
            r = c->ops.sem_wait(c->ops.opaque, port->drain, 50);
            c->ops.enter(c->ops.opaque);
            if (r == LC_WAIT_FAILED) {
                e = backend_error(c);
                port->state = PORT_RETAINED; /* cannot prove quiescence */
                c->retained++;
                c->ops.leave(c->ops.opaque);
                return fail(error, e);
            }
        }
    }
    e = finalize(c, port);
    c->ops.leave(c->ops.opaque);
    return e ? fail(error, e) : 1;
}

unsigned lc_iocp_open_ports(lc_iocp_context *c)
{
    unsigned n;
    if (!c || c->magic != LC_MAGIC) return 0;
    c->ops.enter(c->ops.opaque);
    n = c->open_ports;
    c->ops.leave(c->ops.opaque);
    return n;
}

unsigned lc_iocp_busy(lc_iocp_context *c)
{
    unsigned i, n = 0;
    if (!c || c->magic != LC_MAGIC) return 0;
    c->ops.enter(c->ops.opaque);
    for (i = 0; i < LC_PORT_CAPACITY; i++)
        if (c->ports[i].state == PORT_OPEN || c->ports[i].state == PORT_CLOSING || c->ports[i].waiters) n++;
    c->ops.leave(c->ops.opaque);
    return n;
}
