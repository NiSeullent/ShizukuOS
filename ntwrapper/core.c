/* SPDX-License-Identifier: GPL-2.0-only */
#include "include/ntwrapper.h"
static int valid(const struct ntw_context *c) {
    return c && c->version == NTW_ABI_VERSION && c->lock.enter && c->lock.leave;
}
static struct ntw_object *lookup(struct ntw_context *c, ntw_handle h,
                                  uint32_t access, int *status) {
    uint32_t index = h & 0xffffu, generation = h >> 16;
    struct ntw_object *o;
    *status = NTW_BAD_HANDLE;
    if (!index || index > NTW_MAX_OBJECTS || !generation) return NULL;
    o = &c->objects[index - 1];
    if (!o->occupied || !o->open || o->generation != generation) return NULL;
    if ((access & o->access) != access) { *status = NTW_ACCESS_DENIED; return NULL; }
    *status = NTW_OK;
    return o;
}
int ntw_initialize(struct ntw_context *c, const struct ntw_lock_ops *ops) {
    uint32_t i;
    if (!c || !ops || !ops->enter || !ops->leave) return NTW_INVALID;
    /* Initialization requires exclusive ownership of uninitialized storage. */
    c->lock = *ops;
    for (i = 0; i < NTW_MAX_OBJECTS; ++i) {
        struct ntw_object *o = &c->objects[i];
        o->generation = o->references = o->access = 0;
        o->occupied = o->open = o->manual_reset = o->signaled = 0;
    }
    c->version = NTW_ABI_VERSION;
    return NTW_OK;
}
int ntw_event_create(struct ntw_context *c, int manual, int signaled,
                     uint32_t access, ntw_handle *out) {
    uintptr_t saved;
    uint32_t i;
    if (!valid(c) || !out || (access & ~NTW_EVENT_ALL) ||
        (manual != 0 && manual != 1) || (signaled != 0 && signaled != 1))
        return NTW_INVALID;
    *out = 0;
    saved = c->lock.enter(c->lock.opaque);
    for (i = 0; i < NTW_MAX_OBJECTS; ++i) {
        struct ntw_object *o = &c->objects[i];
        /* Retire a slot rather than resurrect an old handle on wrap. */
        if (o->occupied || o->generation == 0xffffu) continue;
        ++o->generation;
        o->occupied = o->open = 1;
        o->references = 1;
        o->manual_reset = (uint8_t)manual;
        o->signaled = (uint8_t)signaled;
        o->access = access;
        *out = (o->generation << 16) | (i + 1u);
        break;
    }
    c->lock.leave(c->lock.opaque, saved);
    return *out ? NTW_OK : NTW_NO_MEMORY;
}
int ntw_reference(struct ntw_context *c, ntw_handle h, uint32_t access,
                  struct ntw_lease *lease) {
    uintptr_t saved;
    struct ntw_object *o;
    int status;
    if (!valid(c) || !lease || lease->owner || (access & ~NTW_EVENT_ALL)) return NTW_INVALID;
    saved = c->lock.enter(c->lock.opaque);
    o = lookup(c, h, access, &status);
    if (o) {
        if (o->references == UINT32_MAX) status = NTW_NO_MEMORY;
        else {
            ++o->references;
            lease->owner = c; lease->index = (h & 0xffffu) - 1;
            lease->generation = h >> 16;
        }
    }
    c->lock.leave(c->lock.opaque, saved);
    return status;
}
int ntw_dereference(struct ntw_lease *lease) {
    struct ntw_context *c;
    struct ntw_object *o;
    uintptr_t saved;
    int status = NTW_BAD_HANDLE;
    if (!lease || !valid(lease->owner) || lease->index >= NTW_MAX_OBJECTS)
        return NTW_INVALID;
    c = lease->owner;
    saved = c->lock.enter(c->lock.opaque);
    o = &c->objects[lease->index];
    if (o->occupied && o->generation == lease->generation &&
        o->references > (uint32_t)o->open) {
        if (--o->references == 0) o->occupied = 0;
        lease->owner = NULL;
        status = NTW_OK;
    }
    c->lock.leave(c->lock.opaque, saved);
    return status;
}
int ntw_close(struct ntw_context *c, ntw_handle h) {
    uintptr_t saved;
    int status;
    struct ntw_object *o;
    if (!valid(c)) return NTW_INVALID;
    saved = c->lock.enter(c->lock.opaque);
    o = lookup(c, h, 0, &status);
    if (o) { o->open = 0; if (--o->references == 0) o->occupied = 0; }
    c->lock.leave(c->lock.opaque, saved);
    return status;
}
static int event_op(struct ntw_context *c, ntw_handle h, int op, int *value) {
    uintptr_t saved;
    struct ntw_object *o;
    int status;
    uint32_t access = op == 2 ? NTW_EVENT_QUERY :
                      op == 3 ? NTW_EVENT_WAIT : NTW_EVENT_MODIFY;
    if (!valid(c)) return NTW_INVALID;
    saved = c->lock.enter(c->lock.opaque);
    o = lookup(c, h, access, &status);
    if (o) {
        if (value) *value = o->signaled;
        if (op < 2) o->signaled = (uint8_t)op;
        else if (op == 3) {
            if (!o->signaled) status = NTW_PENDING;
            else if (!o->manual_reset) o->signaled = 0;
        }
    }
    c->lock.leave(c->lock.opaque, saved);
    return status;
}
int ntw_event_set(struct ntw_context *c, ntw_handle h, int *p) { return event_op(c,h,1,p); }
int ntw_event_reset(struct ntw_context *c, ntw_handle h, int *p) { return event_op(c,h,0,p); }
int ntw_event_query(struct ntw_context *c, ntw_handle h, int *p) {
    return p ? event_op(c,h,2,p) : NTW_INVALID;
}
int ntw_event_try_wait(struct ntw_context *c, ntw_handle h) { return event_op(c,h,3,NULL); }
int ntw_shutdown(struct ntw_context *c) {
    uintptr_t saved;
    uint32_t i;
    if (!valid(c)) return NTW_INVALID;
    saved = c->lock.enter(c->lock.opaque);
    for (i = 0; i < NTW_MAX_OBJECTS; ++i) if (c->objects[i].occupied) {
        c->lock.leave(c->lock.opaque, saved); return NTW_BUSY;
    }
    c->version = 0;
    c->lock.leave(c->lock.opaque, saved);
    return NTW_OK;
}
