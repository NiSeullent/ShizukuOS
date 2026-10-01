/* SPDX-License-Identifier: GPL-2.0-only -- original freestanding single-owner service. */
#ifndef SHZ_PMA_SERVICE_H
#define SHZ_PMA_SERVICE_H
#include "../abi/shz_ipc.h"
#include "../abi/shz_vmm_pma.h"

#define SHZ_PMA_MAX_OWNERS 8u
#define SHZ_PMA_MAX_THREADS 32u
#define SHZ_PMA_MAX_OBJECTS 32u
#define SHZ_PMA_MAX_WAITS 64u
#define SHZ_PMA_MAX_COMPLETIONS 128u
_Static_assert(SHZ_PMA_MAX_COMPLETIONS >= SHZ_PMA_MAX_WAITS + 2u,
               "WAIT reservations must leave control completion capacity");

typedef struct { shz_msg_hdr_t header; uint8_t payload[64]; } shz_pma_frame_t;
typedef struct {
    uint32_t initialized, self_domain, peer_domain, generation, stopped;
    uint64_t last_sequence;
    uint32_t ready_head, ready_tail;
    struct { uint32_t pid, generation, state; } owners[SHZ_PMA_MAX_OWNERS];
    struct { uint32_t owner, tid, generation, state; } threads[SHZ_PMA_MAX_THREADS];
    struct { uint32_t generation, owner, used, manual, signaled; } objects[SHZ_PMA_MAX_OBJECTS];
    struct {
        uint32_t used, object, owner, thread, completion;
        uint64_t deadline_ns;
    } waits[SHZ_PMA_MAX_WAITS];
    struct {
        uint32_t state, next_ready;
        shz_pma_frame_t frame;
    } completions[SHZ_PMA_MAX_COMPLETIONS];
} shz_pma_service_t;

static inline int shz_pma_service_init(shz_pma_service_t *s, uint32_t self_domain,
                                      uint32_t peer_domain, uint32_t generation)
{
    if (!s || !generation || !self_domain || !peer_domain || self_domain == peer_domain ||
        self_domain >= SHZ_DOM_MAX || peer_domain >= SHZ_DOM_MAX)
        return SHZ_E_INVALID;
    SHZ_IPC_MEMSET(s, 0, sizeof *s);
    s->self_domain = self_domain; s->peer_domain = peer_domain; s->generation = generation;
    s->ready_head = s->ready_tail = SHZ_PMA_MAX_COMPLETIONS;
    s->initialized = SHZ_PMA_MAGIC;
    return SHZ_OK;
}

/* Every admitted request owns one completion slot, including a pending WAIT.
 * The ready list does not reuse request IDs or wrap an ordering counter. */
static inline void shz_pma_ready(shz_pma_service_t *s, uint32_t index, int32_t status)
{
    shz_pma_completion_t completion;
    SHZ_IPC_MEMCPY(&completion, s->completions[index].frame.payload, sizeof completion);
    completion.status = status;
    SHZ_IPC_MEMCPY(s->completions[index].frame.payload, &completion, sizeof completion);
    s->completions[index].frame.header.status = status;
    s->completions[index].state = 2;
    s->completions[index].next_ready = SHZ_PMA_MAX_COMPLETIONS;
    if (s->ready_tail < SHZ_PMA_MAX_COMPLETIONS)
        s->completions[s->ready_tail].next_ready = index;
    else
        s->ready_head = index;
    s->ready_tail = index;
}

static inline void shz_pma_finish_wait(shz_pma_service_t *s, uint32_t index, int32_t status)
{
    shz_pma_ready(s, s->waits[index].completion, status);
    s->waits[index].used = 0;
}

static inline unsigned shz_pma_service_tick(shz_pma_service_t *s, uint64_t now_ns)
{
    uint32_t i;
    unsigned expired = 0;
    if (!s || s->initialized != SHZ_PMA_MAGIC)
        return 0;
    for (i = 0; i < SHZ_PMA_MAX_WAITS; ++i)
        if (s->waits[i].used && s->waits[i].deadline_ns != UINT64_MAX &&
            now_ns >= s->waits[i].deadline_ns) {
            shz_pma_finish_wait(s, i, SHZ_E_TIMEOUT);
            ++expired;
        }
    return expired;
}

static inline const shz_pma_frame_t *shz_pma_service_peek(const shz_pma_service_t *s)
{
    return s && s->initialized == SHZ_PMA_MAGIC && s->ready_head < SHZ_PMA_MAX_COMPLETIONS
           ? &s->completions[s->ready_head].frame : 0;
}
static inline int shz_pma_service_ack(shz_pma_service_t *s, uint64_t request_id)
{
    const shz_pma_frame_t *frame = shz_pma_service_peek(s);
    uint32_t index;
    if (!frame || frame->header.request_id != request_id)
        return SHZ_E_NOENT;
    index = s->ready_head;
    s->ready_head = s->completions[index].next_ready;
    if (s->ready_head == SHZ_PMA_MAX_COMPLETIONS)
        s->ready_tail = SHZ_PMA_MAX_COMPLETIONS;
    SHZ_IPC_MEMSET(&s->completions[index], 0, sizeof s->completions[index]);
    return SHZ_OK;
}

static inline int shz_pma_service_restart(shz_pma_service_t *s, uint32_t generation)
{
    if (!s || s->initialized != SHZ_PMA_MAGIC || !generation || generation <= s->generation)
        return SHZ_E_INVALID;
    return shz_pma_service_init(s, s->self_domain, s->peer_domain, generation);
}

static inline void shz_pma_frame_init(shz_pma_service_t *s, uint32_t slot,
                                     const shz_msg_hdr_t *m, const shz_pma_request_t *r)
{
    shz_pma_completion_t c;
    shz_pma_frame_t *f = &s->completions[slot].frame;
    SHZ_IPC_MEMSET(f, 0, sizeof *f);
    f->header.magic = SHZ_MSG_MAGIC;
    f->header.abi_major = SHZ_ABI_MAJOR; f->header.abi_minor = SHZ_ABI_MINOR;
    f->header.header_size = sizeof f->header; f->header.flags = SHZ_MSGF_REPLY;
    f->header.message_size = sizeof *f;
    f->header.opcode = m->opcode;
    f->header.src_domain = (uint16_t)s->self_domain; f->header.dst_domain = (uint16_t)s->peer_domain;
    f->header.generation = s->generation; f->header.request_id = m->request_id;
    f->header.payload_offset = sizeof f->header; f->header.payload_length = sizeof c;
    SHZ_IPC_MEMSET(&c, 0, sizeof c);
    c.magic = SHZ_PMA_MAGIC; c.abi_major = SHZ_PMA_ABI_MAJOR; c.abi_minor = SHZ_PMA_ABI_MINOR;
    c.size = sizeof c; c.features = SHZ_PMA_FEATURES;
    c.domain = r->domain; c.pid = r->pid; c.tid = r->tid;
    c.owner_generation = r->owner_generation; c.thread_generation = r->thread_generation;
    c.object = r->object; c.sequence = m->request_id;
    SHZ_IPC_MEMCPY(f->payload, &c, sizeof c);
    s->completions[slot].state = 1;
}

static inline int shz_pma_object_index(const shz_pma_service_t *s, uint32_t handle,
                                      uint32_t owner, uint32_t *index)
{
    const uint32_t low = handle & 0xffffu, generation = handle >> 16;
    if (!low || low > SHZ_PMA_MAX_OBJECTS || !generation)
        return SHZ_E_NOENT;
    *index = low - 1;
    if (!s->objects[*index].used || s->objects[*index].generation != generation)
        return SHZ_E_NOENT;
    return s->objects[*index].owner == owner ? SHZ_OK : SHZ_E_DENIED;
}

static inline void shz_pma_release_object(shz_pma_service_t *s, uint32_t object)
{
    uint32_t i;
    for (i = 0; i < SHZ_PMA_MAX_WAITS; ++i)
        if (s->waits[i].used && s->waits[i].object == object)
            shz_pma_finish_wait(s, i, SHZ_E_CANCELLED);
    s->objects[object].used = s->objects[object].signaled = 0;
}

static inline int shz_pma_service_shutdown(shz_pma_service_t *s)
{
    uint32_t i;
    if (!s || s->initialized != SHZ_PMA_MAGIC)
        return SHZ_E_INVALID;
    if (s->stopped)
        return SHZ_OK;
    s->stopped = 1;
    /* Each deferred WAIT already owns its terminal completion: shutdown
     * needs no free slots and leaves already-ready replies unchanged. */
    for (i = 0; i < SHZ_PMA_MAX_WAITS; ++i)
        if (s->waits[i].used) shz_pma_finish_wait(s, i, SHZ_E_CANCELLED);
    for (i = 0; i < SHZ_PMA_MAX_OBJECTS; ++i)
        s->objects[i].used = s->objects[i].signaled = 0;
    for (i = 0; i < SHZ_PMA_MAX_THREADS; ++i)
        if (s->threads[i].state) s->threads[i].state = 2;
    for (i = 0; i < SHZ_PMA_MAX_OWNERS; ++i)
        if (s->owners[i].state) s->owners[i].state = 2;
    return SHZ_OK;
}

static inline void shz_pma_wake_event(shz_pma_service_t *s, uint32_t object)
{
    uint32_t i, oldest = SHZ_PMA_MAX_WAITS;
    uint64_t oldest_id = UINT64_MAX;
    for (i = 0; i < SHZ_PMA_MAX_WAITS; ++i) {
        uint64_t id;
        if (!s->waits[i].used || s->waits[i].object != object)
            continue;
        if (s->objects[object].manual)
            shz_pma_finish_wait(s, i, SHZ_OK);
        else {
            id = s->completions[s->waits[i].completion].frame.header.request_id;
            if (oldest == SHZ_PMA_MAX_WAITS || id < oldest_id) { oldest = i; oldest_id = id; }
        }
    }
    if (s->objects[object].manual)
        s->objects[object].signaled = 1;
    else if (oldest < SHZ_PMA_MAX_WAITS) {
        shz_pma_finish_wait(s, oldest, SHZ_OK);
        s->objects[object].signaled = 0;
    } else
        s->objects[object].signaled = 1;
}

/* Caller has already verified the ring CRC. Dispatch copies the fixed payload
 * and checks its envelope. E_QUEUE_FULL leaves the request unaccepted: retain
 * the input and retry after transmitting ready completions. Other rejected
 * requests do not consume sequence IDs and produce no service completion. */
static inline int shz_pma_service_dispatch(shz_pma_service_t *s, const shz_msg_hdr_t *m,
                                          const void *payload, uint64_t now_ns)
{
    shz_pma_request_t r;
    uint32_t i, owner = SHZ_PMA_MAX_OWNERS, owner_free = SHZ_PMA_MAX_OWNERS;
    uint32_t thread = SHZ_PMA_MAX_THREADS, thread_free = SHZ_PMA_MAX_THREADS;
    uint32_t completion = SHZ_PMA_MAX_COMPLETIONS, object = 0;
    int status = SHZ_OK, revive = 0;
    if (!s || s->initialized != SHZ_PMA_MAGIC || !m || !payload)
        return SHZ_E_INVALID;
    if (s->stopped)
        return SHZ_E_CANCELLED;
    if (m->generation != s->generation || !m->request_id || m->request_id <= s->last_sequence)
        return SHZ_E_STALE;
    if (m->src_domain != s->peer_domain || m->dst_domain != s->self_domain)
        return SHZ_E_DENIED;
    if (m->magic != SHZ_MSG_MAGIC || m->abi_major != SHZ_ABI_MAJOR ||
        m->header_size != sizeof *m || m->flags || m->payload_length != sizeof r ||
        m->payload_offset != sizeof *m || m->message_size != sizeof *m + sizeof r ||
        m->buffer_offset || m->buffer_length || m->capability_id)
        return SHZ_E_PROTO;
    if (m->opcode < SHZ_OP_PMA_QUERY || m->opcode > SHZ_OP_PMA_PROCESS_EXIT)
        return SHZ_E_UNSUPPORTED;
    SHZ_IPC_MEMCPY(&r, payload, sizeof r);
    if (r.magic != SHZ_PMA_MAGIC || r.size != sizeof r)
        return SHZ_E_PROTO;
    if (r.abi_major != SHZ_PMA_ABI_MAJOR || (r.required_features & ~SHZ_PMA_FEATURES))
        return SHZ_E_UNSUPPORTED;
    if (r.domain != s->peer_domain)
        return SHZ_E_DENIED;
    if (!r.pid || !r.tid || !r.owner_generation || !r.thread_generation ||
        (m->opcode == SHZ_OP_PMA_EVENT_CREATE ? (r.flags & ~3u) : r.flags) ||
        (m->opcode != SHZ_OP_PMA_EVENT_WAIT && r.deadline_ns) ||
        (m->opcode != SHZ_OP_PMA_CANCEL && r.target_sequence) ||
        ((m->opcode == SHZ_OP_PMA_QUERY || m->opcode == SHZ_OP_PMA_EVENT_CREATE ||
          m->opcode >= SHZ_OP_PMA_CANCEL) && r.object))
        return SHZ_E_INVALID;
    for (i = 0; i < SHZ_PMA_MAX_OWNERS; ++i) {
        if (s->owners[i].state && s->owners[i].pid == r.pid) { owner = i; break; }
        if (!s->owners[i].state && owner_free == SHZ_PMA_MAX_OWNERS) owner_free = i;
    }
    if (owner < SHZ_PMA_MAX_OWNERS) {
        if (s->owners[owner].state == 2) {
            if (r.owner_generation <= s->owners[owner].generation) return SHZ_E_STALE;
            revive = 1;
        } else if (r.owner_generation != s->owners[owner].generation)
            return SHZ_E_STALE;
    } else {
        if (owner_free == SHZ_PMA_MAX_OWNERS) return SHZ_E_NOMEM;
        owner = owner_free;
    }
    /* Process death is authorized by the process lifetime, independently of
     * any notifying thread. The last thread can already be dead, and rundown
     * must work even when all thread identity slots are occupied. */
    if (m->opcode != SHZ_OP_PMA_PROCESS_EXIT) {
        for (i = 0; i < SHZ_PMA_MAX_THREADS; ++i) {
            if (!revive && s->threads[i].state && s->threads[i].owner == owner && s->threads[i].tid == r.tid) {
                thread = i; break;
            }
            if ((!s->threads[i].state || (revive && s->threads[i].owner == owner)) &&
                thread_free == SHZ_PMA_MAX_THREADS) thread_free = i;
        }
        if (thread < SHZ_PMA_MAX_THREADS) {
            if (s->threads[thread].state == 2 ? r.thread_generation <= s->threads[thread].generation
                                              : r.thread_generation != s->threads[thread].generation)
                return SHZ_E_STALE;
        } else {
            if (thread_free == SHZ_PMA_MAX_THREADS) return SHZ_E_NOMEM;
            thread = thread_free;
        }
    }
    for (i = 0; i < SHZ_PMA_MAX_COMPLETIONS; ++i)
        if (!s->completions[i].state) { completion = i; break; }
    if (completion == SHZ_PMA_MAX_COMPLETIONS)
        return SHZ_E_QUEUE_FULL;
    if (revive)
        for (i = 0; i < SHZ_PMA_MAX_THREADS; ++i)
            if (s->threads[i].state && s->threads[i].owner == owner)
                SHZ_IPC_MEMSET(&s->threads[i], 0, sizeof s->threads[i]);
    s->owners[owner].pid = r.pid; s->owners[owner].generation = r.owner_generation; s->owners[owner].state = 1;
    if (m->opcode != SHZ_OP_PMA_PROCESS_EXIT) {
        s->threads[thread].owner = owner; s->threads[thread].tid = r.tid;
        s->threads[thread].generation = r.thread_generation; s->threads[thread].state = 1;
    }
    shz_pma_frame_init(s, completion, m, &r);
    s->last_sequence = m->request_id;
    (void)shz_pma_service_tick(s, now_ns);
    if (m->opcode == SHZ_OP_PMA_QUERY) {
        shz_pma_info_t info;
        SHZ_IPC_MEMSET(&info, 0, sizeof info);
        info.magic = SHZ_PMA_MAGIC; info.abi_major = SHZ_PMA_ABI_MAJOR; info.abi_minor = SHZ_PMA_ABI_MINOR;
        info.size = sizeof info; info.features = SHZ_PMA_FEATURES;
        info.max_owners = SHZ_PMA_MAX_OWNERS; info.max_threads = SHZ_PMA_MAX_THREADS;
        info.max_objects = SHZ_PMA_MAX_OBJECTS; info.max_waits = SHZ_PMA_MAX_WAITS;
        info.max_completions = SHZ_PMA_MAX_COMPLETIONS; info.now_ns = now_ns;
        info.generation = s->generation; info.self_domain = s->self_domain; info.peer_domain = s->peer_domain;
        shz_pma_ready(s, completion, SHZ_OK);
        SHZ_IPC_MEMCPY(s->completions[completion].frame.payload, &info, sizeof info);
        return SHZ_OK;
    }
    if (m->opcode == SHZ_OP_PMA_EVENT_CREATE) {
        shz_pma_completion_t c;
        for (i = 0; i < SHZ_PMA_MAX_OBJECTS; ++i)
            if (!s->objects[i].used && s->objects[i].generation < 0xffffu) break;
        if (i == SHZ_PMA_MAX_OBJECTS)
            status = SHZ_E_NOMEM;
        else {
            s->objects[i].used = 1; s->objects[i].owner = owner; ++s->objects[i].generation;
            s->objects[i].manual = (r.flags & SHZ_PMA_EVENT_MANUAL_RESET) != 0;
            s->objects[i].signaled = (r.flags & SHZ_PMA_EVENT_SIGNALED) != 0;
            SHZ_IPC_MEMCPY(&c, s->completions[completion].frame.payload, sizeof c);
            c.object = (s->objects[i].generation << 16) | (i + 1);
            SHZ_IPC_MEMCPY(s->completions[completion].frame.payload, &c, sizeof c);
        }
    } else if (m->opcode >= SHZ_OP_PMA_EVENT_WAIT && m->opcode <= SHZ_OP_PMA_EVENT_CLOSE) {
        status = shz_pma_object_index(s, r.object, owner, &object);
        if (status == SHZ_OK) {
            switch (m->opcode) {
            case SHZ_OP_PMA_EVENT_WAIT:
                if (s->objects[object].signaled) {
                    if (!s->objects[object].manual) s->objects[object].signaled = 0;
                } else if (r.deadline_ns != UINT64_MAX && now_ns >= r.deadline_ns)
                    status = SHZ_E_TIMEOUT;
                else {
                    for (i = 0; i < SHZ_PMA_MAX_WAITS; ++i) if (!s->waits[i].used) break;
                    if (i == SHZ_PMA_MAX_WAITS) status = SHZ_E_BUSY;
                    else {
                        s->waits[i].used = 1; s->waits[i].object = object;
                        s->waits[i].owner = owner; s->waits[i].thread = thread;
                        s->waits[i].completion = completion; s->waits[i].deadline_ns = r.deadline_ns;
                        return SHZ_OK;
                    }
                }
                break;
            case SHZ_OP_PMA_EVENT_SIGNAL: shz_pma_wake_event(s, object); break;
            case SHZ_OP_PMA_EVENT_RESET: s->objects[object].signaled = 0; break;
            case SHZ_OP_PMA_EVENT_CLOSE: shz_pma_release_object(s, object); break;
            default: break;
            }
        }
    } else if (m->opcode == SHZ_OP_PMA_CANCEL) {
        status = SHZ_E_NOENT;
        for (i = 0; i < SHZ_PMA_MAX_WAITS; ++i)
            if (s->waits[i].used && s->waits[i].owner == owner && s->waits[i].thread == thread &&
                s->completions[s->waits[i].completion].frame.header.request_id == r.target_sequence) {
                shz_pma_finish_wait(s, i, SHZ_E_CANCELLED); status = SHZ_OK; break;
            }
    } else if (m->opcode == SHZ_OP_PMA_THREAD_EXIT) {
        for (i = 0; i < SHZ_PMA_MAX_WAITS; ++i)
            if (s->waits[i].used && s->waits[i].thread == thread)
                shz_pma_finish_wait(s, i, SHZ_E_CANCELLED);
        s->threads[thread].state = 2;
    } else if (m->opcode == SHZ_OP_PMA_PROCESS_EXIT) {
        for (i = 0; i < SHZ_PMA_MAX_OBJECTS; ++i)
            if (s->objects[i].used && s->objects[i].owner == owner) shz_pma_release_object(s, i);
        for (i = 0; i < SHZ_PMA_MAX_THREADS; ++i)
            if (s->threads[i].state && s->threads[i].owner == owner) s->threads[i].state = 2;
        s->owners[owner].state = 2;
    }
    shz_pma_ready(s, completion, status);
    return SHZ_OK;
}
#endif
