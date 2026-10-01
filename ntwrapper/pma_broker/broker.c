/* SPDX-License-Identifier: GPL-2.0-only -- original bounded Win98 PMA broker.
 */
#include "broker.h"
#include <stddef.h>
static void zero(void *p, size_t n) {
  uint8_t *q = p;
  while (n--)
    *q++ = 0;
}
static void copy(void *d, const void *s, size_t n) {
  uint8_t *q = d;
  const uint8_t *p = s;
  while (n--)
    *q++ = *p++;
}
/* Owner: 1=live,2=closing,3=dead,4=rundown acked but replies draining.
 * Thread:1=live,2=closing,3=dead. Entries:1=staged,2=sent,3=ready. */
static uint32_t token(const struct ntwp_owner *o, uint32_t i) {
  return (o->generation << 8) | (i + 1u);
}
static int context_ok(const struct ntwp_context *c) {
  return c && c->vm && c->process && c->thread && c->device;
}
static int owner_index(const struct ntwp_broker *s,
                       const struct ntwp_context *c, uint32_t session) {
  uint32_t i = (session & 255u) - 1u;
  if (!s || !context_ok(c) || i >= NTWP_MAX_OWNERS)
    return -1;
  if (s->owners[i].state != 1 || token(&s->owners[i], i) != session ||
      s->owners[i].vm != c->vm || s->owners[i].process != c->process ||
      s->owners[i].device != c->device)
    return -1;
  return (int)i;
}
static int has_pending(const struct ntwp_broker *s, uint32_t o, int t) {
  uint32_t i;
  for (i = 0; i < NTWP_MAX_PENDING; i++)
    if (s->pending[i].state && s->pending[i].owner == o &&
        (t < 0 || s->pending[i].thread == (uint32_t)t))
      return 1;
  return 0;
}
static void collect(struct ntwp_broker *s, uint32_t o) {
  uint32_t i;
  if (s->owners[o].state == 4 && !has_pending(s, o, -1)) {
    s->owners[o].state = 3;
    for (i = 0; i < NTWP_MAX_THREADS; i++)
      if (s->threads[i].owner == o && s->threads[i].state)
        s->threads[i].state = 3;
  }
}
int ntwp_init(struct ntwp_broker *s, uint32_t self, uint32_t peer,
              uint32_t gen) {
  if (!s || self != SHZ_DOM_WIN98 || peer != SHZ_DOM_KERNEL64 || !gen)
    return SHZ_E_INVALID;
  zero(s, sizeof *s);
  s->self = self;
  s->peer = peer;
  s->generation = gen;
  s->next_ticket = UINT64_C(0x8000000000000001);
  return SHZ_OK;
}
int ntwp_open(struct ntwp_broker *s, const struct ntwp_context *c,
              struct ntwp_open_info *out) {
  uint32_t i, free_slot = NTWP_MAX_OWNERS;
  struct ntwp_owner *o;
  if (!s || !context_ok(c) || !out)
    return SHZ_E_INVALID;
  if (s->stopped)
    return SHZ_E_CANCELLED;
  for (i = 0; i < NTWP_MAX_OWNERS; i++) {
    o = &s->owners[i];
    if (o->state && o->state != 3 && o->vm == c->vm &&
        o->process == c->process) {
      if (o->state != 1 || o->device != c->device)
        return SHZ_E_BUSY;
      free_slot = i;
      break;
    }
    if ((!o->state || o->state == 3) && o->generation < 0xffffffu &&
        free_slot == NTWP_MAX_OWNERS)
      free_slot = i;
  }
  if (free_slot == NTWP_MAX_OWNERS)
    return SHZ_E_NOMEM;
  o = &s->owners[free_slot];
  if (o->state != 1) {
    o->generation++;
    o->state = 1;
    o->vm = c->vm;
    o->process = c->process;
    o->device = c->device;
  }
  out->size = sizeof *out;
  out->session = token(o, free_slot);
  out->domain = s->self;
  out->generation = s->generation;
  out->max_pending = NTWP_MAX_USER_PENDING;
  out->max_waits = NTWP_MAX_WAITS;
  out->pid = free_slot + 1u;
  out->owner_generation = o->generation;
  return SHZ_OK;
}
/* A wire TID slot stays bound to its original broker PID. The backend keeps
 * tombstones for (PID,TID) until that PID revives or the channel restarts.
 * Migrating a dead slot to another PID would exhaust the backend registry. */
static int thread_index(struct ntwp_broker *s, uint32_t o, uint32_t native,
                        int create) {
  uint32_t i, free_slot = NTWP_MAX_THREADS;
  for (i = 0; i < NTWP_MAX_THREADS; i++) {
    struct ntwp_thread *t = &s->threads[i];
    if (t->state && t->owner == o && t->native_thread == native) {
      if (t->state == 1)
        return (int)i;
      if (t->state == 2 || has_pending(s, o, (int)i))
        return -1;
    }
    if ((!t->state || (t->state == 3 && t->owner == o &&
                       !has_pending(s, t->owner, (int)i))) &&
        t->generation != UINT32_MAX && free_slot == NTWP_MAX_THREADS)
      free_slot = i;
  }
  if (!create || free_slot == NTWP_MAX_THREADS)
    return -1;
  s->threads[free_slot].state = 1;
  s->threads[free_slot].owner = o;
  s->threads[free_slot].native_thread = native;
  s->threads[free_slot].generation++;
  return (int)free_slot;
}
static struct ntwp_entry *free_entry(struct ntwp_broker *s) {
  uint32_t i;
  for (i = 0; i < NTWP_MAX_PENDING; i++)
    if (!s->pending[i].state)
      return &s->pending[i];
  return 0;
}
static void stage(struct ntwp_broker *s, struct ntwp_entry *e, uint32_t o,
                  uint32_t t, uint32_t opcode, uint32_t internal) {
  zero(e, sizeof *e);
  e->state = 1;
  e->owner = o;
  e->thread = t;
  e->internal = internal;
  e->ticket = s->next_ticket++;
  e->header.request_id = e->ticket;
  e->header.src_domain = (uint16_t)s->self;
  e->header.dst_domain = (uint16_t)s->peer;
  e->header.generation = s->generation;
  e->header.opcode = opcode;
  e->header.payload_length = sizeof e->request;
  e->request.magic = SHZ_PMA_MAGIC;
  e->request.abi_major = SHZ_PMA_ABI_MAJOR;
  e->request.abi_minor = SHZ_PMA_ABI_MINOR;
  e->request.size = sizeof e->request;
  e->request.domain = s->self;
  e->request.pid = o + 1u;
  e->request.tid = t + 1u;
  e->request.owner_generation = s->owners[o].generation;
  e->request.thread_generation = s->threads[t].generation;
}
int ntwp_submit(struct ntwp_broker *s, const struct ntwp_context *c,
                uint32_t session, const struct ntwp_submit *r,
                uint64_t *ticket) {
  int o, t;
  uint32_t i, n = 0, w = 0;
  struct ntwp_entry *e;
  if (!s || !r || !ticket || r->size != sizeof *r ||
      r->opcode < SHZ_OP_PMA_QUERY || r->opcode > SHZ_OP_PMA_CANCEL)
    return SHZ_E_INVALID;
  if (s->stopped)
    return SHZ_E_CANCELLED;
  if (r->required_features & ~SHZ_PMA_FEATURES)
    return SHZ_E_UNSUPPORTED;
  if ((r->opcode == SHZ_OP_PMA_QUERY || r->opcode == SHZ_OP_PMA_EVENT_CREATE ||
       r->opcode == SHZ_OP_PMA_CANCEL) &&
      r->object)
    return SHZ_E_INVALID;
  o = owner_index(s, c, session);
  if (o < 0)
    return SHZ_E_DENIED;
  for (i = 0; i < NTWP_MAX_PENDING; i++)
    if (s->pending[i].state && !s->pending[i].internal) {
      n++;
      if (s->pending[i].header.opcode == SHZ_OP_PMA_EVENT_WAIT)
        w++;
    }
  if (n >= NTWP_MAX_USER_PENDING ||
      (r->opcode == SHZ_OP_PMA_EVENT_WAIT && w >= NTWP_MAX_WAITS))
    return SHZ_E_BUSY;
  if (s->next_ticket == UINT64_MAX)
    return SHZ_E_STALE;
  e = free_entry(s);
  if (!e)
    return SHZ_E_BUSY;
  if (r->flags &&
      (r->opcode != SHZ_OP_PMA_EVENT_CREATE ||
       (r->flags & ~(SHZ_PMA_EVENT_MANUAL_RESET | SHZ_PMA_EVENT_SIGNALED))))
    return SHZ_E_INVALID;
  if (r->opcode != SHZ_OP_PMA_EVENT_WAIT && r->deadline_ns)
    return SHZ_E_INVALID;
  if (r->opcode != SHZ_OP_PMA_CANCEL && r->target_ticket)
    return SHZ_E_INVALID;
  t = thread_index(s, (uint32_t)o, c->thread, 1);
  if (t < 0)
    return SHZ_E_NOMEM;
  if (r->opcode == SHZ_OP_PMA_CANCEL) {
    for (i = 0; i < NTWP_MAX_PENDING; i++)
      if (s->pending[i].state && s->pending[i].ticket == r->target_ticket &&
          s->pending[i].owner == (uint32_t)o &&
          s->pending[i].thread == (uint32_t)t &&
          s->pending[i].header.opcode == SHZ_OP_PMA_EVENT_WAIT)
        break;
    if (i == NTWP_MAX_PENDING)
      return SHZ_E_DENIED;
  }
  stage(s, e, (uint32_t)o, (uint32_t)t, r->opcode, 0);
  e->request.object = r->object;
  e->request.flags = r->flags;
  e->request.deadline_ns = r->deadline_ns;
  e->request.target_sequence = r->target_ticket;
  e->request.required_features = r->required_features;
  *ticket = e->ticket;
  return SHZ_OK;
}
const struct ntwp_entry *ntwp_tx_peek(const struct ntwp_broker *s) {
  uint32_t i;
  const struct ntwp_entry *e = 0;
  if (!s)
    return 0;
  for (i = 0; i < NTWP_MAX_PENDING; i++)
    if (s->pending[i].state == 1 && (!e || s->pending[i].ticket < e->ticket))
      e = &s->pending[i];
  return e;
}
int ntwp_tx_ack(struct ntwp_broker *s, uint64_t ticket) {
  const struct ntwp_entry *p = ntwp_tx_peek(s);
  if (!p || p->ticket != ticket)
    return SHZ_E_STALE;
  ((struct ntwp_entry *)p)->state = 2;
  return SHZ_OK;
}
int ntwp_receive(struct ntwp_broker *s, const shz_msg_hdr_t *h,
                 const void *payload) {
  uint32_t i;
  struct ntwp_entry *e;
  shz_pma_completion_t c;
  shz_pma_info_t q;
  if (!s || !h || !payload || h->flags != SHZ_MSGF_REPLY ||
      h->src_domain != s->peer || h->dst_domain != s->self ||
      h->generation != s->generation || h->payload_length != 64 ||
      h->buffer_offset || h->buffer_length)
    return SHZ_E_PROTO;
  for (i = 0; i < NTWP_MAX_PENDING; i++)
    if (s->pending[i].state == 2 && s->pending[i].ticket == h->request_id)
      break;
  if (i == NTWP_MAX_PENDING)
    return SHZ_E_STALE;
  e = &s->pending[i];
  if (e->header.opcode != h->opcode)
    return SHZ_E_PROTO;
  if (h->opcode == SHZ_OP_PMA_QUERY && h->status == SHZ_OK) {
    copy(&q, payload, sizeof q);
    if (q.magic != SHZ_PMA_MAGIC || q.abi_major != SHZ_PMA_ABI_MAJOR ||
        q.size != sizeof q || q.flags || q.generation != s->generation ||
        q.self_domain != s->peer || q.peer_domain != s->self ||
        (q.features & e->request.required_features) !=
            e->request.required_features)
      return SHZ_E_PROTO;
  } else {
    copy(&c, payload, sizeof c);
    if (c.magic != SHZ_PMA_MAGIC || c.abi_major != SHZ_PMA_ABI_MAJOR ||
        c.size != sizeof c || c.flags || c.reserved ||
        c.sequence != e->ticket || c.status != h->status ||
        c.domain != s->self || c.pid != e->request.pid ||
        c.tid != e->request.tid ||
        c.owner_generation != e->request.owner_generation ||
        c.thread_generation != e->request.thread_generation ||
        (h->opcode != SHZ_OP_PMA_EVENT_CREATE && c.object != e->request.object))
      return SHZ_E_PROTO;
  }
  if (e->internal || s->owners[e->owner].state != 1) {
    uint32_t o = e->owner;
    if (e->internal && h->status != SHZ_OK)
      return SHZ_E_PROTO; /* failed rundown must remain visible, never fake
                             release */
    if (e->internal && h->opcode == SHZ_OP_PMA_THREAD_EXIT)
      s->threads[e->thread].state = 3;
    if (e->internal && h->opcode == SHZ_OP_PMA_PROCESS_EXIT)
      s->owners[o].state = 4;
    zero(e, sizeof *e);
    collect(s, o);
    return SHZ_OK;
  }
  e->reply.ticket = e->ticket;
  e->reply.opcode = h->opcode;
  e->reply.status = h->status;
  copy(e->reply.payload, payload, 64);
  e->state = 3;
  return SHZ_OK;
}
const struct ntwp_reply *ntwp_reply_peek(const struct ntwp_broker *s,
                                         const struct ntwp_context *c,
                                         uint32_t session, uint64_t ticket) {
  int o = owner_index(s, c, session);
  uint32_t i;
  if (o < 0)
    return 0;
  for (i = 0; i < NTWP_MAX_PENDING; i++)
    if (s->pending[i].state == 3 && s->pending[i].owner == (uint32_t)o &&
        (!ticket || s->pending[i].ticket == ticket))
      return &s->pending[i].reply;
  return 0;
}
int ntwp_reply_ack(struct ntwp_broker *s, const struct ntwp_context *c,
                   uint32_t session, uint64_t ticket) {
  const struct ntwp_reply *r = ntwp_reply_peek(s, c, session, ticket);
  uint32_t i;
  if (!r)
    return SHZ_E_DENIED;
  for (i = 0; i < NTWP_MAX_PENDING; i++)
    if (&s->pending[i].reply == r) {
      zero(&s->pending[i], sizeof s->pending[i]);
      return SHZ_OK;
    }
  return SHZ_E_STALE;
}
static int close_owner(struct ntwp_broker *s, uint32_t o) {
  uint32_t i, t = NTWP_MAX_THREADS;
  struct ntwp_entry *e;
  if (s->owners[o].state != 1)
    return SHZ_OK;
  if (s->next_ticket == UINT64_MAX)
    return SHZ_E_STALE;
  /* Close never needs to admit a new thread; PROCESS_EXIT permits dead TIDs. */
  for (i = 0; i < NTWP_MAX_THREADS; i++)
    if (s->threads[i].state && s->threads[i].owner == o) {
      t = i;
      break;
    }
  if (t == NTWP_MAX_THREADS) {
    s->owners[o].state = 3;
    return SHZ_OK;
  } /* no request ever admitted, no backend owner */
  e = free_entry(s);
  if (!e)
    return SHZ_E_BUSY;
  stage(s, e, o, t, SHZ_OP_PMA_PROCESS_EXIT, 1);
  s->owners[o].state = 2;
  for (i = 0; i < NTWP_MAX_PENDING; i++)
    if (s->pending[i].owner == o && !s->pending[i].internal &&
        (s->pending[i].state == 1 || s->pending[i].state == 3))
      zero(&s->pending[i], sizeof s->pending[i]);
  return SHZ_OK;
}
int ntwp_close(struct ntwp_broker *s, const struct ntwp_context *c,
               uint32_t session) {
  int o = owner_index(s, c, session);
  if (o < 0)
    return SHZ_E_DENIED;
  return close_owner(s, (uint32_t)o);
}
int ntwp_thread_dead(struct ntwp_broker *s, uint32_t vm, uint32_t native) {
  uint32_t i, j;
  int n = 0;
  if (!s || !vm || !native)
    return SHZ_E_INVALID;
  for (i = 0; i < NTWP_MAX_THREADS; i++)
    if (s->threads[i].state == 1 && s->threads[i].native_thread == native &&
        s->owners[s->threads[i].owner].vm == vm &&
        s->owners[s->threads[i].owner].state == 1) {
      struct ntwp_entry *e = free_entry(s);
      if (!e || s->next_ticket == UINT64_MAX)
        return SHZ_E_BUSY;
      stage(s, e, s->threads[i].owner, i, SHZ_OP_PMA_THREAD_EXIT, 1);
      s->threads[i].state = 2;
      n++;
      /* These requests never reached the peer. Cancelling them is definitive;
       * SENT requests still require the peer's correlated terminal response. */
      for (j = 0; j < NTWP_MAX_PENDING; j++)
        if (s->pending[j].state == 1 && !s->pending[j].internal &&
            s->pending[j].thread == i) {
          struct ntwp_entry *p = &s->pending[j];
          shz_pma_completion_t cancelled;
          zero(&cancelled, sizeof cancelled);
          cancelled.magic = SHZ_PMA_MAGIC;
          cancelled.abi_major = SHZ_PMA_ABI_MAJOR;
          cancelled.abi_minor = SHZ_PMA_ABI_MINOR;
          cancelled.size = sizeof cancelled;
          cancelled.features = SHZ_PMA_FEATURES;
          cancelled.domain = p->request.domain;
          cancelled.pid = p->request.pid;
          cancelled.tid = p->request.tid;
          cancelled.owner_generation = p->request.owner_generation;
          cancelled.thread_generation = p->request.thread_generation;
          cancelled.object = p->request.object;
          cancelled.sequence = p->ticket;
          cancelled.status = SHZ_E_CANCELLED;
          p->reply.ticket = p->ticket;
          p->reply.opcode = p->header.opcode;
          p->reply.status = SHZ_E_CANCELLED;
          copy(p->reply.payload, &cancelled, sizeof cancelled);
          p->state = 3;
        }
    }
  return n;
}
int ntwp_vm_dead(struct ntwp_broker *s, uint32_t vm) {
  uint32_t i;
  int rc;
  if (!s || !vm)
    return SHZ_E_INVALID;
  for (i = 0; i < NTWP_MAX_OWNERS; i++)
    if (s->owners[i].state == 1 && s->owners[i].vm == vm) {
      rc = close_owner(s, i);
      if (rc != SHZ_OK)
        return rc;
    }
  return SHZ_OK;
}
int ntwp_unload_ready(const struct ntwp_broker *s) {
  uint32_t i;
  if (!s)
    return 0;
  for (i = 0; i < NTWP_MAX_PENDING; i++)
    if (s->pending[i].state)
      return 0;
  for (i = 0; i < NTWP_MAX_OWNERS; i++)
    if (s->owners[i].state == 1 || s->owners[i].state == 2 ||
        s->owners[i].state == 4)
      return 0;
  return 1;
}
int ntwp_restart_proven(struct ntwp_broker *s, uint32_t gen) {
  if (!s || gen <= s->generation)
    return SHZ_E_STALE;
  return ntwp_init(s, s->self, s->peer, gen);
}
