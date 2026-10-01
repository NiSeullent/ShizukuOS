/* SPDX-License-Identifier: GPL-2.0-only -- actual production service/ring
 * checks. */
#include "../../../shizukudos/pma_bridge/service.h"
#include "../broker.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#define CHECK(x)                                                               \
  do {                                                                         \
    ++checks;                                                                  \
    if (!(x)) {                                                                \
      fprintf(stderr, "line%d: %s\n", __LINE__, #x);                           \
      exit(1);                                                                 \
    }                                                                          \
  } while (0)
static unsigned checks;
static struct ntwp_broker b;
static shz_pma_service_t service;
static _Alignas(64) uint8_t memory[SHZ_IPC_REGION_SIZE];
static shz_ring_hdr_t *tx, *rx;
static uint64_t now_ns = 100;
static struct ntwp_context a = {0xabc, 0x123, 0x111, 7};
static struct ntwp_open_info opened;
static void setup(void) {
  shz_channel_hdr_t *h = (shz_channel_hdr_t *)memory;
  CHECK(ntwp_init(&b, SHZ_DOM_WIN98, SHZ_DOM_KERNEL64, 1) == SHZ_OK);
  CHECK(shz_pma_service_init(&service, SHZ_DOM_KERNEL64, SHZ_DOM_WIN98, 1) ==
        SHZ_OK);
  CHECK(shz_channel_init(memory, sizeof memory, 2, SHZ_DOM_WIN98,
                         SHZ_DOM_KERNEL64, 8, 1) == SHZ_OK);
  tx = shz_channel_ring_tx(memory, h, SHZ_DOM_WIN98);
  rx = shz_channel_ring_rx(memory, h, SHZ_DOM_WIN98);
  CHECK(ntwp_open(&b, &a, &opened) == SHZ_OK);
  CHECK(opened.pid != a.process && opened.pid && opened.owner_generation == 1);
  now_ns = 100;
}
static uint64_t submit(struct ntwp_context c, uint32_t session, uint32_t opcode,
                       uint32_t object, uint32_t flags, uint64_t deadline,
                       uint64_t target) {
  struct ntwp_submit r = {sizeof r, opcode, object,          flags,
                          deadline, target, SHZ_PMA_FEATURES};
  uint64_t ticket = 0;
  CHECK(ntwp_submit(&b, &c, session, &r, &ticket) == SHZ_OK);
  CHECK(ticket != 0);
  return ticket;
}
static unsigned send_staged(void) {
  unsigned n = 0;
  const struct ntwp_entry *e;
  while ((e = ntwp_tx_peek(&b)) != NULL) {
    shz_msg_hdr_t h = e->header;
    int rc = shz_ring_push(tx, &h, &e->request);
    if (rc == SHZ_E_QUEUE_FULL) {
      CHECK(ntwp_tx_peek(&b) == e);
      break;
    }
    CHECK(rc == SHZ_OK);
    CHECK(ntwp_tx_ack(&b, e->ticket) == SHZ_OK);
    n++;
  }
  return n;
}
static unsigned server_pump(void) {
  shz_msg_hdr_t h;
  uint8_t payload[SHZ_MSG_MAX_INLINE];
  int why, rc;
  unsigned n = 0;
  const shz_pma_frame_t *f;
  while ((rc = shz_ring_pop(tx, &h, payload, sizeof payload, &why)) !=
         SHZ_E_NOENT) {
    CHECK(rc == SHZ_OK);
    CHECK(shz_pma_service_dispatch(&service, &h, payload, now_ns) == SHZ_OK);
    n++;
  }
  shz_pma_service_tick(&service, now_ns);
  while ((f = shz_pma_service_peek(&service)) != NULL) {
    h = f->header;
    rc = shz_ring_push(rx, &h, f->payload);
    if (rc == SHZ_E_QUEUE_FULL) {
      CHECK(shz_pma_service_peek(&service) == f);
      break;
    }
    CHECK(rc == SHZ_OK);
    CHECK(shz_pma_service_ack(&service, h.request_id) == SHZ_OK);
    n++;
  }
  return n;
}
static unsigned receive(void) {
  shz_msg_hdr_t h;
  uint8_t payload[SHZ_MSG_MAX_INLINE];
  int why, rc;
  unsigned n = 0;
  while ((rc = shz_ring_pop(rx, &h, payload, sizeof payload, &why)) !=
         SHZ_E_NOENT) {
    CHECK(rc == SHZ_OK);
    CHECK(ntwp_receive(&b, &h, payload) == SHZ_OK);
    n++;
  }
  return n;
}
static void pump(void) {
  unsigned n;
  do {
    n = send_staged() + server_pump() + receive();
  } while (n);
}
static struct ntwp_reply take(struct ntwp_context c, uint32_t session,
                              uint64_t id, int status) {
  const struct ntwp_reply *p = ntwp_reply_peek(&b, &c, session, id);
  struct ntwp_reply r;
  CHECK(p != NULL);
  r = *p;
  CHECK(r.ticket == id && r.status == status);
  CHECK(ntwp_reply_peek(&b, &c, session, id) == p);
  CHECK(ntwp_reply_ack(&b, &c, session, id) == SHZ_OK);
  CHECK(ntwp_reply_peek(&b, &c, session, id) == NULL);
  return r;
}
static uint32_t create(struct ntwp_context c, uint32_t session,
                       uint32_t flags) {
  uint64_t id = submit(c, session, SHZ_OP_PMA_EVENT_CREATE, 0, flags, 0, 0);
  shz_pma_completion_t p;
  struct ntwp_reply r;
  pump();
  r = take(c, session, id, SHZ_OK);
  memcpy(&p, r.payload, sizeof p);
  CHECK(p.object != 0);
  return p.object;
}
static void test_events_identity(void) {
  uint32_t object;
  uint64_t w, s, q;
  struct ntwp_context thread = a, thief = a;
  struct ntwp_open_info other;
  struct ntwp_reply reply;
  shz_pma_info_t info;
  setup();
  q = submit(a, opened.session, SHZ_OP_PMA_QUERY, 0, 0, 0, 0);
  pump();
  reply = take(a, opened.session, q, SHZ_OK);
  memcpy(&info, reply.payload, sizeof info);
  CHECK(info.now_ns == 100);
  object = create(a, opened.session, 0);
  w = submit(a, opened.session, SHZ_OP_PMA_EVENT_WAIT, object, 0, UINT64_MAX,
             0);
  pump();
  CHECK(ntwp_reply_peek(&b, &a, opened.session, w) == NULL);
  thief.process++;
  thief.device++;
  CHECK(ntwp_open(&b, &thief, &other) == SHZ_OK);
  CHECK(ntwp_reply_peek(&b, &thief, opened.session, w) == NULL);
  CHECK(ntwp_reply_ack(&b, &thief, opened.session, w) == SHZ_E_DENIED);
  thread.thread++;
  s = submit(thread, opened.session, SHZ_OP_PMA_EVENT_SIGNAL, object, 0, 0, 0);
  pump();
  take(thread, opened.session, s, SHZ_OK);
  take(a, opened.session, w, SHZ_OK);
  w = submit(a, opened.session, SHZ_OP_PMA_EVENT_WAIT, object, 0, 0, 0);
  pump();
  take(a, opened.session, w, SHZ_E_TIMEOUT);
  object = create(a, opened.session, SHZ_PMA_EVENT_MANUAL_RESET);
  w = submit(a, opened.session, SHZ_OP_PMA_EVENT_WAIT, object, 0, UINT64_MAX,
             0);
  q = submit(thread, opened.session, SHZ_OP_PMA_EVENT_WAIT, object, 0,
             UINT64_MAX, 0);
  s = submit(thread, opened.session, SHZ_OP_PMA_EVENT_SIGNAL, object, 0, 0, 0);
  pump();
  take(a, opened.session, w, SHZ_OK);
  take(thread, opened.session, q, SHZ_OK);
  take(thread, opened.session, s, SHZ_OK);
  s = submit(a, opened.session, SHZ_OP_PMA_EVENT_RESET, object, 0, 0, 0);
  pump();
  take(a, opened.session, s, SHZ_OK);
  w = submit(a, opened.session, SHZ_OP_PMA_EVENT_WAIT, object, 0, 100, 0);
  pump();
  take(a, opened.session, w, SHZ_E_TIMEOUT);
}
static void test_completion_validation(void) {
  shz_msg_hdr_t h;
  uint8_t payload[192];
  shz_pma_completion_t bad;
  int why;
  uint64_t id;
  const struct ntwp_reply *p;
  struct ntwp_context thief = a;
  setup();
  id = submit(a, opened.session, SHZ_OP_PMA_EVENT_CREATE, 0, 0, 0, 0);
  send_staged();
  server_pump();
  CHECK(shz_ring_pop(rx, &h, payload, sizeof payload, &why) == SHZ_OK);
  memcpy(&bad, payload, sizeof bad);
  bad.pid++;
  CHECK(ntwp_receive(&b, &h, &bad) == SHZ_E_PROTO);
  CHECK(ntwp_receive(&b, &h, payload) == SHZ_OK);
  CHECK(ntwp_receive(&b, &h, payload) == SHZ_E_STALE);
  p = ntwp_reply_peek(&b, &a, opened.session, id);
  CHECK(p);
  thief.device++;
  CHECK(ntwp_reply_peek(&b, &thief, opened.session, id) == NULL);
  CHECK(ntwp_reply_peek(&b, &a, opened.session, id) == p);
  take(a, opened.session, id, SHZ_OK);
}
static void test_lifecycle(void) {
  uint32_t object;
  uint64_t wait;
  struct ntwp_open_info next;
  struct ntwp_context reused = a;
  setup();
  object = create(a, opened.session, 0);
  wait = submit(a, opened.session, SHZ_OP_PMA_EVENT_WAIT, object, 0, UINT64_MAX,
                0);
  pump();
  CHECK(ntwp_thread_dead(&b, a.vm, a.thread) == 1);
  CHECK(ntwp_thread_dead(&b, a.vm, a.thread) == 0);
  pump();
  take(a, opened.session, wait, SHZ_E_CANCELLED);
  CHECK(ntwp_close(&b, &a, opened.session) == SHZ_OK);
  CHECK(ntwp_open(&b, &a, &next) == SHZ_E_BUSY);
  CHECK(!ntwp_unload_ready(&b));
  pump();
  CHECK(ntwp_unload_ready(&b));
  CHECK(ntwp_open(&b, &a, &next) == SHZ_OK);
  CHECK(next.pid == opened.pid &&
        next.owner_generation == opened.owner_generation + 1);
  CHECK(ntwp_reply_peek(&b, &a, opened.session, wait) == NULL);
  reused.thread++;
  object = create(reused, next.session, 0);
  CHECK(object);
  CHECK(ntwp_vm_dead(&b, a.vm) == SHZ_OK);
  pump();
  CHECK(ntwp_unload_ready(&b));
  CHECK(ntwp_restart_proven(&b, 1) == SHZ_E_STALE);
  CHECK(ntwp_restart_proven(&b, 2) == SHZ_OK);
  CHECK(ntwp_open(&b, &a, &next) == SHZ_OK && next.generation == 2);
}
static void test_dead_thread_does_not_publish_unsent(void) {
  uint32_t object;
  uint64_t signal, wait;
  struct ntwp_context worker = a;
  setup();
  object = create(a, opened.session, 0);
  signal = submit(a, opened.session, SHZ_OP_PMA_EVENT_SIGNAL, object, 0, 0, 0);
  CHECK(ntwp_thread_dead(&b, a.vm, a.thread) == 1);
  pump();
  worker.thread++;
  take(worker, opened.session, signal, SHZ_E_CANCELLED);
  wait = submit(worker, opened.session, SHZ_OP_PMA_EVENT_WAIT, object, 0, 0, 0);
  pump();
  take(worker, opened.session, wait, SHZ_E_TIMEOUT);
}
static void test_wire_thread_slots_do_not_migrate_across_owners(void) {
  uint32_t i;
  struct ntwp_context thread = a, other = a;
  struct ntwp_open_info other_open;
  struct ntwp_submit query = {sizeof query, SHZ_OP_PMA_QUERY, 0, 0, 0, 0, 0};
  uint64_t ticket;
  setup();
  for (i = 0; i < 32; i++) {
    thread.thread = a.thread + i;
    ticket = submit(thread, opened.session, SHZ_OP_PMA_QUERY, 0, 0, 0, 0);
    pump();
    take(thread, opened.session, ticket, SHZ_OK);
  }
  for (i = 0; i < 32; i++) {
    CHECK(ntwp_thread_dead(&b, a.vm, a.thread + i) == 1);
    pump();
  }
  other.process++;
  other.device++;
  other.thread += 100;
  CHECK(ntwp_open(&b, &other, &other_open) == SHZ_OK);
  CHECK(ntwp_submit(&b, &other, other_open.session, &query, &ticket) ==
        SHZ_E_NOMEM);
  CHECK(ntwp_tx_peek(&b) == NULL);
  thread.thread = a.thread;
  ticket = submit(thread, opened.session, SHZ_OP_PMA_QUERY, 0, 0, 0, 0);
  pump();
  take(thread, opened.session, ticket, SHZ_OK);
}
static void test_capacity(void) {
  uint64_t waits[NTWP_MAX_WAITS], signal;
  uint32_t i, object;
  struct ntwp_submit r;
  uint64_t unused;
  setup();
  object = create(a, opened.session, SHZ_PMA_EVENT_MANUAL_RESET);
  for (i = 0; i < NTWP_MAX_WAITS; i++) {
    waits[i] = submit(a, opened.session, SHZ_OP_PMA_EVENT_WAIT, object, 0,
                      UINT64_MAX, 0);
    pump();
  }
  r = (struct ntwp_submit){
      sizeof r, SHZ_OP_PMA_EVENT_WAIT, object, 0, UINT64_MAX, 0, 0};
  CHECK(ntwp_submit(&b, &a, opened.session, &r, &unused) == SHZ_E_BUSY);
  signal = submit(a, opened.session, SHZ_OP_PMA_EVENT_SIGNAL, object, 0, 0, 0);
  pump();
  for (i = 0; i < NTWP_MAX_WAITS; i++)
    take(a, opened.session, waits[i], SHZ_OK);
  take(a, opened.session, signal, SHZ_OK);
}
static void test_full_lifecycle_reservations(void) {
  struct ntwp_context owners[8];
  struct ntwp_open_info sessions[8];
  uint32_t objects[8], i, j;
  setup();
  for (i = 0; i < 8; i++) {
    owners[i] = a;
    owners[i].process += i;
    owners[i].device += i;
    owners[i].thread += i * 4;
    CHECK(ntwp_open(&b, &owners[i], &sessions[i]) == SHZ_OK);
    objects[i] = create(owners[i], sessions[i].session, 0);
    for (j = 1; j < 4; j++) {
      struct ntwp_context t = owners[i];
      uint64_t q;
      t.thread += j;
      q = submit(t, sessions[i].session, SHZ_OP_PMA_QUERY, 0, 0, 0, 0);
      pump();
      take(t, sessions[i].session, q, SHZ_OK);
    }
  }
  for (i = 0; i < 48; i++)
    submit(owners[i % 8], sessions[i % 8].session, SHZ_OP_PMA_EVENT_WAIT,
           objects[i % 8], 0, UINT64_MAX, 0);
  for (i = 0; i < 16; i++)
    submit(owners[i % 8], sessions[i % 8].session, SHZ_OP_PMA_QUERY, 0, 0, 0,
           0);
  while (ntwp_tx_peek(&b)) {
    send_staged();
    server_pump();
  } /* leave all replies at the service/ring */
  for (i = 0; i < 8; i++)
    for (j = 0; j < 4; j++)
      CHECK(ntwp_thread_dead(&b, owners[i].vm, owners[i].thread + j) == 1);
  for (i = 0; i < 8; i++)
    CHECK(ntwp_close(&b, &owners[i], sessions[i].session) == SHZ_OK);
  CHECK(!ntwp_unload_ready(&b));
  pump();
  CHECK(ntwp_unload_ready(&b));
  for (i = 0; i < 8; i++)
    CHECK(ntwp_open(&b, &owners[i], &sessions[i]) == SHZ_OK &&
          sessions[i].owner_generation == 2);
}
int main(void) {
  test_events_identity();
  test_completion_validation();
  test_lifecycle();
  test_dead_thread_does_not_publish_unsent();
  test_wire_thread_slots_do_not_migrate_across_owners();
  test_capacity();
  test_full_lifecycle_reservations();
  printf("broker %u checks\n", checks);
  return 0;
}
