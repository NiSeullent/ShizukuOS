/* SPDX-License-Identifier: GPL-2.0-only -- original Win98 PMA broker. */
#ifndef NTWP_BROKER_H
#define NTWP_BROKER_H
#include "../../shizukudos/abi/shz_vmm_pma.h"
#include <stdint.h>
/* The native VxD captures these, never copies them from user input. */
struct ntwp_context {
  uint32_t vm, process, thread, device;
};
#define NTWP_MAX_OWNERS 8u
#define NTWP_MAX_THREADS 32u
#define NTWP_MAX_PENDING 104u
#define NTWP_MAX_USER_PENDING 64u
#define NTWP_MAX_WAITS 48u
/* Broker adapter input only; canonical native owner defines the user IOCTL ABI.
 * Identities/sequence/endpoints are always assigned in ring0. */
struct ntwp_submit {
  uint32_t size, opcode, object, flags;
  uint64_t deadline_ns, target_ticket, required_features;
};
struct ntwp_open_info {
  uint32_t size, session, domain, generation, max_pending, max_waits, pid,
      owner_generation;
};
struct ntwp_reply {
  uint64_t ticket;
  uint32_t opcode;
  int32_t status;
  uint8_t payload[64];
};
struct ntwp_entry {
  uint32_t state, owner, thread, internal;
  uint64_t ticket;
  shz_msg_hdr_t header;
  shz_pma_request_t request;
  struct ntwp_reply reply;
};
struct ntwp_owner {
  uint32_t state, vm, process, device, generation;
};
struct ntwp_thread {
  uint32_t state, owner, native_thread, generation;
};
struct ntwp_broker {
  uint32_t self, peer, generation, stopped;
  uint64_t next_ticket;
  struct ntwp_owner owners[NTWP_MAX_OWNERS];
  struct ntwp_thread threads[NTWP_MAX_THREADS];
  struct ntwp_entry pending[NTWP_MAX_PENDING];
};
/* Serialized by the existing transport's admission token. No blocking/locks. */
int ntwp_init(struct ntwp_broker *, uint32_t, uint32_t, uint32_t);
int ntwp_open(struct ntwp_broker *, const struct ntwp_context *,
              struct ntwp_open_info *);
int ntwp_submit(struct ntwp_broker *, const struct ntwp_context *, uint32_t,
                const struct ntwp_submit *, uint64_t *);
const struct ntwp_entry *ntwp_tx_peek(const struct ntwp_broker *);
int ntwp_tx_ack(struct ntwp_broker *, uint64_t);
int ntwp_receive(struct ntwp_broker *, const shz_msg_hdr_t *, const void *);
const struct ntwp_reply *ntwp_reply_peek(const struct ntwp_broker *,
                                         const struct ntwp_context *, uint32_t,
                                         uint64_t);
int ntwp_reply_ack(struct ntwp_broker *, const struct ntwp_context *, uint32_t,
                   uint64_t);
int ntwp_close(struct ntwp_broker *, const struct ntwp_context *, uint32_t);
int ntwp_thread_dead(struct ntwp_broker *, uint32_t, uint32_t);
int ntwp_vm_dead(struct ntwp_broker *, uint32_t);
int ntwp_unload_ready(const struct ntwp_broker *);
/* Only after Supervisor proves old channel is gone; a strictly newer epoch. */
int ntwp_restart_proven(struct ntwp_broker *, uint32_t);
#endif
