/* SPDX-License-Identifier: GPL-2.0-only */
#ifndef NTW_STEAM_ACCEPT_OP_H
#define NTW_STEAM_ACCEPT_OP_H

/* Provider-side AcceptEx operation registry and output-block writer.
 *
 * This is the provider half that accept_buffer.c (the reader) required:
 * it validates the original AcceptEx reservations at submission, writes the
 * Wine-layout address blocks (LE int32 length + Windows sockaddr) only into
 * the declared address reservations, records the ACTUAL accepted (received)
 * byte count separately from the receive reservation, and tracks the exact
 * submitted allocation so the VOID GetAcceptExSockaddrs ABI can be decoded
 * against a real, provider-owned length.
 *
 * Every socket and owner is named by an (id, generation) pair; a reused id
 * with another generation never matches. Operation tokens carry their own slot
 * generation, so a stale token after cancel/close/release is refused.
 *
 * Freestanding: no allocation, no libc, no locking. The integrating provider
 * (e.g. kernel64 net_sock under its net mutex) must serialize every call on a
 * given table. Nothing here performs a socket operation, completes an IRP, or
 * copies to user memory; it returns which transitions the provider must make.
 */
#include <stddef.h>
#include <stdint.h>
#include "accept_buffer.h"

enum ntw_acceptex_status {
    NTW_ACCEPTEX_OK = 0,
    NTW_ACCEPTEX_ARGUMENT,      /* WSAEFAULT/WSAEINVAL class: bad pointer/length */
    NTW_ACCEPTEX_FAMILY,        /* WSAEAFNOSUPPORT: not exact IPv4/IPv6 */
    NTW_ACCEPTEX_RESERVATION,   /* address reservation < sockaddr + 16 */
    NTW_ACCEPTEX_OVERFLOW,      /* DWORD / pointer range overflow */
    NTW_ACCEPTEX_BUSY,          /* accept socket or buffer already in a live op */
    NTW_ACCEPTEX_FULL,          /* no free slot: WSAENOBUFS */
    NTW_ACCEPTEX_STALE,         /* token/generation/owner mismatch */
    NTW_ACCEPTEX_STATE,         /* wrong transition for current state */
    NTW_ACCEPTEX_RECEIVED,      /* accepted bytes exceed receive reservation */
    NTW_ACCEPTEX_NOT_FOUND,     /* no completed tracked allocation */
    NTW_ACCEPTEX_EXHAUSTED      /* every slot's 16-bit generation space is spent */
};

struct ntw_ref {
    uint32_t id;
    uint32_t generation;        /* 0 is never a valid live generation */
};

struct ntw_acceptex_plan {
    uint32_t receive_reserved;  /* dwReceiveDataLength */
    uint32_t local_reserved;    /* dwLocalAddressLength */
    uint32_t remote_reserved;   /* dwRemoteAddressLength */
    uint32_t total;             /* receive + local + remote, DWORD-checked */
    uint16_t family;            /* listening socket family, 2 or 23 */
};

/* Validate original AcceptEx lengths for the listening socket family. */
enum ntw_acceptex_status ntw_acceptex_plan_make(
    uint16_t family, uint32_t receive_reserved, uint32_t local_reserved,
    uint32_t remote_reserved, struct ntw_acceptex_plan *out);

/* Write both address blocks into out[0 .. local+remote) which corresponds to
 * buffer offset plan->receive_reserved (NOT the received byte count). The
 * unused tail of each reservation is zeroed so no stale provider bytes leak.
 * Each sockaddr must be the exact family size of plan->family and carry that
 * family in its first two little-endian bytes. out is unchanged on error. */
enum ntw_acceptex_status ntw_acceptex_encode_blocks(
    const struct ntw_acceptex_plan *plan,
    const uint8_t *local_sockaddr, uint32_t local_len,
    const uint8_t *remote_sockaddr, uint32_t remote_len,
    uint8_t *out, size_t out_bytes);

enum ntw_acceptex_state {
    NTW_ACCEPTEX_FREE = 0,
    NTW_ACCEPTEX_PENDING,
    NTW_ACCEPTEX_COMPLETED,
    NTW_ACCEPTEX_RETIRED        /* generation 65535 spent: slot never reissued */
};

struct ntw_acceptex_op {
    enum ntw_acceptex_state state;
    uint16_t generation;
    uint8_t context_updated;    /* SO_UPDATE_ACCEPT_CONTEXT applied */
    struct ntw_ref owner;       /* process (id, generation) */
    struct ntw_ref listen;
    struct ntw_ref accept;
    uint64_t buffer;            /* owner address of the AcceptEx buffer */
    struct ntw_acceptex_plan plan;
    uint32_t accepted_bytes;    /* actual received bytes, <= receive_reserved */
};

#define NTW_ACCEPTEX_SLOTS 64u

struct ntw_acceptex_table {
    struct ntw_acceptex_op op[NTW_ACCEPTEX_SLOTS];
};

/* A slot whose generation reaches 65535 is retired permanently on free, so a
 * token can never alias a later op. When every slot is retired, submit returns
 * NTW_ACCEPTEX_EXHAUSTED (a truthful resource error, WSAENOBUFS class).
 * Token: slot index in low 16 bits, slot generation in high 16 bits. */
typedef uint32_t ntw_acceptex_token;

void ntw_acceptex_table_init(struct ntw_acceptex_table *table);

/* Register a pending AcceptEx. Refuses an accept socket already named by a
 * pending/completed op, the listen socket used as accept socket, and a buffer
 * range overlapping any PENDING op of the same owner. A COMPLETED op of the
 * same owner whose range overlaps is retired (the application reused its
 * buffer, so the old borrowed addresses are invalid). */
enum ntw_acceptex_status ntw_acceptex_submit(
    struct ntw_acceptex_table *table, struct ntw_ref owner,
    struct ntw_ref listen, struct ntw_ref accept, uint64_t buffer,
    const struct ntw_acceptex_plan *plan, ntw_acceptex_token *token);

/* PENDING -> COMPLETED once the provider has copied received bytes and the
 * encoded blocks into the owner buffer. accepted_bytes is the actual count. */
enum ntw_acceptex_status ntw_acceptex_complete(
    struct ntw_acceptex_table *table, ntw_acceptex_token token,
    uint32_t accepted_bytes);

/* PENDING -> FREE (cancel/error). Provider completes its IRP as cancelled. */
enum ntw_acceptex_status ntw_acceptex_cancel(
    struct ntw_acceptex_table *table, ntw_acceptex_token token);

/* Any non-FREE -> FREE by the owning process (e.g. on accept-socket reuse). */
enum ntw_acceptex_status ntw_acceptex_release(
    struct ntw_acceptex_table *table, struct ntw_ref owner,
    ntw_acceptex_token token);

/* A socket (listen or accept role) or process is gone. Every op naming it is
 * freed; for each op that was PENDING, cancelled(ctx, token) is called first so
 * the provider can complete that IRP with STATUS_CANCELLED. Returns the
 * number of freed ops. Matches either role when is_process is 0. */
uint32_t ntw_acceptex_forget(
    struct ntw_acceptex_table *table, struct ntw_ref subject, int is_process,
    void (*cancelled)(void *ctx, ntw_acceptex_token token), void *ctx);

/* setsockopt(accept, SOL_SOCKET, SO_UPDATE_ACCEPT_CONTEXT, &listen): only
 * valid for a COMPLETED op of this owner binding exactly these two refs. */
enum ntw_acceptex_status ntw_acceptex_update_context(
    struct ntw_acceptex_table *table, struct ntw_ref owner,
    struct ntw_ref accept, struct ntw_ref listen);

/* Resolve a GetAcceptExSockaddrs call: the buffer address and all three
 * reservations must equal one COMPLETED op of the owner. On success *op_out
 * describes the tracked allocation (buffer, plan.total) to pass to
 * ntw_accept_decode with NTW_ACCEPT_LAYOUT_WINE_LENGTH32. */
enum ntw_acceptex_status ntw_acceptex_lookup(
    const struct ntw_acceptex_table *table, struct ntw_ref owner,
    uint64_t buffer, uint32_t receive_reserved, uint32_t local_reserved,
    uint32_t remote_reserved, const struct ntw_acceptex_op **op_out);

#endif
