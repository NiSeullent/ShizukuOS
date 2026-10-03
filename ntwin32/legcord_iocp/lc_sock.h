/* Winsock overlapped-completion -> completion port bridge (Legcord libuv port).
 * SPDX-License-Identifier: GPL-2.0-only
 *
 * Win98 Winsock2 completes overlapped WSARecv/WSASend/WSARecvFrom/WSASendTo
 * only through event objects (no completion ports, no RegisterWaitForSingle
 * Object). A socket associated with an lc_iocp port gets its overlapped
 * operations armed with a pooled manual-reset event; one worker waits on the
 * armed events, collects the real result and posts (bytes, key, overlapped)
 * to the port with OVERLAPPED.Internal holding an NTSTATUS
 * (0 or 0xC0070000 | winsock error, which libuv decodes as FACILITY_NTWIN32).
 * ConnectEx is emulated with connect() + FD_CONNECT event selection.
 * Unassociated sockets pass through unchanged. Capacity exhaustion is
 * reported, never silently dropped.
 */
#ifndef LC_SOCK_H
#define LC_SOCK_H
#include <stdint.h>
#ifdef __cplusplus
extern "C" {
#endif

enum { LC_SOCK_ASSOC_CAPACITY = 256, LC_SOCK_OP_CAPACITY = 63 /* + control = 64 waits */ };
enum { LC_SOCK_IO = 1, LC_SOCK_CONNECT = 2 };
enum { LC_SOCK_FAILED = 0, LC_SOCK_ARMED = 1, LC_SOCK_PASSTHROUGH = 2 };
#define LC_SOCK_WAIT_FAILED UINT32_MAX
#define LC_SOCK_STATUS(err) ((err) ? (0xC0070000u | ((uint32_t)(err) & 0xffffu)) : 0u)
#define LC_WSA_OPERATION_ABORTED 995u

typedef struct lc_sock_ops {
    void *opaque;
    void (*enter)(void *);
    void (*leave)(void *);
    uintptr_t (*event_create)(void *, int manual_reset); /* nonsignaled; 0 = failure */
    void (*event_reset)(void *, uintptr_t);
    void (*event_set)(void *, uintptr_t);
    void (*event_close)(void *, uintptr_t);
    /* Waits for any; returns signaled index (auto-reset events are consumed). */
    uint32_t (*wait_any)(void *, const uintptr_t *events, uint32_t count);
    /* Starts worker(arg) holding a module reference; 1 on success. */
    int (*thread_start)(void *, void (*worker)(void *), void *arg);
    /* Last statement of the worker: drops the module reference (may not return). */
    void (*thread_exit)(void *);
    void (*io_result)(void *, uintptr_t sock, void *ov, uint32_t *bytes, uint32_t *wsaerr);
    void (*connect_result)(void *, uintptr_t sock, uintptr_t event, uint32_t *wsaerr);
    /* Writes OVERLAPPED Internal/InternalHigh/hEvent and signals the caller's event. */
    void (*finish)(void *, void *ov, uint32_t status, uint32_t bytes, uintptr_t caller_event);
    int (*post)(void *, uint32_t port, uint32_t bytes, uintptr_t key, void *ov, uint32_t *error);
} lc_sock_ops;

typedef struct lc_sock_assoc {
    uintptr_t sock, key;
    uint32_t port, generation;
    unsigned state; /* 0 free, 1 open, 2 closing (draining pending) */
    unsigned pending;
} lc_sock_assoc;

typedef struct lc_sock_op {
    uintptr_t event, caller_event, sock;
    void *ov;
    uint32_t generation, assoc, assoc_generation;
    unsigned state; /* 0 free, 1 armed, 2 pending */
    unsigned kind, immediate;
} lc_sock_op;

typedef struct lc_sock_context {
    lc_sock_ops ops;
    lc_sock_assoc assoc[LC_SOCK_ASSOC_CAPACITY];
    lc_sock_op op[LC_SOCK_OP_CAPACITY];
    uintptr_t control; /* auto-reset worker wakeup */
    unsigned magic, active, running, rotate;
    unsigned long dropped; /* completions whose port was already closed */
} lc_sock_context;

int lc_sock_init(lc_sock_context *, const lc_sock_ops *);
/* Binds an already validated port to a socket. Duplicate live association
 * -> LC_INVALID_PARAMETER (87); table full / worker start failure -> 1450. */
int lc_sock_associate(lc_sock_context *, uint32_t port, uintptr_t sock, uintptr_t key, uint32_t *error);
/* Returns LC_SOCK_ARMED (token/event valid; caller must commit or abort),
 * LC_SOCK_PASSTHROUGH (socket not associated) or LC_SOCK_FAILED (*error). */
int lc_sock_begin(lc_sock_context *, uintptr_t sock, void *ov, uintptr_t caller_event, unsigned kind,
                  uint32_t *token, uintptr_t *event, uint32_t *error);
/* Submission accepted (pending or completed): hand the op to the worker.
 * immediate: completion already known (connect returned 0); event is set. */
void lc_sock_commit(lc_sock_context *, uint32_t token, int immediate);
/* Submission failed synchronously: no completion will be posted. */
void lc_sock_abort(lc_sock_context *, uint32_t token);
/* Close protocol around the real closesocket. begin returns 1 and a token
 * when associated; end(ok=0) restores the association (socket still open). */
int lc_sock_close_begin(lc_sock_context *, uintptr_t sock, uint32_t *token);
void lc_sock_close_end(lc_sock_context *, uint32_t token, int ok);
unsigned lc_sock_active(lc_sock_context *);
unsigned lc_sock_worker_running(lc_sock_context *);
/* Only when no association and no worker remain: closes pooled events. */
int lc_sock_release(lc_sock_context *);

#ifdef __cplusplus
}
#endif
#endif
