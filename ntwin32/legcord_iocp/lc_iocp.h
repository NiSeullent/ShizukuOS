/* Process-local I/O completion port core for the Legcord Node/libuv port.
 * SPDX-License-Identifier: GPL-2.0-only
 *
 * Windows 98 KERNEL32 has no I/O completion ports, while libuv's Windows event
 * loop is built on CreateIoCompletionPort, PostQueuedCompletionStatus and
 * GetQueuedCompletionStatus(Ex). uv_async_send, threadpool work completion
 * (including all uv_fs_* requests) and loop wakeups use only posted packets.
 * This core implements that posted-packet subset with ordinary Win98
 * primitives supplied through lc_iocp_ops. File/socket association is not
 * implemented and returns LC_NOT_SUPPORTED; it never pretends success.
 */
#ifndef LC_IOCP_H
#define LC_IOCP_H
#include <stddef.h>
#include <stdint.h>
#ifdef __cplusplus
extern "C" {
#endif

/* Win32 error numbers so the native wrapper can SetLastError directly. */
enum {
    LC_OK = 0,
    LC_INVALID_HANDLE = 6,
    LC_NOT_ENOUGH_MEMORY = 8,
    LC_NOT_SUPPORTED = 50,
    LC_INVALID_PARAMETER = 87,
    LC_WAIT_TIMEOUT = 258,
    LC_ABANDONED_WAIT_0 = 735,
    LC_NO_SYSTEM_RESOURCES = 1450,
    LC_BAD_BACKEND = 31 /* ERROR_GEN_FAILURE */
};
enum { LC_PORT_CAPACITY = 64, LC_PACKET_CAPACITY = 4096, LC_INFINITE = 0xffffffffu };
#define LC_WAIT_FAILED UINT32_MAX

/* Backend primitives. Locks must not fail and must not be reentrant.
 * sem_wait returns 0 (signaled), 258 (timeout) or LC_WAIT_FAILED. */
typedef struct lc_iocp_ops {
    void *opaque;
    void (*enter)(void *);
    void (*leave)(void *);
    uintptr_t (*sem_create)(void *, uint32_t maximum);
    int (*sem_release)(void *, uintptr_t, uint32_t count);
    uint32_t (*sem_wait)(void *, uintptr_t, uint32_t timeout_ms);
    int (*sem_close)(void *, uintptr_t);
    uint32_t (*error)(void *);
} lc_iocp_ops;

/* Same field order/size as Win32 OVERLAPPED_ENTRY (checked by the native TU). */
typedef struct lc_entry {
    uintptr_t key;
    void *overlapped;
    uintptr_t internal;
    uint32_t bytes;
} lc_entry;

typedef struct lc_packet {
    uintptr_t key;
    void *overlapped;
    uint32_t bytes;
    int next;
} lc_packet;

typedef struct lc_port {
    uintptr_t semaphore;
    uintptr_t drain; /* released by the last waiter leaving a closing port; owned by the closer */
    uint32_t generation;
    unsigned state; /* 0 free, 1 open, 2 closing (waiters still inside) */
    unsigned waiters;
    unsigned queued;
    int head, tail;
} lc_port;

typedef struct lc_iocp_context {
    lc_iocp_ops ops;
    lc_port ports[LC_PORT_CAPACITY];
    lc_packet packets[LC_PACKET_CAPACITY];
    int free_packet;
    unsigned magic, open_ports, retained;
} lc_iocp_context;

/* Initialize once before any thread uses the context; the context and ops
 * outlive every call. Returns 1 on success. */
int lc_iocp_init(lc_iocp_context *, const lc_iocp_ops *);
/* Handles are nonzero, generation-bound (index | generation << 8); a stale or
 * foreign handle yields LC_INVALID_HANDLE. concurrency is accepted only as a
 * hint (0 = processor count); this core does not throttle running threads. */
int lc_iocp_create(lc_iocp_context *, uint32_t concurrency, uint32_t *handle, uint32_t *error);
int lc_iocp_associate(lc_iocp_context *, uint32_t handle, uintptr_t file, uintptr_t key, uint32_t *error);
/* 1 if handle names an open port (no side effect), else LC_INVALID_HANDLE. */
int lc_iocp_validate(lc_iocp_context *, uint32_t handle, uint32_t *error);
int lc_iocp_post(lc_iocp_context *, uint32_t handle, uint32_t bytes, uintptr_t key, void *overlapped, uint32_t *error);
/* GetQueuedCompletionStatusEx semantics without alertable waits: blocks until
 * at least one packet, timeout, or close; then removes up to count packets in
 * FIFO order. Close while waiting fails with LC_ABANDONED_WAIT_0. */
int lc_iocp_get(lc_iocp_context *, uint32_t handle, lc_entry *entries, uint32_t count,
                uint32_t *removed, uint32_t timeout_ms, uint32_t *error);
/* Invalidates the handle immediately. Queued packets are discarded and blocked
 * waiters are woken and fail with LC_ABANDONED_WAIT_0. Close then WAITS FOR
 * QUIESCENCE: it returns only after every getter has left the port state and
 * the context lock, so a successful return means no thread still depends on
 * the port or on the lock. Do not call it from a thread that holds anything a
 * getter needs to return (the wait is unbounded). A getter's final return
 * instructions may still be executing inside the provider code; the module
 * must not be unloaded until those threads are joined (see README). */
int lc_iocp_close(lc_iocp_context *, uint32_t handle, uint32_t *error);
unsigned lc_iocp_open_ports(lc_iocp_context *);
/* Number of ports that are open, closing or still have a thread inside. The
 * lock may be destroyed (DLL detach) only when this is zero; open_ports alone
 * drops at the start of close and is not a quiescence signal. */
unsigned lc_iocp_busy(lc_iocp_context *);

#ifdef __cplusplus
}
#endif
#endif
