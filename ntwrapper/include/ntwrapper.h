/* SPDX-License-Identifier: GPL-2.0-only
 * Original NTWrapper9x core. No NT/KernelEx binary or implementation dependency.
 * The embedding kernel supplies a non-reentrant, IRQ-safe lock pair. */
#ifndef NTWRAPPER9X_H
#define NTWRAPPER9X_H
#include <stdint.h>
#include <stddef.h>
#define NTW_ABI_VERSION 1u
#define NTW_MAX_OBJECTS 64u
#define NTW_EVENT_QUERY 1u
#define NTW_EVENT_MODIFY 2u
#define NTW_EVENT_WAIT 4u
#define NTW_EVENT_ALL 7u
typedef uint32_t ntw_handle;
enum ntw_status { NTW_OK = 0, NTW_PENDING = 1, NTW_INVALID = -1,
    NTW_NO_MEMORY = -2, NTW_BAD_HANDLE = -3, NTW_ACCESS_DENIED = -4,
    NTW_BUSY = -5, NTW_UNSUPPORTED = -6 };
struct ntw_lock_ops {
    uintptr_t (*enter)(void *opaque);
    void (*leave)(void *opaque, uintptr_t saved);
    void *opaque;
};
struct ntw_object {
    uint32_t generation, references, access;
    uint8_t occupied, open, manual_reset, signaled;
};
struct ntw_context {
    uint32_t version;
    struct ntw_lock_ops lock;
    struct ntw_object objects[NTW_MAX_OBJECTS];
};
/* Zero-initialize a lease before first use. It must not be copied, reused while
 * live, used concurrently or released twice. Its contents
 * are private to the core. Close invalidates the handle but preserves leases. */
struct ntw_lease { struct ntw_context *owner; uint32_t index, generation; };
int ntw_initialize(struct ntw_context *, const struct ntw_lock_ops *);
int ntw_event_create(struct ntw_context *, int manual, int signaled,
                     uint32_t access, ntw_handle *);
int ntw_reference(struct ntw_context *, ntw_handle, uint32_t access,
                  struct ntw_lease *);
int ntw_dereference(struct ntw_lease *);
int ntw_close(struct ntw_context *, ntw_handle);
int ntw_event_set(struct ntw_context *, ntw_handle, int *previous);
int ntw_event_reset(struct ntw_context *, ntw_handle, int *previous);
int ntw_event_query(struct ntw_context *, ntw_handle, int *signaled);
/* Nonblocking acquisition. PENDING means no signal was consumed. */
int ntw_event_try_wait(struct ntw_context *, ntw_handle);
int ntw_shutdown(struct ntw_context *);
#endif
