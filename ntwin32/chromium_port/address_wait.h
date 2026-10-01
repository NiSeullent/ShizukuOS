/* SPDX-License-Identifier: GPL-2.0-only */
#ifndef NTW_ADDRESS_WAIT_H
#define NTW_ADDRESS_WAIT_H
#include <stddef.h>
#include <stdint.h>
#ifdef __cplusplus
extern "C" {
#endif
enum { AW_CAPACITY=128, AW_INVALID_PARAMETER=87, AW_NO_MEMORY=8,
       AW_BUSY=170, AW_TIMEOUT=1460, AW_BAD_BACKEND=31 };
#define AW_WAIT_FAILED UINT32_MAX
typedef struct aw_ops {
 void *opaque;
 void (*enter)(void *); void (*leave)(void *);
 uintptr_t (*create)(void *); int (*signal)(void *,uintptr_t);
 uint32_t (*wait)(void *,uintptr_t,uint32_t); int (*close)(void *,uintptr_t);
 uint32_t (*error)(void *);
} aw_ops;
typedef struct aw_slot {
 volatile void *address; uintptr_t event;
 int next; unsigned state,signaled;
} aw_slot;
typedef struct aw_context {
 aw_ops ops; aw_slot slots[AW_CAPACITY];
 unsigned magic,active,retained; int head,tail;
} aw_context;
/* Initialized once before threads start. The context and ops outlive all calls.
 * All callbacks must be non-reentrant. Locks must not fail. Caller memory must
 * remain valid. This is process-local, with explicit capacity/resource limits. */
int aw_init(aw_context *,const aw_ops *);
int aw_wait(aw_context *,volatile void *,const void *,size_t,uint32_t,uint32_t *);
int aw_wake(aw_context *,const void *,int,uint32_t *);
/* May be called only after every calling thread has joined. A failed Close
 * retains ownership in a non-reusable slot; cleanup retries those handles. */
int aw_cleanup(aw_context *,int,uint32_t *);
unsigned aw_pending(aw_context *);
#ifdef __cplusplus
}
#endif
#endif
