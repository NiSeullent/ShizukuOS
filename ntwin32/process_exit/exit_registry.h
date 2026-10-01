/* SPDX-License-Identifier: GPL-2.0-only */
#ifndef NTW_EXIT_REGISTRY_H
#define NTW_EXIT_REGISTRY_H
#include <stddef.h>
#include <stdint.h>
#if defined(_WIN32) && defined(__i386__)
#define PX_CALL __attribute__((stdcall))
#else
#define PX_CALL
#endif
#ifdef __cplusplus
extern "C" {
#endif
enum { PX_CALLBACKS=8, PX_SNAPSHOTS=128, PX_INVALID=87, PX_BUSY=170,
       PX_NO_MEMORY=8, PX_NOT_FOUND=1168 };
#define PX_CLOSED UINT32_C(0x80000000)
typedef void (PX_CALL *px_callback)(void *,uint32_t,uintptr_t);
typedef struct px_record {px_callback callback;void *context;size_t bytes;uint32_t token;} px_record;
typedef struct px_snapshot {uint32_t count;px_record records[PX_CALLBACKS];} px_snapshot;
typedef struct px_ops {
 void *opaque;
 uint32_t (*load)(void *,volatile uint32_t *);
 uint32_t (*cas)(void *,volatile uint32_t *,uint32_t,uint32_t);
 int (*validate)(void *,px_callback,void *,size_t);
} px_ops;
typedef struct px_registry {
 px_ops ops;uint32_t magic,next_snapshot,next_token;
 volatile uint32_t current,mutating;
 px_snapshot snapshots[PX_SNAPSHOTS];
} px_registry;
/* Initialize before calls; never move/reinitialize the registry afterwards.
 * Atomic operations are acquire/release (CAS is acquire/release on success).
 * Every published snapshot is immutable and never reused. Capacity exhaustion
 * is explicit, including unregister: context must stay alive if it fails.
 * Callback/context are borrowed through successful unregister or process exit.
 * validate must establish process-lifetime native-EXE code/static-data storage.
 */
int px_init(px_registry *,const px_ops *);
int px_register(px_registry *,px_callback,void *,size_t,uint32_t *,uint32_t *);
int px_unregister(px_registry *,uint32_t,uint32_t *);
/* ONLY for the OS process-termination DLL notification after other threads
 * have stopped. This takes no mutation lock; a stopped publisher may retain it.
 * reserved must be nonzero; dynamic unload is not termination. No resources
 * are freed and no native DLL is unloaded. Callbacks have DllMain restrictions.
 */
int px_terminate(px_registry *,uint32_t,uintptr_t,uint32_t *);
uint32_t px_count(px_registry *);
#ifdef __cplusplus
}
#endif
#endif
