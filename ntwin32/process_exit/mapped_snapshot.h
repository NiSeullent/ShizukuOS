/* SPDX-License-Identifier: GPL-2.0-only */
#ifndef MX_SNAPSHOT_H
#define MX_SNAPSHOT_H
#include <stddef.h>
#include <stdint.h>
#define MX_OWNERS 3u
#define MX_CALLBACKS 4u
#define MX_MAGIC 0x4d585031u
#define MX_KERNEL32 1u
#define MX_OWN_OBSERVER 2u
enum mx_error {MX_OK=0,MX_BAD_STATE,MX_BAD_IMAGE,MX_BAD_CODE,MX_BAD_TLS,
               MX_BAD_OWNER,MX_MISSING_TLS,MX_DETACHED_DEPENDENCY};
typedef struct mx_owner {uint32_t thread_id;uintptr_t tls_data;uint32_t tls_bytes,marker;} mx_owner;
typedef struct mx_spec {
 uintptr_t image_base;uint32_t image_bytes,tls_slot,dependencies;
 uint32_t entry_rva,callback_count,callbacks[MX_CALLBACKS];
 uint32_t owner_count;mx_owner owners[MX_OWNERS];
} mx_spec;
typedef struct mx_snapshot {uint32_t sealed;mx_spec spec;} mx_snapshot;
typedef int (*mx_code_guard)(void *,uint32_t);
/* One caller publishes only after its real image, graph attach and every
 * eligible thread TLS publication completed. Native manager registration is
 * the release publication. The resulting snapshot is never mutated/reused.
 * This helper does not allocate, invoke code or infer thread liveness.
 */
enum mx_error mx_seal(mx_snapshot *,const mx_spec *,mx_code_guard,void *);
enum mx_error mx_dispatch_guard(const mx_snapshot *,uint32_t,uintptr_t,uint32_t);
#endif
