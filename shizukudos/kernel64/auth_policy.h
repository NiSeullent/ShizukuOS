/* SPDX-License-Identifier: GPL-2.0-only */
#ifndef SHZ_AUTH_POLICY_H
#define SHZ_AUTH_POLICY_H
#include "proc_internal.h"
#include "../accounts/account.h"
struct fsnode;
int32_t shz_auth_object_name(process_t *,char *,size_t);
int shz_auth_gui_take_entry(process_t *);
int shz_auth_process_access(process_t *,process_t *);
int shz_auth_saw_process_access(process_t *,process_t *);
int shz_auth_sound_control_allowed(process_t *); /* actual normal/elevated session; no bootstrap/sandbox grant */
int shz_auth_saw_force_allowed(process_t *); /* enrolled, elevated administrator only */
int shz_auth_thread_access(process_t *,uint64_t);
int shz_auth_inherit(process_t *,process_t *);
int shz_auth_process_pending(process_t *);
void shz_auth_process_ready(process_t *);
/* Anonymous W64 bridge admission is development-only, not authentication.
 * Final publication shares account enrollment's authority mutex. */
int shz_auth_bridge_development_allowed(void);
int32_t shz_auth_bridge_development_publish(process_t *,thread_t *);
int shz_auth_handle_allowed(process_t *,kobject_t *);
void shz_auth_process_gone(process_t *);
int shz_auth_path_access(process_t *,const char *,int);
int shz_auth_node_access(process_t *,const struct fsnode *,int);
int shz_auth_special_allowed(process_t *,uint32_t);
int shz_auth_syscall_allowed(process_t *,uint32_t);
int32_t shz_auth_bootstrap_prepare(process_t *,void *);
/* Kernel boot supervisor only; ctx is the loader-verified immutable RAM fsnode. */
int32_t shz_auth_logon_prepare(process_t *,void *);
int shz_auth_logon_child_pid(void);
int32_t shz_auth_syscall(process_t *,uint64_t,uint64_t,uint64_t,uint64_t);
/* ---- Persistent account store (implemented by the SFS/fs worker) ----
 * load: copy the last committed record into buf; 0 + *len, SHZ_AUTH_STORE_ABSENT
 *   when never written, negative on I/O error. commit: atomically replace the
 *   record (temp write, flush, replace, flush); 0 only once durable, and on
 *   failure the previous record must remain intact. Callbacks run under the
 *   account authority mutex and must not call shz_auth_*. The record holds
 *   salts and PBKDF2 digests only.
 * SHZ_AUTH_STORE_DIR is the single protected store directory: the ShizukuFS
 * record wall on the installed system volume (sfs_mount.h SFSK_ACCOUNT_DIR),
 * used by auth_store_sfs.c. shz_auth_path_access/shz_auth_node_access deny it
 * (any drive, with/without drive letter, \\??\\ etc., case-insensitive, '/'
 * or '\\') to every user-mode subject in every realm state. */
#define SHZ_AUTH_STORE_ABSENT 1
#define SHZ_AUTH_STORE_DIR "\\SHZ\\ACCOUNTS"
typedef struct shz_auth_store_ops {
    int (*load)(void *ctx,void *buf,size_t cap,size_t *len);
    int (*commit)(void *ctx,const void *buf,size_t len);
    void *ctx;
} shz_auth_store_ops;
/* Once, after the SFS volume mounts and before any user process. Corrupt or
 * unreadable stores seal the realm: enrolled, no usable account, no anonymous
 * development mode (fail closed). */
int32_t shz_auth_store_attach(const shz_auth_store_ops *ops);
/* For the attacher's boot log: realm storage state and account count. */
#define SHZ_AUTH_STORE_VOLATILE 0
#define SHZ_AUTH_STORE_PERSISTENT 1
#define SHZ_AUTH_STORE_SEALED 2
int shz_auth_store_state(uint32_t *accounts);

/* ---- Authenticated endpoint broker (consumed by subsys64.c) ----
 * `owner` is the opaque generational W64 endpoint owner derived by the service
 * from VxD context; it is never a SID and 0 is invalid. Owners must never be
 * reused after departure. All entries fail closed without an enrolled realm. */
#define SHZ_AUTH_EP_STANDARD 0u   /* least privilege: medium integrity, no roles */
#define SHZ_AUTH_EP_ELEVATED 1u   /* consumes a single-use confirmed elevation */
#define SHZ_AUTH_EP_SANDBOX 2u    /* low integrity sandbox of the bound subject */
#define SHZ_AUTH_EP_LIMIT 16u
#define SHZ_AUTH_EP_ELEVATION_MS 30000u
typedef struct {uint64_t owner,epoch;uint32_t mode,reserved;shz_subject subject;} shz_auth_endpoint_grant;
int32_t shz_auth_endpoint_login(uint64_t owner,const char *user,const void *pw,size_t pw_bytes);
int32_t shz_auth_endpoint_confirm_elevation(uint64_t owner,const char *user,const void *pw,size_t pw_bytes);
int32_t shz_auth_endpoint_register(uint64_t owner,const char *user,const void *pw,size_t pw_bytes,uint32_t roles);
int32_t shz_auth_endpoint_query(uint64_t owner,shz_subject *out,uint64_t *epoch);
void shz_auth_endpoint_depart(uint64_t owner);
int32_t shz_auth_endpoint_prepare(uint64_t owner,uint32_t mode,shz_auth_endpoint_grant *grant);
/* ldr_create_ex_t.prepare with prepare_ctx = grant; use with hold_pending=1. */
int32_t shz_auth_endpoint_bind_child(process_t *child,void *grant);
int32_t shz_auth_endpoint_publish(const shz_auth_endpoint_grant *grant,process_t *,thread_t *);
int shz_auth_endpoint_child_owned(uint64_t owner,uint64_t epoch,process_t *);
/* Channel epoch (service channel generation) change: drops every endpoint
 * login, pending elevation ticket and unpublished grant/held child bound to a
 * different channel epoch, including owners that never created a child. */
void shz_auth_endpoint_epoch_reset(uint64_t channel_epoch);
/* 1 only when `owner` has a live login in the current channel epoch whose
 * login generation equals `epoch`, and `child` is the exact process bound to it
 * and published by shz_auth_endpoint_publish. Non-blocking (irq_save only);
 * for every slot op and async publication in subsys64.c. */
int shz_auth_endpoint_binding_current(uint64_t owner,uint64_t epoch,process_t *child);
#endif
