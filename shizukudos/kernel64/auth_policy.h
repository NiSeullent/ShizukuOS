/* SPDX-License-Identifier: GPL-2.0-only */
#ifndef SHZ_AUTH_POLICY_H
#define SHZ_AUTH_POLICY_H
#include "proc_internal.h"
#include "../accounts/account.h"
struct fsnode;
int32_t shz_auth_object_name(process_t *,char *,size_t);
int shz_auth_gui_take_entry(process_t *);
int shz_auth_process_access(process_t *,process_t *);
int shz_auth_thread_access(process_t *,uint64_t);
int shz_auth_inherit(process_t *,process_t *);
int shz_auth_process_pending(process_t *);
void shz_auth_process_ready(process_t *);
int shz_auth_handle_allowed(process_t *,kobject_t *);
void shz_auth_process_gone(process_t *);
int shz_auth_path_access(process_t *,const char *,int);
int shz_auth_node_access(process_t *,const struct fsnode *,int);
int shz_auth_special_allowed(process_t *,uint32_t);
int shz_auth_syscall_allowed(process_t *,uint32_t);
int32_t shz_auth_bootstrap_prepare(process_t *,void *);
int32_t shz_auth_syscall(process_t *,uint64_t,uint64_t,uint64_t,uint64_t);
#endif
