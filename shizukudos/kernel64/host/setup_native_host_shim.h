#ifndef SHZ_NATIVE_HOST_SHIM_H
#define SHZ_NATIVE_HOST_SHIM_H
/* SPDX-License-Identifier: GPL-2.0-only */
#include "blk_authority_host_shim.h"
#include "../ntsys.h"
typedef struct {int pid,teardown;} process_t;
int copy_from_user(process_t *,void *,uint64_t,uint64_t);
int copy_to_user(process_t *,uint64_t,const void *,uint64_t);

#endif
