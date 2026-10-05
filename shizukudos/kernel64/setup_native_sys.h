/* SPDX-License-Identifier: GPL-2.0-only */
#ifndef SHZ_SETUP_NATIVE_SYS_H
#define SHZ_SETUP_NATIVE_SYS_H
#include "proc_internal.h"
int32_t setup_native_syscall(process_t *,uint64_t,uint64_t);
int32_t setup_target_syscall(process_t *,uint64_t,uint64_t);
/* Kernel-only before-first-thread constructor, with actual loader node custody. */
int32_t setup_target_prepare(process_t *,void *);
int setup_target_prepared(process_t *);
void setup_native_process_teardown(process_t *);
#endif
