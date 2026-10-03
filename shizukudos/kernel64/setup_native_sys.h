/* SPDX-License-Identifier: GPL-2.0-only */
#ifndef SHZ_SETUP_NATIVE_SYS_H
#define SHZ_SETUP_NATIVE_SYS_H
#include "proc_internal.h"
int32_t setup_native_syscall(process_t *,uint64_t,uint64_t);
void setup_native_process_teardown(process_t *);
#endif
