/* SPDX-License-Identifier: GPL-2.0-only */
#ifndef K64_SAW_H
#define K64_SAW_H
#include "proc_internal.h"
#include "../abi/shz_saw.h"
/* Kernel callers only; user requests and executable names cannot set protection. */
void process_saw_protect(process_t *, uint32_t);
int32_t process_attach_parent(process_t *, process_t *);
int32_t saw_execute(process_t *, const shz_saw_request *, shz_saw_reply *);
int32_t saw_syscall(process_t *, uint64_t, uint64_t, uint64_t, uint64_t);
int32_t sys_ext_saw(process_t *, struct regs *, uint32_t, uint64_t, uint64_t, uint64_t, uint64_t);
#endif
