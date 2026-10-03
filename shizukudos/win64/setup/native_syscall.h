/* SPDX-License-Identifier: GPL-2.0-only */
#ifndef SHZ_SETUP_NATIVE_SYSCALL_H
#define SHZ_SETUP_NATIVE_SYSCALL_H
#include "../../kernel64/setup_native_abi.h"
/* Connected typed transport, not a complete native_provider backend. Caller
 * still must use the retained capability handle, never legacy raw blk calls.
 * The current kernel reports producer_admission_available=0. */
int32_t shz_native_call(shz_native_call_v1 *);
void shz_native_call_init(shz_native_call_v1 *,uint32_t);
#endif
