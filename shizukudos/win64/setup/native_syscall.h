/* SPDX-License-Identifier: GPL-2.0-only */
#ifndef SHZ_SETUP_NATIVE_SYSCALL_H
#define SHZ_SETUP_NATIVE_SYSCALL_H
#include "../../kernel64/setup_native_abi.h"
/* Connected typed transport, not a complete native_provider backend. Caller
 * still must use the retained capability handle, never legacy raw blk calls.
 * Public kernels report state0 (absent); state1 is available, state2 is configured but invalid and must refuse. */
int32_t shz_native_call(shz_native_call_v1 *);
void shz_native_call_init(shz_native_call_v1 *,uint32_t);
#endif
