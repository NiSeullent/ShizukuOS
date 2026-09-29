/* SPDX-License-Identifier: GPL-2.0-only
 * Win32-shaped Add/Remove adapter over the existing ReactOS-reference
 * registry. Handles are numeric tokens, not ReactOS list-node pointers.
 * A NULL callback is rejected. This does not install a CPU exception hook.
 */
#ifndef NTW_K32VEH_H
#define NTW_K32VEH_H
#include <stdint.h>
#include "veh.h"
#if defined(__i386__)
#define NTW_VEH_CALL __attribute__((stdcall))
#else
#define NTW_VEH_CALL
#endif
typedef int32_t (NTW_VEH_CALL *ntw_vectored_handler)(void *exception_pointers);
int ntw_k32_init(void);
int ntw_k32_add(uint32_t first, ntw_vectored_handler handler, void **out_handle);
int ntw_k32_remove(void *handle);
int ntw_k32_dispatch(void *record, void *context, int32_t *disposition);
void ntw_k32_test_reset(void);
#endif
