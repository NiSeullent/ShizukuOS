/* SPDX-License-Identifier: GPL-2.0-only
 * Single-thread FLS. Index 0 stays unused, matching the project's m98_fls.c.
 * Values are per calling thread id. No fiber switch is implemented.
 * Callbacks run on FlsFree when the current value is non-NULL.
 */
#ifndef NTW_FLS_H
#define NTW_FLS_H
#include <stdint.h>
#define NTW_FLS_LIMIT 128u
#define NTW_FLS_OUT_OF_INDEXES 0xffffffffu
#if defined(__i386__)
#define NTW_FLS_CALL __attribute__((stdcall))
#else
#define NTW_FLS_CALL
#endif
typedef void (NTW_FLS_CALL *ntw_fls_callback)(void *value);
uint32_t ntw_fls_alloc(ntw_fls_callback callback);
uint32_t ntw_fls_free(uint32_t index);
void *ntw_fls_get(uint32_t index);
uint32_t ntw_fls_set(uint32_t index, void *value);
uint32_t ntw_fls_last_error(void);
#endif
