/* SPDX-License-Identifier: GPL-2.0-only
 * One-time initialization. A failed callback leaves the cell clear so another
 * call can try again. Wine sync.c was not copied.
 */
#ifndef NTW_INITONCE_H
#define NTW_INITONCE_H
#include <stdint.h>
typedef void (*ntw_init_pause)(void);
#ifdef NTW_I386_LOADER
typedef uint32_t __attribute__((stdcall)) (*ntw_init_fn)(uint32_t once, uint32_t param, uint32_t *context);
#else
typedef uint32_t (*ntw_init_fn)(uint32_t once, uint32_t param, uint32_t *context);
#endif
void ntw_init_set_pause(ntw_init_pause pause);
int ntw_init_execute(uint32_t *once, ntw_init_fn fn, uint32_t param, uint32_t *context, uint32_t *error);
#endif
