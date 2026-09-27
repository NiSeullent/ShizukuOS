/* SPDX-License-Identifier: GPL-2.0-only */
#ifndef NTW_SYNC_H
#define NTW_SYNC_H
#include <stdint.h>
typedef struct { volatile uint32_t state; } ntw_srw;
typedef void (*ntw_yield_fn)(void);
void ntw_srw_init(ntw_srw *);
int ntw_srw_try_exclusive(ntw_srw *);
int ntw_srw_try_shared(ntw_srw *);
void ntw_srw_acquire_exclusive(ntw_srw *, ntw_yield_fn);
void ntw_srw_acquire_shared(ntw_srw *, ntw_yield_fn);
void ntw_srw_release_exclusive(ntw_srw *);
void ntw_srw_release_shared(ntw_srw *);
struct ntw_tick_clock { uint32_t previous, high; };
/* Must be serialized; no inference about wraps before the first sample. */
uint64_t ntw_tick_sample(struct ntw_tick_clock *, uint32_t);
#endif
