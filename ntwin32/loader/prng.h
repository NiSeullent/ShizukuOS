/* SPDX-License-Identifier: GPL-2.0-only
 * bcryptprimitives!ProcessPrng. Microsoft documents this as filling the
 * caller buffer and returning TRUE. A missing or empty buffer is rejected.
 * Entropy failure returns FALSE instead of inventing bytes.
 */
#ifndef NTW_PRNG_H
#define NTW_PRNG_H
#include <stdint.h>
typedef int (*ntw_entropy_fn)(void *user, uint8_t *buffer, uint32_t bytes);
int ntw_process_prng(void *buffer, uint32_t bytes, ntw_entropy_fn fill, void *user, uint32_t *error);
#endif
