/* SPDX-License-Identifier: GPL-2.0-only */
#ifndef NTWP_TABLE_H
#define NTWP_TABLE_H
#include <stdint.h>
#include <stddef.h>

/* Wire layout is the original 32-bit get_api_table ABI, not host pointers. */
typedef int (*ntwp_read_fn)(void *, uint32_t, void *, uint32_t, int);
enum { NTWP_MISSING = 0, NTWP_FOUND = 1, NTWP_INVALID = -1 };
int ntwp_find_table(ntwp_read_fn read, void *context, uint32_t tables,
                    const char *expected_dll, const char *name, uint16_t ordinal,
                    uint32_t *address);
#endif
