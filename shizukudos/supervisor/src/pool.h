/* SPDX-License-Identifier: GPL-2.0-only
 * Page-granular bump allocator over a static .bss pool. Domain page tables, VMCS
 * regions and bitmaps come from here; nothing is ever freed while the Supervisor runs.
 */
#ifndef SHZ_POOL_H
#define SHZ_POOL_H
#include <stddef.h>
#include <stdint.h>

void *pool_alloc_pages(unsigned pages);       /* zeroed, 4 KiB aligned; NULL when exhausted */
uint64_t pool_free_pages(void);
#endif
