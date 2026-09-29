/* SPDX-License-Identifier: GPL-2.0-only */
#include "pool.h"
#include "cpu.h"

#define POOL_PAGES 2048     /* 8 MiB */
static uint8_t pool_mem[POOL_PAGES * 4096] __attribute__((aligned(4096)));
static unsigned pool_used;

void *pool_alloc_pages(unsigned pages)
{
    void *p;
    if (!pages || pages > POOL_PAGES - pool_used)
        return 0;
    p = pool_mem + (size_t)pool_used * 4096;
    pool_used += pages;
    memset(p, 0, (size_t)pages * 4096);
    return p;
}

uint64_t pool_free_pages(void) { return POOL_PAGES - pool_used; }
