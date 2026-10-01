/* SPDX-License-Identifier: GPL-2.0-only */
#ifndef SHZ_K64_GFX_ADDRESS_H
#define SHZ_K64_GFX_ADDRESS_H
#include <stdint.h>

/* gfx_fb.c reserves this first private alias at DIRECT_MAP + 64 GiB.
 * GOP MMIO uses DIRECT_MAP + physical address, so admission stops below it.
 * This conservative limit also excludes the later SYSBLK, KWIN, NTDRV and
 * KUSER aliases without pretending that every larger physical address is free.
 * Both the arena and its admission boundary use this shared definition. */
#define K64_GFX_ARENA_OFFSET (UINT64_C(64) << 30)

#endif
